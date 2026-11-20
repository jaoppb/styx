//! DNSSEC validator walking chains of trust from anchors to responses.

use styx_core::Clock;
use styx_proto::{Message, Name, Question, RData, RecordType, ResourceRecord};

use crate::application::authenticator::{Authenticator, WildcardClaim};
use crate::application::denial_verifier::{
    authenticated_denial_proof, denial_outcome, verify_denial_proofs,
};
use crate::application::descent::{signer_search_name, walk_chain_descent, Descent};
use crate::domain::answer_chain::{AnswerChain, ChainEnd, ChainLink};
use crate::domain::denial::DenialStrength;
use crate::domain::policy::ValidationPolicy;
use crate::domain::ports::ChainSource;
use crate::domain::trust_anchor::TrustAnchors;
use crate::domain::verdict::{ValidationOutcome, ValidationVerdict, VerdictReason};

/// Pure DNSSEC validator orchestrating chain-of-trust verification.
#[derive(Debug)]
pub struct Validator<C: Clock> {
    authenticator: Authenticator<C>,
    anchors: TrustAnchors,
}

impl<C: Clock> Validator<C> {
    /// Constructs a new [`Validator`] over the trust anchors loaded at startup.
    #[must_use]
    pub fn new(clock: C, policy: ValidationPolicy, anchors: TrustAnchors) -> Self {
        Self {
            authenticator: Authenticator::new(clock, policy),
            anchors,
        }
    }

    /// Evaluates a DNS message and returns a [`ValidationOutcome`].
    pub async fn validate<S: ChainSource>(
        &self,
        message: &Message,
        chain_source: &S,
    ) -> ValidationOutcome {
        let Some(question) = message.questions.first() else {
            return ValidationOutcome::indeterminate(VerdictReason::NoPathToAnchor);
        };

        let span = tracing::info_span!(
            "dnssec_validate",
            qname = %question.qname,
            qtype = %question.qtype.value(),
        );
        let _guard = span.enter();

        let outcome = self.validate_inner(message, question, chain_source).await;

        tracing::info!(
            verdict = ?outcome.verdict,
            reason = ?outcome.reason,
            failure_mode = ?self.authenticator.policy().failure_mode,
            "DNSSEC validation completed"
        );
        outcome
    }

    /// Validates every link of the answer chain in the zone that signs it, then the
    /// denial at the end of a chain that dangles. The weakest outcome wins.
    async fn validate_inner<S: ChainSource>(
        &self,
        message: &Message,
        question: &Question,
        chain_source: &S,
    ) -> ValidationOutcome {
        let Some(chain) = AnswerChain::follow(question, &message.answers) else {
            return ValidationOutcome::bogus(VerdictReason::NoValidRrsig);
        };
        let mut combined = ValidationOutcome::secure(VerdictReason::AnchorMatched);
        // Secure is the identity of `weakest`, so the first real outcome replaces it.
        for link in chain.links() {
            let outcome = self.verify_link(link, message, chain_source).await;
            combined = weakest(combined, outcome);
            if combined.verdict == ValidationVerdict::Bogus {
                return combined;
            }
        }
        if let ChainEnd::Dangling(target) = chain.end() {
            let outcome = self
                .verify_absence(target, question.qtype, message, chain_source)
                .await;
            combined = weakest(combined, outcome);
        }
        combined
    }

    /// Verifies one link's records against the keys of the zone that signs them.
    async fn verify_link<S: ChainSource>(
        &self,
        link: &ChainLink<'_>,
        message: &Message,
        chain_source: &S,
    ) -> ValidationOutcome {
        let rtype = link
            .records()
            .first()
            .map_or(RecordType::ANY, |record| record.rtype);
        let search = signer_search_name(link.owner(), rtype);
        let (zone, keys) = match self.descend(&search, chain_source).await {
            Ok(secure) => secure,
            Err(outcome) => return outcome,
        };
        let signatures = message
            .answers
            .iter()
            .filter(|record| matches!(record.rdata, RData::Rrsig(_)));
        let claims = match self.authenticator.authenticate_rrsets(
            link.records().iter().copied(),
            signatures,
            &keys,
        ) {
            Ok(claims) => claims,
            Err(reason) => return ValidationOutcome::bogus(reason),
        };
        match self.verify_wildcard_claims(&zone, &claims, message, &keys) {
            Ok(DenialStrength::Proven) => ValidationOutcome::secure(VerdictReason::AnchorMatched),
            Ok(DenialStrength::OptOut) => denial_outcome(DenialStrength::OptOut),
            Err(outcome) => outcome,
        }
    }

    /// Verifies that `target` holds no `qtype` data: the denial the response carries,
    /// checked in the zone that would sign that data.
    async fn verify_absence<S: ChainSource>(
        &self,
        target: &Name,
        qtype: RecordType,
        message: &Message,
        chain_source: &S,
    ) -> ValidationOutcome {
        let search = signer_search_name(target, qtype);
        match self.descend(&search, chain_source).await {
            Ok((zone, keys)) => {
                verify_denial_proofs(&self.authenticator, &zone, target, qtype, message, &keys)
            }
            Err(outcome) => outcome,
        }
    }

    /// The authenticated zone and keys enclosing `name`, or the outcome that ended the
    /// descent before it got there (an unsigned delegation, a failure).
    async fn descend<S: ChainSource>(
        &self,
        name: &Name,
        chain_source: &S,
    ) -> Result<(Name, Vec<ResourceRecord>), ValidationOutcome> {
        match walk_chain_descent(&self.authenticator, name, chain_source, &self.anchors).await? {
            Descent::Secure { zone, keys } => Ok((zone, keys)),
            Descent::Ended(outcome) => Err(outcome),
        }
    }

    fn verify_wildcard_claims(
        &self,
        zone: &Name,
        claims: &[WildcardClaim],
        message: &Message,
        dnskeys: &[ResourceRecord],
    ) -> Result<DenialStrength, ValidationOutcome> {
        if claims.is_empty() {
            return Ok(DenialStrength::Proven);
        }
        let proof = authenticated_denial_proof(&self.authenticator, message, dnskeys)?;
        let cap = self.authenticator.policy().nsec3_max_iterations;
        let mut strength = DenialStrength::Proven;
        for claim in claims {
            let claimed = proof
                .verify_wildcard_expansion(zone, &claim.owner, claim.sig_labels, cap)
                .map_err(ValidationOutcome::from)?;
            if claimed == DenialStrength::OptOut {
                strength = DenialStrength::OptOut;
            }
        }
        Ok(strength)
    }
}

/// The weaker of two outcomes: Bogus, then Indeterminate, then Insecure, then Secure.
/// A chain is only as strong as its weakest link. On a tie the later outcome wins, so a
/// response that is nothing but a proven denial reports that proof as its reason.
fn weakest(left: ValidationOutcome, right: ValidationOutcome) -> ValidationOutcome {
    const fn rank(verdict: ValidationVerdict) -> u8 {
        match verdict {
            ValidationVerdict::Secure => 0,
            ValidationVerdict::Insecure => 1,
            ValidationVerdict::Indeterminate => 2,
            ValidationVerdict::Bogus => 3,
        }
    }
    if rank(right.verdict) >= rank(left.verdict) {
        right
    } else {
        left
    }
}
