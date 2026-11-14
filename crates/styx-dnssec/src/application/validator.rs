//! DNSSEC validator walking chains of trust from anchors to responses.

use styx_core::Clock;
use styx_proto::{Message, Name, Question, RData, RecordType, ResourceRecord};

use crate::application::authenticator::{Authenticator, WildcardClaim};
use crate::application::denial_verifier::verify_denial_proofs;
use crate::application::descent::{walk_chain_descent, Descent};
use crate::domain::denial::DenialProof;
use crate::domain::policy::ValidationPolicy;
use crate::domain::ports::{ChainSource, TrustAnchorSource};
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

const MAX_CNAME_HOPS: usize = 8;

/// Pure DNSSEC validator orchestrating chain-of-trust verification.
#[derive(Debug)]
pub struct Validator<C: Clock> {
    authenticator: Authenticator<C>,
}

impl<C: Clock> Validator<C> {
    /// Constructs a new [`Validator`].
    #[must_use]
    pub fn new(clock: C, policy: ValidationPolicy) -> Self {
        Self {
            authenticator: Authenticator::new(clock, policy),
        }
    }

    /// Evaluates a DNS message and returns a [`ValidationOutcome`].
    pub async fn validate<S: ChainSource, A: TrustAnchorSource>(
        &self,
        message: &Message,
        chain_source: &S,
        anchor_source: &A,
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

        let outcome = self
            .validate_inner(message, question, chain_source, anchor_source)
            .await;

        tracing::info!(
            verdict = ?outcome.verdict,
            reason = ?outcome.reason,
            failure_mode = ?self.authenticator.policy().failure_mode,
            "DNSSEC validation completed"
        );
        outcome
    }

    async fn validate_inner<S: ChainSource, A: TrustAnchorSource>(
        &self,
        message: &Message,
        question: &Question,
        chain_source: &S,
        anchor_source: &A,
    ) -> ValidationOutcome {
        let anchors = match anchor_source.anchors() {
            Ok(anchors) if !anchors.is_empty() => anchors,
            Ok(_) => {
                tracing::warn!("trust anchor set is empty");
                return ValidationOutcome::indeterminate(VerdictReason::NoPathToAnchor);
            }
            Err(error) => {
                tracing::warn!(%error, "failed to load trust anchors");
                return ValidationOutcome::indeterminate(VerdictReason::TrustAnchorUnavailable);
            }
        };

        match walk_chain_descent(&self.authenticator, &question.qname, chain_source, &anchors).await
        {
            Ok(Descent::Secure { zone, keys }) => {
                if message.answers.is_empty() {
                    verify_denial_proofs(
                        &self.authenticator,
                        &zone,
                        &question.qname,
                        question.qtype,
                        message,
                        &keys,
                    )
                } else {
                    self.verify_answer_rrsets(&zone, question, message, &keys)
                }
            }
            Ok(Descent::Ended(terminal_outcome)) => terminal_outcome,
            Err(descent_failure) => descent_failure,
        }
    }

    /// Verifies answer RRsets against the authenticated DNSKEYs, binds every answer RRset
    /// to the question (directly or along a CNAME chain), and validates authority denial
    /// proofs when an RRset was synthesized from a wildcard.
    fn verify_answer_rrsets(
        &self,
        zone: &Name,
        question: &Question,
        message: &Message,
        dnskeys: &[ResourceRecord],
    ) -> ValidationOutcome {
        let (signatures, data_records): (Vec<&ResourceRecord>, Vec<&ResourceRecord>) = message
            .answers
            .iter()
            .partition(|record| matches!(record.rdata, RData::Rrsig(_)));

        let wildcard_claims = match self.authenticator.authenticate_rrsets(
            data_records.iter().copied(),
            signatures.iter().copied(),
            dnskeys,
        ) {
            Ok(claims) => claims,
            Err(reason) => return ValidationOutcome::bogus(reason),
        };

        if !answers_match_question(question, &data_records) {
            return ValidationOutcome::bogus(VerdictReason::NoValidRrsig);
        }

        if let Err(outcome) = self.verify_wildcard_claims(zone, &wildcard_claims, message, dnskeys)
        {
            return outcome;
        }

        ValidationOutcome::secure(VerdictReason::AnchorMatched)
    }

    fn verify_wildcard_claims(
        &self,
        zone: &Name,
        claims: &[WildcardClaim],
        message: &Message,
        dnskeys: &[ResourceRecord],
    ) -> Result<(), ValidationOutcome> {
        if claims.is_empty() {
            return Ok(());
        }
        let mut denial_records = Vec::new();
        let mut signatures = Vec::new();
        for record in &message.authorities {
            match record.rdata {
                RData::Nsec(_) | RData::Nsec3(_) => denial_records.push(record),
                RData::Rrsig(_) => signatures.push(record),
                _ => {}
            }
        }
        if denial_records.is_empty() {
            return Err(ValidationOutcome::bogus(
                VerdictReason::DenialProofIncomplete,
            ));
        }
        if !self.authenticator.records_signed_by_any(
            denial_records.iter().copied(),
            signatures.iter().copied(),
            dnskeys,
        ) {
            return Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig));
        }
        let proof = DenialProof::from_records(&denial_records).map_err(ValidationOutcome::from)?;
        let cap = self.authenticator.policy().nsec3_max_iterations;
        for claim in claims {
            proof
                .verify_wildcard_expansion(zone, &claim.owner, claim.sig_labels, cap)
                .map_err(ValidationOutcome::from)?;
        }
        Ok(())
    }
}

fn answers_match_question(question: &Question, data_records: &[&ResourceRecord]) -> bool {
    let mut current_target = question.qname.to_canonical();
    let mut visited_owners = Vec::new();
    let mut matched_count = 0usize;

    for _ in 0..=MAX_CNAME_HOPS {
        if visited_owners.contains(&current_target) {
            return false;
        }
        let terminal_count = data_records
            .iter()
            .filter(|record| {
                record.rclass == question.qclass
                    && record.owner.eq_ignore_case(&current_target)
                    && (question.qtype == RecordType::ANY || record.rtype == question.qtype)
            })
            .count();
        if terminal_count > 0 {
            matched_count = matched_count.saturating_add(terminal_count);
            break;
        }
        if question.qtype == RecordType::CNAME {
            break;
        }
        let cnames: Vec<&Name> = data_records
            .iter()
            .filter(|record| {
                record.rclass == question.qclass && record.owner.eq_ignore_case(&current_target)
            })
            .filter_map(|record| match record.rdata {
                RData::Cname(ref next) => Some(next),
                _ => None,
            })
            .collect();
        let [next_target] = cnames.as_slice() else {
            break;
        };
        matched_count = matched_count.saturating_add(1);
        visited_owners.push(current_target);
        current_target = next_target.to_canonical();
    }

    matched_count > 0 && matched_count == data_records.len()
}
