//! DNSSEC validator walking chains of trust from anchors to responses.

use styx_core::Clock;
use styx_proto::{Message, Name, RData, RecordType, ResourceRecord};

use crate::application::authenticator::Authenticator;
use crate::application::denial_verifier::verify_denial_proofs;
use crate::application::descent::walk_chain_descent;
use crate::domain::policy::ValidationPolicy;
use crate::domain::ports::{ChainSource, TrustAnchorSource};
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

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
    pub fn validate<S: ChainSource, A: TrustAnchorSource>(
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

        let outcome = self.execute_validation(
            &question.qname,
            question.qtype,
            message,
            chain_source,
            anchor_source,
        );
        tracing::info!(
            verdict = ?outcome.verdict,
            reason = ?outcome.reason,
            failure_mode = ?self.authenticator.policy().failure_mode,
            "DNSSEC validation completed"
        );
        outcome
    }

    fn execute_validation<S: ChainSource, A: TrustAnchorSource>(
        &self,
        qname: &Name,
        qtype: RecordType,
        message: &Message,
        chain_source: &S,
        anchor_source: &A,
    ) -> ValidationOutcome {
        let anchors = match anchor_source.anchors() {
            Ok(anchors) if !anchors.is_empty() => anchors,
            _ => return ValidationOutcome::indeterminate(VerdictReason::NoPathToAnchor),
        };

        let active_keys =
            match walk_chain_descent(&self.authenticator, qname, chain_source, &anchors) {
                Ok(keys) => keys,
                Err(outcome) => return outcome,
            };

        if message.answers.is_empty() {
            verify_denial_proofs(&self.authenticator, qname, qtype, message, &active_keys)
        } else {
            self.verify_answer_rrsets(message, &active_keys)
        }
    }

    fn verify_answer_rrsets(
        &self,
        message: &Message,
        dnskeys: &[ResourceRecord],
    ) -> ValidationOutcome {
        let (signatures, data_records): (Vec<&ResourceRecord>, Vec<&ResourceRecord>) = message
            .answers
            .iter()
            .partition(|record| matches!(record.rdata, RData::Rrsig(_)));

        if self
            .authenticator
            .records_signed_by_any(&data_records, &signatures, dnskeys)
        {
            ValidationOutcome::secure(VerdictReason::AnchorMatched)
        } else {
            ValidationOutcome::bogus(VerdictReason::NoValidRrsig)
        }
    }
}
