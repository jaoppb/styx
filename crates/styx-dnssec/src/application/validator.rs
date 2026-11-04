//! DNSSEC validator walking chains of trust from anchors to responses.

use styx_core::Clock;
use styx_proto::{Message, RData, ResourceRecord};

use crate::application::authenticator::Authenticator;
use crate::application::denial_verifier::verify_denial_proofs;
use crate::application::descent::{walk_chain_descent, Descent};
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

        let outcome = match walk_chain_descent(
            &self.authenticator,
            &question.qname,
            chain_source,
            &anchors,
        ) {
            Ok(Descent::Secure(active_keys)) => {
                if message.answers.is_empty() {
                    verify_denial_proofs(
                        &self.authenticator,
                        &question.qname,
                        question.qtype,
                        message,
                        &active_keys,
                    )
                } else {
                    self.verify_answer_rrsets(message, &active_keys)
                }
            }
            Ok(Descent::Ended(terminal_outcome)) => terminal_outcome,
            Err(descent_failure) => descent_failure,
        };

        tracing::info!(
            verdict = ?outcome.verdict,
            reason = ?outcome.reason,
            failure_mode = ?self.authenticator.policy().failure_mode,
            "DNSSEC validation completed"
        );
        outcome
    }

    /// Verifies answer RRsets against the authenticated DNSKEYs.
    ///
    /// Note: this intentionally validates that every answer RRset is validly signed by
    /// the authenticated keys, without evaluating whether the answer QNAME relates to
    /// the initial question via CNAME redirection or wildcard synthesis. That QNAME
    /// relationship validation is handled by the resolution pipeline (tracked in #133).
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
