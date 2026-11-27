//! The resolution path's [`ResponseValidator`] port, implemented over `styx-dnssec`.

use styx_core::Clock;
use styx_dnssec::{
    ChainSource, FailureMode, TrustAnchors, ValidationPolicy, ValidationVerdict, Validator,
};
use styx_proto::{Message, Question};
use styx_resolution::{ResponseValidator, SecurityStatus, Validation};

/// Validates every upstream answer with `styx-dnssec`'s [`Validator`], fed by `source`.
pub struct DnssecValidator<C: Clock, S> {
    validator: Validator<C>,
    source: S,
    mode: FailureMode,
}

impl<C: Clock, S: ChainSource> DnssecValidator<C, S> {
    /// Judges answers under `policy` against `anchors`, refusing the verdicts its failure
    /// mode refuses.
    #[must_use]
    pub fn new(clock: C, policy: ValidationPolicy, anchors: TrustAnchors, source: S) -> Self {
        let mode = policy.failure_mode;
        Self {
            validator: Validator::new(clock, policy, anchors),
            source,
            mode,
        }
    }
}

impl<C: Clock, S: ChainSource + 'static> ResponseValidator for DnssecValidator<C, S> {
    async fn validate(&self, _question: &Question, response: &Message) -> Validation {
        let outcome = self.validator.validate(response, &self.source).await;
        Validation {
            status: match outcome.verdict {
                ValidationVerdict::Secure => SecurityStatus::Secure,
                ValidationVerdict::Insecure => SecurityStatus::Insecure,
                ValidationVerdict::Bogus => SecurityStatus::Bogus,
                ValidationVerdict::Indeterminate => SecurityStatus::Indeterminate,
            },
            rejected: outcome.refuses_under(self.mode),
        }
    }
}
