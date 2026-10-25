//! DNSSEC validation verdicts and their mapping onto a response.

use styx_proto::{Message, ResponseCode};

use crate::domain::policy::FailureMode;

/// Primary validation verdict for a DNS resolution outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationVerdict {
    /// Cryptographic chain from a trust anchor to the records is valid.
    Secure,
    /// Proved to be deliberately unsigned (or uses an unsupported algorithm).
    Insecure,
    /// Signatures failed, expired, mismatch detected, or denial is incomplete.
    Bogus,
    /// Chain could not be completed (e.g. missing upstream material).
    Indeterminate,
}

/// Detailed explanation for the given [`ValidationVerdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictReason {
    /// Record or DNSKEY matched a configured trust anchor.
    AnchorMatched,
    /// Non-existence of DS at zone cut was proven via NSEC or NSEC3.
    ProvenUnsignedDelegation,
    /// No trust anchor path or missing intermediate zone cut material.
    NoPathToAnchor,
    /// RRSIG validity period has passed according to the Clock.
    SignatureExpired,
    /// RRSIG validity period is in the future according to the Clock.
    SignatureNotYetValid,
    /// No valid RRSIG was found for the RRset among candidate keys.
    NoValidRrsig,
    /// DS digest does not match candidate DNSKEY.
    DsDnskeyMismatch,
    /// Algorithm is not supported; treated safely as Insecure.
    UnsupportedAlgorithm,
    /// Denial-of-existence proof is missing required covering records.
    DenialProofIncomplete,
    /// NSEC3 iterations parameter exceeded configured safety cap.
    Nsec3IterationsExceeded,
    /// Upstream source failed to supply required chain records.
    ChainMaterialUnavailable,
}

/// The complete outcome of validating a DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationOutcome {
    /// Overall security verdict.
    pub verdict: ValidationVerdict,
    /// Specific reason for the verdict.
    pub reason: VerdictReason,
}

impl ValidationOutcome {
    /// Constructs a new [`ValidationOutcome`].
    #[must_use]
    pub fn new(verdict: ValidationVerdict, reason: VerdictReason) -> Self {
        Self { verdict, reason }
    }

    /// A [`ValidationVerdict::Secure`] outcome.
    #[must_use]
    pub fn secure(reason: VerdictReason) -> Self {
        Self::new(ValidationVerdict::Secure, reason)
    }

    /// A [`ValidationVerdict::Insecure`] outcome.
    #[must_use]
    pub fn insecure(reason: VerdictReason) -> Self {
        Self::new(ValidationVerdict::Insecure, reason)
    }

    /// A [`ValidationVerdict::Bogus`] outcome.
    #[must_use]
    pub fn bogus(reason: VerdictReason) -> Self {
        Self::new(ValidationVerdict::Bogus, reason)
    }

    /// A [`ValidationVerdict::Indeterminate`] outcome.
    #[must_use]
    pub fn indeterminate(reason: VerdictReason) -> Self {
        Self::new(ValidationVerdict::Indeterminate, reason)
    }

    /// Applies the validation outcome to the response's AD bit and, for a `Bogus`
    /// verdict under [`FailureMode::HardFail`], turns the response into SERVFAIL.
    pub fn apply_to_message(&self, message: &mut Message, mode: FailureMode) {
        match self.verdict {
            ValidationVerdict::Secure => {
                message.header.authentic_data = true;
            }
            ValidationVerdict::Insecure | ValidationVerdict::Indeterminate => {
                message.header.authentic_data = false;
            }
            ValidationVerdict::Bogus => {
                message.header.authentic_data = false;
                if mode == FailureMode::HardFail {
                    message.header.rcode = ResponseCode::SERVFAIL;
                    message.answers.clear();
                }
            }
        }
    }
}
