//! DNSSEC validation verdicts and their mapping onto a response.

use styx_proto::{Message, ResponseCode};

use crate::domain::error::DenialError;
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
    /// Non-existence of the queried name or type was cryptographically proven via NSEC or NSEC3.
    ProvenDenialOfExistence,
    /// The denial rests on an NSEC3 Opt-Out span, which may hide an unsigned delegation,
    /// so it cannot be Secure (RFC 5155 §9.2).
    Nsec3OptOut,
    /// No trust anchor path or missing intermediate zone cut material.
    NoPathToAnchor,
    /// Chain descent exceeded the configured maximum number of zone cuts.
    MaxZoneCutsExceeded,
    /// Chain source reported a zone apex mid-descent without parent delegation material.
    UnexpectedZoneApex,
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
    /// Trust anchor source failed to load configured anchors.
    TrustAnchorUnavailable,
    /// Response lacked a question or carried a malformed answer or authority section.
    MalformedResponse,
    /// Signature verification attempt or failure budget was exhausted (KeyTrap protection).
    SignatureBudgetExceeded,
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

    /// Whether `mode` answers this outcome with SERVFAIL instead of the data: under
    /// [`FailureMode::HardFail`], every `Bogus` and every below-anchor `Indeterminate` (all
    /// but `NoPathToAnchor`, which no configured anchor covers). Never under `WarnOnly`.
    #[must_use]
    pub fn refuses_under(&self, mode: FailureMode) -> bool {
        mode == FailureMode::HardFail
            && match self.verdict {
                ValidationVerdict::Bogus => true,
                ValidationVerdict::Indeterminate => self.reason != VerdictReason::NoPathToAnchor,
                ValidationVerdict::Secure | ValidationVerdict::Insecure => false,
            }
    }

    /// Applies the validation outcome to the response's AD bit and, when
    /// [`Self::refuses_under`] `mode`, turns the response into SERVFAIL.
    pub fn apply_to_message(&self, message: &mut Message, mode: FailureMode) {
        message.header.authentic_data = self.verdict == ValidationVerdict::Secure;
        if self.refuses_under(mode) {
            message.header.rcode = ResponseCode::SERVFAIL;
            message.answers.clear();
            message.authorities.clear();
            message.additionals.clear();
        }
    }
}

impl From<DenialError> for ValidationOutcome {
    fn from(error: DenialError) -> Self {
        match error {
            DenialError::Nsec3IterationsExceeded => {
                Self::bogus(VerdictReason::Nsec3IterationsExceeded)
            }
            DenialError::UnsupportedHashAlgorithm(_) => {
                Self::insecure(VerdictReason::UnsupportedAlgorithm)
            }
            DenialError::DenialProofIncomplete | DenialError::NotCovered => {
                Self::bogus(VerdictReason::DenialProofIncomplete)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hard_fail_refuses_and_only_bogus_or_below_anchor_indeterminate() {
        let cases = [
            (
                ValidationOutcome::secure(VerdictReason::AnchorMatched),
                false,
            ),
            (
                ValidationOutcome::insecure(VerdictReason::ProvenUnsignedDelegation),
                false,
            ),
            (ValidationOutcome::bogus(VerdictReason::NoValidRrsig), true),
            (
                ValidationOutcome::indeterminate(VerdictReason::ChainMaterialUnavailable),
                true,
            ),
            (
                ValidationOutcome::indeterminate(VerdictReason::NoPathToAnchor),
                false,
            ),
        ];
        for (outcome, refused) in cases {
            assert_eq!(
                outcome.refuses_under(FailureMode::HardFail),
                refused,
                "{outcome:?}"
            );
            assert!(!outcome.refuses_under(FailureMode::WarnOnly), "{outcome:?}");
        }
    }
}
