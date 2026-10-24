//! DNSSEC verdict, policy, and cryptographic algorithm classifications.

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
    /// Whether this verdict was enforced (modifying response or returning SERVFAIL).
    pub enforced: bool,
}

impl ValidationOutcome {
    /// Constructs a new [`ValidationOutcome`].
    #[must_use]
    pub fn new(verdict: ValidationVerdict, reason: VerdictReason, enforced: bool) -> Self {
        Self {
            verdict,
            reason,
            enforced,
        }
    }

    /// Applies the validation outcome to the DNS response message header and answers.
    pub fn apply_to_message(&self, msg: &mut styx_proto::Message) {
        match self.verdict {
            ValidationVerdict::Secure => {
                msg.header.authentic_data = true;
            }
            ValidationVerdict::Insecure | ValidationVerdict::Indeterminate => {
                msg.header.authentic_data = false;
            }
            ValidationVerdict::Bogus => {
                msg.header.authentic_data = false;
                if self.enforced {
                    msg.header.rcode = styx_proto::ResponseCode::SERVFAIL;
                    msg.answers.clear();
                }
            }
        }
    }
}

/// Failure enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailureMode {
    /// Log verdicts at warn level without altering client response or setting SERVFAIL.
    WarnOnly,
    /// Reject bogus responses with SERVFAIL and assert Authentic Data (AD) bit on secure ones.
    #[default]
    HardFail,
}

/// Mandatory cap on NSEC3 hashing iterations (RFC 9276).
///
/// Uncapped NSEC3 is a remote denial of service vector because an attacker can specify
/// high iteration counts in records. RFC 9276 specifies that resolvers should set a
/// maximum iteration cap of 100 for all key sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nsec3IterationsCap(u16);

impl Nsec3IterationsCap {
    /// RFC 9276 recommended maximum iteration cap (100).
    pub const DEFAULT: Self = Self(100);

    /// Creates a new [`Nsec3IterationsCap`].
    #[must_use]
    pub const fn new(cap: u16) -> Self {
        Self(cap)
    }

    /// Returns the numerical iteration cap.
    #[must_use]
    pub const fn value(&self) -> u16 {
        self.0
    }
}

impl Default for Nsec3IterationsCap {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Support status of a cryptographic algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmSupport {
    /// Cryptographic algorithm is supported and safe to evaluate.
    Supported,
    /// Unknown or unrecognised algorithm; zone is treated as Insecure.
    UnknownTreatAsInsecure,
    /// Broken or deprecated algorithm; zone is refused as Bogus.
    Refused,
}

/// Explicit set of cryptographic algorithms recognised by the validator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlgorithmSet;

impl AlgorithmSet {
    /// Creates a new [`AlgorithmSet`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Classifies a DNSSEC signature algorithm number.
    #[must_use]
    pub fn classify_sig(&self, algorithm: u8) -> AlgorithmSupport {
        match algorithm {
            // RSA/SHA-256 (RFC 5702), ECDSA P-256 (RFC 6605), Ed25519 (RFC 8080)
            8 | 13 | 15 => AlgorithmSupport::Supported,
            // Deprecated algorithms (RFC 8624): RSAMD5 (1), DSA (3), DSA-NSEC3-SHA1 (6), RSASHA1-NSEC3-SHA1 (7)
            1 | 3 | 6 | 7 => AlgorithmSupport::Refused,
            _ => AlgorithmSupport::UnknownTreatAsInsecure,
        }
    }

    /// Classifies a DS digest algorithm number.
    #[must_use]
    pub fn classify_digest(&self, digest_type: u8) -> AlgorithmSupport {
        match digest_type {
            // SHA-256 (RFC 4034), SHA-384 (RFC 6605)
            2 | 4 => AlgorithmSupport::Supported,
            // SHA-1 (RFC 4034) is deprecated for DNSSEC DS records (RFC 8624)
            1 => AlgorithmSupport::Refused,
            _ => AlgorithmSupport::UnknownTreatAsInsecure,
        }
    }
}

/// Configuration policy for DNSSEC validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationPolicy {
    /// Enforcement behavior on validation failures.
    pub failure_mode: FailureMode,
    /// Permitted cryptographic algorithms.
    pub algorithms: AlgorithmSet,
    /// Iteration cap for NSEC3 records.
    pub nsec3_max_iterations: Nsec3IterationsCap,
    /// Maximum zone cuts to traverse during descent.
    pub max_zone_cuts: u8,
}

impl ValidationPolicy {
    /// Creates a new [`ValidationPolicy`].
    #[must_use]
    pub fn new(
        failure_mode: FailureMode,
        algorithms: AlgorithmSet,
        nsec3_max_iterations: Nsec3IterationsCap,
        max_zone_cuts: u8,
    ) -> Self {
        Self {
            failure_mode,
            algorithms,
            nsec3_max_iterations,
            max_zone_cuts,
        }
    }
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            failure_mode: FailureMode::default(),
            algorithms: AlgorithmSet::new(),
            nsec3_max_iterations: Nsec3IterationsCap::DEFAULT,
            max_zone_cuts: 10,
        }
    }
}
