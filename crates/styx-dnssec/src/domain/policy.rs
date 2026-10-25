//! Validation policy: failure mode, accepted algorithms and resource caps.

use std::collections::BTreeSet;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmSet {
    supported_sig: BTreeSet<u8>,
    supported_digest: BTreeSet<u8>,
}

impl AlgorithmSet {
    /// RSA/SHA-256 (RFC 5702).
    pub const RSASHA256: u8 = 8;
    /// ECDSA P-256 with SHA-256 (RFC 6605).
    pub const ECDSAP256SHA256: u8 = 13;
    /// Ed25519 (RFC 8080).
    pub const ED25519: u8 = 15;
    /// DS digest type SHA-1 (RFC 4034).
    pub const DIGEST_SHA1: u8 = 1;
    /// DS digest type SHA-256 (RFC 4509).
    pub const DIGEST_SHA256: u8 = 2;
    /// DS digest type SHA-384 (RFC 6605).
    pub const DIGEST_SHA384: u8 = 4;

    /// Creates a new [`AlgorithmSet`] with default supported algorithms.
    #[must_use]
    pub fn new() -> Self {
        Self {
            supported_sig: [Self::RSASHA256, Self::ECDSAP256SHA256, Self::ED25519]
                .into_iter()
                .collect(),
            supported_digest: [Self::DIGEST_SHA256, Self::DIGEST_SHA384]
                .into_iter()
                .collect(),
        }
    }

    /// Classifies a DNSSEC signature algorithm number.
    #[must_use]
    pub fn classify_sig(&self, algorithm: u8) -> AlgorithmSupport {
        if self.supported_sig.contains(&algorithm) {
            return AlgorithmSupport::Supported;
        }
        match algorithm {
            // Deprecated algorithms (RFC 8624): RSAMD5 (1), DSA (3), DSA-NSEC3-SHA1 (6), RSASHA1-NSEC3-SHA1 (7)
            1 | 3 | 6 | 7 => AlgorithmSupport::Refused,
            _ => AlgorithmSupport::UnknownTreatAsInsecure,
        }
    }

    /// Classifies a DS digest algorithm number.
    #[must_use]
    pub fn classify_digest(&self, digest_type: u8) -> AlgorithmSupport {
        if self.supported_digest.contains(&digest_type) {
            return AlgorithmSupport::Supported;
        }
        match digest_type {
            // SHA-1 (RFC 4034) is deprecated for DNSSEC DS records (RFC 8624)
            Self::DIGEST_SHA1 => AlgorithmSupport::Refused,
            _ => AlgorithmSupport::UnknownTreatAsInsecure,
        }
    }
}

impl Default for AlgorithmSet {
    fn default() -> Self {
        Self::new()
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
