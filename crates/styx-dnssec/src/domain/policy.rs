//! Validation policy: failure mode, accepted algorithms and resource caps.

use std::fmt;

/// DNSSEC signature algorithm identifier (RFC 4034, RFC 8624).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnssecAlgorithm(u8);

impl DnssecAlgorithm {
    /// RSA/MD5 (RFC 3110, deprecated per RFC 8624).
    pub const RSAMD5: Self = Self(1);
    /// DSA/SHA-1 (RFC 3755, deprecated/refused per RFC 8624).
    pub const DSA: Self = Self(3);
    /// DSA-NSEC3-SHA1 (RFC 5155, deprecated/refused per RFC 8624).
    pub const DSA_NSEC3_SHA1: Self = Self(6);
    /// RSA/SHA-1-NSEC3-SHA1 (RFC 5155, deprecated/refused per RFC 8624).
    pub const RSASHA1_NSEC3_SHA1: Self = Self(7);
    /// RSA/SHA-256 (RFC 5702).
    pub const RSASHA256: Self = Self(8);
    /// ECDSA P-256 with SHA-256 (RFC 6605).
    pub const ECDSAP256SHA256: Self = Self(13);
    /// Ed25519 (RFC 8080).
    pub const ED25519: Self = Self(15);

    /// Wraps a raw wire DNSSEC algorithm number.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the raw wire algorithm number.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for DnssecAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// DNSSEC Delegation Signer (DS) digest algorithm identifier (RFC 4034, RFC 8624).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DigestType(u8);

impl DigestType {
    /// SHA-1 (RFC 4034, deprecated/refused per RFC 8624).
    pub const SHA1: Self = Self(1);
    /// SHA-256 (RFC 4509).
    pub const SHA256: Self = Self(2);
    /// SHA-384 (RFC 6605).
    pub const SHA384: Self = Self(4);

    /// Wraps a raw wire DS digest type number.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the raw wire digest type number.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// NSEC3 cryptographic hash algorithm identifier (RFC 5155).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nsec3HashAlgorithm(u8);

impl Nsec3HashAlgorithm {
    /// SHA-1 (RFC 5155 §5).
    pub const SHA1: Self = Self(1);

    /// Wraps a raw wire NSEC3 hash algorithm number.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the raw wire NSEC3 hash algorithm number.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for Nsec3HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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

/// Whether the validator can check signatures or digests made with an algorithm.
///
/// Decided by `support()` on [`DnssecAlgorithm`] and [`DigestType`], next to the
/// primitives that implement them, so a supported algorithm always has a primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmSupport {
    /// A primitive exists and the algorithm is safe to rely on.
    Supported,
    /// Unknown, or deprecated by RFC 8624 (RSA/MD5, DSA, the SHA-1 algorithms): a zone
    /// vouched for only by such algorithms is Insecure (RFC 4035 §5.2, RFC 6840 §5.2).
    Unsupported,
}

impl AlgorithmSupport {
    /// A DS record is usable only when both its key algorithm and its digest are.
    #[must_use]
    pub const fn both(signature: Self, digest: Self) -> Self {
        match (signature, digest) {
            (Self::Supported, Self::Supported) => Self::Supported,
            _ => Self::Unsupported,
        }
    }
}

/// Configuration policy for DNSSEC validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationPolicy {
    /// Enforcement behavior on validation failures.
    pub failure_mode: FailureMode,
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
        nsec3_max_iterations: Nsec3IterationsCap,
        max_zone_cuts: u8,
    ) -> Self {
        Self {
            failure_mode,
            nsec3_max_iterations,
            max_zone_cuts,
        }
    }
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            failure_mode: FailureMode::default(),
            nsec3_max_iterations: Nsec3IterationsCap::DEFAULT,
            max_zone_cuts: 10,
        }
    }
}
