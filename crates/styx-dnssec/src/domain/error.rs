//! Domain error types for DNSSEC validation.

use thiserror::Error;

use crate::domain::policy::{DigestType, Nsec3HashAlgorithm};

/// Errors occurring while retrieving chain material.
#[derive(Debug, Error)]
pub enum ChainSourceError {
    /// Requested zone material was unavailable.
    #[error("chain material unavailable for zone {0}")]
    Unavailable(styx_proto::Name),

    /// Upstream resolver failed to supply DNSSEC chain material.
    #[error("upstream cannot serve DNSSEC chain material: {0}")]
    UpstreamFailed(#[from] styx_core::UpstreamError),
}

/// Errors occurring while parsing a single line of a trust anchor file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnchorLineError {
    /// Line did not contain a `DS` record type token.
    #[error("expected a DS record; DNSKEY-form anchors are not supported")]
    MissingDsKeyword,

    /// Line had no owner name before `DS`.
    #[error("the owner name must come before DS")]
    MissingOwner,

    /// Token other than TTL or `IN` appeared between owner and `DS`.
    #[error("only a TTL and the class IN may sit between the owner and DS")]
    UnexpectedTokenBeforeDs,

    /// Owner name could not be parsed.
    #[error("invalid owner name: {0}")]
    InvalidOwner(#[from] styx_proto::NameError),

    /// Missing key tag, algorithm, digest type, or digest fields.
    #[error("expected a key tag, an algorithm, a digest type and a digest")]
    MissingFields,

    /// Key tag could not be parsed as a 16-bit integer.
    #[error("invalid key tag")]
    InvalidKeyTag(#[source] std::num::ParseIntError),

    /// Algorithm number could not be parsed as an 8-bit integer.
    #[error("invalid algorithm")]
    InvalidAlgorithm(#[source] std::num::ParseIntError),

    /// Digest type number could not be parsed as an 8-bit integer.
    #[error("invalid digest type")]
    InvalidDigestType(#[source] std::num::ParseIntError),

    /// Digest field was empty.
    #[error("missing digest")]
    MissingDigest,

    /// Digest was not valid hexadecimal.
    #[error("digest is not hexadecimal: {0}")]
    InvalidHex(#[from] data_encoding::DecodeError),

    /// Decoded digest length did not match the digest type.
    #[error("a digest of type {digest_type} is {expected} octets, got {actual}")]
    DigestLengthMismatch {
        /// Digest type declared on the DS record.
        digest_type: DigestType,
        /// Expected digest length in octets.
        expected: usize,
        /// Decoded digest length in octets.
        actual: usize,
    },
}

/// Errors occurring while retrieving trust anchors.
#[derive(Debug, Error)]
pub enum TrustAnchorError {
    /// IO error reading trust anchor file.
    #[error("IO error reading trust anchor file: {0}")]
    Io(#[from] std::io::Error),

    /// Empty trust anchor set.
    #[error("no trust anchors configured")]
    Empty,

    /// A line of the anchor file could not be read as a DS-form anchor.
    #[error("trust anchor file line {line}: {reason}")]
    Malformed {
        /// The 1-based line number.
        line: usize,
        /// What is wrong with it.
        #[source]
        reason: AnchorLineError,
    },
}

/// Errors occurring during denial-of-existence proof verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DenialError {
    /// Proof is missing required legs (e.g. missing wildcard coverage).
    #[error("denial proof incomplete")]
    DenialProofIncomplete,

    /// NSEC3 iterations cap exceeded (RFC 9276).
    #[error("NSEC3 iterations exceeded cap")]
    Nsec3IterationsExceeded,

    /// Unsupported NSEC3 hash algorithm.
    #[error("unsupported NSEC3 hash algorithm: {0}")]
    UnsupportedHashAlgorithm(Nsec3HashAlgorithm),

    /// Name not covered by denial proof.
    #[error("name not covered by denial proof")]
    NotCovered,
}
