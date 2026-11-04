//! Domain error types for DNSSEC validation.

use thiserror::Error;

/// Top-level error enum for the validator crate.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Failure in chain source.
    #[error("chain source error: {0}")]
    ChainSource(#[from] ChainSourceError),

    /// Failure in trust anchor source.
    #[error("trust anchor error: {0}")]
    TrustAnchor(#[from] TrustAnchorError),

    /// Failure evaluating denial-of-existence proof.
    #[error("denial error: {0}")]
    Denial(#[from] DenialError),

    /// Encoding error during wire serialization.
    #[error("encode error: {0}")]
    Encode(#[from] styx_proto::EncodeError),

    /// Domain name syntax or length error.
    #[error("name error: {0}")]
    Name(#[from] styx_proto::NameError),
}

/// Errors occurring while retrieving chain material.
#[derive(Debug, Error)]
pub enum ChainSourceError {
    /// Requested zone material was unavailable.
    #[error("chain material unavailable for zone {0}")]
    Unavailable(styx_proto::Name),

    /// Forwarder failed to supply DNSSEC material.
    #[error("upstream cannot serve DNSSEC chain material: {0}")]
    UpstreamFailed(String),
}

/// Errors occurring while retrieving trust anchors.
#[derive(Debug, Error)]
pub enum TrustAnchorError {
    /// IO error reading trust anchor file.
    #[error("IO error: {0}")]
    Io(String),

    /// Parsing error in trust anchor configuration.
    #[error("malformed trust anchor: {0}")]
    Malformed(String),

    /// Empty trust anchor set.
    #[error("no trust anchors configured")]
    Empty,
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
    UnsupportedHashAlgorithm(u8),

    /// Name not covered by denial proof.
    #[error("name not covered by denial proof")]
    NotCovered,

    /// Name syntax or length error during proof evaluation.
    #[error("name error: {0}")]
    Name(#[from] styx_proto::NameError),
}
