//! Domain error types for DNSSEC validation.

use thiserror::Error;

use crate::domain::policy::Nsec3HashAlgorithm;

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

/// Errors occurring while retrieving trust anchors.
#[derive(Debug, Error)]
pub enum TrustAnchorError {
    /// IO error reading trust anchor file.
    #[error("IO error reading trust anchor file: {0}")]
    Io(#[from] std::io::Error),

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
    UnsupportedHashAlgorithm(Nsec3HashAlgorithm),

    /// Name not covered by denial proof.
    #[error("name not covered by denial proof")]
    NotCovered,

    /// Name syntax or length error during proof evaluation.
    #[error("name error: {0}")]
    Name(#[from] styx_proto::NameError),
}
