//! Error types for the answer cache.

use thiserror::Error;

/// Errors arising during answer cache operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CacheError {
    /// TTL arithmetic overflowed while calculating a deadline.
    #[error("TTL arithmetic overflowed")]
    TtlOverflow,

    /// Computed deadline occurs in the past relative to the reference instant.
    #[error("computed deadline is in the past")]
    DeadlineInThePast,

    /// The question has a meta-type (e.g. ANY, AXFR, IXFR, OPT) that cannot be cached.
    #[error("question has uncacheable record type: {0}")]
    UncacheableQuestion(styx_proto::RecordType),

    /// A negative response (NXDOMAIN or NODATA) lacked an SOA record in its authority section.
    #[error("denial response missing required SOA record")]
    MissingSoa,

    /// Failed to assemble a valid DNS message from cached records.
    #[error("failed to assemble cached response: {0}")]
    ResponseAssembly(String),

    /// Heap byte accounting arithmetic overflowed.
    #[error("cache byte accounting overflowed")]
    ByteAccountingOverflow,

    /// Configured TTL floor exceeds ceiling.
    #[error("TTL floor ({floor}s) exceeds ceiling ({ceiling}s)")]
    InvalidTtlBounds {
        /// Configured minimum TTL.
        floor: u32,
        /// Configured maximum TTL.
        ceiling: u32,
    },

    /// Attempted to construct an RRset with no RDATA.
    #[error("RRset must contain at least one RDATA record")]
    EmptyRRset,
}
