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

    /// The cache was asked to run with no shards.
    #[error("cache needs at least one shard")]
    ZeroShards,

    /// The configured entry bound cannot give every shard at least one entry.
    #[error("capacity of {max_entries} entries cannot be split across {shards} shards")]
    BudgetBelowShardCount {
        /// Number of shards the budget was to be split across.
        shards: usize,
        /// Configured maximum entry count.
        max_entries: usize,
    },

    /// A shard's byte share could not hold one maximum-size answer.
    #[error(
        "{max_bytes} bytes across {shards} shards leaves a share too small for one answer; \
         {shards} shards need at least {minimum_bytes} bytes"
    )]
    ByteShareBelowFloor {
        /// Number of shards the budget was to be split across.
        shards: usize,
        /// Configured maximum byte count.
        max_bytes: usize,
        /// Smallest total byte budget that clears the floor for this many shards.
        minimum_bytes: usize,
    },

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
