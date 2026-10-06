//! Domain policy, primitives, and traits for the answer cache.

pub mod admission;
pub mod answer_scope;
pub mod bailiwick;
pub mod bytes;
pub mod capacity;
pub mod chain_denial;
pub mod dnssec;
pub mod entry;
pub mod error;
pub mod key;
pub mod negative_entry;
pub mod port;
pub mod positive_entry;
pub mod rrset;
pub mod stats;
pub mod ttl;

pub use admission::{Admission, AdmissionOutcome, RejectReason, RejectedRecord};
pub use bailiwick::Bailiwick;
pub use bytes::HeapBytes;
pub use capacity::{CacheCapacity, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES};
pub use dnssec::DnssecMetadata;
pub use entry::{CacheEntry, SecurityStatus};
pub use error::CacheError;
pub use key::{CacheKey, CanonicalName};
pub use negative_entry::{DenialKind, NegativeEntry};
pub use port::{AdmittedCount, AnswerCache, Lookup, PurgedCount};
pub use positive_entry::{CachedMessage, CachedRRset, MessageFlags, PositiveEntry};
pub use rrset::RRset;
pub use stats::{AtomicCacheCounters, CacheStats};
pub use ttl::{
    Deadline, TtlPolicy, DEFAULT_NEGATIVE_TTL_CEILING_SECS, DEFAULT_TTL_CEILING_SECS,
    DEFAULT_TTL_FLOOR_SECS,
};
