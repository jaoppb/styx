//! Cache entry enum and security validation status.

use std::time::Instant;

use styx_proto::Message;

use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;
use crate::domain::cache::negative_entry::NegativeEntry;
use crate::domain::cache::positive_entry::PositiveEntry;
use crate::domain::cache::ttl::Deadline;

/// Security validation status of a cached DNS record or response.
///
/// In Phase 4, validation logic is deferred to Phase 6 (DNSSEC), so every admitted
/// entry defaults to [`SecurityStatus::Indeterminate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SecurityStatus {
    /// DNSSEC status cannot be determined or validation is not yet implemented.
    #[default]
    Indeterminate,
    /// Authoritatively proven insecure (unsigned zone with valid NSEC/NSEC3 proof of no DS).
    Insecure,
    /// Cryptographically verified with a complete, valid chain of trust to a root anchor.
    Secure,
    /// DNSSEC validation failed (signature mismatch, expired signature, or missing proof).
    Bogus,
}

/// A stored entry in the answer cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheEntry {
    /// A positive response (either a single RRset or a composite message).
    Positive(PositiveEntry),
    /// An RFC 2308 negative response (NXDOMAIN or NODATA).
    Negative(NegativeEntry),
}

impl CacheEntry {
    /// Returns the absolute deadline when this entry stops being fresh.
    #[must_use]
    pub fn deadline(&self) -> Deadline {
        match self {
            Self::Positive(entry) => entry.deadline(),
            Self::Negative(entry) => entry.deadline,
        }
    }

    /// Returns `true` if the entry has not reached its deadline relative to `now`.
    #[must_use]
    pub fn is_fresh(&self, now: Instant) -> bool {
        !self.deadline().has_expired(now)
    }

    /// Returns the estimated heap size consumed by this cache entry.
    #[must_use]
    pub fn heap_size(&self) -> HeapBytes {
        match self {
            Self::Positive(entry) => entry.heap_size(),
            Self::Negative(entry) => entry.heap_size(),
        }
    }

    /// Synthesizes an outgoing DNS response [`Message`] from this cached entry.
    ///
    /// # Errors
    /// Returns [`CacheError`] if TTL recomputation or message assembly fails.
    pub fn to_response(&self, key: &CacheKey, now: Instant) -> Result<Message, CacheError> {
        match self {
            Self::Positive(entry) => entry.to_response(key, now),
            Self::Negative(entry) => entry.to_response(key, now),
        }
    }
}
