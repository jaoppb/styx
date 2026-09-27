//! Answer cache trait (port) and lookup outcome.

use crate::domain::cache::admission::AdmissionOutcome;
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;
use crate::domain::cache::stats::CacheStats;

/// Outcome of querying the answer cache for a [`CacheKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// A fresh cached entry was found.
    Hit(CacheEntry),
    /// No matching entry was found.
    Miss,
    /// A matching entry was found, but it has exceeded its TTL deadline.
    Expired,
}

/// The answer cache port.
///
/// Implementations must be thread-safe (`Send + Sync`) and synchronous.
pub trait AnswerCache: Send + Sync {
    /// Looks up a cached entry for the given query key.
    ///
    /// If an entry is expired, it is removed and [`Lookup::Expired`] is returned.
    fn lookup(&self, key: &CacheKey) -> Lookup;

    /// Stores admitted cache entries from an [`AdmissionOutcome`].
    ///
    /// Returns the number of entries successfully admitted into storage.
    ///
    /// # Errors
    /// Returns [`CacheError`] if byte accounting overflows.
    fn admit(&self, key: &CacheKey, outcome: AdmissionOutcome) -> Result<usize, CacheError>;

    /// Purges all entries from the cache, returning the total number of removed entries.
    fn purge_all(&self) -> usize;

    /// Returns a point-in-time snapshot of cache performance and capacity statistics.
    fn stats(&self) -> CacheStats;
}
