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

/// Count of entries successfully admitted into answer cache storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AdmittedCount(usize);

impl AdmittedCount {
    /// Creates a new `AdmittedCount`.
    #[must_use]
    pub const fn new(count: usize) -> Self {
        Self(count)
    }

    /// Returns the raw count as `usize`.
    #[must_use]
    pub const fn count(self) -> usize {
        self.0
    }

    /// Returns the raw count as `usize`.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

impl std::fmt::Display for AdmittedCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Count of entries purged from answer cache storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PurgedCount(usize);

impl PurgedCount {
    /// Creates a new `PurgedCount`.
    #[must_use]
    pub const fn new(count: usize) -> Self {
        Self(count)
    }

    /// Returns the raw count as `usize`.
    #[must_use]
    pub const fn count(self) -> usize {
        self.0
    }

    /// Returns the raw count as `usize`.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

impl std::fmt::Display for PurgedCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
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
    /// Returns the count of entries successfully admitted into storage.
    ///
    /// # Errors
    /// Returns [`CacheError`] if byte accounting overflows.
    fn admit(&self, key: &CacheKey, outcome: AdmissionOutcome)
        -> Result<AdmittedCount, CacheError>;

    /// Purges all entries from the cache, returning the total count of removed entries.
    fn purge_all(&self) -> PurgedCount;

    /// Returns a point-in-time snapshot of cache performance and capacity statistics.
    fn stats(&self) -> CacheStats;
}
