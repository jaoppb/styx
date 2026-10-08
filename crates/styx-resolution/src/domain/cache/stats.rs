//! Cache performance metrics and operational counters.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::cache::bytes::HeapBytes;

/// Snapshot of operational metrics for the answer cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    /// Number of cache hits for fresh positive entries.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of cache hits for fresh negative entries (NXDOMAIN or NODATA).
    pub negative_hits: u64,
    /// Number of entries successfully admitted into cache.
    pub admitted: u64,
    /// Number of records rejected due to bailiwick rule violations.
    pub rejected_out_of_bailiwick: u64,
    /// Number of whole answers refused because their alias chain led nowhere.
    pub rejected_incomplete_chain: u64,
    /// Number of entries removed due to TTL expiration.
    pub expired: u64,
    /// Number of fresh entries evicted due to capacity bounds.
    pub evicted: u64,
    /// Current total entry count held in cache.
    pub entries: usize,
    /// Current estimated heap bytes held across all entries.
    pub bytes: HeapBytes,
}

/// Thread-safe atomic counters tracking cache operations across all shards.
#[derive(Debug, Default)]
pub struct AtomicCacheCounters {
    hits: AtomicU64,
    misses: AtomicU64,
    negative_hits: AtomicU64,
    admitted: AtomicU64,
    rejected_out_of_bailiwick: AtomicU64,
    rejected_incomplete_chain: AtomicU64,
    expired: AtomicU64,
    evicted: AtomicU64,
}

impl AtomicCacheCounters {
    /// Creates a new zeroed set of atomic counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the positive hit counter.
    pub fn inc_hits(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the miss counter.
    pub fn inc_misses(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the negative hit counter.
    pub fn inc_negative_hits(&self) {
        self.negative_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the admitted entries counter by `count`.
    pub fn inc_admitted(&self, count: u64) {
        self.admitted.fetch_add(count, Ordering::Relaxed);
    }

    /// Increments the out-of-bailiwick rejection counter by `count`.
    pub fn inc_rejected_out_of_bailiwick(&self, count: u64) {
        self.rejected_out_of_bailiwick
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increments the incomplete-chain refusal counter by `count` answers.
    pub fn inc_rejected_incomplete_chain(&self, count: u64) {
        self.rejected_incomplete_chain
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increments the expired entry counter by `count`.
    pub fn inc_expired(&self, count: u64) {
        self.expired.fetch_add(count, Ordering::Relaxed);
    }

    /// Increments the evicted entry counter by `count`.
    pub fn inc_evicted(&self, count: u64) {
        self.evicted.fetch_add(count, Ordering::Relaxed);
    }

    /// Snapshots all atomic counters into a [`CacheStats`] report with current entries and bytes.
    #[must_use]
    pub fn snapshot(&self, entries: usize, bytes: HeapBytes) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            negative_hits: self.negative_hits.load(Ordering::Relaxed),
            admitted: self.admitted.load(Ordering::Relaxed),
            rejected_out_of_bailiwick: self.rejected_out_of_bailiwick.load(Ordering::Relaxed),
            rejected_incomplete_chain: self.rejected_incomplete_chain.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            evicted: self.evicted.load(Ordering::Relaxed),
            entries,
            bytes,
        }
    }
}
