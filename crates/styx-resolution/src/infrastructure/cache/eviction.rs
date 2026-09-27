//! Bounded capacity eviction and expired entry reclamation.

use std::collections::VecDeque;
use std::time::Instant;

use crate::domain::cache::capacity::CacheCapacity;
use crate::domain::cache::key::CacheKey;
use crate::infrastructure::cache::sharded::ShardInner;

/// Report detailing the results of an eviction sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvictionReport {
    /// Number of expired entries reclaimed.
    pub expired_reclaimed: usize,
    /// Number of fresh entries evicted to respect capacity bounds.
    pub evicted_fresh: usize,
}

/// Eviction engine enforcing capacity constraints over a single shard.
pub struct Eviction;

impl Eviction {
    /// Evicts entries from `shard` until it fits within `capacity`.
    ///
    /// Pass 1: Sweeps and removes all expired entries.
    /// Pass 2: If still over capacity, evicts least-recently-used fresh entries.
    #[must_use]
    pub(crate) fn evict(
        shard: &mut ShardInner,
        now: Instant,
        capacity: CacheCapacity,
    ) -> EvictionReport {
        let mut report = EvictionReport::default();

        let (unexpired, reclaimed) = Self::reclaim_expired(shard, now);
        shard.recency = unexpired;
        report.expired_reclaimed = reclaimed;

        // Pass 2: Evict least-recently-used fresh entries if capacity is still exceeded
        while capacity.needs_eviction(shard.map.len(), shard.bytes) {
            let Some(oldest_key) = shard.recency.pop_front() else {
                break;
            };

            if Self::remove_entry(shard, &oldest_key) {
                report.evicted_fresh = report.evicted_fresh.saturating_add(1);
            }
        }

        report
    }

    fn reclaim_expired(shard: &mut ShardInner, now: Instant) -> (VecDeque<CacheKey>, usize) {
        let mut unexpired_recency = VecDeque::with_capacity(shard.recency.len());
        let mut reclaimed: usize = 0;

        while let Some(key) = shard.recency.pop_front() {
            let is_expired = shard
                .map
                .get(&key)
                .is_some_and(|entry| !entry.is_fresh(now));

            if !is_expired {
                unexpired_recency.push_back(key);
                continue;
            }

            if Self::remove_entry(shard, &key) {
                reclaimed = reclaimed.saturating_add(1);
            }
        }

        (unexpired_recency, reclaimed)
    }

    fn remove_entry(shard: &mut ShardInner, key: &CacheKey) -> bool {
        let Some(entry) = shard.map.remove(key) else {
            return false;
        };
        shard.bytes = shard.bytes.saturating_sub(entry.heap_size());
        true
    }
}
