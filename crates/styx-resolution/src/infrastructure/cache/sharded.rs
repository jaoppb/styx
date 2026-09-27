//! Sharded concurrent answer cache implementation.

use std::collections::{HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, RwLock};

use crate::domain::cache::admission::{AdmissionOutcome, RejectReason};
use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::capacity::CacheCapacity;
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;
use crate::domain::cache::port::{AnswerCache, Lookup};
use crate::domain::cache::stats::{AtomicCacheCounters, CacheStats};
use crate::domain::cache::ttl::TtlPolicy;
use crate::domain::clock::Clock;
use crate::infrastructure::cache::eviction::Eviction;

/// Default number of concurrent shards (32).
pub const DEFAULT_SHARDS: usize = 32;

/// Internal state held within a single cache shard.
#[derive(Debug, Default)]
pub struct ShardInner {
    /// Mapping from canonical query key to cache entry.
    pub map: HashMap<CacheKey, CacheEntry>,
    /// Access recency queue for LRU eviction.
    pub recency: VecDeque<CacheKey>,
    /// Accumulated heap byte accounting for this shard.
    pub bytes: HeapBytes,
}

/// A concurrency-isolated shard within [`ShardedAnswerCache`].
#[derive(Debug, Default)]
pub struct Shard {
    inner: RwLock<ShardInner>,
}

impl Shard {
    /// Returns a read guard to the inner shard state.
    ///
    /// # Errors
    /// Returns a poison error if the lock was poisoned.
    pub fn read(
        &self,
    ) -> Result<
        std::sync::RwLockReadGuard<'_, ShardInner>,
        std::sync::PoisonError<std::sync::RwLockReadGuard<'_, ShardInner>>,
    > {
        self.inner.read()
    }
}

/// A concurrent, sharded in-memory answer cache.
pub struct ShardedAnswerCache<C> {
    shards: Vec<Shard>,
    clock: Arc<C>,
    capacity: CacheCapacity,
    ttl_policy: TtlPolicy,
    counters: AtomicCacheCounters,
}

impl<C: Clock> ShardedAnswerCache<C> {
    /// Creates a new `ShardedAnswerCache` with the specified parameters.
    #[must_use]
    pub fn new(
        clock: Arc<C>,
        capacity: CacheCapacity,
        ttl_policy: TtlPolicy,
        shard_count: usize,
    ) -> Self {
        let count = shard_count.max(1);
        let mut shards = Vec::with_capacity(count);
        for _ in 0..count {
            shards.push(Shard::default());
        }

        Self {
            shards,
            clock,
            capacity,
            ttl_policy,
            counters: AtomicCacheCounters::new(),
        }
    }

    /// Creates a new `ShardedAnswerCache` using default capacity and TTL policies.
    #[must_use]
    pub fn with_defaults(clock: Arc<C>) -> Self {
        Self::new(
            clock,
            CacheCapacity::default(),
            TtlPolicy::default(),
            DEFAULT_SHARDS,
        )
    }

    /// Returns the number of shards in this cache.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Returns a reference to the shard at the given index.
    #[must_use]
    pub fn shard(&self, index: usize) -> Option<&Shard> {
        self.shards.get(index)
    }

    /// Returns the shard index for the given cache key.
    #[must_use]
    pub fn shard_index(&self, key: &CacheKey) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();
        let len = self.shards.len();
        let Ok(len_u64) = u64::try_from(len) else {
            return 0;
        };
        let Some(non_zero_u64) = std::num::NonZeroU64::new(len_u64) else {
            return 0;
        };
        let rem_u64 = hash.checked_rem(non_zero_u64.get()).unwrap_or(0);
        usize::try_from(rem_u64).unwrap_or(0)
    }

    fn get_shard(&self, key: &CacheKey) -> Option<&Shard> {
        let idx = self.shard_index(key);
        self.shards.get(idx)
    }

    fn touch_key(shard: &Shard, key: &CacheKey) {
        if let Ok(mut write_guard) = shard.inner.write() {
            write_guard.recency.retain(|k| k != key);
            write_guard.recency.push_back(key.clone());
        }
    }

    fn purge_expired_entry(&self, shard: &Shard, key: &CacheKey) {
        let Ok(mut write_guard) = shard.inner.write() else {
            return;
        };
        let Some(removed) = write_guard.map.remove(key) else {
            return;
        };
        write_guard.recency.retain(|k| k != key);
        write_guard.bytes = write_guard.bytes.saturating_sub(removed.heap_size());
        self.counters.inc_expired(1);
    }

    /// Returns the configured TTL policy.
    #[must_use]
    pub const fn ttl_policy(&self) -> &TtlPolicy {
        &self.ttl_policy
    }

    /// Returns the configured capacity limits.
    #[must_use]
    pub const fn capacity(&self) -> &CacheCapacity {
        &self.capacity
    }
}

impl<C: Clock> AnswerCache for ShardedAnswerCache<C> {
    fn lookup(&self, key: &CacheKey) -> Lookup {
        let Some(shard) = self.get_shard(key) else {
            self.counters.inc_misses();
            return Lookup::Miss;
        };

        let now = self.clock.now_monotonic();

        // 1. Optimistic read lock
        let read_result = shard.inner.read();
        let guard = match read_result {
            Ok(g) => g,
            Err(_) => {
                self.counters.inc_misses();
                return Lookup::Miss;
            }
        };

        let entry_opt = guard.map.get(key).cloned();
        drop(guard);

        let Some(entry) = entry_opt else {
            self.counters.inc_misses();
            return Lookup::Miss;
        };

        if entry.is_fresh(now) {
            match &entry {
                CacheEntry::Positive(_) => self.counters.inc_hits(),
                CacheEntry::Negative(_) => self.counters.inc_negative_hits(),
            }

            Self::touch_key(shard, key);
            Lookup::Hit(entry)
        } else {
            self.purge_expired_entry(shard, key);
            Lookup::Expired
        }
    }

    fn admit(&self, key: &CacheKey, outcome: AdmissionOutcome) -> Result<usize, CacheError> {
        for rej in &outcome.rejected {
            if rej.reason == RejectReason::OutOfBailiwick {
                tracing::warn!(owner = %rej.owner, rtype = ?rej.rtype, "rejected out-of-bailiwick record");
                self.counters.inc_rejected_out_of_bailiwick(1);
            }
        }

        if outcome.admitted.is_empty() {
            return Ok(0);
        }

        let Some(shard) = self.get_shard(key) else {
            return Ok(0);
        };

        let Ok(mut guard) = shard.inner.write() else {
            return Ok(0);
        };

        let now = self.clock.now_monotonic();
        let mut count: usize = 0;

        for entry in outcome.admitted {
            let entry_bytes = entry.heap_size();
            let new_bytes = match guard.bytes.checked_add(entry_bytes) {
                Ok(b) => b,
                Err(err) => {
                    tracing::warn!(%err, "cache byte accounting overflow; admission skipped");
                    continue;
                }
            };

            guard.bytes = new_bytes;
            if let Some(old) = guard.map.insert(key.clone(), entry) {
                guard.bytes = guard.bytes.saturating_sub(old.heap_size());
            }
            guard.recency.retain(|k| k != key);
            guard.recency.push_back(key.clone());
            count = count.saturating_add(1);
        }

        self.counters.inc_admitted(count as u64);

        if self.capacity.needs_eviction(guard.map.len(), guard.bytes) {
            let report = Eviction::evict(&mut guard, now, self.capacity);
            if report.expired_reclaimed > 0 {
                self.counters.inc_expired(report.expired_reclaimed as u64);
            }
            if report.evicted_fresh > 0 {
                self.counters.inc_evicted(report.evicted_fresh as u64);
                tracing::debug!(
                    evicted = report.evicted_fresh,
                    "cache capacity eviction performed"
                );
            }
        }

        Ok(count)
    }

    fn purge_all(&self) -> usize {
        let mut total: usize = 0;
        for shard in &self.shards {
            if let Ok(mut guard) = shard.inner.write() {
                total = total.saturating_add(guard.map.len());
                guard.map.clear();
                guard.recency.clear();
                guard.bytes = HeapBytes::zero();
            }
        }
        total
    }

    fn stats(&self) -> CacheStats {
        let mut total_entries: usize = 0;
        let mut total_bytes = HeapBytes::zero();

        for shard in &self.shards {
            if let Ok(guard) = shard.inner.read() {
                total_entries = total_entries.saturating_add(guard.map.len());
                total_bytes = guard.bytes.checked_add(total_bytes).unwrap_or(guard.bytes);
            }
        }

        self.counters.snapshot(total_entries, total_bytes)
    }
}
