//! Sharded concurrent answer cache implementation.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::Arc;

use styx_core::Clock;

use crate::domain::cache::admission_outcome::{AdmissionOutcome, AdmittedEntries, RejectReason};
use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::capacity::{
    CacheCapacity, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES, MIN_SHARD_BYTES,
};
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;
use crate::domain::cache::port::{AdmittedCount, AnswerCache, Lookup, PurgedCount};
use crate::domain::cache::stats::{AtomicCacheCounters, CacheStats};
use crate::domain::cache::ttl::TtlPolicy;
use crate::infrastructure::cache::eviction::{Eviction, EvictionReport};
use crate::infrastructure::cache::shard::{Shard, ShardInner};

pub use crate::domain::cache::capacity::DEFAULT_SHARDS;

// `with_defaults` is infallible only because the default budget can be split this way.
const _: () = assert!(
    DEFAULT_MAX_ENTRIES >= DEFAULT_SHARDS
        && DEFAULT_MAX_BYTES >= DEFAULT_SHARDS.saturating_mul(MIN_SHARD_BYTES)
);

/// A concurrent, sharded in-memory answer cache.
///
/// `S` picks the shard for a key. The default [`RandomState`] is seeded per process, so an
/// outside party cannot work out which names share a shard; a test injects a fixed-seed
/// hasher to keep placement deterministic.
pub struct ShardedAnswerCache<C, S = RandomState> {
    shards: Vec<Shard>,
    hasher: S,
    clock: Arc<C>,
    capacity: CacheCapacity,
    ttl_policy: TtlPolicy,
    counters: AtomicCacheCounters,
}

impl<C: Clock> ShardedAnswerCache<C> {
    /// Creates a new `ShardedAnswerCache` whose `capacity` bounds the cache as a whole,
    /// placing keys with a hasher seeded at random for this process.
    ///
    /// The budget is split across the shards once, here, so no shard can hold more than
    /// its share and the shares sum to the configured total.
    ///
    /// # Errors
    /// Returns [`CacheError::ZeroShards`] for a shard count of zero, and
    /// [`CacheError::BudgetBelowShardCount`] if `capacity` has fewer entries than shards, and
    /// [`CacheError::ByteShareBelowFloor`] if a shard's byte share could not hold one answer.
    pub fn new(
        clock: Arc<C>,
        capacity: CacheCapacity,
        ttl_policy: TtlPolicy,
        shard_count: usize,
    ) -> Result<Self, CacheError> {
        Self::with_hasher(clock, capacity, ttl_policy, shard_count, RandomState::new())
    }

    /// Creates a new `ShardedAnswerCache` using default capacity and TTL policies.
    #[must_use]
    pub fn with_defaults(clock: Arc<C>) -> Self {
        let capacity = CacheCapacity::default();
        let built = Self::new(
            Arc::clone(&clock),
            capacity,
            TtlPolicy::default(),
            DEFAULT_SHARDS,
        );
        // The const assertion above rules the error out; one whole-budget shard is the
        // fallback that keeps this constructor free of a panic.
        built.unwrap_or_else(|_| {
            Self::from_shards(
                clock,
                capacity,
                TtlPolicy::default(),
                vec![Shard::new(capacity)],
                RandomState::new(),
            )
        })
    }
}

impl<C: Clock, S: BuildHasher> ShardedAnswerCache<C, S> {
    /// Creates a new `ShardedAnswerCache` that places keys with `hasher`.
    ///
    /// # Errors
    /// The same as [`ShardedAnswerCache::new`].
    pub fn with_hasher(
        clock: Arc<C>,
        capacity: CacheCapacity,
        ttl_policy: TtlPolicy,
        shard_count: usize,
        hasher: S,
    ) -> Result<Self, CacheError> {
        let shards = capacity
            .partition(shard_count)?
            .into_iter()
            .map(Shard::new)
            .collect();
        Ok(Self::from_shards(
            clock, capacity, ttl_policy, shards, hasher,
        ))
    }

    fn from_shards(
        clock: Arc<C>,
        capacity: CacheCapacity,
        ttl_policy: TtlPolicy,
        shards: Vec<Shard>,
        hasher: S,
    ) -> Self {
        Self {
            shards,
            hasher,
            clock,
            capacity,
            ttl_policy,
            counters: AtomicCacheCounters::new(),
        }
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
        let hash = self.hasher.hash_one(key);
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

    /// Logs and counts what admission refused. An outcome is one answer: forged
    /// records count one each, and an answer refused whole counts once and logs once,
    /// whatever the number of records it carried.
    fn record_rejections(&self, outcome: &AdmissionOutcome) {
        for rej in outcome.rejected() {
            match rej.reason {
                RejectReason::OutOfBailiwick => {
                    tracing::warn!(owner = %rej.owner, rtype = ?rej.rtype, "rejected out-of-bailiwick record");
                    self.counters.inc_rejected_out_of_bailiwick(1);
                }
                RejectReason::ErrorResponse => {
                    tracing::debug!(owner = %rej.owner, rtype = ?rej.rtype, "dropped a record carried by an error reply");
                }
                _ => {}
            }
        }
        let Some(refusal) = outcome.refusal() else {
            return;
        };
        match refusal.reason() {
            RejectReason::IncompleteChain => {
                tracing::debug!(
                    records = outcome.rejected().len(),
                    "refused an answer whose alias chain leads nowhere"
                );
                self.counters.inc_rejected_incomplete_chain(1);
            }
            RejectReason::QuestionMismatch => {
                tracing::debug!(
                    expected = ?outcome.key(),
                    echoed = ?refusal.echoed(),
                    records = outcome.rejected().len(),
                    "refused an answer that echoed a question other than the client's"
                );
                self.counters.inc_rejected_question_mismatch(1);
            }
            RejectReason::MultipleQuestions => {
                tracing::debug!(
                    expected = ?outcome.key(),
                    echoed = ?refusal.echoed(),
                    records = outcome.rejected().len(),
                    "refused an answer that echoed more than one question"
                );
                self.counters.inc_rejected_multiple_questions(1);
            }
            _ => {}
        }
    }

    fn purge_expired_entry(&self, shard: &Shard, key: &CacheKey) {
        let Ok(mut write_guard) = shard.inner.write() else {
            return;
        };
        // Another thread may have replaced the entry since the read lock was released.
        if !write_guard.is_stale(key, self.clock.now_monotonic()) {
            return;
        }
        if write_guard.remove(key).is_some() {
            self.counters.inc_expired(1);
        }
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

impl<C: Clock, S: BuildHasher> ShardedAnswerCache<C, S> {
    /// Stores one entry in its shard, making room first. Returns `true` if it was stored.
    ///
    /// The entry already stored under `key` is superseded either way: it is removed before
    /// anything else, so a refused refresh never leaves the older answer to be served.
    /// An entry larger than the shard's whole byte budget is then refused: admitting it
    /// could only empty the shard to no purpose. Room is made before the insert, so the
    /// entry just admitted is never its own victim.
    fn admit_entry(&self, guard: &mut ShardInner, key: &CacheKey, entry: CacheEntry) -> bool {
        guard.remove(key);
        let entry_bytes = entry.heap_size();
        if entry_bytes > guard.capacity().max_bytes() {
            tracing::debug!(%entry_bytes, "refused an entry larger than its shard's byte budget");
            self.counters.inc_rejected_oversized(1);
            return false;
        }

        let report = Eviction::make_room(guard, self.clock.now_monotonic(), entry_bytes);
        self.record_eviction(report);

        if let Err(err) = guard.insert(key, entry) {
            tracing::warn!(%err, "cache byte accounting overflow; admission skipped");
            return false;
        }
        true
    }

    fn record_eviction(&self, report: EvictionReport) {
        if report.expired_reclaimed > 0 {
            self.counters
                .inc_expired(u64::try_from(report.expired_reclaimed).unwrap_or(u64::MAX));
        }
        if report.evicted_fresh > 0 {
            self.counters
                .inc_evicted(u64::try_from(report.evicted_fresh).unwrap_or(u64::MAX));
            tracing::debug!(
                evicted = report.evicted_fresh,
                "cache capacity eviction performed"
            );
        }
    }
}

impl<C: Clock, S: BuildHasher + Send + Sync> AnswerCache for ShardedAnswerCache<C, S> {
    fn lookup(&self, key: &CacheKey) -> Lookup {
        let Some(shard) = self.get_shard(key) else {
            self.counters.inc_misses();
            return Lookup::Miss;
        };

        let now = self.clock.now_monotonic();

        // A hit only reads the shard: marking the entry used is an atomic store.
        let Ok(guard) = shard.inner.read() else {
            self.counters.inc_misses();
            return Lookup::Miss;
        };
        let entry_opt = guard.touch(key);
        drop(guard);

        let Some(entry) = entry_opt else {
            self.counters.inc_misses();
            return Lookup::Miss;
        };

        if entry.is_fresh(now) {
            match &*entry {
                CacheEntry::Positive(_) => self.counters.inc_hits(),
                CacheEntry::Negative(_) => self.counters.inc_negative_hits(),
            }
            Lookup::Hit(entry)
        } else {
            self.purge_expired_entry(shard, key);
            Lookup::Expired
        }
    }

    fn admit(&self, outcome: AdmissionOutcome) -> Result<AdmittedCount, CacheError> {
        self.record_rejections(&outcome);
        let AdmittedEntries { key, entries } = outcome.into_admitted();
        let key = &key;

        if entries.is_empty() {
            return Ok(AdmittedCount::new(0));
        }

        let Some(shard) = self.get_shard(key) else {
            return Ok(AdmittedCount::new(0));
        };

        let Ok(mut guard) = shard.inner.write() else {
            return Ok(AdmittedCount::new(0));
        };

        let mut count: usize = 0;
        for entry in entries {
            if self.admit_entry(&mut guard, key, entry) {
                count = count.saturating_add(1);
            }
        }

        self.counters
            .inc_admitted(u64::try_from(count).unwrap_or(u64::MAX));
        Ok(AdmittedCount::new(count))
    }

    fn purge_all(&self) -> PurgedCount {
        let mut total: usize = 0;
        for shard in &self.shards {
            if let Ok(mut guard) = shard.inner.write() {
                total = total.saturating_add(guard.len());
                guard.clear();
            }
        }
        PurgedCount::new(total)
    }

    fn stats(&self) -> CacheStats {
        let mut total_entries: usize = 0;
        let mut total_bytes = HeapBytes::zero();

        for shard in &self.shards {
            if let Ok(guard) = shard.inner.read() {
                total_entries = total_entries.saturating_add(guard.len());
                total_bytes = guard.bytes().saturating_add(total_bytes);
            }
        }

        self.counters.snapshot(total_entries, total_bytes)
    }
}
