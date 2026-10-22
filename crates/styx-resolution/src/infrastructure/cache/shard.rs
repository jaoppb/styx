//! One concurrency-isolated shard of the answer cache.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::capacity::CacheCapacity;
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;
use crate::infrastructure::cache::ring::{ClockRing, SlotId};

/// State held within a single cache shard.
#[derive(Debug)]
pub(crate) struct ShardInner {
    /// Mapping from canonical query key to the entry's slot in the ring.
    index: HashMap<CacheKey, SlotId>,
    /// The entries, in a second-chance ring.
    ring: ClockRing,
    /// Accumulated heap byte accounting for this shard.
    bytes: HeapBytes,
    /// This shard's share of the cache's overall capacity.
    capacity: CacheCapacity,
}

impl ShardInner {
    fn new(capacity: CacheCapacity) -> Self {
        Self {
            index: HashMap::new(),
            ring: ClockRing::default(),
            bytes: HeapBytes::zero(),
            capacity,
        }
    }

    /// This shard's share of the cache's overall capacity.
    pub(crate) fn capacity(&self) -> CacheCapacity {
        self.capacity
    }

    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }

    pub(crate) fn bytes(&self) -> HeapBytes {
        self.bytes
    }

    pub(crate) fn slot_count(&self) -> usize {
        self.ring.slot_count()
    }

    pub(crate) fn contains(&self, key: &CacheKey) -> bool {
        self.index.contains_key(key)
    }

    /// Returns a shared handle to the entry for `key` and marks it recently used. Needs
    /// no exclusive access, which is what lets a hit run under the shard's read lock.
    pub(crate) fn touch(&self, key: &CacheKey) -> Option<Arc<CacheEntry>> {
        let id = self.index.get(key)?;
        self.ring.touch(*id)
    }

    /// Returns `true` if `key` is present and no longer fresh at `now`.
    pub(crate) fn is_stale(&self, key: &CacheKey, now: Instant) -> bool {
        self.index
            .get(key)
            .is_some_and(|id| !self.ring.is_fresh(*id, now))
    }

    /// Stores `entry` under `key`; the caller has already made room for it.
    ///
    /// # Errors
    /// Returns [`CacheError::ByteAccountingOverflow`] if the byte count would overflow,
    /// in which case nothing is stored.
    pub(crate) fn insert(&mut self, key: &CacheKey, entry: CacheEntry) -> Result<(), CacheError> {
        let bytes = self.bytes.checked_add(entry.heap_size())?;
        let id = self.ring.insert(key.clone(), entry);
        self.index.insert(key.clone(), id);
        self.bytes = bytes;
        Ok(())
    }

    /// Removes the entry for `key`, returning the bytes it released.
    pub(crate) fn remove(&mut self, key: &CacheKey) -> Option<HeapBytes> {
        let id = self.index.remove(key)?;
        let removed = self.ring.remove(id)?;
        let released = removed.entry.heap_size();
        self.bytes = self.bytes.saturating_sub(released);
        Some(released)
    }

    /// Takes the next entry the hand picks out of the shard, releasing its bytes.
    pub(crate) fn evict_next(&mut self, now: Instant) -> Option<EvictedEntry> {
        let victim = self.ring.next_victim(now)?;
        self.index.remove(&victim.removed.key);
        self.bytes = self.bytes.saturating_sub(victim.removed.entry.heap_size());
        Some(EvictedEntry {
            expired: victim.expired,
        })
    }

    pub(crate) fn clear(&mut self) {
        self.index.clear();
        self.ring.clear();
        self.bytes = HeapBytes::zero();
    }
}

/// What the hand removed from a shard.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EvictedEntry {
    /// The entry had outlived its TTL.
    pub(crate) expired: bool,
}

/// A concurrency-isolated shard within [`ShardedAnswerCache`](super::ShardedAnswerCache).
#[derive(Debug)]
pub struct Shard {
    pub(crate) inner: RwLock<ShardInner>,
}

impl Shard {
    pub(crate) fn new(capacity: CacheCapacity) -> Self {
        Self {
            inner: RwLock::new(ShardInner::new(capacity)),
        }
    }

    /// Returns `true` if this shard contains an entry for `key`.
    #[must_use]
    pub fn contains_key(&self, key: &CacheKey) -> bool {
        self.inner.read().is_ok_and(|guard| guard.contains(key))
    }

    /// Returns the number of entries currently stored in this shard.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.inner.read().map_or(0, |guard| guard.len())
    }

    /// Returns the number of ring slots this shard has allocated, live or free.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.inner.read().map_or(0, |guard| guard.slot_count())
    }

    /// Returns the estimated heap bytes used by entries in this shard.
    #[must_use]
    pub fn heap_bytes(&self) -> HeapBytes {
        self.inner
            .read()
            .map_or_else(|_| HeapBytes::zero(), |guard| guard.bytes())
    }
}
