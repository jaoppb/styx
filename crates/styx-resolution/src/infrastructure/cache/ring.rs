//! A slab used as a CLOCK ring: second-chance recency without a recency list.
//!
//! A hit only sets an atomic `visited` bit on the entry's slot, which needs no more than
//! a shared reference, so a shard serves hits under its read lock. Eviction sweeps a hand
//! round the slab under the write lock: it clears a set bit and moves on, and takes the
//! first slot whose bit is already clear. Every sweep step is O(1) and each set bit costs
//! one step to clear, so admission is amortised O(1). The slab grows only when no slot is
//! free, so it never outgrows the entries the shard may hold, and the hand's sweep is
//! bounded by that share however the traffic comes and goes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::key::CacheKey;

/// Position of an entry in a [`ClockRing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotId(usize);

#[derive(Debug)]
struct Slot {
    key: CacheKey,
    entry: Arc<CacheEntry>,
    visited: AtomicBool,
}

/// An entry taken out of the ring.
#[derive(Debug)]
pub(crate) struct Removed {
    pub(crate) key: CacheKey,
    pub(crate) entry: Arc<CacheEntry>,
}

/// An entry the hand chose to evict, and why.
#[derive(Debug)]
pub(crate) struct Victim {
    pub(crate) removed: Removed,
    /// The entry had outlived its TTL, whatever its visited bit said.
    pub(crate) expired: bool,
}

/// Slab of cache entries swept by a second-chance hand.
#[derive(Debug, Default)]
pub(crate) struct ClockRing {
    slots: Vec<Option<Slot>>,
    free: Vec<usize>,
    hand: usize,
}

impl ClockRing {
    /// Stores an entry with a clear visited bit, so it must be hit once to survive a sweep.
    pub(crate) fn insert(&mut self, key: CacheKey, entry: CacheEntry) -> SlotId {
        let slot = Some(Slot {
            key,
            entry: Arc::new(entry),
            visited: AtomicBool::new(false),
        });
        let reusable = self
            .free
            .pop()
            .and_then(|position| self.slots.get_mut(position).map(|place| (position, place)));
        if let Some((position, place)) = reusable {
            *place = slot;
            return SlotId(position);
        }
        self.slots.push(slot);
        SlotId(self.slots.len().saturating_sub(1))
    }

    /// Takes the entry in `id` out of the ring.
    pub(crate) fn remove(&mut self, id: SlotId) -> Option<Removed> {
        let slot = self.slots.get_mut(id.0)?.take()?;
        self.free.push(id.0);
        Some(Removed {
            key: slot.key,
            entry: slot.entry,
        })
    }

    /// Returns a shared handle to the entry in `id` and marks it visited. Needs only
    /// `&self`, and copies no more than a reference count.
    pub(crate) fn touch(&self, id: SlotId) -> Option<Arc<CacheEntry>> {
        let slot = self.slots.get(id.0)?.as_ref()?;
        slot.visited.store(true, Ordering::Relaxed);
        Some(Arc::clone(&slot.entry))
    }

    /// Returns `true` if the entry in `id` is still fresh at `now`.
    pub(crate) fn is_fresh(&self, id: SlotId, now: Instant) -> bool {
        self.slots
            .get(id.0)
            .and_then(Option::as_ref)
            .is_some_and(|slot| slot.entry.is_fresh(now))
    }

    /// Advances the hand to the next entry to evict and takes it out of the ring.
    ///
    /// An expired entry is taken on sight; a visited one is spared once and its bit
    /// cleared. Returns `None` only when the ring is empty.
    pub(crate) fn next_victim(&mut self, now: Instant) -> Option<Victim> {
        let steps = self.slots.len().saturating_mul(2);
        for _ in 0..steps {
            let position = self.advance_hand()?;
            let Some(slot) = self.slots.get_mut(position).and_then(Option::as_mut) else {
                continue;
            };
            let expired = !slot.entry.is_fresh(now);
            if !expired && slot.visited.swap(false, Ordering::Relaxed) {
                continue;
            }
            let removed = self.remove(SlotId(position))?;
            return Some(Victim { removed, expired });
        }
        None
    }

    /// Returns how many slots the ring has allocated, live or free.
    pub(crate) fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Empties the ring.
    pub(crate) fn clear(&mut self) {
        self.slots.clear();
        self.free.clear();
        self.hand = 0;
    }

    /// Returns the slot the hand points at and moves it on, wrapping at the end.
    fn advance_hand(&mut self) -> Option<usize> {
        let position = self.hand;
        self.hand = position.saturating_add(1).checked_rem(self.slots.len())?;
        Some(position)
    }
}
