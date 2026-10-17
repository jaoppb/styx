//! Capacity eviction and expired entry reclamation, driven by the shard's CLOCK hand.

use std::time::Instant;

use crate::domain::cache::bytes::HeapBytes;
use crate::infrastructure::cache::shard::ShardInner;

/// Report detailing the results of making room in a shard.
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
    /// Evicts entries from `shard` until one more entry of `incoming` bytes fits within
    /// the shard's capacity.
    ///
    /// The hand takes an expired entry on sight and spares a recently hit one once, so
    /// each call does work proportional to the entries it evicts, not to the shard's size.
    #[must_use]
    pub(crate) fn make_room(
        shard: &mut ShardInner,
        now: Instant,
        incoming: HeapBytes,
    ) -> EvictionReport {
        let mut report = EvictionReport::default();
        while Self::needs_room(shard, incoming) {
            let Some(evicted) = shard.evict_next(now) else {
                break;
            };
            if evicted.expired {
                report.expired_reclaimed = report.expired_reclaimed.saturating_add(1);
            } else {
                report.evicted_fresh = report.evicted_fresh.saturating_add(1);
            }
        }
        report
    }

    fn needs_room(shard: &ShardInner, incoming: HeapBytes) -> bool {
        shard.capacity().needs_eviction(
            shard.len().saturating_add(1),
            shard.bytes().saturating_add(incoming),
        )
    }
}
