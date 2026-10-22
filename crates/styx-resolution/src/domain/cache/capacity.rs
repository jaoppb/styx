//! Answer cache capacity limits and eviction triggers.

use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::error::CacheError;

/// Default maximum entries bound (10,000 entries).
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default maximum memory bound (20 MiB).
pub const DEFAULT_MAX_BYTES: usize = 20 * 1024 * 1024;

/// Default number of concurrent shards (32).
pub const DEFAULT_SHARDS: usize = 32;

/// Fewest bytes a shard's share of the budget may hold: one maximum-size answer.
///
/// A 64 KiB wire message is the largest a reply can be. [`HeapBytes`] estimates 16 bytes per
/// RDATA and 128 per signature, which puts the worst such answer near four times its wire
/// size, so a share below this could refuse a legitimate answer as oversized.
pub const MIN_SHARD_BYTES: usize = 256 * 1024;

/// Upper memory and entry bounds for the answer cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheCapacity {
    max_entries: usize,
    max_bytes: HeapBytes,
}

impl Default for CacheCapacity {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: HeapBytes::new(DEFAULT_MAX_BYTES),
        }
    }
}

impl CacheCapacity {
    /// Creates a new `CacheCapacity` constraint.
    #[must_use]
    pub const fn new(max_entries: usize, max_bytes: HeapBytes) -> Self {
        Self {
            max_entries,
            max_bytes,
        }
    }

    /// Maximum number of cached entries allowed.
    #[must_use]
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Maximum estimated heap bytes allowed across all entries.
    #[must_use]
    pub const fn max_bytes(&self) -> HeapBytes {
        self.max_bytes
    }

    /// Returns `true` if current entry count or byte usage exceeds the configured bounds.
    #[must_use]
    pub fn needs_eviction(&self, entries: usize, bytes: HeapBytes) -> bool {
        entries > self.max_entries || bytes > self.max_bytes
    }

    /// Splits this budget into one share per shard, so the shares sum to exactly the
    /// configured total and the bound holds for the whole cache.
    ///
    /// The remainder of each division goes one unit apiece to the first shards.
    ///
    /// # Errors
    /// Returns [`CacheError::ZeroShards`] for no shards, [`CacheError::BudgetBelowShardCount`]
    /// when there are fewer entries than shards, and [`CacheError::ByteShareBelowFloor`]
    /// when the smallest byte share could not hold [`MIN_SHARD_BYTES`], which would leave a
    /// shard that refuses ordinary answers and a cache that silently stops caching.
    pub fn partition(&self, shard_count: usize) -> Result<Vec<Self>, CacheError> {
        if shard_count == 0 {
            return Err(CacheError::ZeroShards);
        }
        if self.max_entries < shard_count {
            return Err(CacheError::BudgetBelowShardCount {
                shards: shard_count,
                max_entries: self.max_entries,
            });
        }
        let smallest_share = self.max_bytes.get().checked_div(shard_count);
        if smallest_share.is_none_or(|share| share < MIN_SHARD_BYTES) {
            return Err(CacheError::ByteShareBelowFloor {
                shards: shard_count,
                max_bytes: self.max_bytes.get(),
                minimum_bytes: MIN_SHARD_BYTES.saturating_mul(shard_count),
            });
        }
        let entry_shares = Self::split(self.max_entries, shard_count)?;
        let byte_shares = Self::split(self.max_bytes.get(), shard_count)?;
        Ok(entry_shares
            .zip(byte_shares)
            .map(|(max_entries, max_bytes)| Self::new(max_entries, HeapBytes::new(max_bytes)))
            .collect())
    }

    /// Divides `total` into `parts` shares that sum to `total`, larger shares first.
    fn split(total: usize, parts: usize) -> Result<impl Iterator<Item = usize>, CacheError> {
        let base = total.checked_div(parts).ok_or(CacheError::ZeroShards)?;
        let remainder = total.checked_rem(parts).ok_or(CacheError::ZeroShards)?;
        Ok((0..parts).map(move |index| {
            if index < remainder {
                base.saturating_add(1)
            } else {
                base
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shares(entries: usize, bytes: usize, shards: usize) -> Vec<CacheCapacity> {
        CacheCapacity::new(entries, HeapBytes::new(bytes))
            .partition(shards)
            .expect("partition")
    }

    #[test]
    fn shares_sum_to_exactly_the_configured_total() {
        let parts = shares(100, 20 * 1024 * 1024, 32);
        assert_eq!(parts.len(), 32);
        assert_eq!(
            parts.iter().map(CacheCapacity::max_entries).sum::<usize>(),
            100
        );
        assert_eq!(
            parts
                .iter()
                .map(|part| part.max_bytes().get())
                .sum::<usize>(),
            20 * 1024 * 1024
        );
    }

    #[test]
    fn remainder_goes_to_the_first_shards_one_apiece() {
        let parts = shares(10, 4 * MIN_SHARD_BYTES + 3, 4);
        let entries: Vec<usize> = parts.iter().map(CacheCapacity::max_entries).collect();
        assert_eq!(entries, [3, 3, 2, 2]);
        let bytes: Vec<usize> = parts.iter().map(|part| part.max_bytes().get()).collect();
        assert_eq!(
            bytes,
            [
                MIN_SHARD_BYTES + 1,
                MIN_SHARD_BYTES + 1,
                MIN_SHARD_BYTES + 1,
                MIN_SHARD_BYTES
            ]
        );
    }

    #[test]
    fn every_share_holds_at_least_one_entry() {
        let parts = shares(32, 32 * MIN_SHARD_BYTES, 32);
        assert!(parts.iter().all(|part| part.max_entries() == 1));
    }

    #[test]
    fn rejects_zero_shards() {
        let capacity = CacheCapacity::default();
        assert_eq!(capacity.partition(0), Err(CacheError::ZeroShards));
    }

    #[test]
    fn rejects_fewer_entries_than_shards() {
        let capacity = CacheCapacity::new(31, HeapBytes::new(1 << 30));
        assert_eq!(
            capacity.partition(32),
            Err(CacheError::BudgetBelowShardCount {
                shards: 32,
                max_entries: 31,
            })
        );
    }

    #[test]
    fn rejects_a_byte_share_below_the_floor_and_names_the_minimum_total() {
        let capacity = CacheCapacity::new(1000, HeapBytes::new(32 * MIN_SHARD_BYTES - 1));
        assert_eq!(
            capacity.partition(32),
            Err(CacheError::ByteShareBelowFloor {
                shards: 32,
                max_bytes: 32 * MIN_SHARD_BYTES - 1,
                minimum_bytes: 32 * MIN_SHARD_BYTES,
            })
        );
    }

    #[test]
    fn accepts_a_budget_exactly_at_the_floor() {
        let parts = shares(32, 32 * MIN_SHARD_BYTES, 32);
        assert!(parts
            .iter()
            .all(|part| part.max_bytes().get() == MIN_SHARD_BYTES));
    }
}
