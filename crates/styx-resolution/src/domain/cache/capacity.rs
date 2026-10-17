//! Answer cache capacity limits and eviction triggers.

use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::error::CacheError;

/// Default maximum entries bound (10,000 entries).
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default maximum memory bound (20 MiB).
pub const DEFAULT_MAX_BYTES: usize = 20 * 1024 * 1024;

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
    /// Returns [`CacheError::ZeroShards`] for no shards, and
    /// [`CacheError::BudgetBelowShardCount`] when either bound is smaller than the shard
    /// count, which would leave a shard that can hold nothing.
    pub fn partition(&self, shard_count: usize) -> Result<Vec<Self>, CacheError> {
        if shard_count == 0 {
            return Err(CacheError::ZeroShards);
        }
        let too_small = CacheError::BudgetBelowShardCount {
            shards: shard_count,
            max_entries: self.max_entries,
            max_bytes: self.max_bytes.get(),
        };
        if self.max_entries < shard_count || self.max_bytes.get() < shard_count {
            return Err(too_small);
        }
        let entry_shares = Self::split(self.max_entries, shard_count).ok_or(too_small.clone())?;
        let byte_shares = Self::split(self.max_bytes.get(), shard_count).ok_or(too_small)?;
        Ok(entry_shares
            .zip(byte_shares)
            .map(|(max_entries, max_bytes)| Self::new(max_entries, HeapBytes::new(max_bytes)))
            .collect())
    }

    /// Divides `total` into `parts` shares that sum to `total`, larger shares first.
    fn split(total: usize, parts: usize) -> Option<impl Iterator<Item = usize>> {
        let base = total.checked_div(parts)?;
        let remainder = total.checked_rem(parts)?;
        Some((0..parts).map(move |index| {
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
        let parts = shares(10, 1000, 4);
        let entries: Vec<usize> = parts.iter().map(CacheCapacity::max_entries).collect();
        assert_eq!(entries, [3, 3, 2, 2]);
    }

    #[test]
    fn every_share_holds_at_least_one_entry() {
        let parts = shares(32, 32, 32);
        assert!(parts.iter().all(|part| part.max_entries() == 1));
    }

    #[test]
    fn rejects_zero_shards() {
        let capacity = CacheCapacity::default();
        assert_eq!(capacity.partition(0), Err(CacheError::ZeroShards));
    }

    #[test]
    fn rejects_fewer_entries_than_shards() {
        let capacity = CacheCapacity::new(31, HeapBytes::new(1 << 20));
        assert!(matches!(
            capacity.partition(32),
            Err(CacheError::BudgetBelowShardCount {
                shards: 32,
                max_entries: 31,
                ..
            })
        ));
    }

    #[test]
    fn rejects_fewer_bytes_than_shards() {
        let capacity = CacheCapacity::new(1000, HeapBytes::new(31));
        assert!(matches!(
            capacity.partition(32),
            Err(CacheError::BudgetBelowShardCount {
                shards: 32,
                max_bytes: 31,
                ..
            })
        ));
    }
}
