//! Answer cache capacity limits and eviction triggers.

use crate::domain::cache::bytes::HeapBytes;

/// Default maximum entries bound (10,000 entries).
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default maximum memory bound (20 MiB).
pub const DEFAULT_MAX_BYTES: usize = 20 * 1024 * 1024;

/// Upper memory and entry bounds for the answer cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheCapacity {
    /// Maximum number of cached entries allowed.
    pub max_entries: usize,
    /// Maximum estimated heap bytes allowed across all entries.
    pub max_bytes: HeapBytes,
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

    /// Returns `true` if current entry count or byte usage exceeds the configured bounds.
    #[must_use]
    pub fn needs_eviction(&self, entries: usize, bytes: HeapBytes) -> bool {
        entries > self.max_entries || bytes > self.max_bytes
    }
}
