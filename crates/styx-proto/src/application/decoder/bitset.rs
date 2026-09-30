//! Compact bitset for tracking byte offsets up to the message length.

const INLINE_BITS: usize = 512;
const INLINE_WORDS: usize = 8;
const WORD_SHIFT: usize = 6;
const WORD_MASK: usize = 63;

#[derive(Debug, Clone)]
enum Storage {
    Inline([u64; INLINE_WORDS]),
    Heap(Vec<u64>),
}

/// A compact bitset for tracking message byte offsets.
///
/// An inline array of 8 `u64` words (512 bits) covers standard DNS queries
/// and responses without any heap allocations. Buffers larger than 512 octets
/// use a single heap-allocated vector of 64-bit words.
#[derive(Debug, Clone)]
pub struct OffsetBitset {
    storage: Storage,
}

impl OffsetBitset {
    /// Creates a new `OffsetBitset` sized to cover `capacity_bits`.
    #[must_use]
    pub fn new(capacity_bits: usize) -> Self {
        if capacity_bits <= INLINE_BITS {
            Self {
                storage: Storage::Inline([0u64; INLINE_WORDS]),
            }
        } else {
            let words = capacity_bits.saturating_add(63) >> WORD_SHIFT;
            Self {
                storage: Storage::Heap(vec![0u64; words]),
            }
        }
    }

    /// Resets all bits to zero.
    pub fn clear(&mut self) {
        match &mut self.storage {
            Storage::Inline(arr) => arr.fill(0),
            Storage::Heap(vec) => vec.fill(0),
        }
    }

    /// Sets the bit corresponding to `bit_index`.
    pub fn insert(&mut self, bit_index: usize) {
        let word_idx = bit_index >> WORD_SHIFT;
        let bit_in_word = bit_index & WORD_MASK;
        let mask = 1u64 << bit_in_word;

        match &mut self.storage {
            Storage::Inline(arr) => {
                if let Some(word) = arr.get_mut(word_idx) {
                    *word |= mask;
                }
            }
            Storage::Heap(vec) => {
                if let Some(word) = vec.get_mut(word_idx) {
                    *word |= mask;
                }
            }
        }
    }

    /// Returns `true` if the bit corresponding to `bit_index` is set.
    #[must_use]
    pub fn contains(&self, bit_index: usize) -> bool {
        let word_idx = bit_index >> WORD_SHIFT;
        let bit_in_word = bit_index & WORD_MASK;
        let mask = 1u64 << bit_in_word;

        match &self.storage {
            Storage::Inline(arr) => arr.get(word_idx).is_some_and(|word| (*word & mask) != 0),
            Storage::Heap(vec) => vec.get(word_idx).is_some_and(|word| (*word & mask) != 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inline_bitset() {
        let mut bs = OffsetBitset::new(128);
        assert!(!bs.contains(12));
        bs.insert(12);
        assert!(bs.contains(12));
        assert!(!bs.contains(13));
        bs.clear();
        assert!(!bs.contains(12));
    }

    #[test]
    fn test_heap_bitset() {
        let mut bs = OffsetBitset::new(4096);
        assert!(!bs.contains(1024));
        bs.insert(1024);
        assert!(bs.contains(1024));
        assert!(!bs.contains(1025));
        bs.clear();
        assert!(!bs.contains(1024));
    }
}
