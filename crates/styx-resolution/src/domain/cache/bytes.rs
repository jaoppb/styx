//! Checked byte accounting for cache memory capacity.

use std::fmt;

use crate::domain::cache::error::CacheError;

/// An estimated heap byte count with overflow protection and saturating subtraction.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct HeapBytes {
    octets: usize,
}

impl HeapBytes {
    /// Creates a new `HeapBytes` count.
    #[must_use]
    pub const fn new(octets: usize) -> Self {
        Self { octets }
    }

    /// Returns zero bytes.
    #[must_use]
    pub const fn zero() -> Self {
        Self { octets: 0 }
    }

    /// Returns the underlying byte count as `usize`.
    #[must_use]
    pub const fn get(&self) -> usize {
        self.octets
    }

    /// Adds two `HeapBytes` counts with overflow detection.
    ///
    /// # Errors
    /// Returns [`CacheError::ByteAccountingOverflow`] if the addition overflows `usize`.
    pub fn checked_add(&self, other: Self) -> Result<Self, CacheError> {
        self.octets
            .checked_add(other.octets)
            .map(|octets| Self { octets })
            .ok_or(CacheError::ByteAccountingOverflow)
    }

    /// Subtracts `other` from `self`, saturating at zero.
    #[must_use]
    pub fn saturating_sub(&self, other: Self) -> Self {
        Self {
            octets: self.octets.saturating_sub(other.octets),
        }
    }
}

impl fmt::Debug for HeapBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeapBytes({} B)", self.octets)
    }
}

impl fmt::Display for HeapBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} B", self.octets)
    }
}
