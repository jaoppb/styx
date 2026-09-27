//! Configurable upstream weight newtype.
//!
//! Encapsulates relative selection weight with bounds-checked arithmetic.

/// Validated relative weight assigned to an upstream in a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Weight(u32);

impl Weight {
    /// Creates a new `Weight`.
    ///
    /// Accepts any `u32` value including zero. All-zero pool weight handling
    /// is deferred to the weighted selection strategy.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw numeric weight.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.0
    }

    /// Computes the sum of a slice of weights using checked arithmetic.
    ///
    /// Returns `None` if the sum overflows [`u32::MAX`].
    #[must_use]
    pub fn checked_sum(weights: &[Self]) -> Option<Self> {
        let mut total: u32 = 0;
        for w in weights {
            total = total.checked_add(w.0)?;
        }
        Some(Self(total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_sum_overflow() {
        let weights = [Weight::new(u32::MAX), Weight::new(1)];
        assert_eq!(Weight::checked_sum(&weights), None);

        let valid = [Weight::new(10), Weight::new(20), Weight::new(30)];
        assert_eq!(Weight::checked_sum(&valid), Some(Weight::new(60)));
    }
}
