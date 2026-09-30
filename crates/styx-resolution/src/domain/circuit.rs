//! Circuit breaker types, states, and configuration for pool members.

use std::time::{Duration, Instant};

/// Monotonically saturating failure counter.
///
/// Wraps a `u32` value and prevents overflow or raw arithmetic side-effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FailureCount(u32);

impl FailureCount {
    /// Creates a new failure count initialized to zero.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Returns the underlying numeric failure count.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.0
    }

    /// Returns a new failure count incremented by 1, saturating at [`u32::MAX`].
    #[must_use]
    pub const fn increment_saturating(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// State machine states for an upstream member's circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation; healthy and admitting all traffic.
    Closed,
    /// Down/tripped; traffic shed until the cooldown period elapses.
    Open {
        /// Timestamp when the circuit tripped into open state.
        since: Instant,
    },
    /// Testing recovery; admitting a limited probe or trial traffic.
    HalfOpen {
        /// Whether a trial query or probe is currently in flight.
        in_flight: bool,
    },
}

/// Tunable policy thresholds for tripping and recovering the circuit breaker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitConfig {
    /// Consecutive upstream faults required to trip circuit from Closed to Open.
    pub failure_threshold: u32,
    /// Cooldown duration an open circuit must wait before attempting HalfOpen.
    pub open_cooldown: Duration,
    /// Consecutive successful trials required in HalfOpen to return to Closed.
    pub half_open_successes: u32,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            open_cooldown: Duration::from_secs(30),
            half_open_successes: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_count_saturating() {
        let count = FailureCount::zero();
        assert_eq!(count.value(), 0);
        let count = count.increment_saturating();
        assert_eq!(count.value(), 1);

        let max = FailureCount(u32::MAX);
        assert_eq!(max.increment_saturating().value(), u32::MAX);
    }
}
