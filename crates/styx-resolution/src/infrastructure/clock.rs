//! System implementation of the [`Clock`] port.

use std::time::{Instant, SystemTime};

use crate::domain::clock::Clock;

/// Production [`Clock`] implementation backed directly by operating system clocks.
///
/// This is the only component in shipping code that queries the OS clock directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// Creates a new `SystemClock`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now_utc(&self) -> SystemTime {
        SystemTime::now()
    }

    fn now_monotonic(&self) -> Instant {
        Instant::now()
    }
}
