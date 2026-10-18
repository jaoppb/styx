//! Controllable test clock implementation.

use std::sync::Mutex;

use std::time::{Duration, Instant, SystemTime};
use tokio::sync::futures::Notified;
use tokio::sync::Notify;

use crate::domain::clock::Clock;

#[derive(Debug)]
struct ClockState {
    wall_now: SystemTime,
    mono_base: Instant,
    mono_offset: Duration,
}

/// Controllable test double implementing [`Clock`].
///
/// Allows advancing monotonic and wall-clock offsets deterministically
/// without sleeping or relying on non-deterministic real-world delays.
#[derive(Debug)]
pub struct TestClock {
    state: Mutex<ClockState>,
    advanced: Notify,
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TestClock {
    /// Creates a new `TestClock` initialized to the current system time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ClockState {
                wall_now: SystemTime::now(),
                mono_base: Instant::now(),
                mono_offset: Duration::ZERO,
            }),
            advanced: Notify::new(),
        }
    }

    /// Advances both monotonic instant and wall-clock system time by `duration`.
    pub fn advance(&self, duration: Duration) {
        let mut s = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        s.wall_now = match s.wall_now.checked_add(duration) {
            Some(t) => t,
            None => s.wall_now,
        };
        s.mono_offset = s.mono_offset.saturating_add(duration);
        drop(s);
        self.advanced.notify_waiters();
    }

    /// Returns a future that completes the next time [`Self::advance`] is called.
    pub(crate) fn advanced(&self) -> Notified<'_> {
        self.advanced.notified()
    }

    /// Overrides the wall-clock time without moving monotonic instant.
    pub fn set_utc(&self, time: SystemTime) {
        let mut s = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        s.wall_now = time;
    }
}

impl Clock for TestClock {
    fn now_utc(&self) -> SystemTime {
        let s = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        s.wall_now
    }

    fn now_monotonic(&self) -> Instant {
        let s = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match s.mono_base.checked_add(s.mono_offset) {
            Some(t) => t,
            None => s.mono_base,
        }
    }
}
