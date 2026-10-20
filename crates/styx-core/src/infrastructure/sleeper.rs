//! System implementation of the [`Sleeper`] port.

use std::future::Future;
use std::time::Duration;

use crate::domain::sleeper::Sleeper;

/// Production [`Sleeper`] implementation backed by the tokio timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSleeper;

impl SystemSleeper {
    /// Creates a new `SystemSleeper`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Sleeper for SystemSleeper {
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}
