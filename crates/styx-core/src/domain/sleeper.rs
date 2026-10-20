//! Injectable async sleep port.

use std::future::Future;
use std::time::Duration;

/// Injected source of delays, the async companion to [`Clock`](crate::Clock).
///
/// Production code uses `SystemSleeper` in `infrastructure::sleeper`. Test harnesses use
/// `TestSleeper` in `test_util::sleeper`, which completes when a `TestClock` has been advanced
/// past the delay rather than when real time has passed.
pub trait Sleeper: Send + Sync + 'static {
    /// Completes once `duration` has elapsed on this sleeper's notion of time.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}
