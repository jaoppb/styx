//! Injectable time abstraction port.
//!
//! Provides the [`Clock`] trait, abstracting both monotonic and wall-clock
//! time for deterministic testing and DNSSEC/cache timing accuracy.

use std::time::{Instant, SystemTime};

/// Injected time provider for wall-clock and monotonic time.
///
/// Implementations must be thread-safe (`Send + Sync + 'static`).
///
/// Production code uses `SystemClock` in `infrastructure::clock`.
/// Test harnesses use `TestClock` in `test_util::clock`.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current wall-clock UTC time.
    ///
    /// Used for RRSIG inception/expiration comparison (phase 6) and
    /// query-log rollup bucket boundaries (phase 10).
    fn now_utc(&self) -> SystemTime;

    /// Returns the current monotonic instant.
    ///
    /// Used for SRTT decay, circuit-breaker timing, idle-window probes
    /// (phase 3), TTL expiry (phase 4), and query timeouts.
    fn now_monotonic(&self) -> Instant;
}
