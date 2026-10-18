//! Shared foundation for styx: cross-resolution contracts and ports.
//!
//! Provides the primary domain traits and value types shared across resolution,
//! filtering, recursion, and listener components:
//! - [`Clock`] and [`SystemClock`] for time abstraction.
//! - [`Sleeper`] and [`SystemSleeper`] for injectable async delays.
//! - [`Upstream`], [`UpstreamId`], [`UpstreamKind`], [`UpstreamResponse`],
//!   [`UpstreamError`], and [`FailureClass`] for the unified resolution contract.
//! - [`TestClock`] and [`TestSleeper`] behind the `test-support` feature for deterministic tests.

pub mod domain;
pub mod infrastructure;

#[cfg(feature = "test-support")]
pub mod test_util;

pub use domain::clock::Clock;
pub use domain::error::{FailureClass, ReplyFault, UpstreamError};
pub use domain::sleeper::Sleeper;
pub use domain::upstream::{Upstream, UpstreamId, UpstreamKind, UpstreamResponse};
pub use infrastructure::{SystemClock, SystemSleeper};

#[cfg(feature = "test-support")]
pub use test_util::{TestClock, TestSleeper};
