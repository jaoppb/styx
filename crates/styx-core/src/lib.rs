//! Shared foundation for styx: cross-resolution contracts and ports.
//!
//! Provides the primary domain traits and value types shared across resolution,
//! filtering, recursion, and listener components:
//! - [`Clock`] and [`SystemClock`] for time abstraction.
//! - [`Upstream`], [`UpstreamId`], [`UpstreamKind`], [`UpstreamResponse`],
//!   [`UpstreamError`], and [`FailureClass`] for the unified resolution contract.
//! - [`TestClock`] behind the `test-support` feature for deterministic tests.

pub mod domain;
pub mod infrastructure;

#[cfg(feature = "test-support")]
pub mod test_util;

pub use domain::clock::Clock;
pub use domain::error::{FailureClass, UpstreamError};
pub use domain::upstream::{Upstream, UpstreamId, UpstreamKind, UpstreamResponse};
pub use infrastructure::SystemClock;

#[cfg(feature = "test-support")]
pub use test_util::TestClock;
