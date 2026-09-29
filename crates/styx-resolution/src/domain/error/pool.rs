//! Upstream pool errors.

use thiserror::Error;

/// Errors returned by the upstream pool dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PoolError {
    /// All configured upstreams in the pool are currently down / unavailable.
    #[error("all upstreams in pool are unavailable")]
    AllUpstreamsDown,

    /// All attempted candidate upstreams failed to produce a valid response.
    #[error("exhausted all candidate upstreams in pool; last error: {last_error:?}")]
    Exhausted {
        /// The last upstream error encountered, if any.
        last_error: Option<styx_core::UpstreamError>,
    },
}
