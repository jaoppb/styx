//! Domain layer: ports (traits) and core resolution contracts.

pub mod clock;
pub mod error;
pub mod sleeper;
pub mod upstream;

pub use clock::Clock;
pub use error::{FailureClass, UpstreamError};
pub use sleeper::Sleeper;
pub use upstream::{Upstream, UpstreamId, UpstreamKind, UpstreamResponse};
