//! Domain layer: ports (traits) and core resolution contracts.

pub mod clock;
pub mod error;
pub mod sleeper;
pub mod toml_key;
pub mod upstream;

pub use clock::Clock;
pub use error::{FailureClass, UpstreamError};
pub use sleeper::Sleeper;
pub use toml_key::format_toml_key;
pub use upstream::{Upstream, UpstreamId, UpstreamKind, UpstreamResponse};
