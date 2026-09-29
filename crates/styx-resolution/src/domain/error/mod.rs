//! Domain error types, split by concept.

pub mod config;
pub mod listener;
pub mod pipeline;
pub mod pool;
pub mod server;

pub use config::ConfigError;
pub use listener::ListenerError;
pub use pipeline::PipelineError;
pub use pool::PoolError;
pub use server::ServerError;
