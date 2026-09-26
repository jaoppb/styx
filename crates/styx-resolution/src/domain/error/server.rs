//! Server lifecycle error taxonomy.

use std::net::SocketAddr;

use thiserror::Error;

use super::listener::ListenerError;

/// Errors arising during server binding, startup, or task supervision.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Failed to bind to a configured socket address.
    #[error("failed to bind to {addr}: {source}")]
    Bind {
        /// Target socket address.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A transport listener encountered a fatal error.
    #[error("listener failure: {0}")]
    Listener(#[from] ListenerError),

    /// Server task join or shutdown failure.
    #[error("server task failure: {0}")]
    Task(String),
}
