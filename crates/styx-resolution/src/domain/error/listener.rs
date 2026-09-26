//! Listener error taxonomy.

use styx_proto::{DecodeError, EncodeError};
use thiserror::Error;

/// Errors arising during transport listening, socket I/O, or message framing.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// Underlying socket or transport I/O failure.
    #[error("transport I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// DNS message decode failure.
    #[error("wire decode error: {0}")]
    Decode(#[from] DecodeError),

    /// DNS message encode failure.
    #[error("wire encode error: {0}")]
    Encode(#[from] EncodeError),

    /// TCP stream framing error (e.g. truncated length prefix or oversized message).
    #[error("stream framing error: {0}")]
    Framing(String),
}
