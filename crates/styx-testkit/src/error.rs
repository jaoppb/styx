//! Harness error definitions.

use thiserror::Error;

/// Errors arising within the integration test harness.
#[derive(Debug, Error)]
pub enum HarnessError {
    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Wire protocol decode error.
    #[error("protocol decode error: {0}")]
    Decode(#[from] styx_proto::DecodeError),

    /// Wire protocol encode error.
    #[error("protocol encode error: {0}")]
    Encode(#[from] styx_proto::EncodeError),

    /// Startup or supervision failure of a server under test.
    ///
    /// Carried as text because this crate names no feature crate's error type.
    #[error("server error: {0}")]
    Server(String),

    /// Hickory test oracle protocol error.
    #[error("hickory error: {0}")]
    Hickory(#[from] hickory_proto::ProtoError),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Protocol assertion or framing failure.
    #[error("protocol error: {0}")]
    Protocol(String),
}
