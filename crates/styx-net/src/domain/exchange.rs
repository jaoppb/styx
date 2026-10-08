//! The outcome of one outbound Do53 exchange.

use std::io::ErrorKind;

use styx_proto::{DecodeError, EncodeError, Message};
use thiserror::Error;

/// A response that passed the exchange's matching checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchanged {
    /// The decoded response, whose ID and question matched the query sent.
    pub message: Message,
    /// Whether the response arrived over TCP after a truncated UDP response.
    pub via_tcp: bool,
}

/// Errors from one outbound Do53 exchange.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExchangeError {
    /// No matching response arrived before the deadline or the per-transport timeout.
    #[error("dns exchange timed out")]
    Timeout,

    /// A socket operation failed.
    #[error("dns exchange transport error: {0}")]
    Transport(ErrorKind),

    /// The query message could not be encoded.
    #[error("dns query could not be encoded: {0}")]
    Encode(#[from] EncodeError),

    /// The query message carried no question to match a response against.
    #[error("dns query carries no question")]
    NoQuestion,

    /// A TCP response did not decode as a DNS message.
    #[error("dns response malformed: {0}")]
    Malformed(#[from] DecodeError),

    /// A TCP response's transaction ID or question did not match the query.
    ///
    /// Over UDP a mismatched datagram is discarded and the exchange keeps listening,
    /// because an off-path forger can send one; over a connected TCP stream there is
    /// no second response to wait for.
    #[error("dns response id or question did not match the query")]
    Mismatched,

    /// The response was still truncated after the TCP retry.
    #[error("dns response truncated over tcp")]
    Truncated,

    /// The query did not fit a TCP frame's two-octet length prefix.
    #[error("dns query of {length} octets exceeds the tcp frame limit")]
    OversizeFrame {
        /// The offending query length in octets.
        length: usize,
    },
}
