//! Transport-adjacent framing helpers for DNS messages.
//!
//! Provides TCP length-prefixed framing support (RFC 1035 §4.2.2) without
//! performing any socket or synchronous I/O operations.

use crate::domain::error::{DecodeError, EncodeError};

/// Maximum message size supported by DNS over TCP (65535 octets).
pub const MAX_TCP_MESSAGE_LEN: usize = 65535;

/// Frames a serialized DNS message with a 2-octet big-endian length prefix.
///
/// # Errors
///
/// Returns [`EncodeError::RdLengthOverflow`] if the message exceeds 65535 octets.
pub fn frame_tcp(message_bytes: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let len = message_bytes.len();
    let len_u16 = u16::try_from(len).map_err(|_| EncodeError::RdLengthOverflow(len))?;
    let mut framed = Vec::with_capacity(len.saturating_add(2));
    framed.extend_from_slice(&len_u16.to_be_bytes());
    framed.extend_from_slice(message_bytes);
    Ok(framed)
}

/// Reads the 2-octet big-endian prefix specifying the expected message length.
///
/// # Errors
///
/// Returns [`DecodeError::UnexpectedEof`] if `header_bytes` has fewer than 2 octets.
pub fn read_tcp_frame_length(header_bytes: &[u8]) -> Result<u16, DecodeError> {
    let Some(&b0) = header_bytes.first() else {
        return Err(DecodeError::UnexpectedEof(0));
    };
    let Some(&b1) = header_bytes.get(1) else {
        return Err(DecodeError::UnexpectedEof(1));
    };
    Ok(u16::from_be_bytes([b0, b1]))
}
