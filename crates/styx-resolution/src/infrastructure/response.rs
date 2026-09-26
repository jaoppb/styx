//! DNS response serialization and wire truncation handling.

use styx_proto::application::Encoder;
use styx_proto::{EncodeError, Message, MAX_TCP_MESSAGE_LEN};

use crate::domain::request::{MaxResponseSize, RequestContext, Transport};

/// Serializes DNS response messages and manages transport-specific truncation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResponseWriter;

impl ResponseWriter {
    /// Creates a new `ResponseWriter`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Truncates a message if its encoded representation exceeds `max_size`.
    ///
    /// If the message fits within `max_size.fits(...)`, it is returned unchanged.
    /// If it exceeds `max_size`, the TC bit is set and sections are dropped
    /// in order: Additionals -> Authorities -> Answers, until it fits.
    /// The Header and Questions sections are never dropped.
    #[must_use]
    pub fn truncate_if_needed(mut message: Message, max_size: MaxResponseSize) -> Message {
        if Self::message_fits(&message, max_size) {
            return message;
        }

        message.header.truncated = true;

        if !message.additionals.is_empty() {
            message.additionals.clear();
            if Self::message_fits(&message, max_size) {
                return message;
            }
        }

        if !message.authorities.is_empty() {
            message.authorities.clear();
            if Self::message_fits(&message, max_size) {
                return message;
            }
        }

        if !message.answers.is_empty() {
            message.answers.clear();
        }

        message
    }

    /// Serializes a response message for transmission over the context's transport.
    ///
    /// On UDP, truncation is applied against `ctx.max_response_size`.
    /// On TCP, a 2-byte big-endian frame prefix is prepended.
    ///
    /// # Errors
    /// Returns [`EncodeError`] on wire formatting failure or overflow.
    pub fn write(&self, message: Message, ctx: &RequestContext) -> Result<Vec<u8>, EncodeError> {
        match ctx.transport {
            Transport::Udp => {
                let prepared = Self::truncate_if_needed(message, ctx.max_response_size);
                let mut encoder = Encoder::new(usize::from(ctx.max_response_size.as_u16()));
                encoder.encode_message(&prepared)?;
                Ok(encoder.buf)
            }
            Transport::Tcp => {
                let mut encoder = Encoder::new(MAX_TCP_MESSAGE_LEN);
                encoder.encode_message(&message)?;
                styx_proto::frame_tcp(&encoder.buf)
            }
        }
    }

    fn message_fits(message: &Message, max_size: MaxResponseSize) -> bool {
        let mut encoder = Encoder::new(MAX_TCP_MESSAGE_LEN);
        if encoder.encode_message(message).is_err() {
            return false;
        }
        max_size.fits(encoder.buf.len())
    }
}
