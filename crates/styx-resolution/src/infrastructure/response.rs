//! DNS response serialization and wire truncation handling.

use styx_proto::application::Encoder;
use styx_proto::{EncodeError, Message, Opt, MAX_TCP_MESSAGE_LEN};

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
        let budget = usize::from(max_size.as_u16());
        let mut encoder = Encoder::new(budget);
        if encoder.encode_message(&message).is_ok() {
            return message;
        }

        message.header.truncated = true;

        if !message.additionals.is_empty() {
            message.additionals.clear();
            let mut encoder = Encoder::new(budget);
            if encoder.encode_message(&message).is_ok() {
                return message;
            }
        }

        if !message.authorities.is_empty() {
            message.authorities.clear();
            let mut encoder = Encoder::new(budget);
            if encoder.encode_message(&message).is_ok() {
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
    /// The response's EDNS OPT record is normalized to the server's configured payload size
    /// if the query included EDNS, or stripped if the query did not include EDNS (RFC 6891 §6.1.1).
    /// On UDP, truncation is applied against `ctx.max_response_size`.
    /// On TCP, the body is returned without a length prefix; the caller frames it on the
    /// wire through [`styx_net::write_framed`].
    ///
    /// # Errors
    /// Returns [`EncodeError`] on wire formatting failure or overflow.
    pub fn write(&self, message: Message, ctx: &RequestContext) -> Result<Vec<u8>, EncodeError> {
        let message = Self::normalize_opt(message, ctx);
        match ctx.transport {
            Transport::Udp => {
                let budget = usize::from(ctx.max_response_size.as_u16());
                let mut encoder = Encoder::new(budget);
                match encoder.encode_message(&message) {
                    Ok(()) => Ok(encoder.buf),
                    Err(EncodeError::BudgetExceeded { .. }) => {
                        Self::encode_truncated_udp(message, budget)
                    }
                    Err(err) => Err(err),
                }
            }
            Transport::Tcp => {
                let mut encoder = Encoder::new(MAX_TCP_MESSAGE_LEN);
                encoder.encode_message(&message)?;
                Ok(encoder.buf)
            }
        }
    }

    fn normalize_opt(mut message: Message, ctx: &RequestContext) -> Message {
        if ctx.query.opt.is_some() {
            let server_size = ctx.server_payload_size.as_u16();
            if let Some(opt) = message.opt.as_mut() {
                opt.set_udp_payload_size(server_size);
            } else {
                message.opt = Some(Opt::new(server_size, 0, 0, false, Vec::new()));
            }
        } else {
            message.opt = None;
        }
        message
    }

    fn encode_truncated_udp(mut message: Message, budget: usize) -> Result<Vec<u8>, EncodeError> {
        message.header.truncated = true;

        if !message.additionals.is_empty() {
            message.additionals.clear();
            let mut encoder = Encoder::new(budget);
            if encoder.encode_message(&message).is_ok() {
                return Ok(encoder.buf);
            }
        }

        if !message.authorities.is_empty() {
            message.authorities.clear();
            let mut encoder = Encoder::new(budget);
            if encoder.encode_message(&message).is_ok() {
                return Ok(encoder.buf);
            }
        }

        if !message.answers.is_empty() {
            message.answers.clear();
        }

        let mut encoder = Encoder::new(budget);
        encoder.encode_message(&message)?;
        Ok(encoder.buf)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Instant;

    use styx_proto::application::Decoder;
    use styx_proto::{Header, Opcode};

    use super::*;
    use crate::domain::request::ClientId;

    #[test]
    fn tcp_output_is_the_unframed_body() {
        let query = Message::new(Header::new_query(0xBEEF, Opcode::Query, true));
        let client = ClientId::from_socket_addr(SocketAddr::from(([127, 0, 0, 1], 5353)));
        let ctx = RequestContext::new(
            query.clone(),
            client,
            Transport::Tcp,
            MaxResponseSize::tcp_ceiling(),
            MaxResponseSize::from_edns_advertised(1232),
            Instant::now(),
        );

        let body = ResponseWriter::new()
            .write(query.clone(), &ctx)
            .expect("write");

        assert_eq!(body.get(..2), Some(&0xBEEFu16.to_be_bytes()[..]));
        let mut encoder = Encoder::new(MAX_TCP_MESSAGE_LEN);
        encoder.encode_message(&query).expect("encode");
        assert_eq!(body, encoder.buf);
    }

    #[test]
    fn response_opt_advertises_server_payload_size() {
        let mut query = Message::new(Header::new_query(1, Opcode::Query, true));
        query.opt = Some(Opt::new(65535, 0, 0, false, Vec::new()));
        let client = ClientId::from_socket_addr(SocketAddr::from(([127, 0, 0, 1], 5353)));
        let server_payload = MaxResponseSize::from_edns_advertised(1232);
        let ctx = RequestContext::new(
            query.clone(),
            client,
            Transport::Udp,
            server_payload,
            server_payload,
            Instant::now(),
        );

        let mut response = Message::new(Header::new_query(1, Opcode::Query, false));
        // Upstream response or terminal had client's advertised size
        response.opt = Some(Opt::new(65535, 0, 0, false, Vec::new()));

        let bytes = ResponseWriter::new().write(response, &ctx).expect("write");
        let decoded = Decoder::new(&bytes).decode_message().expect("decode");

        let opt = decoded.opt.expect("opt present");
        assert_eq!(opt.udp_payload_size(), 1232);
    }

    #[test]
    fn response_opt_is_stripped_when_query_has_no_opt() {
        let query = Message::new(Header::new_query(1, Opcode::Query, true));
        let client = ClientId::from_socket_addr(SocketAddr::from(([127, 0, 0, 1], 5353)));
        let server_payload = MaxResponseSize::from_edns_advertised(1232);
        let ctx = RequestContext::new(
            query,
            client,
            Transport::Udp,
            MaxResponseSize::classic(),
            server_payload,
            Instant::now(),
        );

        let mut response = Message::new(Header::new_query(1, Opcode::Query, false));
        // Upstream responded with an OPT
        response.opt = Some(Opt::new(4096, 0, 0, false, Vec::new()));

        let bytes = ResponseWriter::new().write(response, &ctx).expect("write");
        let decoded = Decoder::new(&bytes).decode_message().expect("decode");

        assert!(
            decoded.opt.is_none(),
            "OPT must be stripped when query had no EDNS"
        );
    }

    #[test]
    fn response_creates_opt_when_query_has_opt_and_response_had_none() {
        let mut query = Message::new(Header::new_query(1, Opcode::Query, true));
        query.opt = Some(Opt::new(4096, 0, 0, false, Vec::new()));
        let client = ClientId::from_socket_addr(SocketAddr::from(([127, 0, 0, 1], 5353)));
        let server_payload = MaxResponseSize::from_edns_advertised(1232);
        let ctx = RequestContext::new(
            query.clone(),
            client,
            Transport::Udp,
            server_payload,
            server_payload,
            Instant::now(),
        );

        let response = Message::new(Header::new_query(1, Opcode::Query, false));

        let bytes = ResponseWriter::new().write(response, &ctx).expect("write");
        let decoded = Decoder::new(&bytes).decode_message().expect("decode");

        let opt = decoded.opt.expect("opt generated");
        assert_eq!(opt.udp_payload_size(), 1232);
    }
}
