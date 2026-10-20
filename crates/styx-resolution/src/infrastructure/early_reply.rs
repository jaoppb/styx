//! Replies to a query the listener rejects before it reaches the pipeline.
//!
//! UDP and TCP build the same replies; only the sending differs. A message that is itself a
//! response (QR=1) is never answered, or two such servers could answer each other forever.

use styx_proto::{Header, Message, MessageKind, Opcode, ResponseCode, UnsupportedEdns};

use crate::domain::bad_edns_version_response;

/// FORMERR for bytes that did not decode, or `None` when they cannot be answered: a response
/// (QR=1), or too short to carry a transaction ID.
#[must_use]
pub(crate) fn formerr_reply(bytes: &[u8]) -> Option<Message> {
    if bytes.get(2).is_some_and(|&flags| (flags & 0x80) != 0) {
        return None;
    }
    let (&high, &low) = (bytes.first()?, bytes.get(1)?);
    let mut reply = Message::new(Header::new_query(
        u16::from_be_bytes([high, low]),
        Opcode::Query,
        false,
    ));
    reply.header.kind = MessageKind::Response;
    reply.header.rcode = ResponseCode::FORMERR;
    Some(reply)
}

/// BADVERS for a query that asked for an unsupported EDNS version (RFC 6891 §6.1.3), or
/// `None` when the rejected message is itself a response.
#[must_use]
pub(crate) fn badvers_reply(rejected: &UnsupportedEdns) -> Option<Message> {
    if rejected.header().kind == MessageKind::Response {
        return None;
    }
    Some(bad_edns_version_response(rejected))
}

#[cfg(test)]
mod tests {
    use styx_proto::application::{Decoder, Encoder};
    use styx_proto::{DecodeError, Opt};

    use super::*;

    #[test]
    fn formerr_echoes_the_transaction_id() {
        let reply = formerr_reply(&[0xAB, 0xCD, 0x01, 0x00]).expect("reply");

        assert_eq!(reply.header.id, 0xABCD);
        assert_eq!(reply.header.rcode, ResponseCode::FORMERR);
    }

    #[test]
    fn a_response_or_a_stub_gets_no_formerr() {
        assert!(formerr_reply(&[0xAB, 0xCD, 0x80, 0x00]).is_none());
        assert!(formerr_reply(&[0xAB]).is_none());
    }

    /// Runs a message with an EDNS version 1 OPT through the real decoder.
    fn rejected_edns(kind: MessageKind) -> UnsupportedEdns {
        let mut message = Message::new(Header::new_query(0x1234, Opcode::Query, true));
        message.header.kind = kind;
        message.opt = Some(Opt::new(1232, 1, false, Vec::new()));
        let mut encoder = Encoder::new(512);
        encoder.encode_message(&message).expect("encode");
        match Decoder::new(&encoder.buf).decode_message() {
            Err(DecodeError::UnsupportedEdnsVersion(rejected)) => rejected,
            other => panic!("expected an unsupported EDNS version, got {other:?}"),
        }
    }

    #[test]
    fn badvers_echoes_the_transaction_id() {
        let reply = badvers_reply(&rejected_edns(MessageKind::Query)).expect("reply");

        assert_eq!(reply.header.id, 0x1234);
        assert_eq!(reply.header.rcode, ResponseCode::BADVERS_OR_BADSIG);
        assert_eq!(reply.opt.as_ref().map(Opt::version), Some(0));
    }

    #[test]
    fn a_response_gets_no_badvers() {
        assert!(badvers_reply(&rejected_edns(MessageKind::Response)).is_none());
    }
}
