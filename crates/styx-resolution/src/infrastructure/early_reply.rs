//! Replies to a query the listener rejects before it reaches the pipeline.
//!
//! UDP and TCP build the same replies; only the sending differs. A message that is itself a
//! response (QR=1) is never answered, or two such servers could answer each other forever.

use styx_proto::{Header, Message, MessageKind, Opcode, ResponseCode, UnsupportedEdns};

use crate::domain::bad_edns_version_response;
use crate::domain::client_reply::conform_header;

/// RD in the third header byte, which a query that failed to decode may still carry.
const RD_FLAG: u8 = 0x01;
/// CD in the fourth header byte.
const CD_FLAG: u8 = 0x10;

/// FORMERR for bytes that did not decode, or `None` when they cannot be answered: a response
/// (QR=1), or too short to carry a transaction ID.
///
/// The header flags are read straight from the bytes, so RD and CD are echoed when the datagram
/// got that far; the question section is not, since the message never decoded.
#[must_use]
pub(crate) fn formerr_reply(bytes: &[u8]) -> Option<Message> {
    if bytes.get(2).is_some_and(|&flags| (flags & 0x80) != 0) {
        return None;
    }
    let (&high, &low) = (bytes.first()?, bytes.get(1)?);
    let id = u16::from_be_bytes([high, low]);
    let recursion_desired = bytes.get(2).is_some_and(|&flags| (flags & RD_FLAG) != 0);
    let mut asked = Header::new_query(id, Opcode::Query, recursion_desired);
    asked.checking_disabled = bytes.get(3).is_some_and(|&flags| (flags & CD_FLAG) != 0);
    let mut reply = Message::new(Header::new_query(id, Opcode::Query, false));
    reply.header.kind = MessageKind::Response;
    reply.header.rcode = ResponseCode::FORMERR;
    conform_header(&mut reply.header, &asked);
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
        rejected_edns_with(kind, false)
    }

    fn rejected_edns_with(kind: MessageKind, checking_disabled: bool) -> UnsupportedEdns {
        let mut message = Message::new(Header::new_query(0x1234, Opcode::Query, true));
        message.header.kind = kind;
        message.header.checking_disabled = checking_disabled;
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
    fn formerr_takes_rd_and_cd_from_the_header_bytes_and_is_recursion_available() {
        let reply = formerr_reply(&[0xAB, 0xCD, 0x01, 0x10]).expect("reply");

        assert!(reply.header.recursion_desired);
        assert!(reply.header.checking_disabled);
        assert!(reply.header.recursion_available);
        assert!(!reply.header.authoritative);
    }

    #[test]
    fn formerr_leaves_rd_and_cd_clear_when_the_query_did_not_set_them() {
        let reply = formerr_reply(&[0xAB, 0xCD, 0x00, 0x00]).expect("reply");

        assert!(!reply.header.recursion_desired);
        assert!(!reply.header.checking_disabled);
        assert!(reply.header.recursion_available);
    }

    #[test]
    fn badvers_copies_cd_and_is_recursion_available() {
        let rejected = rejected_edns_with(MessageKind::Query, true);

        let reply = badvers_reply(&rejected).expect("reply");

        assert!(reply.header.recursion_desired);
        assert!(reply.header.checking_disabled);
        assert!(reply.header.recursion_available);
        assert!(!reply.header.authoritative);
    }

    #[test]
    fn a_response_gets_no_badvers() {
        assert!(badvers_reply(&rejected_edns(MessageKind::Response)).is_none());
    }
}
