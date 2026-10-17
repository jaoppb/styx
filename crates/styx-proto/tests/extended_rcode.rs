//! The 12-bit response code spans the header nibble and the OPT's upper octet
//! (RFC 6891 §6.1.3). `Header::rcode` is the only place the whole value lives:
//! the decoder merges the two halves on the way in, the encoder splits them on
//! the way out, and a rejected EDNS version hands the query back to the caller.

use styx_proto::domain::error::{DecodeError, EncodeError, NameError};
use styx_proto::domain::header::{Header, MessageKind, Opcode, ResponseCode};
use styx_proto::domain::name::Name;
use styx_proto::domain::question::Question;
use styx_proto::domain::record::{RecordClass, RecordType};
use styx_proto::{Message, Opt};

const HEADER_LEN: usize = 12;
/// Offset of the OPT TTL's first octet (the extended RCODE) in a message with no
/// questions: root owner (1) + type (2) + class (2) past the header.
const OPT_EXTENDED_RCODE_OFFSET: usize = HEADER_LEN + 5;

fn header_bytes(flags: u16, qdcount: u16, arcount: u16) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN);
    bytes.extend_from_slice(&0x1234u16.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&qdcount.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&arcount.to_be_bytes());
    bytes
}

fn badvers_response() -> Message {
    let mut header = Header::new_query(0x1234, Opcode::Query, false);
    header.kind = MessageKind::Response;
    header.rcode = ResponseCode::BADVERS_OR_BADSIG;
    let mut message = Message::new(header);
    message.opt = Some(Opt::new(1232, 0, false, Vec::new()));
    message
}

fn encode(message: &Message) -> Result<Vec<u8>, EncodeError> {
    let mut out = vec![0u8; 512];
    let written = message.encode(&mut out, 512)?;
    out.truncate(written);
    Ok(out)
}

#[test]
fn decoder_merges_the_opt_upper_octet_into_the_header_rcode() {
    let mut bytes = header_bytes(0x8000, 0, 1);
    // OPT: root owner, type 41, class 1232, TTL = ext rcode 1 / version 0 / flags 0.
    bytes.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let message = Message::decode(&bytes).expect("decode");

    assert_eq!(message.header.rcode, ResponseCode::BADVERS_OR_BADSIG);
}

#[test]
fn encoder_splits_the_header_rcode_across_nibble_and_opt() {
    let bytes = encode(&badvers_response()).expect("encode");

    assert_eq!(bytes.get(3).map(|flags| flags & 0x0F), Some(0));
    assert_eq!(bytes.get(OPT_EXTENDED_RCODE_OFFSET), Some(&1));
}

#[test]
fn extended_rcode_survives_a_roundtrip() {
    let bytes = encode(&badvers_response()).expect("encode");

    let decoded = Message::decode(&bytes).expect("decode");

    assert_eq!(decoded, badvers_response());
}

#[test]
fn encoder_rejects_an_extended_rcode_without_an_opt() {
    let mut message = badvers_response();
    message.opt = None;

    assert_eq!(
        encode(&message),
        Err(EncodeError::ExtendedRcodeWithoutOpt(
            ResponseCode::BADVERS_OR_BADSIG
        ))
    );
}

fn example_query_with_opt_version(version: u8) -> Vec<u8> {
    let mut bytes = header_bytes(0x0100, 1, 1);
    bytes.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3]);
    bytes.extend_from_slice(b"com");
    bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
    bytes.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0x00, version, 0x00, 0x00, 0x00, 0x00]);
    bytes
}

fn expected_question() -> Result<Question, NameError> {
    let name = Name::from_ascii("example.com.")?;
    Ok(Question::new(name, RecordType::A, RecordClass::In))
}

#[test]
fn unsupported_edns_version_hands_back_the_query() {
    let bytes = example_query_with_opt_version(1);

    let Err(DecodeError::UnsupportedEdnsVersion(found)) = Message::decode(&bytes) else {
        panic!("expected UnsupportedEdnsVersion");
    };

    assert_eq!(found.version(), 1);
    assert_eq!(found.header().id, 0x1234);
    assert_eq!(found.header().opcode, Opcode::Query);
    assert!(found.header().recursion_desired);
    assert_eq!(found.questions(), [expected_question().expect("question")]);
}

#[test]
fn unsupported_edns_version_wins_over_what_follows_the_opt() {
    // ARCOUNT claims a second record that never arrives.
    let mut bytes = example_query_with_opt_version(1);
    bytes
        .get_mut(10..12)
        .expect("arcount")
        .copy_from_slice(&2u16.to_be_bytes());

    assert!(matches!(
        Message::decode(&bytes),
        Err(DecodeError::UnsupportedEdnsVersion(_))
    ));
}

#[test]
fn unsupported_edns_version_wins_over_a_malformed_option_body() {
    let mut bytes = example_query_with_opt_version(1);
    // RDLENGTH 3 with a body that is not a whole option under version 0 rules.
    let rdlength_at = bytes.len().saturating_sub(2);
    bytes
        .get_mut(rdlength_at..)
        .expect("rdlength")
        .copy_from_slice(&3u16.to_be_bytes());
    bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF]);

    assert!(matches!(
        Message::decode(&bytes),
        Err(DecodeError::UnsupportedEdnsVersion(_))
    ));
}
