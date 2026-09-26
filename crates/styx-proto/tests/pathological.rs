//! Hand-assembled pathological byte vectors testing defensive limits and edge cases.
//!
//! Validates loop detection, expansion budget, length limits, pointer validation,
//! EDNS error taxonomy, and TCP framing boundaries.

use styx_proto::domain::error::{DecodeError, EncodeError, NameError};
use styx_proto::domain::header::{Header, Opcode};
use styx_proto::domain::name::{Label, Name};
use styx_proto::domain::question::Question;
use styx_proto::domain::rdata::RData;
use styx_proto::domain::record::{RecordClass, RecordType};
use styx_proto::infrastructure::{frame_tcp, read_tcp_frame_length, MAX_TCP_MESSAGE_LEN};
use styx_proto::Message;

fn base_header(qdcount: u16, ancount: u16, nscount: u16, arcount: u16) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(12);
    hdr.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    hdr.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD
    hdr.extend_from_slice(&qdcount.to_be_bytes());
    hdr.extend_from_slice(&ancount.to_be_bytes());
    hdr.extend_from_slice(&nscount.to_be_bytes());
    hdr.extend_from_slice(&arcount.to_be_bytes());
    hdr
}

#[test]
fn test_self_referential_pointer() {
    let mut bytes = base_header(1, 0, 0, 0);
    // Question name at offset 12 points to offset 12
    bytes.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::CompressionLoop(12));
}

#[test]
fn test_two_pointer_cycle() {
    let mut bytes = base_header(1, 0, 0, 0);
    // Question: label "a" at 12..14, followed by pointer to 12 at 14..16
    bytes.extend_from_slice(&[1, b'a', 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::CompressionLoop(12));
}

#[test]
fn test_forward_pointer() {
    let mut bytes = base_header(1, 0, 0, 0);
    // Offset 12 points forward to offset 18
    bytes.extend_from_slice(&[0xC0, 0x12, 0x00, 0x01, 0x00, 0x01, 0x00]);
    let err = Message::decode(&bytes).unwrap_err();
    match err {
        DecodeError::PointerOutOfRange { pointer, .. } => assert_eq!(pointer, 18),
        other => panic!("expected PointerOutOfRange, got {other:?}"),
    }
}

#[test]
fn test_pointer_past_buffer() {
    let mut bytes = base_header(1, 0, 0, 0);
    // Pointer target 0x00FE > buffer len
    bytes.extend_from_slice(&[0xC0, 0xFE, 0x00, 0x01, 0x00, 0x01]);
    let err = Message::decode(&bytes).unwrap_err();
    match err {
        DecodeError::PointerOutOfRange { pointer, len } => {
            assert_eq!(pointer, 0xFE);
            assert_eq!(len, bytes.len());
        }
        other => panic!("expected PointerOutOfRange, got {other:?}"),
    }
}

#[test]
fn test_pointer_into_middle_of_label() {
    let mut bytes = base_header(1, 1, 0, 0);
    // Question: "example.com." at offset 12..25
    bytes.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

    // Answer at offset 29: pointer targeting offset 15 (inside "example")
    bytes.extend_from_slice(&[
        0xC0, 15, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 1, 2, 3, 4,
    ]);
    let err = Message::decode(&bytes).unwrap_err();
    match err {
        DecodeError::PointerOutOfRange { pointer, .. } => assert_eq!(pointer, 15),
        other => panic!("expected PointerOutOfRange, got {other:?}"),
    }
}

#[test]
fn test_acyclic_pointer_chain_budget() {
    // 75 questions all pointing to a 63-byte label exceeds the 4096 expansion budget
    let mut bytes = base_header(75, 0, 0, 0);
    // First question: 63-byte label + root at offset 12..76
    bytes.push(63);
    bytes.extend_from_slice(&[b'a'; 63]);
    bytes.push(0);
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    // Next 74 questions each have a pointer to offset 12
    for _ in 1..75 {
        bytes.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    }

    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::ExpansionBudgetExceeded);
}

#[test]
fn test_label_length_limits() {
    // 63-octet label is accepted
    let valid_label = vec![b'x'; 63];
    assert!(Label::new(valid_label).is_ok());

    // 64-octet label is rejected at domain construction
    let invalid_label = vec![b'x'; 64];
    assert_eq!(Label::new(invalid_label), Err(NameError::LabelTooLong(64)));

    // On wire, length byte 64 has top bits 01 (reserved/extended)
    let mut bytes = base_header(1, 0, 0, 0);
    bytes.push(64);
    bytes.extend_from_slice(&[b'x'; 64]);
    bytes.push(0);
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::ReservedBitsSet);
}

#[test]
fn test_name_length_limits() {
    // Exactly 255 wire octets: 4 labels of 63 chars (4 * 64 = 256... wait: 3 * 63 + 1 * 60 = 249 + 4 = 253 + 1 = 254 + root)
    // 63 + 1 + 63 + 1 + 63 + 1 + 59 + 1 + 1 (root) = 253 bytes
    // Let's make exactly 255: 63 + 1 + 63 + 1 + 63 + 1 + 61 + 1 + 1 = 255 bytes.
    let labels_255 = vec![
        Label::new(vec![b'a'; 63]).unwrap(),
        Label::new(vec![b'b'; 63]).unwrap(),
        Label::new(vec![b'c'; 63]).unwrap(),
        Label::new(vec![b'd'; 61]).unwrap(),
    ];
    let name_255 = Name::new(labels_255).unwrap();
    assert_eq!(name_255.wire_len(), 255);

    // 256 wire octets: 63 + 1 + 63 + 1 + 63 + 1 + 62 + 1 + 1 = 256 bytes.
    let labels_256 = vec![
        Label::new(vec![b'a'; 63]).unwrap(),
        Label::new(vec![b'b'; 63]).unwrap(),
        Label::new(vec![b'c'; 63]).unwrap(),
        Label::new(vec![b'd'; 62]).unwrap(),
    ];
    assert_eq!(Name::new(labels_256), Err(NameError::NameTooLong(256)));
}

#[test]
fn test_rdlength_mismatch() {
    // A record with RDLENGTH=3 instead of 4
    let mut bytes = base_header(0, 1, 0, 0);
    bytes.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]); // TYPE=A, CLASS=IN, TTL=60
    bytes.extend_from_slice(&[0x00, 0x03, 1, 2, 3]); // RDLENGTH=3
    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        DecodeError::BadRdLength {
            expected: 4,
            actual: 3
        }
    );

    // A record with RDLENGTH=5 instead of 4
    let mut bytes5 = base_header(0, 1, 0, 0);
    bytes5.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
    bytes5.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]);
    bytes5.extend_from_slice(&[0x00, 0x05, 1, 2, 3, 4, 5]); // RDLENGTH=5
    let err5 = Message::decode(&bytes5).unwrap_err();
    assert_eq!(
        err5,
        DecodeError::BadRdLength {
            expected: 4,
            actual: 5
        }
    );
}

#[test]
fn test_header_counts_exceeding_payload() {
    // QDCOUNT=1, but 0 bytes follow the header
    let bytes = base_header(1, 0, 0, 0);
    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::SectionCountMismatch);

    // ANCOUNT=65535 in a 12-byte packet
    let bytes_an = base_header(0, 65535, 0, 0);
    let err_an = Message::decode(&bytes_an).unwrap_err();
    assert_eq!(err_an, DecodeError::SectionCountMismatch);
}

#[test]
fn test_message_size_boundaries() {
    // Zero-length input
    assert!(matches!(
        Message::decode(&[]),
        Err(DecodeError::UnexpectedEof(_))
    ));

    // Exactly 12-octet header with 0 counts
    let bytes = base_header(0, 0, 0, 0);
    let msg = Message::decode(&bytes).expect("12-byte header should decode");
    assert_eq!(msg.questions.len(), 0);
    assert_eq!(msg.answers.len(), 0);
    assert_eq!(msg.authorities.len(), 0);
    assert_eq!(msg.additionals.len(), 0);
    assert!(msg.opt.is_none());
}

#[test]
fn test_multiple_opt_records() {
    let mut bytes = base_header(0, 0, 0, 2);
    // First OPT record in additional section
    bytes.extend_from_slice(&[0, 0x00, 41, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Second OPT record
    bytes.extend_from_slice(&[0, 0x00, 41, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::MultipleOptRecords);
}

#[test]
fn test_opt_unsupported_version() {
    let mut bytes = base_header(0, 0, 0, 1);
    // OPT record with version = 1 (TTL bytes: ext_rcode=0, ver=1, flags=0)
    bytes.extend_from_slice(&[0, 0x00, 41, 0x04, 0xD0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::UnsupportedEdnsVersion(1));
}

#[test]
fn test_opt_rdata_overrun() {
    let mut bytes = base_header(0, 0, 0, 1);
    // OPT record with RDLENGTH=3, but option declares option_len=10
    bytes.extend_from_slice(&[0, 0x00, 41, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
    bytes.extend_from_slice(&[0x00, 0x08, 0x00, 0x0A]); // option_code=8, option_len=10 > 3-4
    let err = Message::decode(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::MalformedOpt);
}

#[test]
fn test_txt_zero_vs_empty_string() {
    // TXT with RDLENGTH=0 (zero character-strings)
    let mut bytes0 = base_header(0, 1, 0, 0);
    bytes0.extend_from_slice(&[0, 0x00, 16, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00]);
    assert_eq!(
        Message::decode(&bytes0).unwrap_err(),
        DecodeError::BadRdLength {
            expected: 1,
            actual: 0
        }
    );

    // TXT with RDLENGTH=1 and 1 empty character string: [0x00]
    let mut bytes1 = base_header(0, 1, 0, 0);
    bytes1.extend_from_slice(&[
        0, 0x00, 16, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x01, 0x00,
    ]);
    let msg = Message::decode(&bytes1).expect("empty character string in TXT should decode");
    match &msg.answers[0].rdata {
        RData::Txt(txt) => {
            assert_eq!(txt.strings().len(), 1);
            assert_eq!(txt.strings()[0].octets, b"");
        }
        other => panic!("expected TXT, got {other:?}"),
    }
}

#[test]
fn test_unknown_rrtype_opaque_bytes() {
    let mut bytes = base_header(0, 1, 0, 0);
    // RRTYPE=65001 (0xFDE9) with RDATA containing pointer-like bytes [0xC0, 0x00]
    bytes.extend_from_slice(&[
        0, 0xFD, 0xE9, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x02, 0xC0, 0x00,
    ]);
    let msg = Message::decode(&bytes).expect("unknown RRTYPE should decode opaquely");
    match &msg.answers[0].rdata {
        RData::Unknown(unk) => {
            assert_eq!(unk.rtype().value(), 65001);
            assert_eq!(unk.octets(), &[0xC0, 0x00]);
        }
        other => panic!("expected Unknown RData, got {other:?}"),
    }
}

#[test]
fn test_encode_size_budget_boundary() {
    let name = Name::from_ascii("example.com.").unwrap();
    let q = Question::new(name, RecordType::A, RecordClass::In);
    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.questions.push(q);

    let mut buf = vec![0u8; 512];
    let exact_len = msg.encode(&mut buf, 512).expect("should fit in 512 bytes");

    // With budget exactly equal to encoded length
    let mut exact_buf = vec![0u8; exact_len];
    assert!(msg.encode(&mut exact_buf, exact_len).is_ok());

    // With budget one octet smaller
    let mut small_buf = vec![0u8; exact_len.saturating_sub(1)];
    let err = msg
        .encode(&mut small_buf, exact_len.saturating_sub(1))
        .unwrap_err();
    match err {
        EncodeError::BudgetExceeded { bytes_written } => {
            assert!(bytes_written <= exact_len.saturating_sub(1))
        }
        other => panic!("expected BudgetExceeded, got {other:?}"),
    }
}

#[test]
fn test_tcp_framing_limits() {
    let max_data = vec![0x42u8; MAX_TCP_MESSAGE_LEN];
    let framed = frame_tcp(&max_data).expect("65535 bytes should frame");
    assert_eq!(framed.len(), 65537);
    assert_eq!(read_tcp_frame_length(&framed[..2]).unwrap(), 65535);

    let too_large = vec![0x42u8; 65536];
    assert_eq!(
        frame_tcp(&too_large).unwrap_err(),
        EncodeError::RdLengthOverflow(65536)
    );
}
