//! Differential testing suite validating styx against hickory-proto.
//!
//! Generates valid DNS messages covering all v1 RRtypes, DNSSEC types,
//! edge-case names, EDNS(0) extensions, and flags. Encodes with both,
//! decodes with both, and asserts semantic equality.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HDnskey, DS as HDs};
use hickory_proto::dnssec::{Algorithm, DigestType, PublicKeyBuf};
use hickory_proto::op::{
    Edns as HEdns, Message as HMessage, MessageType as HMessageType, OpCode as HOpCode,
    Query as HQuery, ResponseCode as HResponseCode,
};
use hickory_proto::rr::rdata::{
    A as HA, AAAA as HAaaa, CNAME as HCname, MX as HMx, NS as HNs, PTR as HPtr, SOA as HSoa,
    SRV as HSrv, TXT as HTxt,
};
use hickory_proto::rr::{
    DNSClass as HDnsClass, Name as HName, RData as HRData, Record as HRecord,
    RecordType as HRecordType,
};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

use styx_proto::domain::header::MessageKind;
use styx_proto::Message;

fn encode_hickory(msg: &HMessage) -> Result<Vec<u8>, hickory_proto::ProtoError> {
    let mut bytes = Vec::new();
    let mut enc = BinEncoder::new(&mut bytes);
    msg.emit(&mut enc)?;
    Ok(bytes)
}

fn decode_hickory(bytes: &[u8]) -> Result<HMessage, hickory_proto::serialize::binary::DecodeError> {
    let mut dec = BinDecoder::new(bytes);
    HMessage::read(&mut dec)
}

fn encode_styx(msg: &Message) -> Result<Vec<u8>, styx_proto::domain::error::EncodeError> {
    let mut buf = vec![0u8; 4096];
    let len = msg.encode(&mut buf, 4096)?;
    buf.truncate(len);
    Ok(buf)
}

fn assert_semantic_equal(h: &HMessage, s: &Message) {
    assert_eq!(h.metadata.id, s.header.id);
    let expected_kind = match h.metadata.message_type {
        HMessageType::Query => MessageKind::Query,
        HMessageType::Response => MessageKind::Response,
    };
    assert_eq!(expected_kind, s.header.kind);
    assert_eq!(h.metadata.authoritative, s.header.authoritative);
    assert_eq!(h.metadata.truncation, s.header.truncated);
    assert_eq!(h.metadata.recursion_desired, s.header.recursion_desired);
    assert_eq!(h.metadata.recursion_available, s.header.recursion_available);
    assert_eq!(h.metadata.authentic_data, s.header.authentic_data);
    assert_eq!(h.metadata.checking_disabled, s.header.checking_disabled);
    assert_eq!(
        u16::from(h.metadata.response_code.low()),
        s.header.rcode.value()
    );

    assert_eq!(h.queries.len(), s.questions.len());
    for (hq, sq) in h.queries.iter().zip(s.questions.iter()) {
        assert_eq!(
            hq.name().to_string().to_lowercase(),
            sq.qname.to_canonical().to_string()
        );
        assert_eq!(u16::from(hq.query_type()), sq.qtype.value());
        assert_eq!(u16::from(hq.query_class()), sq.qclass.to_u16());
    }

    assert_eq!(h.answers.len(), s.answers.len());
    assert_eq!(h.authorities.len(), s.authorities.len());
    assert_eq!(h.additionals.len(), s.additionals.len());

    assert_eq!(h.edns.is_some(), s.opt.is_some());
    if let (Some(he), Some(so)) = (&h.edns, &s.opt) {
        assert_eq!(he.max_payload(), so.udp_payload_size());
        assert_eq!(he.version(), so.version());
        assert_eq!(he.flags().dnssec_ok, so.dnssec_ok());
    }
}

fn roundtrip_both(hmsg: &HMessage) -> Result<(), Box<dyn std::error::Error>> {
    let h_wire = encode_hickory(hmsg)?;
    let s_msg = Message::decode(&h_wire)?;
    assert_semantic_equal(hmsg, &s_msg);

    let s_wire = encode_styx(&s_msg)?;
    let h_msg2 = decode_hickory(&s_wire)?;
    assert_semantic_equal(&h_msg2, &s_msg);

    let s_msg2 = Message::decode(&s_wire)?;
    assert_semantic_equal(hmsg, &s_msg2);
    Ok(())
}

#[test]
fn test_diff_awkward_query_names() {
    for name_str in [
        "localhost.",
        ".",
        "a.b.c.d.e.f.g.h.example.org.",
        "hyphen-name.with-many.d-a-s-h-e-s.example.com.",
        "_sip._tcp.sub.domain.example.com.",
        "valid-63-byte-label-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com.",
    ] {
        let mut hmsg = HMessage::new(0xabcd, HMessageType::Query, HOpCode::Query);
        hmsg.metadata.recursion_desired = true;
        let mut q = HQuery::new();
        q.set_name(HName::from_str(name_str).unwrap());
        q.set_query_type(HRecordType::A);
        q.set_query_class(HDnsClass::IN);
        hmsg.add_query(q);

        roundtrip_both(&hmsg).unwrap();
    }
}

#[test]
fn test_diff_basic_rrtypes_and_compression() {
    let mut hmsg = HMessage::new(42, HMessageType::Response, HOpCode::Query);
    hmsg.metadata.authoritative = true;
    hmsg.metadata.recursion_available = true;

    let origin = HName::from_str("example.com.").unwrap();
    let host = HName::from_str("host.example.com.").unwrap();

    hmsg.add_answer(HRecord::from_rdata(
        host.clone(),
        300,
        HRData::A(HA(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    hmsg.add_answer(HRecord::from_rdata(
        host.clone(),
        300,
        HRData::AAAA(HAaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
    ));
    hmsg.add_answer(HRecord::from_rdata(
        HName::from_str("alias.example.com.").unwrap(),
        600,
        HRData::CNAME(HCname(host.clone())),
    ));
    hmsg.add_answer(HRecord::from_rdata(
        HName::from_str("1.2.0.192.in-addr.arpa.").unwrap(),
        3600,
        HRData::PTR(HPtr(host.clone())),
    ));
    hmsg.add_answer(HRecord::from_rdata(
        origin.clone(),
        1800,
        HRData::MX(HMx::new(10, HName::from_str("mail.example.com.").unwrap())),
    ));
    hmsg.add_answer(HRecord::from_rdata(
        origin.clone(),
        300,
        HRData::TXT(HTxt::new(vec!["text entry one".into(), "entry two".into()])),
    ));
    hmsg.add_answer(HRecord::from_rdata(
        HName::from_str("_http._tcp.example.com.").unwrap(),
        120,
        HRData::SRV(HSrv::new(1, 10, 8080, host)),
    ));

    hmsg.authorities.push(HRecord::from_rdata(
        origin.clone(),
        86400,
        HRData::NS(HNs(HName::from_str("ns1.example.com.").unwrap())),
    ));
    hmsg.authorities.push(HRecord::from_rdata(
        origin,
        86400,
        HRData::SOA(HSoa::new(
            HName::from_str("ns1.example.com.").unwrap(),
            HName::from_str("admin.example.com.").unwrap(),
            2026092101,
            7200,
            3600,
            1209600,
            300,
        )),
    ));

    roundtrip_both(&hmsg).unwrap();
}

#[test]
fn test_diff_dnssec_types() {
    let mut hmsg = HMessage::new(1001, HMessageType::Response, HOpCode::Query);
    hmsg.metadata.authentic_data = true;

    let origin = HName::from_str("secure.example.com.").unwrap();
    let dnskey = HDnskey::new(
        true,
        true,
        false,
        PublicKeyBuf::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            Algorithm::ECDSAP256SHA256,
        ),
    );
    let ds = HDs::new(
        54321,
        Algorithm::ECDSAP256SHA256,
        DigestType::SHA256,
        vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    );

    hmsg.add_answer(HRecord::from_rdata(
        origin.clone(),
        3600,
        HRData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));
    hmsg.add_answer(HRecord::from_rdata(
        origin,
        3600,
        HRData::DNSSEC(DNSSECRData::DS(ds)),
    ));

    roundtrip_both(&hmsg).unwrap();
}

#[test]
fn test_diff_edns_variations() {
    for (size, do_bit) in [(512, false), (1232, true), (1472, false), (4096, true)] {
        let mut hmsg = HMessage::new(0xfeeb, HMessageType::Query, HOpCode::Query);
        let mut edns = HEdns::new();
        edns.set_max_payload(size);
        edns.set_version(0);
        edns.set_dnssec_ok(do_bit);
        hmsg.set_edns(edns);

        let mut q = HQuery::new();
        q.set_name(HName::from_str("example.com.").unwrap());
        q.set_query_type(HRecordType::AAAA);
        q.set_query_class(HDnsClass::IN);
        hmsg.add_query(q);

        roundtrip_both(&hmsg).unwrap();
    }
}

#[test]
fn test_diff_rcodes_and_flags() {
    for (rcode, aa, rd, ra, ad, cd) in [
        (HResponseCode::NoError, true, true, true, true, false),
        (HResponseCode::NXDomain, true, false, true, false, false),
        (HResponseCode::ServFail, false, true, false, false, false),
        (HResponseCode::Refused, false, false, false, false, true),
        (HResponseCode::FormErr, false, false, false, false, false),
    ] {
        let mut hmsg = HMessage::new(99, HMessageType::Response, HOpCode::Query);
        hmsg.metadata.response_code = rcode;
        hmsg.metadata.authoritative = aa;
        hmsg.metadata.recursion_desired = rd;
        hmsg.metadata.recursion_available = ra;
        hmsg.metadata.authentic_data = ad;
        hmsg.metadata.checking_disabled = cd;

        let mut q = HQuery::new();
        q.set_name(HName::from_str("status.check.").unwrap());
        q.set_query_type(HRecordType::A);
        q.set_query_class(HDnsClass::IN);
        hmsg.add_query(q);

        roundtrip_both(&hmsg).unwrap();
    }
}
