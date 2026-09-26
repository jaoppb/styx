//! Oracle fixture suite proving styx decoder against hickory-proto encoder.
//!
//! Validates field-by-field correctness across all supported v1 RRtypes,
//! flags, section counts, and EDNS(0) extensions.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HDnskey, DS as HDs};
use hickory_proto::dnssec::{Algorithm, DigestType, PublicKeyBuf};
use hickory_proto::op::{
    Message as HMessage, MessageType as HMessageType, OpCode as HOpCode,
    ResponseCode as HResponseCode,
};
use hickory_proto::rr::rdata::{
    CNAME as HCname, MX as HMx, NS as HNs, PTR as HPtr, SOA as HSoa, SRV as HSrv, TXT as HTxt,
};
use hickory_proto::rr::{
    DNSClass as HDnsClass, Name as HName, RData as HRData, Record as HRecord,
    RecordType as HRecordType,
};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use styx_proto::domain::header::{MessageKind, Opcode, ResponseCode};
use styx_proto::domain::record::{RecordClass, RecordType};
use styx_proto::Message;

fn encode_hickory(msg: &HMessage) -> Result<Vec<u8>, hickory_proto::ProtoError> {
    let mut bytes = Vec::new();
    let mut encoder = BinEncoder::new(&mut bytes);
    msg.emit(&mut encoder)?;
    Ok(bytes)
}

#[test]
fn test_oracle_basic_query() {
    let mut hmsg = HMessage::new(0x1234, HMessageType::Query, HOpCode::Query);
    hmsg.metadata.recursion_desired = true;

    let mut q = hickory_proto::op::Query::new();
    q.set_name(HName::from_str("example.com.").unwrap());
    q.set_query_type(HRecordType::A);
    q.set_query_class(HDnsClass::IN);
    hmsg.add_query(q);

    let wire = encode_hickory(&hmsg).unwrap();
    let decoded = Message::decode(&wire).expect("styx failed to decode basic query");

    assert_eq!(decoded.header.id, 0x1234);
    assert_eq!(decoded.header.kind, MessageKind::Query);
    assert_eq!(decoded.header.opcode, Opcode::Query);
    assert!(decoded.header.recursion_desired);
    assert_eq!(decoded.header.rcode, ResponseCode::NOERROR);
    assert_eq!(decoded.questions.len(), 1);
    assert_eq!(decoded.questions[0].qname.to_string(), "example.com.");
    assert_eq!(decoded.questions[0].qtype, RecordType::A);
    assert_eq!(decoded.questions[0].qclass, RecordClass::In);
}

#[test]
fn test_oracle_a_and_aaaa_records() {
    let mut hmsg = HMessage::new(42, HMessageType::Response, HOpCode::Query);
    hmsg.metadata.authoritative = true;
    hmsg.metadata.response_code = HResponseCode::NoError;

    let name = HName::from_str("host.example.com.").unwrap();
    let a_rec = HRecord::from_rdata(
        name.clone(),
        300,
        HRData::A(Ipv4Addr::new(93, 184, 216, 34).into()),
    );
    let aaaa_rec = HRecord::from_rdata(
        name,
        3600,
        HRData::AAAA(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946).into()),
    );
    hmsg.add_answer(a_rec);
    hmsg.add_answer(aaaa_rec);

    let wire = encode_hickory(&hmsg).unwrap();
    let decoded = Message::decode(&wire).expect("styx failed to decode A/AAAA response");

    assert_eq!(decoded.header.id, 42);
    assert_eq!(decoded.header.kind, MessageKind::Response);
    assert!(decoded.header.authoritative);
    assert_eq!(decoded.answers.len(), 2);

    match &decoded.answers[0].rdata {
        styx_proto::RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("expected A record, got {other:?}"),
    }
    assert_eq!(decoded.answers[0].ttl.seconds(), 300);

    match &decoded.answers[1].rdata {
        styx_proto::RData::Aaaa(ip) => {
            assert_eq!(
                *ip,
                Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946)
            )
        }
        other => panic!("expected AAAA record, got {other:?}"),
    }
    assert_eq!(decoded.answers[1].ttl.seconds(), 3600);
}

#[test]
fn test_oracle_cname_ns_ptr() {
    let mut hmsg = HMessage::new(100, HMessageType::Response, HOpCode::Query);

    let origin = HName::from_str("example.com.").unwrap();
    let cname_rec = HRecord::from_rdata(
        HName::from_str("alias.example.com.").unwrap(),
        300,
        HRData::CNAME(HCname(origin.clone())),
    );
    let ns_rec = HRecord::from_rdata(
        origin.clone(),
        86400,
        HRData::NS(HNs(HName::from_str("ns1.example.com.").unwrap())),
    );
    let ptr_rec = HRecord::from_rdata(
        HName::from_str("34.216.184.93.in-addr.arpa.").unwrap(),
        3600,
        HRData::PTR(HPtr(origin)),
    );

    hmsg.add_answer(cname_rec);
    hmsg.add_answer(ns_rec);
    hmsg.add_answer(ptr_rec);

    let wire = encode_hickory(&hmsg).unwrap();
    let decoded = Message::decode(&wire).expect("styx failed to decode records");

    assert_eq!(decoded.answers.len(), 3);

    match &decoded.answers[0].rdata {
        styx_proto::RData::Cname(n) => assert_eq!(n.to_string(), "example.com."),
        other => panic!("expected CNAME, got {other:?}"),
    }
    match &decoded.answers[1].rdata {
        styx_proto::RData::Ns(n) => assert_eq!(n.to_string(), "ns1.example.com."),
        other => panic!("expected NS, got {other:?}"),
    }
    match &decoded.answers[2].rdata {
        styx_proto::RData::Ptr(n) => assert_eq!(n.to_string(), "example.com."),
        other => panic!("expected PTR, got {other:?}"),
    }
}

#[test]
fn test_oracle_mx_txt_srv() {
    let mut hmsg = HMessage::new(101, HMessageType::Response, HOpCode::Query);

    let origin = HName::from_str("example.com.").unwrap();
    let mx_rec = HRecord::from_rdata(
        origin.clone(),
        1800,
        HRData::MX(HMx::new(10, HName::from_str("mail.example.com.").unwrap())),
    );
    let txt_rec = HRecord::from_rdata(
        origin,
        600,
        HRData::TXT(HTxt::new(vec!["v=spf1 -all".to_string()])),
    );
    let srv_rec = HRecord::from_rdata(
        HName::from_str("_sip._tcp.example.com.").unwrap(),
        300,
        HRData::SRV(HSrv::new(
            10,
            60,
            5060,
            HName::from_str("sip.example.com.").unwrap(),
        )),
    );

    hmsg.add_answer(mx_rec);
    hmsg.add_answer(txt_rec);
    hmsg.add_answer(srv_rec);

    let wire = encode_hickory(&hmsg).unwrap();
    let decoded = Message::decode(&wire).expect("styx failed to decode records");

    assert_eq!(decoded.answers.len(), 3);

    match &decoded.answers[0].rdata {
        styx_proto::RData::Mx(mx) => {
            assert_eq!(mx.preference(), 10);
            assert_eq!(mx.exchange().to_string(), "mail.example.com.");
        }
        other => panic!("expected MX, got {other:?}"),
    }
    match &decoded.answers[1].rdata {
        styx_proto::RData::Txt(txt) => {
            assert_eq!(txt.strings().len(), 1);
            assert_eq!(txt.strings()[0].to_string(), "v=spf1 -all");
        }
        other => panic!("expected TXT, got {other:?}"),
    }
    match &decoded.answers[2].rdata {
        styx_proto::RData::Srv(srv) => {
            assert_eq!(srv.priority(), 10);
            assert_eq!(srv.weight(), 60);
            assert_eq!(srv.port(), 5060);
            assert_eq!(srv.target().to_string(), "sip.example.com.");
        }
        other => panic!("expected SRV, got {other:?}"),
    }
}

#[test]
fn test_oracle_soa() {
    let mut hmsg = HMessage::new(777, HMessageType::Response, HOpCode::Query);

    let origin = HName::from_str("example.com.").unwrap();
    let soa = HSoa::new(
        HName::from_str("ns1.example.com.").unwrap(),
        HName::from_str("hostmaster.example.com.").unwrap(),
        2026092101,
        7200,
        3600,
        1209600,
        300,
    );
    hmsg.authorities
        .push(HRecord::from_rdata(origin, 86400, HRData::SOA(soa)));

    let wire = encode_hickory(&hmsg).unwrap();
    let decoded = Message::decode(&wire).expect("styx failed to decode SOA");

    assert_eq!(decoded.authorities.len(), 1);
    match &decoded.authorities[0].rdata {
        styx_proto::RData::Soa(soa) => {
            assert_eq!(soa.mname().to_string(), "ns1.example.com.");
            assert_eq!(soa.rname().to_string(), "hostmaster.example.com.");
            assert_eq!(soa.serial(), 2026092101);
            assert_eq!(soa.refresh(), 7200);
            assert_eq!(soa.retry(), 3600);
            assert_eq!(soa.expire(), 1209600);
            assert_eq!(soa.minimum(), 300);
        }
        other => panic!("expected SOA, got {other:?}"),
    }
}

#[test]
fn test_oracle_edns_opt() {
    let mut hmsg = HMessage::new(0xbeef, HMessageType::Query, HOpCode::Query);

    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    edns.set_version(0);
    edns.set_dnssec_ok(true);
    hmsg.set_edns(edns);

    let wire = encode_hickory(&hmsg).unwrap();
    let decoded = Message::decode(&wire).expect("styx failed to decode EDNS OPT");

    assert!(decoded.opt.is_some());
    let opt = decoded.opt.as_ref().unwrap();
    assert_eq!(opt.udp_payload_size(), 1232);
    assert_eq!(opt.version(), 0);
    assert!(opt.dnssec_ok());
    assert_eq!(opt.extended_rcode(), 0);
}

#[test]
fn test_oracle_dnssec_dnskey_and_ds() {
    let mut hmsg = HMessage::new(999, HMessageType::Response, HOpCode::Query);

    let origin = HName::from_str("example.com.").unwrap();
    let dnskey = HDnskey::new(
        true,
        true,
        false,
        PublicKeyBuf::new(vec![1, 2, 3, 4, 5, 6, 7, 8], Algorithm::ECDSAP256SHA256),
    );
    let ds = HDs::new(
        12345,
        Algorithm::ECDSAP256SHA256,
        DigestType::SHA256,
        vec![0xaa, 0xbb, 0xcc, 0xdd],
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

    let wire = encode_hickory(&hmsg).unwrap();
    let decoded = Message::decode(&wire).expect("styx failed to decode DNSKEY and DS");

    assert_eq!(decoded.answers.len(), 2);
    match &decoded.answers[0].rdata {
        styx_proto::RData::Dnskey(k) => {
            assert_eq!(k.flags(), 257);
            assert_eq!(k.protocol(), 3);
            assert_eq!(k.algorithm(), 13);
            assert_eq!(k.public_key(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        }
        other => panic!("expected DNSKEY, got {other:?}"),
    }
    match &decoded.answers[1].rdata {
        styx_proto::RData::Ds(ds) => {
            assert_eq!(ds.key_tag(), 12345);
            assert_eq!(ds.algorithm(), 13);
            assert_eq!(ds.digest_type(), 2);
            assert_eq!(ds.digest(), &[0xaa, 0xbb, 0xcc, 0xdd]);
        }
        other => panic!("expected DS, got {other:?}"),
    }
}

#[test]
fn test_oracle_rcodes_and_flags() {
    for (hrc, src) in [
        (HResponseCode::NXDomain, ResponseCode::NXDOMAIN),
        (HResponseCode::ServFail, ResponseCode::SERVFAIL),
        (HResponseCode::Refused, ResponseCode::REFUSED),
        (HResponseCode::FormErr, ResponseCode::FORMERR),
    ] {
        let mut hmsg = HMessage::new(123, HMessageType::Response, HOpCode::Query);
        hmsg.metadata.response_code = hrc;
        hmsg.metadata.checking_disabled = true;
        hmsg.metadata.authentic_data = true;

        let wire = encode_hickory(&hmsg).unwrap();
        let decoded = Message::decode(&wire).expect("failed to decode response with rcode");

        assert_eq!(decoded.header.rcode, src);
        assert!(decoded.header.checking_disabled);
        assert!(decoded.header.authentic_data);
    }
}
