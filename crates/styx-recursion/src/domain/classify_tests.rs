use std::net::Ipv4Addr;

use styx_proto::{Header, MessageKind, Opcode, Ttl, UnknownRdata};

use super::*;
use crate::domain::topology::GlueOrigin;

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn question(qname: &str, qtype: RecordType) -> Question {
    Question::new(name(qname), qtype, RecordClass::In)
}

fn response(asked: &Question, rcode: ResponseCode, authoritative: bool) -> Message {
    let mut header = Header::new_query(1, Opcode::Query, false);
    header.kind = MessageKind::Response;
    header.rcode = rcode;
    header.authoritative = authoritative;
    let mut message = Message::new(header);
    message.questions.push(asked.clone());
    message
}

fn record(owner: &str, rdata: RData) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        rdata.rtype(),
        RecordClass::In,
        Ttl::from_secs(300),
        rdata,
    )
}

fn kind(zone: &str, sent: &Question, intermediate: bool, message: &Message) -> ResponseKind {
    classify(&name(zone), sent, intermediate, message, Instant::now())
}

#[test]
fn a_referral_keeps_in_bailiwick_glue_and_discards_the_rest() {
    let sent = question("example.com.", RecordType::NS);
    let mut message = response(&sent, ResponseCode::NOERROR, false);
    message
        .authorities
        .push(record("example.com.", RData::Ns(name("ns1.example.com."))));
    message
        .authorities
        .push(record("example.com.", RData::Ns(name("ns.other.net."))));
    message.additionals.push(record(
        "ns1.example.com.",
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    message
        .additionals
        .push(record("ns.other.net.", RData::A(Ipv4Addr::new(6, 6, 6, 6))));

    let ResponseKind::Referral(delegation) = kind("com.", &sent, true, &message) else {
        panic!("expected a referral");
    };
    assert_eq!(delegation.child_zone(), &name("example.com."));
    let servers = delegation.nameservers();
    assert_eq!(servers[0].addresses.len(), 1);
    assert_eq!(servers[0].glue_origin, GlueOrigin::InBailiwickGlue);
    assert!(
        servers[1].addresses.is_empty(),
        "poisoned glue must not be believed"
    );
    assert_eq!(servers[1].glue_origin, GlueOrigin::OutOfBailiwickDiscarded);
}

#[test]
fn a_sideways_or_upward_referral_is_lame() {
    let sent = question("example.com.", RecordType::NS);
    let mut upward = response(&sent, ResponseCode::NOERROR, false);
    upward
        .authorities
        .push(record(".", RData::Ns(name("a.root-servers.net."))));
    assert_eq!(kind("com.", &sent, true, &upward), ResponseKind::Lame);

    let mut sideways = response(&sent, ResponseCode::NOERROR, false);
    sideways
        .authorities
        .push(record("other.com.", RData::Ns(name("ns.other.com."))));
    assert_eq!(kind("com.", &sent, true, &sideways), ResponseKind::Lame);
}

#[test]
fn an_empty_authoritative_answer_is_an_ent_only_for_a_minimised_question() {
    let minimised = question("b.example.com.", RecordType::NS);
    let message = response(&minimised, ResponseCode::NOERROR, true);
    assert_eq!(
        kind("example.com.", &minimised, true, &message),
        ResponseKind::NoDataAtEmptyNonTerminal
    );
    let final_question = question("b.example.com.", RecordType::A);
    let nodata = response(&final_question, ResponseCode::NOERROR, true);
    assert_eq!(
        kind("example.com.", &final_question, false, &nodata),
        ResponseKind::AuthoritativeAnswer
    );
}

#[test]
fn a_non_authoritative_empty_answer_is_lame() {
    let sent = question("www.example.com.", RecordType::A);
    let message = response(&sent, ResponseCode::NOERROR, false);
    assert_eq!(
        kind("example.com.", &sent, false, &message),
        ResponseKind::Lame
    );
}

#[test]
fn rcodes_split_into_refusal_failure_and_name_error() {
    let sent = question("example.com.", RecordType::NS);
    for rcode in [
        ResponseCode::FORMERR,
        ResponseCode::NOTIMP,
        ResponseCode::REFUSED,
    ] {
        let message = response(&sent, rcode, false);
        assert_eq!(
            kind("com.", &sent, true, &message),
            ResponseKind::MinimisationRefused
        );
        assert_eq!(
            kind("com.", &sent, false, &message),
            ResponseKind::ServerFailure
        );
    }
    let servfail = response(&sent, ResponseCode::SERVFAIL, false);
    assert_eq!(
        kind("com.", &sent, true, &servfail),
        ResponseKind::ServerFailure
    );
    let nxdomain = response(&sent, ResponseCode::NXDOMAIN, true);
    assert_eq!(
        kind("com.", &sent, true, &nxdomain),
        ResponseKind::NameError
    );
}

#[test]
fn a_cname_outside_the_servers_bailiwick_is_not_followed() {
    let sent = question("www.example.com.", RecordType::A);
    let mut message = response(&sent, ResponseCode::NOERROR, true);
    message.answers.push(record(
        "www.example.com.",
        RData::Cname(name("cdn.example.net.")),
    ));
    let ResponseKind::Alias(link) = kind("example.com.", &sent, false, &message) else {
        panic!("expected an alias");
    };
    assert_eq!(link.target, name("cdn.example.net."));
    assert_eq!(
        kind("other.org.", &sent, false, &message),
        ResponseKind::Lame
    );
}

#[test]
fn a_dname_target_is_computed_not_trusted() {
    let sent = question("www.old.example.", RecordType::A);
    let mut message = response(&sent, ResponseCode::NOERROR, true);
    let wire = vec![
        3, b'n', b'e', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
    ];
    message.answers.push(ResourceRecord::new(
        name("old.example."),
        DNAME,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Unknown(UnknownRdata::new(DNAME, wire)),
    ));
    message.answers.push(record(
        "www.old.example.",
        RData::Cname(name("evil.example.")),
    ));

    let ResponseKind::Alias(link) = kind("example.", &sent, false, &message) else {
        panic!("expected an alias");
    };
    assert_eq!(link.kind, AliasKind::Dname);
    assert_eq!(link.target, name("www.new.example."));
    assert_eq!(
        link.records[1].rdata,
        RData::Cname(name("www.new.example.")),
        "the lying synthesized CNAME is replaced"
    );
}

#[test]
fn a_minimised_ns_answered_from_the_apex_is_a_delegation() {
    let sent = question("sub.example.com.", RecordType::NS);
    let mut message = response(&sent, ResponseCode::NOERROR, true);
    message.answers.push(record(
        "sub.example.com.",
        RData::Ns(name("ns.sub.example.com.")),
    ));
    message.additionals.push(record(
        "ns.sub.example.com.",
        RData::A(Ipv4Addr::new(192, 0, 2, 9)),
    ));
    assert!(matches!(
        kind("example.com.", &sent, true, &message),
        ResponseKind::Referral(_)
    ));
}
