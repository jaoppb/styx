//! The fake name server's scripted behaviours, checked over real sockets.
//!
//! The fake is the oracle the recursion suite trusts; a fake that quietly answered
//! wrong would make that suite prove nothing. Each behaviour a descent test relies
//! on is pinned here.

use std::net::Ipv4Addr;

use styx_proto::{
    Header, Message, Name, Opcode, Opt, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, Ttl,
};
use styx_testkit::{DnsClient, FakeNameServer, FakeRole, ZoneScript};

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

fn query(qname: &str, qtype: RecordType) -> Message {
    let mut message = Message::new(Header::new_query(0x4242, Opcode::Query, false));
    message
        .questions
        .push(Question::new(name(qname), qtype, RecordClass::In));
    message
}

fn query_with_edns(qname: &str, qtype: RecordType, dnssec_ok: bool) -> Message {
    let mut message = query(qname, qtype);
    message.opt = Some(Opt::new(1232, 0, 0, dnssec_ok, Vec::new()));
    message
}

fn a_record(owner: &str, ip: Ipv4Addr) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(ip),
    )
}

fn cname_record(owner: &str, target: &str) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        RecordType::CNAME,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Cname(name(target)),
    )
}

fn owners(records: &[ResourceRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| record.owner.to_string())
        .collect()
}

async fn ask(
    server: &FakeNameServer,
    message: &Message,
) -> Result<Message, styx_testkit::HarnessError> {
    DnsClient::new().query_udp(server.udp_addr(), message).await
}

#[tokio::test]
async fn the_question_is_echoed_and_recorded_exactly_as_sent() {
    let server = FakeNameServer::start(FakeRole::Tld, ZoneScript::new())
        .await
        .expect("start");

    let response = ask(
        &server,
        &query_with_edns("ExAmple.COM.", RecordType::NS, true),
    )
    .await
    .expect("query");

    let echoed = response.questions.first().expect("echoed question");
    assert_eq!(echoed.qtype, RecordType::NS);
    let received = server.received();
    let first = received.first().expect("one query");
    assert_eq!(first.question.qname.to_string(), "ExAmple.COM.");
    assert_eq!(first.question.qtype, RecordType::NS);
    assert!(first.dnssec_ok);
    assert!(!first.via_tcp);
    server.shutdown();
}

#[tokio::test]
async fn a_referral_names_the_deepest_delegation_with_its_glue() {
    let script = ZoneScript::new()
        .refer("com.", "a.gtld.net.", Ipv4Addr::new(192, 0, 2, 1))
        .refer(
            "example.com.",
            "ns1.example.com.",
            Ipv4Addr::new(192, 0, 2, 2),
        )
        .refer_without_glue("glueless.com.", "ns.elsewhere.org.")
        .extra_glue("bank.example.org.", Ipv4Addr::new(6, 6, 6, 6));
    let server = FakeNameServer::start(FakeRole::Root, script)
        .await
        .expect("start");

    let deep = ask(&server, &query("www.example.com.", RecordType::A))
        .await
        .expect("query");
    assert!(!deep.header.authoritative);
    assert_eq!(owners(&deep.authorities), ["example.com."]);
    assert_eq!(
        owners(&deep.additionals),
        ["ns1.example.com.", "bank.example.org."]
    );

    let glueless = ask(&server, &query("glueless.com.", RecordType::NS))
        .await
        .expect("query");
    assert_eq!(owners(&glueless.authorities), ["glueless.com."]);
    assert_eq!(owners(&glueless.additionals), ["bank.example.org."]);
    server.shutdown();
}

#[tokio::test]
async fn an_empty_non_terminal_is_nodata_and_an_absent_name_is_nxdomain() {
    let script = ZoneScript::new().origin("example.com.", 120).answer(
        "a.b.example.com.",
        RecordType::A,
        vec![a_record("a.b.example.com.", Ipv4Addr::new(192, 0, 2, 3))],
    );
    let server = FakeNameServer::start(FakeRole::Authoritative, script)
        .await
        .expect("start");

    let empty_non_terminal = ask(&server, &query("b.example.com.", RecordType::NS))
        .await
        .expect("query");
    assert_eq!(empty_non_terminal.header.rcode, ResponseCode::NOERROR);
    assert!(empty_non_terminal.answers.is_empty());
    assert_eq!(owners(&empty_non_terminal.authorities), ["example.com."]);

    let absent = ask(&server, &query("c.example.com.", RecordType::A))
        .await
        .expect("query");
    assert_eq!(absent.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(owners(&absent.authorities), ["example.com."]);

    let wrong_type = ask(&server, &query("a.b.example.com.", RecordType::AAAA))
        .await
        .expect("query");
    assert_eq!(wrong_type.header.rcode, ResponseCode::NOERROR);
    assert!(wrong_type.answers.is_empty());
    server.shutdown();
}

#[tokio::test]
async fn cname_and_dname_chains_are_followed_within_the_script() {
    let script = ZoneScript::new()
        .answer(
            "www.example.com.",
            RecordType::CNAME,
            vec![cname_record("www.example.com.", "host.example.com.")],
        )
        .answer(
            "host.example.com.",
            RecordType::A,
            vec![a_record("host.example.com.", Ipv4Addr::new(192, 0, 2, 4))],
        )
        .dname("old.example.com.", "example.com.");
    let server = FakeNameServer::start(FakeRole::Authoritative, script)
        .await
        .expect("start");

    let chased = ask(&server, &query("www.example.com.", RecordType::A))
        .await
        .expect("query");
    assert!(chased.header.authoritative);
    assert_eq!(
        owners(&chased.answers),
        ["www.example.com.", "host.example.com."]
    );

    let rewritten = ask(&server, &query("www.old.example.com.", RecordType::A))
        .await
        .expect("query");
    let types: Vec<RecordType> = rewritten
        .answers
        .iter()
        .map(|record| record.rtype)
        .collect();
    assert_eq!(
        types,
        [
            RecordType::from_u16(39),
            RecordType::CNAME,
            RecordType::CNAME,
            RecordType::A
        ]
    );
    let owner_itself = ask(&server, &query("old.example.com.", RecordType::NS))
        .await
        .expect("query");
    assert_eq!(
        owner_itself.header.rcode,
        ResponseCode::NOERROR,
        "a DNAME owner exists: NODATA, not NXDOMAIN"
    );
    let synthesized = rewritten.answers.get(1).expect("synthesized cname");
    assert_eq!(synthesized.owner.to_string(), "www.old.example.com.");
    assert_eq!(synthesized.rdata, RData::Cname(name("www.example.com.")));
    server.shutdown();
}

#[tokio::test]
async fn scripted_faults_behave_as_scripted() {
    let refusing =
        ZoneScript::new().rcode("example.com.", Some(RecordType::NS), ResponseCode::REFUSED);
    let server = FakeNameServer::start(FakeRole::Tld, refusing)
        .await
        .expect("start");
    let refused = ask(&server, &query("example.com.", RecordType::NS))
        .await
        .expect("query");
    assert_eq!(refused.header.rcode, ResponseCode::REFUSED);
    let other_type = ask(&server, &query("example.com.", RecordType::A))
        .await
        .expect("query");
    assert_eq!(other_type.header.rcode, ResponseCode::NXDOMAIN);
    server.shutdown();

    let lame = FakeNameServer::start(FakeRole::Authoritative, ZoneScript::new().lame())
        .await
        .expect("start");
    let lame_answer = ask(&lame, &query("example.com.", RecordType::A))
        .await
        .expect("query");
    assert!(!lame_answer.header.authoritative);
    assert_eq!(lame_answer.header.rcode, ResponseCode::NOERROR);
    assert!(lame_answer.answers.is_empty() && lame_answer.authorities.is_empty());
    lame.shutdown();

    let intolerant =
        FakeNameServer::start(FakeRole::Authoritative, ZoneScript::new().edns_intolerant())
            .await
            .expect("start");
    let rejected = ask(
        &intolerant,
        &query_with_edns("example.com.", RecordType::A, true),
    )
    .await
    .expect("query");
    assert_eq!(rejected.header.rcode, ResponseCode::FORMERR);
    assert!(rejected.opt.is_none());
    let plain = ask(&intolerant, &query("example.com.", RecordType::A))
        .await
        .expect("query");
    assert_eq!(plain.header.rcode, ResponseCode::NXDOMAIN);
    intolerant.shutdown();
}

#[tokio::test]
async fn a_truncating_server_answers_in_full_only_over_tcp() {
    let script = ZoneScript::new().truncate_udp().answer(
        "example.com.",
        RecordType::A,
        vec![a_record("example.com.", Ipv4Addr::new(192, 0, 2, 5))],
    );
    let server = FakeNameServer::start(FakeRole::Authoritative, script)
        .await
        .expect("start");
    let message = query("example.com.", RecordType::A);

    let over_udp = ask(&server, &message).await.expect("query");
    assert!(over_udp.header.truncated);
    assert!(over_udp.answers.is_empty());

    let over_tcp = DnsClient::new()
        .query_tcp(server.tcp_addr(), &message)
        .await
        .expect("tcp query");
    assert!(!over_tcp.header.truncated);
    assert_eq!(owners(&over_tcp.answers), ["example.com."]);
    let transports: Vec<bool> = server
        .received()
        .iter()
        .map(|query| query.via_tcp)
        .collect();
    assert_eq!(transports, [false, true]);
    server.shutdown();
}

#[tokio::test]
async fn an_unservable_record_type_fails_at_start() {
    let script = ZoneScript::new().answer(
        "example.com.",
        RecordType::MX,
        vec![ResourceRecord::new(
            name("example.com."),
            RecordType::MX,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::Mx(styx_proto::MxRdata::new(10, name("mail.example.com."))),
        )],
    );

    assert!(FakeNameServer::start(FakeRole::Authoritative, script)
        .await
        .is_err());
}
