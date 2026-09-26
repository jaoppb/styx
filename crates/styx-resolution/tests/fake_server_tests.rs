//! In-process fake DNS name server integration tests.

mod harness;

use std::net::Ipv4Addr;

use harness::{DnsClient, FakeNameServer, FakeRole, ZoneScript};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, Ttl,
};

fn make_query(name: &str, rtype: RecordType) -> Message {
    let qname = match Name::from_ascii(name) {
        Ok(q) => q,
        Err(_) => Name::root(),
    };
    let header = Header::new_query(0x3000, Opcode::Query, true);
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname, rtype, RecordClass::In));
    msg
}

#[tokio::test]
async fn test_fake_root_referral_delegation() {
    let script =
        ZoneScript::new().refer("com.", "a.gtld-servers.net.", Ipv4Addr::new(192, 5, 6, 30));

    let fake_root = FakeNameServer::start(FakeRole::Root, script)
        .await
        .expect("start fake root");
    let client = DnsClient::new();

    let query = make_query("example.com.", RecordType::A);
    let response = client
        .query_udp(fake_root.udp_addr(), &query)
        .await
        .expect("query fake root");

    assert_eq!(response.header.id, 0x3000);
    assert_eq!(response.header.rcode, ResponseCode::NOERROR);
    assert!(
        !response.authorities.is_empty(),
        "Referral must carry NS in authority"
    );
    assert!(
        !response.additionals.is_empty(),
        "Referral must carry glue in additionals"
    );

    let received = fake_root.received_queries();
    assert_eq!(received.len(), 1);
    if let Some(first) = received.first() {
        assert_eq!(first.qname.to_string(), "example.com.");
    }

    fake_root.shutdown();
}

#[tokio::test]
async fn test_fake_authoritative_scripted_answer() {
    let name = match Name::from_ascii("example.com.") {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    let script = ZoneScript::new().answer(
        "example.com.",
        RecordType::A,
        vec![ResourceRecord::new(
            name,
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(3600),
            RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        )],
    );

    let fake_auth = FakeNameServer::start(FakeRole::Authoritative, script)
        .await
        .expect("start fake auth");
    let client = DnsClient::new();

    // Query UDP
    let query = make_query("example.com.", RecordType::A);
    let udp_resp = client
        .query_udp(fake_auth.udp_addr(), &query)
        .await
        .expect("query udp");
    assert_eq!(udp_resp.header.rcode, ResponseCode::NOERROR);
    assert!(!udp_resp.answers.is_empty());

    // Query TCP
    let tcp_resp = client
        .query_tcp(fake_auth.tcp_addr(), &query)
        .await
        .expect("query tcp");
    assert_eq!(tcp_resp.header.rcode, ResponseCode::NOERROR);
    assert!(!tcp_resp.answers.is_empty());

    // Query unscripted domain -> NXDOMAIN
    let unknown_query = make_query("nonexistent.com.", RecordType::A);
    let unknown_resp = client
        .query_udp(fake_auth.udp_addr(), &unknown_query)
        .await
        .expect("query unknown");
    assert_eq!(unknown_resp.header.rcode, ResponseCode::NXDOMAIN);

    fake_auth.shutdown();
}
