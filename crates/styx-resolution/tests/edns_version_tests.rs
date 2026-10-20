//! A query asking for an EDNS version the server does not implement is answered with BADVERS
//! and an OPT advertising version 0, not FORMERR (RFC 6891 §6.1.3).

mod harness;

use std::time::Duration;

use harness::{DnsClient, TestServer};
use styx_proto::{
    Header, Message, MessageKind, Name, Opcode, Opt, Question, RecordClass, RecordType,
    ResponseCode,
};

fn query_with_edns_version(version: u8) -> Message {
    let name = Name::from_ascii("example.com.").unwrap_or_else(|_| Name::root());
    let mut message = Message::new(Header::new_query(0x2222, Opcode::Query, true));
    message
        .questions
        .push(Question::new(name, RecordType::A, RecordClass::In));
    message.opt = Some(Opt::new(1232, version, false, Vec::new()));
    message
}

fn assert_badvers_reply(query: &Message, reply: &Message) {
    assert_eq!(reply.header.kind, MessageKind::Response);
    assert_eq!(reply.header.id, query.header.id);
    assert_eq!(reply.header.rcode, ResponseCode::BADVERS_OR_BADSIG);
    assert_eq!(reply.questions, query.questions);
    assert_eq!(reply.opt.as_ref().map(Opt::version), Some(0));
}

#[tokio::test]
async fn test_udp_edns_version_one_is_answered_with_badvers() {
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let query = query_with_edns_version(1);

    let reply = DnsClient::new()
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query");

    assert_badvers_reply(&query, &reply);
    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_tcp_edns_version_one_is_answered_with_badvers() {
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let query = query_with_edns_version(1);

    let reply = DnsClient::new()
        .query_tcp(server.tcp_addr(), &query)
        .await
        .expect("query");

    assert_badvers_reply(&query, &reply);
    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_udp_response_with_edns_version_one_is_dropped_silently() {
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let mut response = query_with_edns_version(1);
    response.header.kind = MessageKind::Response;
    let mut out = vec![0u8; 512];
    let written = response.encode(&mut out, 512).expect("encode");
    out.truncate(written);

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    socket.send_to(&out, server.udp_addr()).await.expect("send");

    let mut buf = [0u8; 512];
    let received =
        tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buf)).await;
    assert!(received.is_err(), "a QR=1 datagram must not be answered");
    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_edns_version_zero_is_still_served() {
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let query = query_with_edns_version(0);

    let reply = DnsClient::new()
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query");

    assert_eq!(reply.header.rcode, ResponseCode::REFUSED);
    server.shutdown().await.expect("shutdown");
}
