//! DNS over TLS and DNS over HTTPS against a real server on ephemeral ports, over real TLS
//! (issue #9). Queries are built and answers read with `hickory-proto`, the oracle: if our
//! own codec encoded the fixtures, a green suite would prove only self-consistency.

#![allow(clippy::unwrap_used)]

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::encrypted::{
    dot_exchange, read_frame, tls_connect, write_frame, AnsweringTerminal, DohClient,
    EncryptedOptions, EncryptedTestServer,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use styx_resolution::domain::tls::EncryptedLimits;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};

const PROMPTLY: Duration = Duration::from_secs(3);

fn query(name: &str, record_type: RecordType) -> Vec<u8> {
    let mut message = Message::new(0x5157, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    // RFC 6840 §5.7: a resolver sets AD only for a client that asked with AD or DO.
    message.metadata.authentic_data = name.starts_with("signed.");
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
    message.to_vec().unwrap()
}

fn tight(limits: impl FnOnce(&mut EncryptedLimits)) -> EncryptedOptions {
    let mut options = EncryptedOptions::default();
    options.limits.handshake_timeout = Duration::from_millis(300);
    options.limits.idle_timeout = Duration::from_millis(300);
    limits(&mut options.limits);
    options
}

async fn boot(options: EncryptedOptions) -> EncryptedTestServer<AnsweringTerminal> {
    EncryptedTestServer::boot(Arc::new(AnsweringTerminal), options).await
}

async fn udp_exchange(server: std::net::SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(bytes, server).await.unwrap();
    let mut buf = vec![0u8; 65_535];
    let (len, _) = tokio::time::timeout(PROMPTLY, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf.truncate(len);
    buf
}

async fn tcp_exchange(server: std::net::SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(server).await.unwrap();
    write_frame(&mut stream, bytes).await;
    read_frame(&mut stream).await.unwrap()
}

/// Waits for the peer to close: `true` when the stream ends (EOF or reset) in time.
async fn closed_by_server<R: AsyncReadExt + Unpin>(stream: &mut R, within: Duration) -> bool {
    let mut buf = [0u8; 64];
    loop {
        match tokio::time::timeout(within, stream.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_) => return false,
        }
    }
}

/// The same question over every transport. Phase 8 adds its blocked-reply modes, and #133
/// its DNSSEC verdicts, as new questions here rather than a new test.
const CROSS_TRANSPORT_QUESTIONS: &[&str] = &["example.com.", "signed.example.com."];

/// The answer bytes each transport returns for `bytes`, labelled by transport.
async fn answers_over_every_transport(
    server: &EncryptedTestServer<AnsweringTerminal>,
    bytes: &[u8],
) -> Vec<(&'static str, Vec<u8>)> {
    let mut doh = DohClient::connect(server.doh(), &server.certificate).await;
    vec![
        ("udp", udp_exchange(server.udp_addr, bytes).await),
        ("tcp", tcp_exchange(server.tcp_addr, bytes).await),
        (
            "dot",
            dot_exchange(server.dot(), &server.certificate, bytes).await,
        ),
        ("doh-get", doh.get(bytes).await.body),
        ("doh-post", doh.post(bytes).await.body),
    ]
}

#[tokio::test]
async fn every_transport_answers_byte_for_byte_alike() {
    let mut server = boot(EncryptedOptions::default()).await;
    for name in CROSS_TRANSPORT_QUESTIONS {
        let bytes = query(name, RecordType::A);
        let answers = answers_over_every_transport(&server, &bytes).await;
        let (_, reference) = answers.first().unwrap();
        for (transport, answer) in &answers {
            assert_eq!(answer, reference, "{name}: {transport} differs from udp");
        }

        let answer = Message::from_vec(reference).unwrap();
        assert_eq!(answer.answers.len(), 1, "{name}");
        assert_eq!(
            answer.metadata.authentic_data,
            name.starts_with("signed."),
            "{name}"
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn a_large_answer_over_dot_is_whole_and_never_truncated() {
    let mut server = boot(EncryptedOptions::default()).await;
    let bytes = query("large.example.com.", RecordType::TXT);

    let udp = Message::from_vec(&udp_exchange(server.udp_addr, &bytes).await).unwrap();
    assert!(udp.metadata.truncation, "the fixture must overflow UDP");

    let dot =
        Message::from_vec(&dot_exchange(server.dot(), &server.certificate, &bytes).await).unwrap();
    assert!(!dot.metadata.truncation);
    assert_eq!(dot.answers.len(), 300);
    server.shutdown().await;
}

#[tokio::test]
async fn several_queries_share_one_dot_connection() {
    let mut server = boot(EncryptedOptions::default()).await;
    let mut stream = tls_connect(server.dot(), &server.certificate, &[b"dot"])
        .await
        .unwrap();
    for _ in 0..3 {
        write_frame(&mut stream, &query("example.com.", RecordType::A)).await;
        let answer = Message::from_vec(&read_frame(&mut stream).await.unwrap()).unwrap();
        assert_eq!(answer.answers.len(), 1);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn a_client_offering_no_alpn_is_still_served() {
    let mut server = boot(EncryptedOptions::default()).await;
    let mut stream = tls_connect(server.dot(), &server.certificate, &[])
        .await
        .unwrap();
    write_frame(&mut stream, &query("example.com.", RecordType::A)).await;
    assert!(read_frame(&mut stream).await.is_some());
    server.shutdown().await;
}

#[tokio::test]
async fn an_h2_only_client_on_the_dot_port_is_rejected_not_hung() {
    let mut server = boot(EncryptedOptions::default()).await;
    let attempt = tokio::time::timeout(
        PROMPTLY,
        tls_connect(server.dot(), &server.certificate, &[b"h2"]),
    )
    .await
    .expect("the handshake must end, not hang");
    assert!(
        attempt.is_err(),
        "an h2-only client must not get a DoT session"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_client_that_never_finishes_the_handshake_is_closed_at_the_deadline() {
    let mut server = boot(tight(|_| {})).await;
    let mut silent = TcpStream::connect(server.dot()).await.unwrap();
    assert!(closed_by_server(&mut silent, PROMPTLY).await);
    server.shutdown().await;
}

#[tokio::test]
async fn an_idle_dot_connection_is_closed_at_the_idle_timeout() {
    let mut server = boot(tight(|_| {})).await;
    let mut stream = tls_connect(server.dot(), &server.certificate, &[b"dot"])
        .await
        .unwrap();
    assert!(closed_by_server(&mut stream, PROMPTLY).await);
    server.shutdown().await;
}

#[tokio::test]
async fn connections_past_the_ceiling_are_refused_before_the_handshake() {
    let mut server = boot(tight(|limits| {
        limits.max_connections = std::num::NonZeroUsize::MIN;
        limits.idle_timeout = Duration::from_secs(10);
    }))
    .await;
    let _held = tls_connect(server.dot(), &server.certificate, &[b"dot"])
        .await
        .unwrap();
    let refused = tokio::time::timeout(
        PROMPTLY,
        tls_connect(server.dot(), &server.certificate, &[b"dot"]),
    )
    .await
    .expect("refusal must be prompt");
    assert!(refused.is_err());
    server.shutdown().await;
}

#[tokio::test]
async fn a_connection_is_closed_after_its_query_ceiling() {
    let mut server = boot(tight(|limits| {
        limits.max_queries_per_connection = std::num::NonZeroU64::MIN.saturating_add(1);
        limits.idle_timeout = Duration::from_secs(10);
    }))
    .await;
    let mut stream = tls_connect(server.dot(), &server.certificate, &[b"dot"])
        .await
        .unwrap();
    for _ in 0..2 {
        write_frame(&mut stream, &query("example.com.", RecordType::A)).await;
        assert!(read_frame(&mut stream).await.is_some());
    }
    assert!(closed_by_server(&mut stream, PROMPTLY).await);
    server.shutdown().await;
}

#[tokio::test]
async fn malformed_dot_frames_drop_that_connection_and_the_listener_keeps_serving() {
    let mut server = boot(EncryptedOptions::default()).await;

    let mut zero = tls_connect(server.dot(), &server.certificate, &[b"dot"])
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut zero, &[0, 0])
        .await
        .unwrap();
    assert!(closed_by_server(&mut zero, PROMPTLY).await);

    let mut short = tls_connect(server.dot(), &server.certificate, &[b"dot"])
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut short, &[0, 200, 1, 2, 3])
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut short)
        .await
        .unwrap();
    assert!(closed_by_server(&mut short, PROMPTLY).await);

    // A query header promising one question, followed by a label that runs off the end.
    let truncated_question = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 5, b'a'];
    let garbage = dot_exchange(server.dot(), &server.certificate, &truncated_question).await;
    let reply = Message::from_vec(&garbage).unwrap();
    assert_eq!(
        reply.metadata.response_code,
        hickory_proto::op::ResponseCode::FormErr
    );

    let answer = dot_exchange(
        server.dot(),
        &server.certificate,
        &query("example.com.", RecordType::A),
    )
    .await;
    assert_eq!(Message::from_vec(&answer).unwrap().answers.len(), 1);

    server.shutdown().await;
}
