//! `allow_networks` / `deny_networks`: a peer outside the allowed networks gets no UDP
//! answer and its TCP connection is closed (issue #95).
//!
//! The denied client binds `127.0.0.2`, which the Linux loopback answers for the whole of
//! `127.0.0.0/8`, so the test needs no second interface.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use styx_core::{SystemClock, SystemSleeper};
use styx_proto::application::Encoder;
use styx_proto::{frame_tcp, Header, Message, Name, Opcode, Question, RecordClass, RecordType};
use styx_resolution::{
    AllowAllFilter, DiscardObserver, NoLocalRecords, Pipeline, Server, ServerConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};

const ALLOWED: [u8; 4] = [127, 0, 0, 1];
const DENIED: [u8; 4] = [127, 0, 0, 2];
const PATIENCE: Duration = Duration::from_millis(500);

type TestServer = Server<NoLocalRecords, AllowAllFilter, DiscardObserver, SystemClock>;

/// What a client observed after sending one query.
#[derive(Debug, PartialEq, Eq)]
enum Heard {
    /// The server sent bytes back.
    Reply(Vec<u8>),
    /// The server closed (or reset) the TCP connection without sending a byte.
    Closed,
    /// Nothing arrived before the deadline.
    Silence,
}

async fn boot(access_lines: &str) -> Option<TestServer> {
    let config =
        ServerConfig::from_toml_str(&format!("listen_addrs = [\"127.0.0.1:0\"]\n{access_lines}"))
            .ok()?;
    let clock = Arc::new(SystemClock::new());
    let pipeline = Pipeline::new(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        Arc::clone(&clock),
    );
    Server::bind(
        config,
        Arc::new(pipeline),
        clock,
        Arc::new(SystemSleeper::new()),
    )
    .await
    .ok()
}

fn query_bytes() -> Option<Vec<u8>> {
    let mut message = Message::new(Header::new_query(0x9500, Opcode::Query, true));
    let qname = Name::from_ascii("example.com.").ok()?;
    message
        .questions
        .push(Question::new(qname, RecordType::A, RecordClass::In));
    let mut encoder = Encoder::new(512);
    encoder.encode_message(&message).ok()?;
    Some(encoder.buf)
}

/// The bound UDP address; `local_addrs` lists UDP then TCP.
fn udp_addr(server: &TestServer) -> Option<SocketAddr> {
    server.local_addrs().first().copied()
}

fn tcp_addr(server: &TestServer) -> Option<SocketAddr> {
    server.local_addrs().get(1).copied()
}

/// Sends one query over UDP from `source`; `None` only when the client could not be set up.
async fn udp_query_from(source: [u8; 4], server: SocketAddr) -> Option<Heard> {
    let socket = UdpSocket::bind(SocketAddr::from((source, 0))).await.ok()?;
    socket.send_to(&query_bytes()?, server).await.ok()?;
    let mut buf = [0u8; 4096];
    let Ok(received) = tokio::time::timeout(PATIENCE, socket.recv_from(&mut buf)).await else {
        return Some(Heard::Silence);
    };
    let (len, _) = received.ok()?;
    Some(Heard::Reply(buf.get(..len)?.to_vec()))
}

/// Connects from `source`, sends one framed query and reads until the server answers,
/// closes, or stays silent; `None` only when the client could not be set up.
async fn tcp_query_from(source: [u8; 4], server: SocketAddr) -> Option<Heard> {
    let socket = TcpSocket::new_v4().ok()?;
    socket.bind(SocketAddr::from((source, 0))).ok()?;
    let mut stream = socket.connect(server).await.ok()?;
    // The server may already have closed the stream, so a failed write is not an error.
    let _ = stream.write_all(&frame_tcp(&query_bytes()?).ok()?).await;
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(PATIENCE, stream.read(&mut buf)).await {
        Ok(Ok(0) | Err(_)) => Some(Heard::Closed),
        Ok(Ok(len)) => Some(Heard::Reply(buf.get(..len)?.to_vec())),
        Err(_elapsed) => Some(Heard::Silence),
    }
}

fn is_reply(heard: Option<Heard>) -> bool {
    matches!(heard, Some(Heard::Reply(bytes)) if !bytes.is_empty())
}

#[tokio::test]
async fn test_udp_query_from_outside_allow_networks_gets_no_response() {
    let mut server = boot("allow_networks = [\"127.0.0.1/32\"]")
        .await
        .expect("boot");
    let udp = udp_addr(&server).expect("udp addr");

    assert_eq!(udp_query_from(DENIED, udp).await, Some(Heard::Silence));
    assert!(
        is_reply(udp_query_from(ALLOWED, udp).await),
        "allowed peer is answered"
    );

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_tcp_connection_from_outside_allow_networks_is_closed() {
    let mut server = boot("allow_networks = [\"127.0.0.1/32\"]")
        .await
        .expect("boot");
    let tcp = tcp_addr(&server).expect("tcp addr");

    assert_eq!(tcp_query_from(DENIED, tcp).await, Some(Heard::Closed));
    assert!(
        is_reply(tcp_query_from(ALLOWED, tcp).await),
        "allowed peer is answered"
    );

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_deny_networks_overrides_allow_networks_on_both_transports() {
    let mut server = boot("allow_networks = [\"127.0.0.0/8\"]\ndeny_networks = [\"127.0.0.2/32\"]")
        .await
        .expect("boot");
    let udp = udp_addr(&server).expect("udp addr");
    let tcp = tcp_addr(&server).expect("tcp addr");

    assert_eq!(udp_query_from(DENIED, udp).await, Some(Heard::Silence));
    assert_eq!(tcp_query_from(DENIED, tcp).await, Some(Heard::Closed));
    assert!(is_reply(udp_query_from(ALLOWED, udp).await));

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_default_config_answers_loopback() {
    let mut server = boot("").await.expect("boot");
    let udp = udp_addr(&server).expect("udp addr");
    let tcp = tcp_addr(&server).expect("tcp addr");

    assert!(is_reply(udp_query_from(DENIED, udp).await));
    assert!(is_reply(tcp_query_from(ALLOWED, tcp).await));

    server.shutdown().await.expect("shutdown");
}

#[test]
fn test_access_keys_reject_malformed_networks_and_an_empty_allow_list() {
    let parse = |lines: &str| ServerConfig::from_toml_str(lines);
    assert!(parse("allow_networks = []").is_err());
    assert!(parse("allow_networks = [\"10.0.0.0/33\"]").is_err());
    assert!(parse("deny_networks = [\"192.168.1.5/16\"]").is_err());
    assert!(parse("allow_networks = [\"10.0.0.0\"]").is_err());
}

#[test]
fn test_open_resolver_is_flagged_only_for_a_whole_family_on_a_public_bind() {
    let exposes = |lines: &str| {
        ServerConfig::from_toml_str(lines)
            .expect("parses")
            .exposes_open_resolver()
    };
    assert!(exposes(
        "listen_addrs = [\"0.0.0.0:53\"]\nallow_networks = [\"0.0.0.0/0\"]"
    ));
    assert!(exposes(
        "listen_addrs = [\"[::]:53\"]\nallow_networks = [\"::/0\"]"
    ));
    assert!(!exposes(
        "listen_addrs = [\"127.0.0.1:53\"]\nallow_networks = [\"0.0.0.0/0\"]"
    ));
    assert!(!exposes("listen_addrs = [\"0.0.0.0:53\"]"));
}
