//! Socket-level tests of the Do53 exchange's matching and fallback contract.
//!
//! The scripted servers below encode their replies with `styx-proto`. That is
//! acceptable here and only here: these tests exercise the exchange's ID and
//! question matching and its TCP fallback, not the codec, and the codec is held to
//! the `hickory-proto` oracle by its own suite.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use styx_core::test_util::TestClock;
use styx_core::Clock;
use styx_net::{Do53Client, ExchangeError};
use styx_proto::application::{Decoder, Encoder};
use styx_proto::{Header, Message, MessageKind, Name, Opcode, Question, RecordClass, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn question(name: &str) -> Question {
    let name = Name::from_ascii(name).unwrap_or_else(|_| Name::root());
    Question::new(name, RecordType::A, RecordClass::In)
}

fn query(name: &str) -> Message {
    let mut message = Message::new(Header::new_query(0, Opcode::Query, true));
    message.questions.push(question(name));
    message
}

fn reply(id: u16, asked: &Question, truncated: bool) -> Option<Vec<u8>> {
    let mut header = Header::new_query(id, Opcode::Query, true);
    header.kind = MessageKind::Response;
    header.truncated = truncated;
    let mut message = Message::new(header);
    message.questions.push(asked.clone());
    let mut encoder = Encoder::new(512);
    encoder.encode_message(&message).ok()?;
    Some(encoder.buf)
}

fn client() -> (Do53Client<TestClock>, Arc<TestClock>) {
    let clock = Arc::new(TestClock::new());
    let client = Do53Client::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
        Arc::clone(&clock),
    );
    (client, clock)
}

/// Receives one query on `socket` and returns its raw bytes and source address.
async fn receive_query(socket: &UdpSocket) -> std::io::Result<(Vec<u8>, SocketAddr)> {
    let mut buffer = [0u8; 512];
    let (length, peer) = socket.recv_from(&mut buffer).await?;
    let bytes = buffer.get(..length).map(<[u8]>::to_vec).unwrap_or_default();
    Ok((bytes, peer))
}

fn decode(bytes: &[u8]) -> Option<Message> {
    Decoder::new(bytes).decode_message().ok()
}

#[tokio::test]
async fn forged_datagrams_are_discarded_and_the_matching_reply_is_accepted() {
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = server.local_addr().expect("addr");
    let (client, clock) = client();
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let exchange = tokio::spawn(async move {
        client
            .exchange(server_addr, query("example.org."), deadline)
            .await
    });

    let (bytes, peer) = receive_query(&server).await.expect("recv");
    let sent = decode(&bytes).expect("decode query");
    let asked = sent.questions.first().expect("question").clone();
    let wrong_id = sent.header.id.wrapping_add(1);
    server
        .send_to(&reply(wrong_id, &asked, false).expect("reply"), peer)
        .await
        .expect("forged id");
    server
        .send_to(
            &reply(sent.header.id, &question("evil.example."), false).expect("reply"),
            peer,
        )
        .await
        .expect("forged question");
    server.send_to(b"not dns", peer).await.expect("garbage");
    server
        .send_to(&reply(sent.header.id, &asked, false).expect("reply"), peer)
        .await
        .expect("genuine");

    let exchanged = exchange.await.expect("join").expect("exchange");
    assert_eq!(exchanged.message.header.id, sent.header.id);
    assert!(!exchanged.via_tcp);
}

#[tokio::test]
async fn the_query_id_is_overwritten_and_varies_across_exchanges() {
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = server.local_addr().expect("addr");
    let (client, clock) = client();
    let client = Arc::new(client);

    let mut ids = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..8 {
        let deadline = clock.now_monotonic() + Duration::from_secs(1);
        let task_client = Arc::clone(&client);
        let exchange = tokio::spawn(async move {
            task_client
                .exchange(server_addr, query("example.org."), deadline)
                .await
        });
        let (bytes, peer) = receive_query(&server).await.expect("recv");
        let sent = decode(&bytes).expect("decode query");
        let asked = sent.questions.first().expect("question").clone();
        server
            .send_to(&reply(sent.header.id, &asked, false).expect("reply"), peer)
            .await
            .expect("reply");
        exchange.await.expect("join").expect("exchange");
        ids.push(sent.header.id);
        ports.push(peer.port());
    }

    ids.sort_unstable();
    ids.dedup();
    ports.sort_unstable();
    ports.dedup();
    assert!(ids.len() > 1, "every exchange sent the same transaction id");
    assert!(ports.len() > 1, "every exchange reused one source port");
}

#[tokio::test]
async fn truncation_retries_over_tcp_with_the_identical_message() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let server_addr = udp.local_addr().expect("addr");
    let tcp = TcpListener::bind(server_addr).await.expect("bind tcp");
    let (client, clock) = client();
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let exchange = tokio::spawn(async move {
        client
            .exchange(server_addr, query("minimised.example."), deadline)
            .await
    });

    let (udp_bytes, peer) = receive_query(&udp).await.expect("recv");
    let sent = decode(&udp_bytes).expect("decode query");
    let asked = sent.questions.first().expect("question").clone();
    udp.send_to(&reply(sent.header.id, &asked, true).expect("reply"), peer)
        .await
        .expect("truncated reply");

    let (mut stream, _) = tcp.accept().await.expect("accept");
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await.expect("prefix");
    let mut tcp_bytes = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut tcp_bytes).await.expect("body");
    assert_eq!(
        tcp_bytes, udp_bytes,
        "the tcp retry must resend the identical message"
    );

    let body = reply(sent.header.id, &asked, false).expect("reply");
    let framed = styx_proto::frame_tcp(&body).expect("frame");
    stream.write_all(&framed).await.expect("write");

    let exchanged = exchange.await.expect("join").expect("exchange");
    assert!(exchanged.via_tcp);
}

#[tokio::test]
async fn a_mismatched_tcp_reply_is_an_error() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let server_addr = udp.local_addr().expect("addr");
    let tcp = TcpListener::bind(server_addr).await.expect("bind tcp");
    let (client, clock) = client();
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let exchange = tokio::spawn(async move {
        client
            .exchange(server_addr, query("example.org."), deadline)
            .await
    });

    let (udp_bytes, peer) = receive_query(&udp).await.expect("recv");
    let sent = decode(&udp_bytes).expect("decode query");
    let asked = sent.questions.first().expect("question").clone();
    udp.send_to(&reply(sent.header.id, &asked, true).expect("reply"), peer)
        .await
        .expect("truncated reply");

    let (mut stream, _) = tcp.accept().await.expect("accept");
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await.expect("prefix");
    let mut discard = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut discard).await.expect("body");
    let forged = reply(sent.header.id.wrapping_add(1), &asked, false).expect("reply");
    let framed = styx_proto::frame_tcp(&forged).expect("frame");
    stream.write_all(&framed).await.expect("write");

    let error = exchange.await.expect("join").expect_err("mismatch");
    assert_eq!(error, ExchangeError::Mismatched);
}

#[tokio::test]
async fn silence_times_out() {
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = server.local_addr().expect("addr");
    let (client, clock) = client();
    let deadline = clock.now_monotonic() + Duration::from_millis(50);

    let error = client
        .exchange(server_addr, query("example.org."), deadline)
        .await
        .expect_err("timeout");
    assert_eq!(error, ExchangeError::Timeout);
}

#[tokio::test]
async fn a_query_without_a_question_is_refused_before_sending() {
    let (client, clock) = client();
    let deadline = clock.now_monotonic() + Duration::from_secs(1);
    let empty = Message::new(Header::new_query(0, Opcode::Query, true));

    let error = client
        .exchange(SocketAddr::from(([127, 0, 0, 1], 9)), empty, deadline)
        .await
        .expect_err("no question");
    assert_eq!(error, ExchangeError::NoQuestion);
}
