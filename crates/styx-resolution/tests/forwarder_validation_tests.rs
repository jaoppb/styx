//! Socket-level contract tests for Do53 forwarder validation and anti-spoofing.

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::{CommandableUpstream, TestClock, UpstreamBehavior};
use styx_core::{Clock, Upstream, UpstreamError, UpstreamId};
use styx_proto::application::Encoder;
use styx_proto::{Header, Message, MessageKind, Name, Opcode, Question, RecordClass, RecordType};
use styx_resolution::{Do53Forwarder, EdnsBufferSize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn make_test_question(qname: &str) -> Question {
    let name = match Name::from_ascii(qname) {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    Question::new(name, RecordType::A, RecordClass::In)
}

fn create_forwarder(
    id_str: &str,
    upstream: &CommandableUpstream,
    clock: Arc<TestClock>,
    timeout: Duration,
) -> Do53Forwarder<TestClock> {
    Do53Forwarder::new(
        UpstreamId::new(id_str),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        timeout,
        timeout,
        clock,
    )
}

#[tokio::test]
async fn test_forwarder_discards_mismatched_id_and_accepts_valid() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    upstream.set_behavior(UpstreamBehavior::MismatchedIdThenNormal);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(500));
    let query = make_test_question("id.discard.test.");
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let resp = forwarder
        .resolve(&query, deadline)
        .await
        .expect("valid answer accepted");
    let first_q = resp.message.questions.first().expect("first question");
    assert_eq!(first_q.qname, query.qname);
}

#[tokio::test]
async fn test_forwarder_discards_mismatched_question_and_accepts_valid() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    upstream.set_behavior(UpstreamBehavior::MismatchedQuestionThenNormal);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(500));
    let query = make_test_question("question.discard.test.");
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let resp = forwarder
        .resolve(&query, deadline)
        .await
        .expect("valid answer accepted");
    let first_q = resp.message.questions.first().expect("first question");
    assert_eq!(first_q.qname, query.qname);
}

#[tokio::test]
async fn test_forwarder_times_out_on_exclusive_mismatched_id() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    upstream.set_behavior(UpstreamBehavior::MismatchedId);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(100));
    let query = make_test_question("timeout.id.test.");
    let deadline = clock.now_monotonic() + Duration::from_millis(100);

    let err = forwarder
        .resolve(&query, deadline)
        .await
        .expect_err("should time out on mismatched id");
    assert!(matches!(err, UpstreamError::Timeout));
}

#[tokio::test]
async fn test_forwarder_times_out_on_exclusive_mismatched_question() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    upstream.set_behavior(UpstreamBehavior::MismatchedQuestion);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(100));
    let query = make_test_question("timeout.question.test.");
    let deadline = clock.now_monotonic() + Duration::from_millis(100);

    let err = forwarder
        .resolve(&query, deadline)
        .await
        .expect_err("should time out on mismatched question");
    assert!(matches!(err, UpstreamError::Timeout));
}

#[tokio::test]
async fn test_txid_is_randomized_across_queries() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(300));
    let query = make_test_question("random.txid.test.");

    let mut txids = Vec::with_capacity(100);
    for _ in 0..100 {
        let deadline = clock.now_monotonic() + Duration::from_millis(300);
        let resp = forwarder
            .resolve(&query, deadline)
            .await
            .expect("query response");
        txids.push(resp.message.header.id);
    }

    let sequential_pairs = txids
        .windows(2)
        .filter(|pair| match pair {
            [a, b] => b.wrapping_sub(*a) == 1,
            _ => false,
        })
        .count();

    // In a random uniform 16-bit draw, sequential pairs have probability ~1/65536.
    // 100 sequential queries in AtomicU16 would yield 99 sequential pairs.
    assert!(sequential_pairs < 2, "TXIDs appeared sequential: {txids:?}");
}

#[tokio::test]
async fn test_forwarder_tcp_fallback_connection_refused_propagates_transport_error() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start_udp_only()
        .await
        .expect("start udp-only upstream");
    upstream.set_behavior(UpstreamBehavior::TruncateUdp);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(500));
    let query = make_test_question("tcp.refused.test.");
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let err = forwarder
        .resolve(&query, deadline)
        .await
        .expect_err("should fail when TCP connection is refused");

    assert!(
        matches!(
            err,
            UpstreamError::Transport(std::io::ErrorKind::ConnectionRefused)
        ),
        "expected Transport(ConnectionRefused), got: {err:?}"
    );
}

#[tokio::test]
async fn test_forwarder_tcp_fallback_truncated_tcp_yields_truncated_error() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start().await.expect("start upstream");
    upstream.set_behavior(UpstreamBehavior::TruncateTcp);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(500));
    let query = make_test_question("tcp.truncated.test.");
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let err = forwarder
        .resolve(&query, deadline)
        .await
        .expect_err("should fail when TCP response is truncated");

    assert!(
        matches!(err, UpstreamError::Truncated),
        "expected UpstreamError::Truncated, got: {err:?}"
    );
}

fn encode_response(id: u16, question: &Question, truncated: bool) -> Option<Vec<u8>> {
    let mut header = Header::new_query(id, Opcode::Query, false);
    header.kind = MessageKind::Response;
    header.truncated = truncated;
    let mut message = Message::new(header);
    message.questions.push(question.clone());
    let mut encoder = Encoder::new(512);
    encoder.encode_message(&message).ok()?;
    Some(encoder.buf)
}

#[tokio::test]
async fn tcp_fallback_reuses_udp_transaction_id() {
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp");
    let addr = udp.local_addr().expect("udp addr");
    let tcp = tokio::net::TcpListener::bind(addr).await.expect("bind tcp");

    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (n, peer) = udp.recv_from(&mut buf).await.expect("udp recv");
        let query = Message::decode(buf.get(..n).expect("datagram")).expect("decode udp");
        let question = query.questions.first().expect("question").clone();
        let reply = encode_response(query.header.id, &question, true).expect("encode response");
        udp.send_to(&reply, peer).await.expect("udp reply");
        query.header.id
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.expect("accept");
        let mut len_prefix = [0u8; 2];
        stream.read_exact(&mut len_prefix).await.expect("read len");
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_prefix))];
        stream.read_exact(&mut body).await.expect("read body");
        let query = Message::decode(&body).expect("decode tcp");
        let question = query.questions.first().expect("question").clone();
        let reply = encode_response(query.header.id, &question, false).expect("encode response");
        let framed = styx_proto::frame_tcp(&reply).expect("frame");
        stream.write_all(&framed).await.expect("tcp reply");
        query.header.id
    });

    let clock = Arc::new(TestClock::new());
    let forwarder = Do53Forwarder::new(
        UpstreamId::new("fwd"),
        addr,
        EdnsBufferSize::default(),
        Duration::from_secs(2),
        Duration::from_secs(2),
        clock.clone(),
    );
    let query = make_test_question("reuse.id.test.");
    let deadline = clock.now_monotonic() + Duration::from_secs(5);

    let response = forwarder
        .resolve(&query, deadline)
        .await
        .expect("tcp fallback answered");

    assert!(response.via_tcp);
    let udp_id = udp_task.await.expect("udp task");
    let tcp_id = tcp_task.await.expect("tcp task");
    assert_eq!(
        udp_id, tcp_id,
        "TCP retry must reuse the UDP transaction ID"
    );
}
