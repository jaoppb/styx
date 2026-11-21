//! DNS over TLS and DNS over HTTPS against a real server on ephemeral ports, over real TLS
//! (issue #9). Queries are built and answers read with `hickory-proto`, the oracle: if our
//! own codec encoded the fixtures, a green suite would prove only self-consistency.

#![allow(clippy::unwrap_used)]

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::encrypted::{
    connector, dot_exchange, read_frame, tls_connect, write_frame, AnsweringTerminal, DohClient,
    EncryptedOptions, EncryptedTestServer,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use styx_resolution::domain::tls::{BoundedTimeout, EncryptedLimits};
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
    let short = BoundedTimeout::new(Duration::from_millis(300)).unwrap();
    options.limits.handshake_timeout = short;
    options.limits.idle_timeout = short;
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
    assert!(
        !closed_by_server(&mut silent, Duration::from_millis(100)).await,
        "must stay open before the 300ms handshake deadline"
    );
    assert!(closed_by_server(&mut silent, PROMPTLY).await);
    server.shutdown().await;
}

#[tokio::test]
async fn an_idle_dot_connection_is_closed_at_the_idle_timeout() {
    let mut server = boot(tight(|_| {})).await;
    let mut stream = tls_connect(server.dot(), &server.certificate, &[b"dot"])
        .await
        .unwrap();
    assert!(
        !closed_by_server(&mut stream, Duration::from_millis(100)).await,
        "must stay open before the 300ms idle deadline"
    );
    assert!(closed_by_server(&mut stream, PROMPTLY).await);
    server.shutdown().await;
}

#[tokio::test]
async fn connections_past_the_ceiling_are_refused_before_the_handshake() {
    let mut server = boot(tight(|limits| {
        limits.max_connections = std::num::NonZeroUsize::MIN;
        limits.idle_timeout = BoundedTimeout::from_secs(10).unwrap();
    }))
    .await;
    let mut held = tls_connect(server.dot(), &server.certificate, &[b"dot"])
        .await
        .unwrap();
    write_frame(&mut held, &query("example.com.", RecordType::A)).await;
    assert!(read_frame(&mut held).await.is_some());

    // Refusal happens before any TLS handshake: a raw socket sees immediate EOF (0 bytes, no
    // ServerHello).
    let mut raw = TcpStream::connect(server.dot()).await.unwrap();
    let mut byte = [0u8; 1];
    let eof = tokio::time::timeout(PROMPTLY, raw.read(&mut byte))
        .await
        .expect("raw refusal must be prompt")
        .unwrap();
    assert_eq!(eof, 0, "must close with EOF before any ServerHello");

    let refused = tokio::time::timeout(
        PROMPTLY,
        tls_connect(server.dot(), &server.certificate, &[b"dot"]),
    )
    .await
    .expect("refusal must be prompt");
    assert!(refused.is_err());

    // Closing the held stream frees the slot for a new connection.
    drop(held);
    let mut next = wait_tls_connect(server.dot(), &server.certificate, &[b"dot"]).await;
    write_frame(&mut next, &query("example.com.", RecordType::A)).await;
    assert!(read_frame(&mut next).await.is_some());
    server.shutdown().await;
}

async fn wait_tls_connect(
    addr: std::net::SocketAddr,
    certificate: &harness::certificates::TestCertificate,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    tokio::time::timeout(PROMPTLY, async {
        loop {
            if let Ok(stream) = tls_connect(addr, certificate, alpn).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn doh_connections_past_the_ceiling_are_refused_before_the_handshake_and_free_their_slot() {
    let mut server = boot(tight(|limits| {
        limits.max_connections = std::num::NonZeroUsize::MIN;
        limits.idle_timeout = BoundedTimeout::from_secs(10).unwrap();
    }))
    .await;
    let mut held = DohClient::connect(server.doh(), &server.certificate).await;
    assert_eq!(
        held.get(&query("example.com.", RecordType::A)).await.status,
        200
    );

    let mut raw = TcpStream::connect(server.doh()).await.unwrap();
    let mut byte = [0u8; 1];
    let eof = tokio::time::timeout(PROMPTLY, raw.read(&mut byte))
        .await
        .expect("raw refusal must be prompt")
        .unwrap();
    assert_eq!(eof, 0, "must close with EOF before any ServerHello");

    drop(held);
    let tls = wait_tls_connect(server.doh(), &server.certificate, &[b"h2"]).await;
    let (sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut next = DohClient { sender, connection };
    assert_eq!(
        next.get(&query("example.com.", RecordType::A)).await.status,
        200
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_connection_is_closed_after_its_query_ceiling() {
    let mut server = boot(tight(|limits| {
        limits.max_queries_per_connection = std::num::NonZeroU64::MIN.saturating_add(1);
        limits.idle_timeout = BoundedTimeout::from_secs(10).unwrap();
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

async fn send_pipelined_frames<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: W,
    body: Vec<u8>,
    count: usize,
) {
    let len = u16::try_from(body.len()).unwrap().to_be_bytes();
    for _ in 0..count {
        let len_err = tokio::io::AsyncWriteExt::write_all(&mut writer, &len)
            .await
            .is_err();
        let body_err = tokio::io::AsyncWriteExt::write_all(&mut writer, &body)
            .await
            .is_err();
        if len_err || body_err {
            break;
        }
    }
}

#[tokio::test]
async fn a_slow_reading_dot_client_is_closed_within_the_write_timeout() {
    let mut server = boot(EncryptedOptions::default()).await;
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    // Shrink the client receive window and pipeline enough large answers (> 4 MiB) to fill
    // loopback's send buffer so tokio-rustls flush() blocks and hits the 5s write_timeout.
    socket.set_recv_buffer_size(4096).unwrap();
    let tcp = socket.connect(server.dot()).await.unwrap();
    let stream = connector(&server.certificate, &[b"dot"])
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let (mut reader, writer) = tokio::io::split(stream);

    const PIPELINED: usize = 600;
    let large = query("large.example.com.", RecordType::TXT);
    let sender = tokio::spawn(send_pipelined_frames(writer, large, PIPELINED));

    // Never read while the 5s write_timeout expires on the blocked flush.
    tokio::time::sleep(Duration::from_millis(5500)).await;
    let mut received = 0usize;
    while tokio::time::timeout(Duration::from_secs(1), read_frame(&mut reader))
        .await
        .unwrap_or(None)
        .is_some()
    {
        received = received.saturating_add(1);
    }
    let _ = sender.await;
    assert!(
        received < PIPELINED,
        "server must abort the slow-reading DoT connection before sending all {PIPELINED} answers (got {received})"
    );
    server.shutdown().await;
}

async fn encrypted_fixture(
    dot_listen_addrs: Vec<std::net::SocketAddr>,
    doh_listen_addrs: Vec<std::net::SocketAddr>,
) -> (
    styx_resolution::EncryptedListeners,
    harness::certificates::Scratch,
) {
    use styx_resolution::domain::tls::{
        DohResourcePath, OperatorCertificateLoader, TlsConfig, TlsConfigParts,
    };
    use styx_resolution::infrastructure::cert_fs::FilesystemCertificateReader;
    use styx_resolution::{EncryptedListeners, TlsServerSetup};

    let cert = harness::certificates::TestCertificate::valid();
    let scratch = harness::certificates::Scratch::new();
    let (cert_path, key_path) = scratch.write_pair(&cert.cert_pem, &cert.key_pem).await;
    let identity = FilesystemCertificateReader::new()
        .load(&cert_path, &key_path)
        .await
        .unwrap();
    let setup = TlsServerSetup::build(&identity, false).unwrap();
    let tls_cfg = TlsConfig::new(TlsConfigParts {
        dot_listen_addrs,
        doh_listen_addrs,
        cert_path: Some(cert_path),
        key_path: Some(key_path),
        self_signed_dir: std::path::PathBuf::from("unused"),
        self_signed_names: vec!["localhost".into()],
        doh_path: DohResourcePath::new(DohResourcePath::DEFAULT.into()).unwrap(),
        allow_http1: false,
        limits: EncryptedLimits::default(),
    })
    .unwrap();
    (EncryptedListeners::new(tls_cfg, setup), scratch)
}

#[tokio::test]
async fn partial_bind_failure_does_not_leak_earlier_listener_tasks_or_sockets() {
    use styx_resolution::{AllowAllFilter, DiscardObserver, NoLocalRecords, Pipeline, Server};
    use styx_testkit::{bind_udp_tcp_pair, TestClock, TestSleeper};

    // Keep one TCP port occupied so a later bind in the sequence fails with EADDRINUSE.
    let occupied_doh = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let conflict_addr = occupied_doh.local_addr().unwrap();

    // Reserve free ports for the earlier plaintext and DoT binds, then release them.
    let free_plain = bind_udp_tcp_pair(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        .await
        .unwrap();
    let plain_addr = free_plain.tcp.local_addr().unwrap();
    drop(free_plain);
    let free_dot = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dot_addr = free_dot.local_addr().unwrap();
    drop(free_dot);

    let mut server_cfg = harness::server::ServerSettings::default().server_config();
    server_cfg.listen_addrs = vec![plain_addr];
    let (encrypted, _scratch) = encrypted_fixture(vec![dot_addr], vec![conflict_addr]).await;

    let clock = Arc::new(TestClock::new());
    let pipeline = Arc::new(
        Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            Arc::clone(&clock),
        )
        .with_terminal(Arc::new(AnsweringTerminal)),
    );

    let tasks_before = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let outcome = Server::bind_with_encrypted(
        server_cfg,
        Some(encrypted),
        pipeline,
        Arc::clone(&clock),
        Arc::new(TestSleeper::new(clock)),
    )
    .await;
    assert!(outcome.is_err(), "occupied DoH port must fail startup");

    tokio::task::yield_now().await;
    assert_eq!(
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
        tasks_before,
        "partial bind failure must not leave detached supervisor tasks running"
    );

    // Earlier-bound plaintext (UDP + TCP) and DoT sockets must all be closed and rebindable.
    let _rebound_udp = UdpSocket::bind(plain_addr)
        .await
        .expect("plaintext UDP socket must not be held by a leaked task");
    let _rebound_tcp = tokio::net::TcpListener::bind(plain_addr)
        .await
        .expect("plaintext TCP socket must not be held by a leaked task");
    let _rebound_dot = tokio::net::TcpListener::bind(dot_addr)
        .await
        .expect("DoT socket must not be held by a leaked task");
}
