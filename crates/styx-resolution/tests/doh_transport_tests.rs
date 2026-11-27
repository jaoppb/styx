//! DNS over HTTPS over HTTP/2, against a real server over real TLS (issue #9): both request
//! forms, the documented HTTP errors for every malformed request, and each bound.

// The helpers below sit outside `#[test]` functions, where clippy's allowances stop.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod harness;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use harness::encrypted::{
    request, tls_connect, AnsweringTerminal, DohClient, EncryptedOptions, EncryptedTestServer,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use styx_resolution::{BoundedTimeout, StreamConcurrencyLimit, StreamMessageLimit};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const PROMPTLY: Duration = Duration::from_secs(3);
const DOH: &str = "https://localhost/dns-query";

fn query(name: &str) -> Vec<u8> {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

async fn boot(options: EncryptedOptions) -> EncryptedTestServer<AnsweringTerminal> {
    EncryptedTestServer::boot(Arc::new(AnsweringTerminal), options).await
}

#[tokio::test]
async fn get_and_post_answer_with_the_dns_media_type_and_the_answer_ttl() {
    let mut server = boot(EncryptedOptions::default()).await;
    let mut client = DohClient::connect(server.doh(), &server.certificate).await;
    for reply in [
        client.get(&query("example.com.")).await,
        client.post(&query("example.com.")).await,
    ] {
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.content_type.as_deref(),
            Some("application/dns-message")
        );
        assert_eq!(reply.cache_control.as_deref(), Some("max-age=300"));
        let answer = Message::from_vec(&reply.body).unwrap();
        assert_eq!(answer.answers.len(), 1);
    }
    server.shutdown().await;
}

/// Every malformed request shape, with the status it must get under a 512-octet cap.
fn malformed_requests(
    wire: &[u8],
) -> Vec<(
    hyper::Request<http_body_util::Full<hyper::body::Bytes>>,
    u16,
)> {
    let encoded = URL_SAFE_NO_PAD.encode(wire);
    vec![
        (
            request("POST", DOH, Some("application/dns-message"), Vec::new()),
            400,
        ),
        (request("POST", DOH, Some("text/plain"), wire.to_vec()), 415),
        (request("POST", DOH, None, wire.to_vec()), 415),
        (
            request("POST", DOH, Some("application/dns-message"), vec![0; 600]),
            413,
        ),
        (
            request("GET", &format!("{DOH}?dns=***"), None, Vec::new()),
            400,
        ),
        (request("GET", DOH, None, Vec::new()), 400),
        (
            request(
                "GET",
                &format!("{DOH}?dns={}", "A".repeat(4096)),
                None,
                Vec::new(),
            ),
            413,
        ),
        (
            request(
                "GET",
                &format!("https://localhost/other?dns={encoded}"),
                None,
                Vec::new(),
            ),
            404,
        ),
        (request("PUT", DOH, None, wire.to_vec()), 405),
    ]
}

#[tokio::test]
async fn malformed_requests_get_their_documented_status_and_the_connection_keeps_serving() {
    let mut options = EncryptedOptions::default();
    options.limits.max_request_body = StreamMessageLimit::from_configured(512).unwrap();
    let mut server = boot(options).await;
    let mut client = DohClient::connect(server.doh(), &server.certificate).await;
    let wire = query("example.com.");
    let cases = malformed_requests(&wire);
    for (index, (request, status)) in cases.into_iter().enumerate() {
        let reply = client.send(request).await.unwrap();
        assert_eq!(reply.status, status, "case {index}");
        assert!(
            reply.body.is_empty(),
            "case {index}: an error carries no DNS body"
        );
    }

    let non_dns = client
        .send(request(
            "POST",
            DOH,
            Some("application/dns-message"),
            vec![0xAB; 3],
        ))
        .await
        .unwrap();
    assert_eq!(
        non_dns.status, 400,
        "a body too short to be DNS is not answered"
    );

    assert_eq!(client.get(&wire).await.status, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn an_enormous_declared_length_is_refused_without_reading_the_body() {
    let mut server = boot(EncryptedOptions::default()).await;
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, mut connection) = h2::client::handshake(tls).await.unwrap();
    let request = hyper::Request::builder()
        .method("POST")
        .uri(DOH)
        .header(hyper::header::CONTENT_TYPE, "application/dns-message")
        .header(hyper::header::CONTENT_LENGTH, "4294967296")
        .body(())
        .unwrap();
    // The body stream stays open and empty: a server that waited for 4 GiB would hang.
    let (response, _body) = sender.send_request(request, false).unwrap();
    let status = tokio::time::timeout(PROMPTLY, async {
        tokio::select! {
            response = response => response.unwrap().status(),
            _ = &mut connection => panic!("connection ended before the answer"),
        }
    })
    .await
    .expect("the cap is judged on the declared length, before any body arrives");
    assert_eq!(status, 413);
    server.shutdown().await;
}

/// POSTs `chunks` as one body with no `Content-Length`, so the server can judge it only
/// as it streams in, and returns the status it answers with.
async fn post_streamed(
    server: &EncryptedTestServer<AnsweringTerminal>,
    chunks: &[&[u8]],
) -> hyper::StatusCode {
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, mut connection) = h2::client::handshake(tls).await.unwrap();
    let request = hyper::Request::builder()
        .method("POST")
        .uri(DOH)
        .header(hyper::header::CONTENT_TYPE, "application/dns-message")
        .body(())
        .unwrap();
    let (response, mut body) = sender.send_request(request, false).unwrap();
    for chunk in chunks {
        body.send_data(hyper::body::Bytes::copy_from_slice(chunk), false)
            .unwrap();
    }
    // The server may already have answered and reset the stream past the cap.
    let _ = body.send_data(hyper::body::Bytes::new(), true);
    tokio::time::timeout(PROMPTLY, async {
        tokio::select! {
            response = response => response.unwrap().status(),
            _ = &mut connection => panic!("connection ended before the answer"),
        }
    })
    .await
    .expect("a streamed body is answered")
}

#[tokio::test]
async fn a_streamed_body_without_a_declared_length_is_judged_as_it_arrives() {
    let mut options = EncryptedOptions::default();
    options.limits.max_request_body = StreamMessageLimit::from_configured(512).unwrap();
    let mut server = boot(options).await;

    let wire = query("example.com.");
    // Split after the DNS header, so neither chunk is a message on its own.
    let (head, tail) = wire.split_at(12);
    assert_eq!(post_streamed(&server, &[head, tail]).await, 200);
    assert_eq!(
        post_streamed(&server, &[&[0; 300], &[0; 300]]).await,
        413,
        "past the cap while streaming"
    );
    assert_eq!(
        post_streamed(&server, &[]).await,
        400,
        "an empty streamed body"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn the_stream_ceiling_is_advertised_in_the_http2_settings() {
    let mut options = EncryptedOptions::default();
    options.limits.max_streams_per_connection = StreamConcurrencyLimit::from_configured(3).unwrap();
    let mut server = boot(options).await;
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, mut connection) = h2::client::handshake(tls).await.unwrap();
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!(
            "{DOH}?dns={}",
            URL_SAFE_NO_PAD.encode(query("example.com."))
        ))
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    tokio::select! {
        response = response => assert_eq!(response.unwrap().status(), 200),
        _ = &mut connection => panic!("connection ended before the answer"),
    }
    assert_eq!(connection.max_concurrent_send_streams(), 3);
    server.shutdown().await;
}

#[tokio::test]
async fn opening_streams_past_the_ceiling_queues_until_an_open_stream_finishes() {
    let mut options = EncryptedOptions::default();
    options.limits.max_streams_per_connection = StreamConcurrencyLimit::from_configured(2).unwrap();
    let mut server = boot(options).await;
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, mut connection) = h2::client::handshake(tls).await.unwrap();

    let wire = query("example.com.");
    let req = || {
        hyper::Request::builder()
            .method("POST")
            .uri(DOH)
            .header(hyper::header::CONTENT_TYPE, "application/dns-message")
            .body(())
            .unwrap()
    };
    // Complete one stream so the server's SETTINGS_MAX_CONCURRENT_STREAMS = 2 is applied.
    let (res0, mut body0) = sender.send_request(req(), false).unwrap();
    body0
        .send_data(hyper::body::Bytes::copy_from_slice(&wire), true)
        .unwrap();
    tokio::select! {
        r = res0 => assert_eq!(r.unwrap().status(), 200),
        _ = &mut connection => panic!("connection ended early"),
    }
    assert_eq!(connection.max_concurrent_send_streams(), 2);

    // Open 2 concurrent streams without finishing their bodies, then open a 3rd (N+1)
    // stream: h2 queues stream 3 until one of the 2 active streams closes.
    let (res1, mut body1) = sender.send_request(req(), false).unwrap();
    let (res2, mut body2) = sender.send_request(req(), false).unwrap();
    let get3 = hyper::Request::builder()
        .method("GET")
        .uri(format!("{DOH}?dns={}", URL_SAFE_NO_PAD.encode(&wire)))
        .body(())
        .unwrap();
    let (mut res3, _) = sender.send_request(get3, true).unwrap();
    let third_while_full = tokio::select! {
        r = tokio::time::timeout(Duration::from_millis(100), &mut res3) => r,
        _ = &mut connection => panic!("connection ended while 2 streams are open"),
    };
    assert!(
        third_while_full.is_err(),
        "3rd stream must queue while 2 streams hit the ceiling"
    );

    // Finish stream 1; now stream 3 can open and complete.
    body1
        .send_data(hyper::body::Bytes::copy_from_slice(&wire), true)
        .unwrap();
    tokio::select! {
        (r1, r3) = async { tokio::join!(res1, res3) } => {
            assert_eq!(r1.unwrap().status(), 200);
            assert_eq!(r3.unwrap().status(), 200);
        }
        _ = &mut connection => panic!("connection ended before streams 1 and 3 answered"),
    }
    body2
        .send_data(hyper::body::Bytes::copy_from_slice(&wire), true)
        .unwrap();
    tokio::select! {
        r2 = res2 => assert_eq!(r2.unwrap().status(), 200),
        _ = &mut connection => panic!("connection ended before stream 2 answered"),
    }
    server.shutdown().await;
}

#[tokio::test]
async fn the_query_ceiling_counts_streams_and_then_closes_the_connection() {
    let mut options = EncryptedOptions::default();
    options.limits.max_queries_per_connection = NonZeroU64::MIN.saturating_add(1);
    let mut server = boot(options).await;
    let mut client = DohClient::connect(server.doh(), &server.certificate).await;
    assert_eq!(client.get(&query("example.com.")).await.status, 200);
    assert_eq!(client.get(&query("example.com.")).await.status, 200);
    tokio::time::timeout(PROMPTLY, &mut client.connection)
        .await
        .expect("the server closes the connection after its query ceiling")
        .unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn a_stream_accepted_past_the_query_ceiling_gets_503() {
    let mut options = EncryptedOptions::default();
    options.limits.max_queries_per_connection = NonZeroU64::MIN;
    let mut server = boot(options).await;
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
    let get = || {
        hyper::Request::builder()
            .method("GET")
            .uri(format!(
                "{DOH}?dns={}",
                URL_SAFE_NO_PAD.encode(query("example.com."))
            ))
            .body(())
            .unwrap()
    };
    // Both HEADERS frames leave in the connection's first flush, so the server accepts both
    // streams before the spent ceiling sends GOAWAY: one is answered, the other is over.
    let (first, _) = sender.send_request(get(), true).unwrap();
    let (second, _) = sender.send_request(get(), true).unwrap();
    let _connection = tokio::spawn(connection);
    let statuses = tokio::time::timeout(PROMPTLY, async {
        let mut statuses = [
            first.await.unwrap().status().as_u16(),
            second.await.unwrap().status().as_u16(),
        ];
        statuses.sort_unstable();
        statuses
    })
    .await
    .expect("both streams are answered");
    assert_eq!(statuses, [200, 503]);
    server.shutdown().await;
}

#[tokio::test]
async fn an_idle_doh_connection_is_closed_at_the_idle_timeout() {
    let mut options = EncryptedOptions::default();
    options.limits.idle_timeout = BoundedTimeout::new(Duration::from_millis(300)).unwrap();
    let mut server = boot(options).await;
    let mut client = DohClient::connect(server.doh(), &server.certificate).await;
    assert_eq!(client.get(&query("example.com.")).await.status, 200);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut client.connection)
            .await
            .is_err(),
        "connection must stay open before the 300ms idle deadline"
    );
    tokio::time::timeout(PROMPTLY, &mut client.connection)
        .await
        .expect("an idle connection is closed")
        .unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn a_client_that_never_finishes_the_handshake_is_closed_at_the_deadline() {
    let mut options = EncryptedOptions::default();
    options.limits.handshake_timeout = BoundedTimeout::new(Duration::from_millis(300)).unwrap();
    let mut server = boot(options).await;
    let mut silent = TcpStream::connect(server.doh()).await.unwrap();
    let mut buf = [0u8; 16];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), silent.read(&mut buf))
            .await
            .is_err(),
        "silent handshake must stay open before the 300ms deadline"
    );
    let read = tokio::time::timeout(PROMPTLY, silent.read(&mut buf))
        .await
        .expect("the server closes a silent client");
    assert!(matches!(read, Ok(0) | Err(_)));
    server.shutdown().await;
}

#[tokio::test]
async fn alpn_other_than_h2_is_rejected_on_the_doh_port_by_default() {
    let mut server = boot(EncryptedOptions::default()).await;
    for alpn in [&b"dot"[..], &b"http/1.1"[..], &b"h3"[..]] {
        let attempt = tokio::time::timeout(
            PROMPTLY,
            tls_connect(server.doh(), &server.certificate, &[alpn]),
        )
        .await
        .expect("the handshake must end, not hang");
        assert!(attempt.is_err(), "{}", String::from_utf8_lossy(alpn));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn http1_is_served_only_when_enabled() {
    let options = EncryptedOptions {
        allow_http1: true,
        ..EncryptedOptions::default()
    };
    let mut server = boot(options).await;
    let tls = tls_connect(server.doh(), &server.certificate, &[b"http/1.1"])
        .await
        .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(connection);
    let uri = format!(
        "/dns-query?dns={}",
        URL_SAFE_NO_PAD.encode(query("example.com."))
    );
    let mut get = request("GET", &uri, None, Vec::new());
    get.headers_mut().insert(
        hyper::header::HOST,
        hyper::header::HeaderValue::from_static("localhost"),
    );
    let response = sender.send_request(get).await.unwrap();
    assert_eq!(response.status(), 200);
    server.shutdown().await;
}

#[tokio::test]
async fn a_stalled_request_body_times_out_with_408_and_releases_the_connection() {
    let mut options = EncryptedOptions::default();
    options.limits.idle_timeout = BoundedTimeout::new(Duration::from_millis(200)).unwrap();
    let mut server = boot(options).await;
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, mut connection) = h2::client::handshake(tls).await.unwrap();
    let request = hyper::Request::builder()
        .method("POST")
        .uri(DOH)
        .header(hyper::header::CONTENT_TYPE, "application/dns-message")
        .header(hyper::header::CONTENT_LENGTH, "16")
        .body(())
        .unwrap();
    let (response, _body) = sender.send_request(request, false).unwrap();
    let status = tokio::time::timeout(PROMPTLY, async {
        tokio::select! {
            response = response => response.unwrap().status(),
            _ = &mut connection => panic!("connection ended before the 408 response"),
        }
    })
    .await
    .expect("a stalled body must time out rather than hang until shutdown");
    assert_eq!(status, 408);

    tokio::time::timeout(PROMPTLY, &mut connection)
        .await
        .expect(
            "timed-out stream releases its in-flight slot so idle expiry can close the connection",
        )
        .unwrap();
    server.shutdown().await;
}

/// Yields via a brief timer so `tokio::time::timeout(Duration::ZERO, ...)` expires if
/// `received_at` was captured prematurely before body read or budget acquisition.
struct YieldingTerminal;

impl styx_resolution::TerminalHandler for YieldingTerminal {
    async fn handle_terminal(
        &self,
        ctx: &styx_resolution::RequestContext,
    ) -> Result<styx_resolution::ResolutionResponse, styx_resolution::PipelineError> {
        tokio::time::sleep(Duration::from_millis(10)).await;
        AnsweringTerminal.handle_terminal(ctx).await
    }
}

#[tokio::test]
async fn a_slow_streamed_post_body_gets_its_full_query_timeout_after_read_wire() {
    let mut server =
        EncryptedTestServer::boot(Arc::new(YieldingTerminal), EncryptedOptions::default()).await;
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
    let _conn = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("POST")
        .uri(DOH)
        .header(hyper::header::CONTENT_TYPE, "application/dns-message")
        .body(())
        .unwrap();
    let wire = query("example.com.");
    let (head, tail) = wire.split_at(12);

    let (response, mut body) = sender.send_request(request, false).unwrap();
    body.send_data(hyper::body::Bytes::copy_from_slice(head), false)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Advance past the 2s query_timeout while the body is still arriving under idle_timeout.
    server.clock.advance(Duration::from_secs(10));
    body.send_data(hyper::body::Bytes::copy_from_slice(tail), true)
        .unwrap();

    let res = tokio::time::timeout(PROMPTLY, response)
        .await
        .expect("DoH POST must answer promptly")
        .unwrap();
    assert_eq!(res.status(), 200);
    let mut recv = res.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = recv.data().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    let answer = Message::from_vec(&bytes).unwrap();
    assert_eq!(
        answer.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(answer.answers.len(), 1);
    server.shutdown().await;
}

struct GatedTerminal {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    gate_first: std::sync::atomic::AtomicBool,
}

impl styx_resolution::TerminalHandler for GatedTerminal {
    async fn handle_terminal(
        &self,
        ctx: &styx_resolution::RequestContext,
    ) -> Result<styx_resolution::ResolutionResponse, styx_resolution::PipelineError> {
        if self
            .gate_first
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.entered.notify_one();
            self.release.notified().await;
        } else {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        AnsweringTerminal.handle_terminal(ctx).await
    }
}

#[tokio::test]
async fn a_doh_request_waiting_on_the_global_query_budget_gets_its_full_query_timeout() {
    use std::num::NonZeroUsize;
    use styx_resolution::ConcurrencyLimits;

    let terminal = Arc::new(GatedTerminal {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        gate_first: std::sync::atomic::AtomicBool::new(true),
    });
    let defaults = ConcurrencyLimits::default_limits();
    let settings = harness::server::ServerSettings {
        // One permit is held by the idle UDP listener's pre-recv admit(), so 2 permits
        // allow one active DoH query while forcing the second DoH query to wait.
        limits: ConcurrencyLimits::new(
            NonZeroUsize::MIN.saturating_add(1),
            defaults.max_tcp_connections(),
            defaults.max_in_flight_per_connection(),
            defaults.udp_sockets_per_addr(),
            defaults.tcp_write_timeout(),
        ),
        ..harness::server::ServerSettings::default()
    };
    let mut server = EncryptedTestServer::boot_with_server_settings(
        Arc::clone(&terminal),
        EncryptedOptions::default(),
        settings,
    )
    .await;

    let mut client1 = DohClient::connect(server.doh(), &server.certificate).await;
    let mut client2 = DohClient::connect(server.doh(), &server.certificate).await;
    let wire = query("example.com.");
    let first = tokio::spawn({
        let wire = wire.clone();
        async move { client1.get(&wire).await }
    });
    tokio::time::timeout(PROMPTLY, terminal.entered.notified())
        .await
        .expect("query 1 must enter terminal");

    let second = tokio::spawn({
        let wire = wire.clone();
        async move { client2.get(&wire).await }
    });
    // Let query 2 pass read_wire and park on the 1-permit global QueryBudget.
    tokio::time::sleep(Duration::from_millis(50)).await;
    server.clock.advance(Duration::from_secs(10));
    terminal.release.notify_one();

    let _ = tokio::time::timeout(PROMPTLY, first)
        .await
        .expect("query 1 must finish")
        .unwrap();
    let reply2 = tokio::time::timeout(PROMPTLY, second)
        .await
        .expect("query 2 must finish")
        .unwrap();
    assert_eq!(reply2.status, 200);
    let answer = Message::from_vec(&reply2.body).unwrap();
    assert_eq!(
        answer.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(answer.answers.len(), 1);
    tokio::time::timeout(PROMPTLY, server.shutdown())
        .await
        .expect("server must shut down");
}

#[tokio::test]
async fn an_undecodable_dns_message_of_header_length_gets_formerr_in_a_200() {
    let mut server = boot(EncryptedOptions::default()).await;
    let mut client = DohClient::connect(server.doh(), &server.certificate).await;
    // A full header announcing one question that never follows: long enough to be DNS,
    // too short to decode, so it is a DNS error rather than an HTTP one.
    let header_only = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for reply in [
        client.post(&header_only).await,
        client.get(&header_only).await,
    ] {
        assert_eq!(reply.status, 200);
        let answer = Message::from_vec(&reply.body).unwrap();
        assert_eq!(answer.metadata.id, 0x1234);
        assert_eq!(
            answer.metadata.response_code,
            hickory_proto::op::ResponseCode::FormErr
        );
    }
    server.shutdown().await;
}

/// Server settings with a 200 ms send deadline instead of the 5 s default.
fn short_write_timeout() -> harness::server::ServerSettings {
    use styx_resolution::ConcurrencyLimits;

    let defaults = ConcurrencyLimits::default_limits();
    harness::server::ServerSettings {
        limits: ConcurrencyLimits::new(
            defaults.max_in_flight_queries(),
            defaults.max_tcp_connections(),
            defaults.max_in_flight_per_connection(),
            defaults.udp_sockets_per_addr(),
            Duration::from_millis(200),
        ),
        ..harness::server::ServerSettings::default()
    }
}

type ZeroWindowConnection =
    h2::client::Connection<tokio_rustls::client::TlsStream<TcpStream>, hyper::body::Bytes>;

/// Opens a zero-window HTTP/2 connection and sends one GET: the 200 headers arrive, the body
/// cannot. The sender and the response are returned so the caller keeps the stream open.
async fn park_one_answer(
    server: &EncryptedTestServer<AnsweringTerminal>,
) -> (
    h2::client::SendRequest<hyper::body::Bytes>,
    ZeroWindowConnection,
    hyper::Response<h2::RecvStream>,
) {
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, mut connection) = h2::client::Builder::new()
        .initial_window_size(0)
        .handshake::<_, hyper::body::Bytes>(tls)
        .await
        .unwrap();
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!(
            "{DOH}?dns={}",
            URL_SAFE_NO_PAD.encode(query("example.com."))
        ))
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    let res = tokio::time::timeout(PROMPTLY, async {
        tokio::select! {
            response = response => response.unwrap(),
            _ = &mut connection => panic!("connection closed before response headers"),
        }
    })
    .await
    .expect("response headers arrive promptly");
    assert_eq!(res.status(), 200);
    (sender, connection, res)
}

#[tokio::test]
async fn a_zero_window_client_is_closed_at_the_configured_send_deadline() {
    let mut server = EncryptedTestServer::boot_with_server_settings(
        Arc::new(AnsweringTerminal),
        EncryptedOptions::default(),
        short_write_timeout(),
    )
    .await;
    let started = std::time::Instant::now();
    let (sender, mut connection, res) = park_one_answer(&server).await;

    // The 200 ms send deadline must close the stalled connection well before the 30 s idle
    // timeout, and not before the deadline itself.
    let _keep = (sender, res);
    let closed = tokio::time::timeout(Duration::from_secs(2), &mut connection).await;
    assert!(
        closed.is_ok(),
        "zero-window connection must close at the configured 200ms write timeout"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "must not close before the send deadline ({:?})",
        started.elapsed()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_draining_connection_still_closes_at_the_send_deadline() {
    // One query spends the ceiling, so the connection drains right after the first stream.
    // A long handshake timeout must not stretch that drain: only the send deadline bounds it.
    let mut options = EncryptedOptions::default();
    options.limits.max_queries_per_connection = NonZeroU64::MIN;
    options.limits.handshake_timeout = BoundedTimeout::new(Duration::from_secs(60)).unwrap();
    let mut server = EncryptedTestServer::boot_with_server_settings(
        Arc::new(AnsweringTerminal),
        options,
        short_write_timeout(),
    )
    .await;
    let (sender, mut connection, res) = park_one_answer(&server).await;

    let _keep = (sender, res);
    let closed = tokio::time::timeout(Duration::from_secs(2), &mut connection).await;
    assert!(
        closed.is_ok(),
        "a draining connection with a stalled send must close at the 200ms write timeout"
    );
    tokio::time::timeout(PROMPTLY, server.shutdown())
        .await
        .expect("server must shut down");
}

#[tokio::test]
async fn a_draining_connection_is_cut_at_the_query_and_send_deadlines() {
    // Two queries spend the ceiling. The first is a POST whose body never finishes, so only
    // the 30 s idle timeout bounds its read; the second spends the ceiling and starts the
    // drain. Nothing stalls a send, so only the drain bound (query 2 s + write 200 ms) can
    // close the connection, and a 60 s handshake timeout must not stretch it.
    let mut options = EncryptedOptions::default();
    options.limits.max_queries_per_connection = NonZeroU64::MIN.saturating_add(1);
    options.limits.handshake_timeout = BoundedTimeout::new(Duration::from_secs(60)).unwrap();
    let mut server = EncryptedTestServer::boot_with_server_settings(
        Arc::new(AnsweringTerminal),
        options,
        short_write_timeout(),
    )
    .await;
    let tls = tls_connect(server.doh(), &server.certificate, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, mut connection) = h2::client::handshake(tls).await.unwrap();
    let post = hyper::Request::builder()
        .method("POST")
        .uri(DOH)
        .header(hyper::header::CONTENT_TYPE, "application/dns-message")
        .body(())
        .unwrap();
    let (_stuck, mut body) = sender.send_request(post, false).unwrap();
    body.send_data(hyper::body::Bytes::from_static(&[0x12, 0x34]), false)
        .unwrap();
    let get = hyper::Request::builder()
        .method("GET")
        .uri(format!(
            "{DOH}?dns={}",
            URL_SAFE_NO_PAD.encode(query("example.com."))
        ))
        .body(())
        .unwrap();
    let (answered, _) = sender.send_request(get, true).unwrap();

    let closed = tokio::time::timeout(Duration::from_secs(4), &mut connection).await;
    assert!(
        closed.is_ok(),
        "the drain must end at query_timeout + write_timeout, not the handshake timeout"
    );
    let _keep = (sender, body, answered);
    tokio::time::timeout(PROMPTLY, server.shutdown())
        .await
        .expect("server must shut down");
}

struct OversizedTerminal;

impl styx_resolution::TerminalHandler for OversizedTerminal {
    async fn handle_terminal(
        &self,
        ctx: &styx_resolution::RequestContext,
    ) -> Result<styx_resolution::ResolutionResponse, styx_resolution::PipelineError> {
        use styx_proto::domain::rdata::basic::TxtRdata;
        use styx_proto::domain::rdata::CharacterString;
        use styx_proto::{
            Message, RData, RecordClass, RecordType, ResourceRecord, ResponseCode, Ttl,
        };
        use styx_resolution::{ResolutionOutcome, ResolvedSource};

        let question = ctx.query.questions.first().cloned().unwrap();
        let mut response = Message::response_to(ctx.query.header.id, question.clone());
        let txt = CharacterString::new(vec![b'x'; 200]);
        for _ in 0..400 {
            response.answers.push(ResourceRecord::new(
                question.qname.clone(),
                RecordType::TXT,
                RecordClass::In,
                Ttl::from_secs(60),
                RData::Txt(TxtRdata::new(vec![txt.clone()])),
            ));
        }
        let outcome = ResolutionOutcome::Resolved {
            source: ResolvedSource::Upstream,
            rcode: ResponseCode::NOERROR,
            cacheable: false,
            authentic_data: false,
        };
        Ok(styx_resolution::ResolutionResponse::new(response, outcome))
    }
}

#[tokio::test]
async fn a_server_encode_failure_answers_with_500_while_inbound_response_gets_400() {
    let mut server =
        EncryptedTestServer::boot(Arc::new(OversizedTerminal), EncryptedOptions::default()).await;
    let mut client = DohClient::connect(server.doh(), &server.certificate).await;

    let encode_failed = client.post(&query("example.com.")).await;
    assert_eq!(encode_failed.status, 500);
    assert!(encode_failed.body.is_empty());

    let mut inbound_response = Message::new(0x1234, MessageType::Response, OpCode::Query);
    inbound_response.add_query(Query::query(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));
    let unanswerable = client.post(&inbound_response.to_vec().unwrap()).await;
    assert_eq!(unanswerable.status, 400);
    assert!(unanswerable.body.is_empty());

    server.shutdown().await;
}
