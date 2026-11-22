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

#[tokio::test]
async fn a_zero_window_client_that_parks_answers_is_closed_at_the_send_deadline() {
    let options = EncryptedOptions::default();
    // Long idle timeout (30s default) so only the 5s per-stream send deadline can close the
    // connection promptly; meanwhile the held in-flight slot keeps the stream tracked.
    let mut server = boot(options).await;
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
    let started = std::time::Instant::now();
    // The response headers arrive with 200, while the body cannot be sent under a 0 window.
    let res = tokio::time::timeout(PROMPTLY, async {
        tokio::select! {
            response = response => response.unwrap(),
            _ = &mut connection => panic!("connection closed before response headers"),
        }
    })
    .await
    .expect("response headers arrive promptly");
    assert_eq!(res.status(), 200);

    // Keep `sender` and `res` (its RecvStream) alive without polling/updating window; the
    // server must close the stalled connection at the 5s send deadline, well before 30s idle.
    let _keep = (sender, res);
    let closed = tokio::time::timeout(Duration::from_secs(8), &mut connection).await;
    assert!(
        closed.is_ok(),
        "zero-window connection must be closed by the send deadline"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "must not close before the 5s send deadline ({:?})",
        started.elapsed()
    );
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
async fn a_zero_window_client_honors_the_configured_tcp_write_timeout() {
    use styx_resolution::ConcurrencyLimits;

    let defaults = ConcurrencyLimits::default_limits();
    let settings = harness::server::ServerSettings {
        limits: ConcurrencyLimits::new(
            defaults.max_in_flight_queries(),
            defaults.max_tcp_connections(),
            defaults.max_in_flight_per_connection(),
            defaults.udp_sockets_per_addr(),
            Duration::from_millis(200),
        ),
        ..harness::server::ServerSettings::default()
    };
    let mut server = EncryptedTestServer::boot_with_server_settings(
        Arc::new(AnsweringTerminal),
        EncryptedOptions::default(),
        settings,
    )
    .await;

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

    // The 200ms configured tcp_write_timeout must close the stalled connection well before
    // the 5s TCP_WRITE_TIMEOUT default and 30s idle timeout.
    let _keep = (sender, res);
    let closed = tokio::time::timeout(Duration::from_secs(2), &mut connection).await;
    assert!(
        closed.is_ok(),
        "zero-window connection must close at the configured 200ms write timeout"
    );
    server.shutdown().await;
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
