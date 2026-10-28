//! DNS over HTTPS over HTTP/2, against a real server over real TLS (issue #9): both request
//! forms, the documented HTTP errors for every malformed request, and each bound.

#![allow(clippy::unwrap_used)]

mod harness;

use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use harness::encrypted::{
    request, tls_connect, AnsweringTerminal, DohClient, EncryptedOptions, EncryptedTestServer,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use styx_resolution::StreamMessageLimit;
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

#[tokio::test]
async fn the_stream_ceiling_is_advertised_in_the_http2_settings() {
    let mut options = EncryptedOptions::default();
    options.limits.max_streams_per_connection = NonZeroU32::MIN.saturating_add(2);
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
    options.limits.idle_timeout = Duration::from_millis(300);
    let mut server = boot(options).await;
    let mut client = DohClient::connect(server.doh(), &server.certificate).await;
    assert_eq!(client.get(&query("example.com.")).await.status, 200);
    tokio::time::timeout(PROMPTLY, &mut client.connection)
        .await
        .expect("an idle connection is closed")
        .unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn a_client_that_never_finishes_the_handshake_is_closed_at_the_deadline() {
    let mut options = EncryptedOptions::default();
    options.limits.handshake_timeout = Duration::from_millis(300);
    let mut server = boot(options).await;
    let mut silent = TcpStream::connect(server.doh()).await.unwrap();
    let mut buf = [0u8; 16];
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
