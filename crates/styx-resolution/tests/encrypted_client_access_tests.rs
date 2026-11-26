//! `allow_networks` / `deny_networks` reach the encrypted listeners too: the shared stream
//! accept loop closes a refused peer's connection before the TLS handshake (issues #9, #95).
//!
//! The refused client binds `127.0.0.2`, which the Linux loopback answers for the whole of
//! `127.0.0.0/8`, so the test needs no second interface.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod harness;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use harness::encrypted::{connector, AnsweringTerminal, EncryptedOptions, EncryptedTestServer};
use harness::server::ServerSettings;
use rustls::pki_types::ServerName;
use styx_resolution::{ClientAccess, ClientNetwork};
use tokio::net::TcpSocket;

const ALLOWED: [u8; 4] = [127, 0, 0, 1];
const REFUSED: [u8; 4] = [127, 0, 0, 2];
const PROMPTLY: Duration = Duration::from_secs(3);

async fn boot_refusing_127_0_0_2() -> EncryptedTestServer<AnsweringTerminal> {
    let mut config = ServerSettings::default().server_config();
    config.client_access = ClientAccess::new(
        ClientNetwork::private_networks(),
        vec!["127.0.0.2/32".parse().unwrap()],
    )
    .unwrap();
    EncryptedTestServer::boot_with_config(
        Arc::new(AnsweringTerminal),
        EncryptedOptions::default(),
        config,
    )
    .await
}

/// Whether a TLS handshake offering `alpn` from `source` completes.
async fn handshake_from(
    source: [u8; 4],
    server: &EncryptedTestServer<AnsweringTerminal>,
    addr: SocketAddr,
    alpn: &[u8],
) -> bool {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::from((source, 0))).unwrap();
    let tcp = socket.connect(addr).await.unwrap();
    let handshake = connector(&server.certificate, &[alpn])
        .connect(ServerName::try_from("localhost").unwrap(), tcp);
    tokio::time::timeout(PROMPTLY, handshake)
        .await
        .expect("a refused peer must be closed, not left hanging")
        .is_ok()
}

#[tokio::test]
async fn a_refused_peer_gets_no_dot_handshake_and_an_allowed_one_does() {
    let mut server = boot_refusing_127_0_0_2().await;
    let dot = server.dot();
    assert!(!handshake_from(REFUSED, &server, dot, b"dot").await);
    assert!(handshake_from(ALLOWED, &server, dot, b"dot").await);
    server.shutdown().await;
}

#[tokio::test]
async fn a_refused_peer_gets_no_doh_handshake_and_an_allowed_one_does() {
    let mut server = boot_refusing_127_0_0_2().await;
    let doh = server.doh();
    assert!(!handshake_from(REFUSED, &server, doh, b"h2").await);
    assert!(handshake_from(ALLOWED, &server, doh, b"h2").await);
    server.shutdown().await;
}
