//! In-process fake DNS name servers — root, TLD or authoritative — over real
//! UDP and TCP sockets.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use styx_proto::Question;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use crate::convert::hickory_record;
use crate::error::HarnessError;
use crate::responder::{respond, ReceivedQuery};
use crate::script::ZoneScript;

/// Where a fake name server sits in the delegation hierarchy.
///
/// Names the server's place for the reader of a test. Its behaviour comes entirely
/// from its [`ZoneScript`]: a root and an authoritative server given the same
/// script answer identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeRole {
    /// Root DNS server (delegates TLDs via referrals).
    Root,
    /// Top-Level Domain (TLD) server (delegates zones via referrals).
    Tld,
    /// Authoritative server for a specific zone.
    Authoritative,
}

/// In-process fake DNS server whose responses are encoded by `hickory-proto`.
pub struct FakeNameServer {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    received: Arc<Mutex<Vec<ReceivedQuery>>>,
    cancel: CancellationToken,
}

impl FakeNameServer {
    /// Starts a fake server on ephemeral UDP and TCP ports of 127.0.0.1.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails, or if the script contains a
    /// record type the fake cannot serve — reported now rather than as a record
    /// silently missing from some later answer.
    pub async fn start(role: FakeRole, script: ZoneScript) -> Result<Self, HarnessError> {
        Self::start_on(SocketAddr::from(([127, 0, 0, 1], 0)), role, script).await
    }

    /// Starts a fake server on `address`, UDP and TCP alike.
    ///
    /// A recursion test runs one fake per nameserver on distinct loopback
    /// addresses (127.0.0.2, 127.0.0.3, …) sharing one port. A referral carries only
    /// an IP; the resolver under test supplies the port, so every fake must listen on
    /// the same one.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails — the port may be taken on that
    /// address — or if the script contains a record type the fake cannot serve.
    pub async fn start_on(
        address: SocketAddr,
        _role: FakeRole,
        script: ZoneScript,
    ) -> Result<Self, HarnessError> {
        for record in script.answers.iter().flat_map(|answer| &answer.records) {
            hickory_record(record)?;
        }
        let cancel = CancellationToken::new();
        let received = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);

        let udp_socket = Arc::new(UdpSocket::bind(address).await?);
        let udp_addr = udp_socket.local_addr()?;
        let tcp_listener = TcpListener::bind(udp_addr).await?;
        let tcp_addr = tcp_listener.local_addr()?;

        let shared = Shared {
            script,
            received: Arc::clone(&received),
            cancel: cancel.clone(),
        };
        tokio::spawn(serve_udp(udp_socket, shared.clone()));
        tokio::spawn(serve_tcp(tcp_listener, shared));

        Ok(Self {
            udp_addr,
            tcp_addr,
            received,
            cancel,
        })
    }

    /// Returns the OS-assigned UDP listening address.
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    /// Returns the OS-assigned TCP listening address.
    #[must_use]
    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    /// Returns every question this server received, in arrival order, exactly as
    /// it arrived on the wire.
    ///
    /// This is what privacy tests assert on: nothing in an answer reveals whether
    /// the full query name was sent to a server that only needed one label of it.
    #[must_use]
    pub fn received_queries(&self) -> Vec<Question> {
        self.received()
            .into_iter()
            .map(|received| received.question)
            .collect()
    }

    /// Returns every query this server received, with its transport and DO bit.
    #[must_use]
    pub fn received(&self) -> Vec<ReceivedQuery> {
        match self.received.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Shuts down the fake server.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

/// What every serving task needs.
#[derive(Clone)]
struct Shared {
    script: Arc<ZoneScript>,
    received: Arc<Mutex<Vec<ReceivedQuery>>>,
    cancel: CancellationToken,
}

impl Shared {
    /// Answers one raw query, recording it. `None` for bytes that are not a query,
    /// and for every query to a silent server.
    fn answer(&self, bytes: &[u8], via_tcp: bool) -> Option<Vec<u8>> {
        let exchange = respond(bytes, &self.script, via_tcp)?;
        match self.received.lock() {
            Ok(mut guard) => guard.push(exchange.received),
            Err(poisoned) => poisoned.into_inner().push(exchange.received),
        }
        exchange.reply
    }
}

async fn serve_udp(socket: Arc<UdpSocket>, shared: Shared) {
    let mut buffer = [0u8; 4096];
    loop {
        tokio::select! {
            () = shared.cancel.cancelled() => break,
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, peer)) = received else { continue };
                let Some(reply) = buffer.get(..length).and_then(|query| shared.answer(query, false))
                else {
                    continue;
                };
                if socket.send_to(&reply, peer).await.is_err() {
                    continue;
                }
            }
        }
    }
}

async fn serve_tcp(listener: TcpListener, shared: Shared) {
    loop {
        tokio::select! {
            () = shared.cancel.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                tokio::spawn(serve_tcp_connection(stream, shared.clone()));
            }
        }
    }
}

async fn serve_tcp_connection(mut stream: TcpStream, shared: Shared) {
    let mut length_prefix = [0u8; 2];
    loop {
        tokio::select! {
            () = shared.cancel.cancelled() => break,
            read = stream.read_exact(&mut length_prefix) => {
                if read.is_err() {
                    break;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length_prefix))];
                if stream.read_exact(&mut query).await.is_err() {
                    break;
                }
                let Some(framed) = shared
                    .answer(&query, true)
                    .and_then(|reply| styx_proto::frame_tcp(&reply).ok())
                else {
                    continue;
                };
                if stream.write_all(&framed).await.is_err() {
                    break;
                }
            }
        }
    }
}
