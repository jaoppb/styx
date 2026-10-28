//! DNS over TLS (RFC 7858): a TLS-wrapped TCP accept loop whose inner stream carries the
//! same two-octet length-prefix framing as plaintext TCP, served by the same connection
//! handler and the same pipeline.
//!
//! A connection is admitted against this listener's own ceiling before the handshake,
//! because the handshake is the expensive step and a client that never finishes one costs
//! far more than it spends. The handshake then runs under its own deadline. A TLS or
//! framing failure drops that one connection and nothing else.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use styx_core::{Clock, Sleeper, SystemSleeper};

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::domain::error::ListenerError;
use crate::domain::limits::ConcurrencyLimits;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::Transport;
use crate::domain::tls::EncryptedLimits;
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared, WarnLimiter};
use crate::infrastructure::malformed_warning::{ListenerKind, MalformedWarning};
use crate::infrastructure::tcp::{is_descriptor_exhaustion, DESCRIPTOR_EXHAUSTION_BACKOFF};
use crate::infrastructure::tcp_connection::{Connection, ConnectionSettings};

/// DNS-over-TLS listener with its own connection ceiling.
pub struct DotListener<L, F, O, C, T = RefusedTerminal, S = SystemSleeper> {
    listener: TokioTcpListener,
    acceptor: TlsAcceptor,
    shared: ListenerShared<L, F, O, C, T, S>,
    connections: ConnectionBudget,
    settings: ConnectionSettings,
    handshake_timeout: Duration,
    bound_addr: SocketAddr,
    refusal_warning: WarnLimiter,
    malformed_warning: Arc<MalformedWarning<C, S>>,
}

impl<L, F, O, C, T, S> DotListener<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    /// Binds a DoT listener to `addr`.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if the socket cannot be bound.
    pub async fn bind(
        addr: SocketAddr,
        acceptor: TlsAcceptor,
        shared: ListenerShared<L, F, O, C, T, S>,
        limits: EncryptedLimits,
        concurrency: ConcurrencyLimits,
    ) -> Result<Self, ListenerError> {
        let listener = TokioTcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        let settings = ConnectionSettings {
            idle_timeout: limits.idle_timeout,
            write_timeout: concurrency.tcp_write_timeout(),
            max_in_flight: concurrency.max_in_flight_per_connection(),
            transport: Transport::Dot,
            max_queries: Some(limits.max_queries_per_connection),
        };
        let malformed_warning = MalformedWarning::new(
            ListenerKind::Dot,
            bound_addr,
            Arc::clone(&shared.clock),
            Arc::clone(&shared.sleeper),
            shared.tasks.clone(),
            shared.shutdown.clone(),
            shared.abort.clone(),
        );
        Ok(Self {
            listener,
            acceptor,
            shared,
            connections: ConnectionBudget::new(limits.max_connections),
            settings,
            handshake_timeout: limits.handshake_timeout,
            bound_addr,
            refusal_warning: WarnLimiter::default(),
            malformed_warning,
        })
    }

    /// Returns the OS-assigned local address.
    #[must_use]
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Accepts connections until `cancel` fires.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] on a fatal accept failure. Running out of descriptors
    /// is logged and retried.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), ListenerError> {
        while !cancel.is_cancelled() {
            tokio::select! {
                () = cancel.cancelled() => break,
                accepted = self.listener.accept() => self.on_accept(accepted, &cancel).await?,
            }
        }
        Ok(())
    }

    async fn on_accept(
        &self,
        accepted: Result<(TcpStream, SocketAddr), std::io::Error>,
        cancel: &CancellationToken,
    ) -> Result<(), ListenerError> {
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(err) if is_descriptor_exhaustion(&err) => {
                self.warn_limited("out of file descriptors accepting DoT; retrying");
                tokio::time::sleep(DESCRIPTOR_EXHAUSTION_BACKOFF).await;
                return Ok(());
            }
            Err(err) => {
                tracing::error!(%err, addr = %self.bound_addr, "DoT accept error");
                return Err(ListenerError::Io(err));
            }
        };
        let Some(permit) = self.connections.try_admit() else {
            tracing::debug!(%peer, "DoT connection ceiling reached; closing before the handshake");
            self.warn_limited("DoT connection ceiling reached; refusing connections");
            return Ok(());
        };
        let handshake = Handshake {
            acceptor: self.acceptor.clone(),
            timeout: self.handshake_timeout,
            peer,
        };
        let connection = Connection::new(
            self.shared.clone(),
            self.settings,
            Arc::clone(&self.malformed_warning),
            cancel.child_token(),
            peer,
        );
        let abort = self.shared.abort.clone();
        self.shared.tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = abort.cancelled() => {}
                () = serve(handshake, connection, stream) => {}
            }
        });
        Ok(())
    }

    fn warn_limited(&self, message: &'static str) {
        if self
            .refusal_warning
            .allow(self.shared.clock.now_monotonic())
        {
            tracing::warn!(addr = %self.bound_addr, "{message}");
        }
    }
}

/// The TLS handshake a connection must complete before any DNS is read.
struct Handshake {
    acceptor: TlsAcceptor,
    timeout: Duration,
    peer: SocketAddr,
}

async fn serve<L, F, O, C, T, S>(
    handshake: Handshake,
    connection: Connection<L, F, O, C, T, S>,
    stream: TcpStream,
) where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    let peer = handshake.peer;
    let accepted = tokio::time::timeout(handshake.timeout, handshake.acceptor.accept(stream)).await;
    match accepted {
        Ok(Ok(tls)) => connection.run(tls).await,
        Ok(Err(err)) => tracing::debug!(%peer, %err, "DoT handshake failed"),
        Err(_) => tracing::debug!(%peer, "DoT handshake timed out"),
    }
}
