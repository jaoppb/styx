//! DNS over TLS (RFC 7858): a TLS-wrapped TCP accept loop whose inner stream carries the
//! same two-octet length-prefix framing as plaintext TCP, served by the same connection
//! handler and the same pipeline.
//!
//! A connection is admitted against this listener's own ceiling before the handshake,
//! because the handshake is the expensive step and a client that never finishes one costs
//! far more than it spends. The handshake then runs under its own deadline. A TLS or
//! framing failure drops that one connection and nothing else.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
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
use crate::infrastructure::accept::{bind_malformed_warning, ServeStream, StreamListener};
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared};
use crate::infrastructure::connection_bounds::QueryLimit;
use crate::infrastructure::malformed_warning::{ListenerKind, MalformedWarning};
use crate::infrastructure::tcp_connection::{Connection, ConnectionSettings};
use crate::infrastructure::tls::accept_tls;

struct DotServe<L, F, O, C, T, S> {
    acceptor: TlsAcceptor,
    shared: ListenerShared<L, F, O, C, T, S>,
    settings: ConnectionSettings,
    handshake_timeout: Duration,
    malformed_warning: Arc<MalformedWarning<C, S>>,
}

impl<L, F, O, C, T, S> ServeStream for DotServe<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    const LABEL: &'static str = "DoT";

    fn serve(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        closing: CancellationToken,
    ) -> impl Future<Output = ()> + Send + 'static {
        let acceptor = self.acceptor.clone();
        let timeout = self.handshake_timeout;
        let connection = Connection::new(
            self.shared.clone(),
            self.settings,
            Arc::clone(&self.malformed_warning),
            closing,
            peer,
        );
        async move {
            if let Some(tls) = accept_tls(&acceptor, stream, timeout, peer, Self::LABEL).await {
                connection.run(tls).await;
            }
        }
    }
}

/// DNS-over-TLS listener with its own connection ceiling.
pub struct DotListener<L, F, O, C, T = RefusedTerminal, S = SystemSleeper> {
    inner: StreamListener<DotServe<L, F, O, C, T, S>, C>,
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
        let settings = ConnectionSettings {
            idle_timeout: limits.idle_timeout,
            write_timeout: concurrency.tcp_write_timeout(),
            max_in_flight: concurrency.max_in_flight_per_connection(),
            transport: Transport::Dot,
            query_limit: QueryLimit::limited(limits.max_queries_per_connection),
        };
        let connections = ConnectionBudget::new(limits.max_connections);
        let inner = StreamListener::bind(addr, connections, &shared, |bound_addr| DotServe {
            acceptor,
            shared: shared.clone(),
            settings,
            handshake_timeout: limits.handshake_timeout,
            malformed_warning: bind_malformed_warning(ListenerKind::Dot, bound_addr, &shared),
        })
        .await?;
        Ok(Self { inner })
    }

    /// Returns the OS-assigned local address.
    #[must_use]
    pub fn bound_addr(&self) -> SocketAddr {
        self.inner.bound_addr()
    }

    /// Accepts connections until `cancel` fires.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] on a fatal accept failure. Running out of descriptors
    /// is logged and retried.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), ListenerError> {
        self.inner.run(cancel).await
    }
}
