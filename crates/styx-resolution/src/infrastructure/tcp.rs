//! TCP DNS transport listener.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use styx_core::{Clock, Sleeper, SystemSleeper};

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::domain::error::ListenerError;
use crate::domain::limits::ConcurrencyLimits;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::Transport;
use crate::infrastructure::accept::{bind_malformed_warning, ServeStream, StreamListener};
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared};
use crate::infrastructure::connection_bounds::QueryLimit;
use crate::infrastructure::malformed_warning::{ListenerKind, MalformedWarning};
use crate::infrastructure::tcp_connection::{Connection, ConnectionSettings};

/// Default idle timeout for idle TCP client connections (5 seconds).
pub const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

struct TcpServe<L, F, O, C, T, S> {
    shared: ListenerShared<L, F, O, C, T, S>,
    settings: ConnectionSettings,
    malformed_warning: Arc<MalformedWarning<C, S>>,
}

impl<L, F, O, C, T, S> ServeStream for TcpServe<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    const LABEL: &'static str = "TCP";

    fn serve(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        closing: CancellationToken,
    ) -> impl Future<Output = ()> + Send + 'static {
        let connection = Connection::new(
            self.shared.clone(),
            self.settings,
            Arc::clone(&self.malformed_warning),
            closing,
            peer,
        );
        async move {
            connection.run(stream).await;
        }
    }
}

/// TCP DNS listener admitting connections up to a global cap.
pub struct TcpListener<L, F, O, C, T = RefusedTerminal, S = SystemSleeper> {
    inner: StreamListener<TcpServe<L, F, O, C, T, S>, C>,
}

impl<L, F, O, C, T, S> TcpListener<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    /// Binds a TCP listener to the target address.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if socket binding fails.
    pub async fn bind(
        addr: SocketAddr,
        shared: ListenerShared<L, F, O, C, T, S>,
        connections: ConnectionBudget,
        limits: ConcurrencyLimits,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, ListenerError> {
        let settings = ConnectionSettings {
            idle_timeout: idle_timeout.unwrap_or(DEFAULT_TCP_IDLE_TIMEOUT),
            write_timeout: limits.tcp_write_timeout(),
            max_in_flight: limits.max_in_flight_per_connection(),
            transport: Transport::Tcp,
            query_limit: QueryLimit::unlimited(),
        };
        let inner = StreamListener::bind(addr, connections, &shared, |bound_addr| TcpServe {
            shared: shared.clone(),
            settings,
            malformed_warning: bind_malformed_warning(ListenerKind::Tcp, bound_addr, &shared),
        })
        .await?;
        Ok(Self { inner })
    }

    /// Returns the OS-assigned local bound address (allowing port 0 binding).
    #[must_use]
    pub fn bound_addr(&self) -> SocketAddr {
        self.inner.bound_addr()
    }

    /// Runs the TCP listener accept loop until cancellation is signaled.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] on fatal accept failures. Running out of file
    /// descriptors is not fatal: it is logged and retried after a short back-off.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), ListenerError> {
        self.inner.run(cancel).await
    }
}
