//! The DoH accept loop: a per-listener connection ceiling checked before the handshake,
//! then one supervised task per connection.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use styx_core::{Clock, Sleeper, SystemSleeper};

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::domain::error::ListenerError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::tls::EncryptedLimits;
use crate::infrastructure::accept::{bind_malformed_warning, ServeStream, StreamListener};
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared};
use crate::infrastructure::doh::connection::{DohEndpoint, DohSettings};
use crate::infrastructure::malformed_warning::ListenerKind;

struct DohServe<L, F, O, C, T, S> {
    acceptor: TlsAcceptor,
    endpoint: Arc<DohEndpoint<L, F, O, C, T, S>>,
}

impl<L, F, O, C, T, S> ServeStream for DohServe<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    const LABEL: &'static str = "DoH";

    fn serve(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        closing: CancellationToken,
    ) -> impl Future<Output = ()> + Send + 'static {
        let connection = self.endpoint.connection(peer);
        let acceptor = self.acceptor.clone();
        async move {
            connection.serve(acceptor, stream, closing).await;
        }
    }
}

/// DNS-over-HTTPS listener with its own connection ceiling.
pub struct DohListener<L, F, O, C, T = RefusedTerminal, S = SystemSleeper> {
    inner: StreamListener<DohServe<L, F, O, C, T, S>, C>,
}

impl<L, F, O, C, T, S> DohListener<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    /// Binds a DoH listener to `addr`, serving `settings` under `limits`.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if the socket cannot be bound.
    pub async fn bind(
        addr: SocketAddr,
        acceptor: TlsAcceptor,
        shared: ListenerShared<L, F, O, C, T, S>,
        limits: EncryptedLimits,
        settings: DohSettings,
    ) -> Result<Self, ListenerError> {
        let connections = ConnectionBudget::new(limits.max_connections);
        let inner = StreamListener::bind(addr, connections, &shared, |bound_addr| {
            let malformed_warning = bind_malformed_warning(ListenerKind::Doh, bound_addr, &shared);
            let endpoint = Arc::new(DohEndpoint::new(
                shared.clone(),
                malformed_warning,
                limits,
                settings,
            ));
            DohServe { acceptor, endpoint }
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
