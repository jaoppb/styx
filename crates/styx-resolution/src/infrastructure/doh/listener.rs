//! The DoH accept loop: a per-listener connection ceiling checked before the handshake,
//! then one supervised task per connection.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use styx_core::{Clock, Sleeper, SystemSleeper};

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::domain::error::ListenerError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::tls::TlsConfig;
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared, WarnLimiter};
use crate::infrastructure::doh::connection::{serve, DohSettings, StreamHandler};
use crate::infrastructure::malformed_warning::{ListenerKind, MalformedWarning};
use crate::infrastructure::tcp::{is_descriptor_exhaustion, DESCRIPTOR_EXHAUSTION_BACKOFF};

/// DNS-over-HTTPS listener with its own connection ceiling.
pub struct DohListener<L, F, O, C, T = RefusedTerminal, S = SystemSleeper> {
    listener: TokioTcpListener,
    acceptor: TlsAcceptor,
    shared: ListenerShared<L, F, O, C, T, S>,
    connections: ConnectionBudget,
    settings: DohSettings,
    bound_addr: SocketAddr,
    refusal_warning: WarnLimiter,
    malformed_warning: Arc<MalformedWarning<C, S>>,
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
    /// Binds a DoH listener to `addr`, serving `config`'s resource under its limits.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if the socket cannot be bound.
    pub async fn bind(
        addr: SocketAddr,
        acceptor: TlsAcceptor,
        shared: ListenerShared<L, F, O, C, T, S>,
        config: &TlsConfig,
    ) -> Result<Self, ListenerError> {
        let listener = TokioTcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        let malformed_warning = MalformedWarning::new(
            ListenerKind::Doh,
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
            connections: ConnectionBudget::new(config.limits().max_connections),
            settings: DohSettings {
                resource: config.doh_path().clone(),
                limits: config.limits(),
                allow_http1: config.allow_http1(),
            },
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
                self.warn_limited("out of file descriptors accepting DoH; retrying");
                tokio::time::sleep(DESCRIPTOR_EXHAUSTION_BACKOFF).await;
                return Ok(());
            }
            Err(err) => {
                tracing::error!(%err, addr = %self.bound_addr, "DoH accept error");
                return Err(ListenerError::Io(err));
            }
        };
        let Some(permit) = self.connections.try_admit() else {
            tracing::debug!(%peer, "DoH connection ceiling reached; closing before the handshake");
            self.warn_limited("DoH connection ceiling reached; refusing connections");
            return Ok(());
        };
        let handler = Arc::new(StreamHandler::new(
            self.shared.clone(),
            Arc::clone(&self.malformed_warning),
            self.settings.clone(),
            peer,
        ));
        let acceptor = self.acceptor.clone();
        let closing = cancel.child_token();
        let abort = self.shared.abort.clone();
        self.shared.tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = abort.cancelled() => {}
                () = serve(handler, acceptor, stream, closing) => {}
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
