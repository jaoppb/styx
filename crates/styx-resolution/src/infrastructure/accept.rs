//! Shared TCP accept loop for stream-oriented DNS listeners (plaintext TCP, DoT, DoH):
//! listener socket, per-listener connection ceiling, EMFILE/ENFILE back-off, rate-limited
//! warnings, and supervised connection task spawning.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use styx_core::{Clock, Sleeper};

use crate::application::terminal::TerminalHandler;
use crate::domain::error::ListenerError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared, WarnLimiter};
use crate::infrastructure::malformed_warning::{ListenerKind, MalformedWarning};

/// Back-off before retrying `accept()` after the process ran out of descriptors.
pub(crate) const DESCRIPTOR_EXHAUSTION_BACKOFF: Duration = Duration::from_millis(100);

/// `EMFILE`: the process has reached its descriptor limit (same value on Linux and BSDs).
const EMFILE: i32 = 24;

/// `ENFILE`: the system-wide descriptor table is full (same value on Linux and BSDs).
const ENFILE: i32 = 23;

/// Per-transport connection handler plugged into [`StreamListener`].
pub(crate) trait ServeStream: Send + Sync {
    /// Human-readable transport label used in log fields (`"TCP"`, `"DoT"`, `"DoH"`).
    const LABEL: &'static str;

    /// Returns an owned future that serves one accepted TCP connection until completion or
    /// `closing` cancellation.
    fn serve(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        closing: CancellationToken,
    ) -> impl Future<Output = ()> + Send + 'static;
}

/// Shared accept loop parameterized by the transport's [`ServeStream`] handler.
pub(crate) struct StreamListener<H, C> {
    listener: TokioTcpListener,
    connections: ConnectionBudget,
    bound_addr: SocketAddr,
    exhaustion_warning: WarnLimiter,
    refusal_warning: WarnLimiter,
    clock: Arc<C>,
    tasks: TaskTracker,
    abort: CancellationToken,
    handler: H,
}

impl<H, C> StreamListener<H, C>
where
    H: ServeStream,
    C: Clock + Send + Sync + 'static,
{
    /// Binds `addr` and constructs `handler` with the OS-assigned local address.
    pub(crate) async fn bind<L, F, O, T, S>(
        addr: SocketAddr,
        connections: ConnectionBudget,
        shared: &ListenerShared<L, F, O, C, T, S>,
        build_handler: impl FnOnce(SocketAddr) -> H,
    ) -> Result<Self, ListenerError> {
        let listener = TokioTcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            connections,
            bound_addr,
            exhaustion_warning: WarnLimiter::default(),
            refusal_warning: WarnLimiter::default(),
            clock: Arc::clone(&shared.clock),
            tasks: shared.tasks.clone(),
            abort: shared.abort.clone(),
            handler: build_handler(bound_addr),
        })
    }

    /// Returns the OS-assigned local address.
    pub(crate) fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Accepts connections until `cancel` fires.
    pub(crate) async fn run(&self, cancel: CancellationToken) -> Result<(), ListenerError> {
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
                self.warn_limited(
                    &self.exhaustion_warning,
                    "out of file descriptors accepting stream connection; retrying",
                );
                tokio::time::sleep(DESCRIPTOR_EXHAUSTION_BACKOFF).await;
                return Ok(());
            }
            Err(err) => {
                tracing::error!(%err, addr = %self.bound_addr, transport = H::LABEL, "stream accept error");
                return Err(ListenerError::Io(err));
            }
        };
        let Some(permit) = self.connections.try_admit() else {
            tracing::debug!(%peer, transport = H::LABEL, "connection ceiling reached; closing");
            self.warn_limited(
                &self.refusal_warning,
                "connection ceiling reached; refusing connections",
            );
            drop(stream);
            return Ok(());
        };

        let abort = self.abort.clone();
        let fut = self.handler.serve(stream, peer, cancel.child_token());
        self.tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = abort.cancelled() => {}
                () = fut => {}
            }
        });
        Ok(())
    }

    fn warn_limited(&self, limiter: &WarnLimiter, message: &'static str) {
        if limiter.allow(self.clock.now_monotonic()) {
            tracing::warn!(addr = %self.bound_addr, transport = H::LABEL, "{message}");
        }
    }
}

/// Builds a [`MalformedWarning`] tracker bound to a listener's address and shared runtime.
pub(crate) fn bind_malformed_warning<L, F, O, C, T, S>(
    kind: ListenerKind,
    bound_addr: SocketAddr,
    shared: &ListenerShared<L, F, O, C, T, S>,
) -> Arc<MalformedWarning<C, S>>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    MalformedWarning::new(
        kind,
        bound_addr,
        Arc::clone(&shared.clock),
        Arc::clone(&shared.sleeper),
        shared.tasks.clone(),
        shared.shutdown.clone(),
        shared.abort.clone(),
    )
}

/// Returns `true` for accept errors caused by running out of file descriptors.
pub(crate) fn is_descriptor_exhaustion(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(EMFILE | ENFILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_exhaustion_is_retried_not_fatal() {
        assert!(is_descriptor_exhaustion(
            &std::io::Error::from_raw_os_error(EMFILE)
        ));
        assert!(is_descriptor_exhaustion(
            &std::io::Error::from_raw_os_error(ENFILE)
        ));
    }

    #[test]
    fn other_accept_errors_stay_fatal() {
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(!is_descriptor_exhaustion(&refused));
        assert!(!is_descriptor_exhaustion(
            &std::io::Error::from_raw_os_error(13)
        ));
    }
}
