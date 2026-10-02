//! TCP DNS transport listener.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use styx_core::Clock;

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::domain::error::ListenerError;
use crate::domain::limits::ConcurrencyLimits;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared, WarnLimiter};
use crate::infrastructure::tcp_connection::{Connection, ConnectionSettings};

/// Default idle timeout for idle TCP client connections (5 seconds).
pub const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Back-off before retrying `accept()` after the process ran out of descriptors.
const DESCRIPTOR_EXHAUSTION_BACKOFF: Duration = Duration::from_millis(100);

/// `EMFILE`: the process has reached its descriptor limit (same value on Linux and BSDs).
const EMFILE: i32 = 24;

/// `ENFILE`: the system-wide descriptor table is full (same value on Linux and BSDs).
const ENFILE: i32 = 23;

/// TCP DNS listener admitting connections up to a global cap.
pub struct TcpListener<L, F, O, C, T = RefusedTerminal> {
    listener: TokioTcpListener,
    shared: ListenerShared<L, F, O, C, T>,
    connections: ConnectionBudget,
    settings: ConnectionSettings,
    bound_addr: SocketAddr,
    exhaustion_warning: WarnLimiter,
}

impl<L, F, O, C, T> TcpListener<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    /// Binds a TCP listener to the target address.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if socket binding fails.
    pub async fn bind(
        addr: SocketAddr,
        shared: ListenerShared<L, F, O, C, T>,
        connections: ConnectionBudget,
        limits: ConcurrencyLimits,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, ListenerError> {
        let listener = TokioTcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        let settings = ConnectionSettings {
            idle_timeout: idle_timeout.unwrap_or(DEFAULT_TCP_IDLE_TIMEOUT),
            write_timeout: limits.tcp_write_timeout(),
            max_in_flight: limits.max_in_flight_per_connection(),
        };
        Ok(Self {
            listener,
            shared,
            connections,
            settings,
            bound_addr,
            exhaustion_warning: WarnLimiter::default(),
        })
    }

    /// Returns the OS-assigned local bound address (allowing port 0 binding).
    #[must_use]
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Runs the TCP listener accept loop until cancellation is signaled.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] on fatal accept failures. Running out of file
    /// descriptors is not fatal: it is logged and retried after a short back-off.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), ListenerError> {
        while !cancel.is_cancelled() {
            tokio::select! {
                () = cancel.cancelled() => break,
                accept_res = self.listener.accept() => {
                    self.handle_accept_result(accept_res, &cancel).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_accept_result(
        &self,
        accept_res: Result<(TcpStream, SocketAddr), std::io::Error>,
        cancel: &CancellationToken,
    ) -> Result<(), ListenerError> {
        let (stream, peer) = match accept_res {
            Ok(pair) => pair,
            Err(err) if is_descriptor_exhaustion(&err) => {
                self.back_off_exhausted(&err).await;
                return Ok(());
            }
            Err(err) => {
                tracing::error!(%err, addr = %self.bound_addr, "TCP accept error");
                return Err(ListenerError::Io(err));
            }
        };

        let Some(permit) = self.connections.try_admit() else {
            tracing::debug!(%peer, "TCP connection cap reached; closing connection");
            drop(stream);
            return Ok(());
        };

        let connection = Connection::new(
            self.shared.clone(),
            self.settings,
            cancel.child_token(),
            peer,
        );
        let abort = self.shared.abort.clone();
        self.shared.tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = abort.cancelled() => {}
                () = connection.run(stream) => {}
            }
        });
        Ok(())
    }

    async fn back_off_exhausted(&self, err: &std::io::Error) {
        if self
            .exhaustion_warning
            .allow(self.shared.clock.now_monotonic())
        {
            tracing::warn!(
                %err,
                addr = %self.bound_addr,
                "out of file descriptors accepting TCP; retrying"
            );
        }
        tokio::time::sleep(DESCRIPTOR_EXHAUSTION_BACKOFF).await;
    }
}

/// Returns `true` for accept errors caused by running out of file descriptors.
fn is_descriptor_exhaustion(err: &std::io::Error) -> bool {
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
