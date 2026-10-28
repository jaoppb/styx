//! Binding the encrypted listeners next to the plaintext ones, on the same shared
//! collaborators: one pipeline, one query budget, one task tracker, one shutdown.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use styx_core::{Clock, Sleeper};

use crate::application::terminal::TerminalHandler;
use crate::domain::error::{ListenerError, ServerError};
use crate::domain::limits::ConcurrencyLimits;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::tls::TlsConfig;
use crate::infrastructure::admission::ListenerShared;
use crate::infrastructure::dot::DotListener;
use crate::infrastructure::supervisor::{spawn_listener_supervisor, SupervisorBackoffPolicy};
use crate::infrastructure::tls::TlsServerSetup;

use super::bind_error;

/// What the server needs to bring DoT and DoH up: the validated `[tls]` section and the
/// TLS configuration already built from the serving certificate.
#[derive(Clone)]
pub struct EncryptedListeners {
    config: TlsConfig,
    setup: TlsServerSetup,
}

impl EncryptedListeners {
    /// Pairs the section with its TLS setup.
    #[must_use]
    pub fn new(config: TlsConfig, setup: TlsServerSetup) -> Self {
        Self { config, setup }
    }
}

/// The encrypted listeners once bound and supervised.
#[derive(Default)]
pub(super) struct BoundEncrypted {
    pub(super) dot_addrs: Vec<SocketAddr>,
    pub(super) handles: Vec<JoinHandle<Result<(), ListenerError>>>,
}

/// The collaborators every encrypted listener is bound with.
pub(super) struct Binding<'a, L, F, O, C, T, S> {
    pub(super) shared: &'a ListenerShared<L, F, O, C, T, S>,
    pub(super) clock: &'a Arc<C>,
    pub(super) concurrency: ConcurrencyLimits,
    pub(super) supervisor: SupervisorBackoffPolicy,
    pub(super) cancel: &'a CancellationToken,
}

impl<L, F, O, C, T, S> Binding<'_, L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    /// Binds every configured DoT address; any bind failure aborts startup.
    pub(super) async fn bind(
        &self,
        encrypted: &EncryptedListeners,
    ) -> Result<BoundEncrypted, ServerError> {
        let mut bound = BoundEncrypted::default();
        let limits = encrypted.config.limits();
        for &addr in encrypted.config.dot_listen_addrs() {
            let dot = DotListener::bind(
                addr,
                encrypted.setup.dot(),
                self.shared.clone(),
                limits,
                self.concurrency,
            )
            .await
            .map_err(|e| bind_error(addr, e))?;
            bound.dot_addrs.push(dot.bound_addr());
            bound.handles.push(spawn_listener_supervisor(
                dot,
                Arc::clone(self.clock),
                self.supervisor,
                self.cancel.clone(),
            ));
        }
        Ok(bound)
    }
}
