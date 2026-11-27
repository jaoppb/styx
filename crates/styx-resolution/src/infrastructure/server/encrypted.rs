//! Binding the encrypted listeners next to the plaintext ones, on the same shared
//! collaborators: one pipeline, one query budget, one task tracker, one shutdown.

use std::future::Future;
use std::net::SocketAddr;

use styx_core::{Clock, Sleeper};

use crate::application::terminal::TerminalHandler;
use crate::domain::error::{ListenerError, ServerError};
use crate::domain::limits::ConcurrencyLimits;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::tls::TlsConfig;
use crate::infrastructure::admission::ListenerShared;
use crate::infrastructure::doh::{DohListener, DohSettings};
use crate::infrastructure::dot::DotListener;
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

/// The encrypted listeners once bound, ready to be supervised after all binds succeed.
pub(super) struct BoundEncrypted<L, F, O, C, T, S> {
    pub(super) dot_addrs: Vec<SocketAddr>,
    pub(super) doh_addrs: Vec<SocketAddr>,
    pub(super) dot: Vec<DotListener<L, F, O, C, T, S>>,
    pub(super) doh: Vec<DohListener<L, F, O, C, T, S>>,
}

impl<L, F, O, C, T, S> Default for BoundEncrypted<L, F, O, C, T, S> {
    fn default() -> Self {
        Self {
            dot_addrs: Vec::new(),
            doh_addrs: Vec::new(),
            dot: Vec::new(),
            doh: Vec::new(),
        }
    }
}

/// Binds every configured DoT and DoH address on the shared collaborators; any bind failure
/// aborts startup without spawning tasks.
pub(super) async fn bind_encrypted<L, F, O, C, T, S>(
    encrypted: &EncryptedListeners,
    shared: &ListenerShared<L, F, O, C, T, S>,
    concurrency: ConcurrencyLimits,
) -> Result<BoundEncrypted<L, F, O, C, T, S>, ServerError>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    let mut bound = BoundEncrypted::default();
    let limits = encrypted.config.limits();
    let settings = DohSettings::new(
        encrypted.config.doh_path().clone(),
        encrypted.config.allow_http1(),
    );
    bind_group(
        encrypted.config.dot_listen_addrs(),
        |addr| {
            DotListener::bind(
                addr,
                encrypted.setup.dot(),
                shared.clone(),
                limits,
                concurrency,
            )
        },
        DotListener::bound_addr,
        &mut bound.dot_addrs,
        &mut bound.dot,
    )
    .await?;
    bind_group(
        encrypted.config.doh_listen_addrs(),
        |addr| {
            DohListener::bind(
                addr,
                encrypted.setup.doh(),
                shared.clone(),
                limits,
                concurrency,
                settings.clone(),
            )
        },
        DohListener::bound_addr,
        &mut bound.doh_addrs,
        &mut bound.doh,
    )
    .await?;
    Ok(bound)
}

async fn bind_group<Li, Fut>(
    addrs: &[SocketAddr],
    bind_one: impl Fn(SocketAddr) -> Fut,
    addr_of: impl Fn(&Li) -> SocketAddr,
    bound_addrs: &mut Vec<SocketAddr>,
    listeners: &mut Vec<Li>,
) -> Result<(), ServerError>
where
    Fut: Future<Output = Result<Li, ListenerError>>,
{
    for &addr in addrs {
        let listener = bind_one(addr).await.map_err(|e| bind_error(addr, e))?;
        bound_addrs.push(addr_of(&listener));
        listeners.push(listener);
    }
    Ok(())
}
