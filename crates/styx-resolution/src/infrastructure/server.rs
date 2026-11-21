//! DNS server supervisor and configuration management.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use styx_core::{Clock, Sleeper};

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::application::Pipeline;
use crate::domain::error::{ListenerError, ServerError};
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared, QueryBudget};
use crate::infrastructure::supervisor::{
    spawn_listener_supervisor, SupervisedListener, SupervisorBackoffPolicy,
};
use crate::infrastructure::tcp::TcpListener;
use crate::infrastructure::udp::UdpListener;

mod config;
mod deadline;
mod encrypted;
mod strays;

pub use config::ServerConfig;
pub use encrypted::EncryptedListeners;

/// Supervised DNS server managing UDP and TCP listener tasks.
pub struct Server<L, F, O, C, T = RefusedTerminal> {
    _pipeline: Arc<Pipeline<L, F, O, C, T>>,
    _clock: Arc<C>,
    local_addrs: Vec<SocketAddr>,
    dot_addrs: Vec<SocketAddr>,
    doh_addrs: Vec<SocketAddr>,
    listeners: Vec<JoinHandle<Result<(), ListenerError>>>,
    cancel: CancellationToken,
    budget: QueryBudget,
    tasks: TaskTracker,
    abort: CancellationToken,
    shutdown_grace: Duration,
}

impl<L, F, O, C, T> Server<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    /// Binds listeners on all configured addresses and spawns supervised tasks.
    ///
    /// Every listener on every address shares one query budget, one connection budget
    /// and one task tracker.
    ///
    /// # Errors
    /// Returns [`ServerError`] if binding any socket fails.
    pub async fn bind<S>(
        config: ServerConfig,
        pipeline: Arc<Pipeline<L, F, O, C, T>>,
        clock: Arc<C>,
        sleeper: Arc<S>,
    ) -> Result<Self, ServerError>
    where
        S: Sleeper + Send + Sync + 'static,
    {
        Self::bind_with_encrypted(config, None, pipeline, clock, sleeper).await
    }

    /// Binds the plaintext listeners and, when given, DoT and DoH, all feeding the same
    /// pipeline under the same budget, task tracker and shutdown.
    ///
    /// # Errors
    /// Returns [`ServerError`] if binding any socket fails, encrypted ones included: a
    /// listener the operator configured and cannot have is a startup failure, not a
    /// degraded start.
    pub async fn bind_with_encrypted<S>(
        config: ServerConfig,
        encrypted: Option<EncryptedListeners>,
        pipeline: Arc<Pipeline<L, F, O, C, T>>,
        clock: Arc<C>,
        sleeper: Arc<S>,
    ) -> Result<Self, ServerError>
    where
        S: Sleeper + Send + Sync + 'static,
    {
        let cancel = CancellationToken::new();
        let shared = listener_shared(&config, &pipeline, &clock, sleeper, &cancel);
        let plaintext = bind_plaintext(&config, &shared).await?;
        let binding = encrypted::Binding {
            shared: &shared,
            concurrency: config.limits,
        };
        let bound = match &encrypted {
            Some(encrypted) => binding.bind(encrypted).await?,
            None => encrypted::BoundEncrypted::default(),
        };
        let mut listeners = Vec::new();
        spawn_group(
            plaintext.udp,
            &clock,
            config.supervisor,
            &cancel,
            &mut listeners,
        );
        spawn_group(
            plaintext.tcp,
            &clock,
            config.supervisor,
            &cancel,
            &mut listeners,
        );
        spawn_group(
            bound.dot,
            &clock,
            config.supervisor,
            &cancel,
            &mut listeners,
        );
        spawn_group(
            bound.doh,
            &clock,
            config.supervisor,
            &cancel,
            &mut listeners,
        );

        Ok(Self {
            _pipeline: pipeline,
            _clock: clock,
            local_addrs: plaintext.local_addrs,
            dot_addrs: bound.dot_addrs,
            doh_addrs: bound.doh_addrs,
            listeners,
            cancel,
            budget: shared.budget,
            tasks: shared.tasks,
            abort: shared.abort,
            shutdown_grace: config.query_timeout,
        })
    }
}

type ListenerHandles = Vec<JoinHandle<Result<(), ListenerError>>>;

struct BoundPlaintext<L, F, O, C, T, S> {
    local_addrs: Vec<SocketAddr>,
    udp: Vec<UdpListener<L, F, O, C, T, S>>,
    tcp: Vec<TcpListener<L, F, O, C, T, S>>,
}

fn spawn_group<Li, C>(
    listeners: Vec<Li>,
    clock: &Arc<C>,
    policy: SupervisorBackoffPolicy,
    cancel: &CancellationToken,
    handles: &mut ListenerHandles,
) where
    Li: SupervisedListener,
    C: Clock + Send + Sync + 'static,
{
    for listener in listeners {
        handles.push(spawn_listener_supervisor(
            listener,
            Arc::clone(clock),
            policy,
            cancel.clone(),
        ));
    }
}

/// Binds a UDP group and a TCP listener per configured address without spawning tasks yet.
async fn bind_plaintext<L, F, O, C, T, S>(
    config: &ServerConfig,
    shared: &ListenerShared<L, F, O, C, T, S>,
) -> Result<BoundPlaintext<L, F, O, C, T, S>, ServerError>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    let limits = config.limits;
    let connections = ConnectionBudget::new(limits.max_tcp_connections());
    let mut local_addrs = Vec::new();
    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    for &addr in &config.listen_addrs {
        let udp_group =
            UdpListener::bind_group(addr, limits.udp_sockets_per_addr(), shared.clone())
                .await
                .map_err(|e| bind_error(addr, e))?;
        if let Some(first) = udp_group.first() {
            local_addrs.push(first.bound_addr());
        }

        let tcp_listener = TcpListener::bind(
            addr,
            shared.clone(),
            connections.clone(),
            limits,
            Some(config.tcp_idle_timeout),
        )
        .await
        .map_err(|e| bind_error(addr, e))?;
        local_addrs.push(tcp_listener.bound_addr());

        udp.extend(udp_group);
        tcp.push(tcp_listener);
    }
    Ok(BoundPlaintext {
        local_addrs,
        udp,
        tcp,
    })
}

/// Builds the collaborators every listener of one server shares.
fn listener_shared<L, F, O, C, T, S>(
    config: &ServerConfig,
    pipeline: &Arc<Pipeline<L, F, O, C, T>>,
    clock: &Arc<C>,
    sleeper: Arc<S>,
    shutdown: &CancellationToken,
) -> ListenerShared<L, F, O, C, T, S> {
    ListenerShared {
        pipeline: Arc::clone(pipeline),
        clock: Arc::clone(clock),
        sleeper,
        budget: QueryBudget::new(config.limits.max_in_flight_queries()),
        tasks: TaskTracker::new(),
        shutdown: shutdown.clone(),
        abort: CancellationToken::new(),
        query_timeout: config.query_timeout,
        udp_payload_size_default: config.udp_payload_size_default,
    }
}

fn bind_error(addr: SocketAddr, error: ListenerError) -> ServerError {
    match error {
        ListenerError::Io(source) => ServerError::Bind { addr, source },
        other => ServerError::Listener(other),
    }
}

impl<L, F, O, C, T> Server<L, F, O, C, T> {
    /// Returns the OS-assigned bound local addresses: one UDP and one TCP entry per
    /// configured address, in that order, however many UDP sockets back each one.
    #[must_use]
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.local_addrs.clone()
    }

    /// Returns the OS-assigned addresses of the DoT listeners, in configured order.
    #[must_use]
    pub fn dot_addrs(&self) -> Vec<SocketAddr> {
        self.dot_addrs.clone()
    }

    /// Returns the OS-assigned addresses of the DoH listeners, in configured order.
    #[must_use]
    pub fn doh_addrs(&self) -> Vec<SocketAddr> {
        self.doh_addrs.clone()
    }

    /// Returns how many spawned connection and query tasks are still alive.
    #[must_use]
    pub fn active_tasks(&self) -> usize {
        self.tasks.len()
    }

    /// Stops admitting work, drains in-flight queries, and awaits termination.
    ///
    /// In-flight work gets up to the query timeout — which already bounds every query —
    /// to finish; whatever remains is then aborted. Returns only once no task spawned by
    /// the server is alive.
    ///
    /// # Errors
    /// Returns [`ServerError::Task`] if any listener task join fails, or the first
    /// listener error, after the drain has completed either way.
    pub async fn shutdown(&mut self) -> Result<(), ServerError> {
        self.cancel.cancel();
        self.budget.close();
        let mut first_error = None;
        for handle in self.listeners.drain(..) {
            let outcome = match handle.await {
                Ok(res) => res.map_err(ServerError::from),
                Err(err) => Err(ServerError::Task(err.to_string())),
            };
            if let Err(err) = outcome {
                first_error.get_or_insert(err);
            }
        }

        self.tasks.close();
        if tokio::time::timeout(self.shutdown_grace, self.tasks.wait())
            .await
            .is_err()
        {
            tracing::warn!(
                remaining = self.tasks.len(),
                "shutdown grace period expired; aborting in-flight tasks"
            );
            self.abort.cancel();
            self.tasks.wait().await;
        }

        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod schema_keys;
