//! DNS server supervisor and configuration management.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use styx_core::Clock;

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::application::Pipeline;
use crate::domain::config::PoolConfig;
use crate::domain::error::{ConfigError, ListenerError, ServerError};
use crate::domain::limits::{
    ConcurrencyLimits, DEFAULT_MAX_IN_FLIGHT_QUERIES, DEFAULT_MAX_TCP_CONNECTIONS,
    MAX_IN_FLIGHT_PER_CONNECTION, TCP_WRITE_TIMEOUT,
};
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::MaxResponseSize;
use crate::infrastructure::admission::{ConnectionBudget, ListenerShared, QueryBudget};
use crate::infrastructure::tcp::{TcpListener, DEFAULT_TCP_IDLE_TIMEOUT};
use crate::infrastructure::udp::UdpListener;
use crate::infrastructure::udp_socket::default_socket_count;

const DEFAULT_UDP_PAYLOAD_SIZE: u16 = 1232;
const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 2;

fn default_listen_addrs() -> Vec<SocketAddr> {
    vec![SocketAddr::from(([127, 0, 0, 1], 53))]
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default = "default_listen_addrs")]
    listen_addrs: Vec<SocketAddr>,
    #[serde(default = "default_udp_size")]
    udp_payload_size_default: u16,
    #[serde(default = "default_tcp_idle")]
    tcp_idle_timeout_secs: u64,
    #[serde(default = "default_query_timeout")]
    query_timeout_secs: u64,
    #[serde(default)]
    max_in_flight_queries: Option<usize>,
    #[serde(default)]
    max_tcp_connections: Option<usize>,
    #[serde(default)]
    upstream: Option<toml::Value>,
}

const fn default_udp_size() -> u16 {
    DEFAULT_UDP_PAYLOAD_SIZE
}

const fn default_tcp_idle() -> u64 {
    DEFAULT_TCP_IDLE_TIMEOUT.as_secs()
}

const fn default_query_timeout() -> u64 {
    DEFAULT_QUERY_TIMEOUT_SECS
}

/// Infrastructure configuration loaded from a TOML file.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Addresses to bind UDP and TCP listeners on.
    pub listen_addrs: Vec<SocketAddr>,
    /// Default advertised UDP payload size for EDNS.
    pub udp_payload_size_default: MaxResponseSize,
    /// Inactivity timeout for TCP connections.
    pub tcp_idle_timeout: Duration,
    /// Global query resolution timeout.
    pub query_timeout: Duration,
    /// Caps on concurrent listener work.
    pub limits: ConcurrencyLimits,
    /// Upstream pool configuration, if present in TOML.
    pub upstream: Option<PoolConfig>,
}

impl ServerConfig {
    /// Parses configuration from a TOML file path.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the file cannot be read or parsed.
    pub async fn from_toml(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = tokio::fs::read_to_string(path).await?;
        Self::from_toml_str(&content)
    }

    /// Parses configuration directly from a TOML string.
    ///
    /// # Errors
    /// Returns [`ConfigError`] on invalid syntax or schema mismatches.
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(content)?;
        if raw.listen_addrs.is_empty() {
            return Err(ConfigError::Invalid("listen_addrs cannot be empty".into()));
        }

        let upstream = match raw.upstream {
            Some(val) => Some(PoolConfig::from_toml_value(val)?),
            None => None,
        };

        let config = Self {
            listen_addrs: raw.listen_addrs,
            udp_payload_size_default: MaxResponseSize::from_edns_advertised(
                raw.udp_payload_size_default,
            ),
            tcp_idle_timeout: Duration::from_secs(raw.tcp_idle_timeout_secs),
            query_timeout: Duration::from_secs(raw.query_timeout_secs),
            limits: ConcurrencyLimits::new(
                non_zero_cap(
                    "max_in_flight_queries",
                    raw.max_in_flight_queries,
                    DEFAULT_MAX_IN_FLIGHT_QUERIES,
                )?,
                non_zero_cap(
                    "max_tcp_connections",
                    raw.max_tcp_connections,
                    DEFAULT_MAX_TCP_CONNECTIONS,
                )?,
                MAX_IN_FLIGHT_PER_CONNECTION,
                default_socket_count(),
                TCP_WRITE_TIMEOUT,
            ),
            upstream,
        };

        if let Some(pool) = &config.upstream {
            config.check_deadline_covers(pool)?;
        }

        Ok(config)
    }

    /// Checks that `query_timeout` outlasts every pool member's own timeout, so the
    /// pool always settles its health accounting before the pipeline deadline fires.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] naming both durations when some member's UDP or
    /// TCP timeout is not strictly shorter than `query_timeout`.
    pub fn check_deadline_covers(&self, pool: &PoolConfig) -> Result<(), ConfigError> {
        let longest = pool
            .members
            .iter()
            .map(|member| member.timeouts.udp.max(member.timeouts.tcp))
            .max();
        match longest {
            Some(member_timeout) if member_timeout >= self.query_timeout => {
                Err(ConfigError::Invalid(format!(
                    "query_timeout ({}ms) must exceed the longest upstream member timeout ({}ms)",
                    self.query_timeout.as_millis(),
                    member_timeout.as_millis()
                )))
            }
            _ => Ok(()),
        }
    }
}

fn non_zero_cap(
    key: &str,
    raw: Option<usize>,
    default: NonZeroUsize,
) -> Result<NonZeroUsize, ConfigError> {
    match raw {
        None => Ok(default),
        Some(value) => NonZeroUsize::new(value)
            .ok_or_else(|| ConfigError::Invalid(format!("{key} must be greater than zero"))),
    }
}

/// Supervised DNS server managing UDP and TCP listener tasks.
pub struct Server<L, F, O, C, T = RefusedTerminal> {
    _pipeline: Arc<Pipeline<L, F, O, C, T>>,
    _clock: Arc<C>,
    local_addrs: Vec<SocketAddr>,
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
    pub async fn bind(
        config: ServerConfig,
        pipeline: Arc<Pipeline<L, F, O, C, T>>,
        clock: Arc<C>,
    ) -> Result<Self, ServerError> {
        let cancel = CancellationToken::new();
        let limits = config.limits;
        let shared = ListenerShared {
            pipeline: Arc::clone(&pipeline),
            clock: Arc::clone(&clock),
            budget: QueryBudget::new(limits.max_in_flight_queries()),
            tasks: TaskTracker::new(),
            abort: CancellationToken::new(),
            query_timeout: config.query_timeout,
            udp_payload_size_default: config.udp_payload_size_default,
        };
        let connections = ConnectionBudget::new(limits.max_tcp_connections());
        let mut local_addrs = Vec::new();
        let mut listeners = Vec::new();

        for addr in config.listen_addrs {
            let udp_group =
                UdpListener::bind_group(addr, limits.udp_sockets_per_addr(), shared.clone())
                    .await
                    .map_err(|e| bind_error(addr, e))?;
            if let Some(first) = udp_group.first() {
                local_addrs.push(first.bound_addr());
            }

            let tcp = TcpListener::bind(
                addr,
                shared.clone(),
                connections.clone(),
                limits,
                Some(config.tcp_idle_timeout),
            )
            .await
            .map_err(|e| bind_error(addr, e))?;
            local_addrs.push(tcp.bound_addr());

            for udp in udp_group {
                listeners.push(Self::spawn_udp_supervisor(udp, cancel.clone()));
            }
            listeners.push(Self::spawn_tcp_supervisor(tcp, cancel.clone()));
        }

        Ok(Self {
            _pipeline: pipeline,
            _clock: clock,
            local_addrs,
            listeners,
            cancel,
            budget: shared.budget,
            tasks: shared.tasks,
            abort: shared.abort,
            shutdown_grace: config.query_timeout,
        })
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

impl<L, F, O, C, T> Server<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    fn spawn_udp_supervisor(
        udp: UdpListener<L, F, O, C, T>,
        cancel: CancellationToken,
    ) -> JoinHandle<Result<(), ListenerError>> {
        tokio::spawn(run_udp_supervisor(udp, cancel))
    }

    fn spawn_tcp_supervisor(
        tcp: TcpListener<L, F, O, C, T>,
        cancel: CancellationToken,
    ) -> JoinHandle<Result<(), ListenerError>> {
        tokio::spawn(run_tcp_supervisor(tcp, cancel))
    }
}

async fn run_udp_supervisor<L, F, O, C, T>(
    udp: UdpListener<L, F, O, C, T>,
    cancel: CancellationToken,
) -> Result<(), ListenerError>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    let mut backoff = Duration::from_millis(50);
    while !cancel.is_cancelled() {
        let Err(err) = udp.run(cancel.clone()).await else {
            break;
        };
        if handle_listener_crash("UDP", err, &mut backoff, &cancel).await {
            break;
        }
    }
    Ok(())
}

async fn run_tcp_supervisor<L, F, O, C, T>(
    tcp: TcpListener<L, F, O, C, T>,
    cancel: CancellationToken,
) -> Result<(), ListenerError>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    let mut backoff = Duration::from_millis(50);
    while !cancel.is_cancelled() {
        let Err(err) = tcp.run(cancel.clone()).await else {
            break;
        };
        if handle_listener_crash("TCP", err, &mut backoff, &cancel).await {
            break;
        }
    }
    Ok(())
}

async fn handle_listener_crash(
    kind: &'static str,
    err: ListenerError,
    backoff: &mut Duration,
    cancel: &CancellationToken,
) -> bool {
    if cancel.is_cancelled() {
        return true;
    }
    tracing::error!(%err, "{kind} listener crashed; retrying after backoff");
    tokio::time::sleep(*backoff).await;
    *backoff = backoff.saturating_mul(2).min(Duration::from_secs(2));
    cancel.is_cancelled()
}
