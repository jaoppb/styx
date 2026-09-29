//! DNS server supervisor and configuration management.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use styx_core::Clock;

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::application::Pipeline;
use crate::domain::error::{ConfigError, ListenerError, ServerError};
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::MaxResponseSize;
use crate::infrastructure::tcp::{TcpListener, DEFAULT_TCP_IDLE_TIMEOUT};
use crate::infrastructure::udp::UdpListener;

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
        Ok(Self {
            listen_addrs: raw.listen_addrs,
            udp_payload_size_default: MaxResponseSize::from_edns_advertised(
                raw.udp_payload_size_default,
            ),
            tcp_idle_timeout: Duration::from_secs(raw.tcp_idle_timeout_secs),
            query_timeout: Duration::from_secs(raw.query_timeout_secs),
        })
    }
}

/// Supervised DNS server managing UDP and TCP listener tasks.
pub struct Server<L, F, O, C, T = RefusedTerminal> {
    _pipeline: Arc<Pipeline<L, F, O, C, T>>,
    _clock: Arc<C>,
    local_addrs: Vec<SocketAddr>,
    listeners: Vec<JoinHandle<Result<(), ListenerError>>>,
    cancel: CancellationToken,
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
    /// # Errors
    /// Returns [`ServerError`] if binding any socket fails.
    pub async fn bind(
        config: ServerConfig,
        pipeline: Arc<Pipeline<L, F, O, C, T>>,
        clock: Arc<C>,
    ) -> Result<Self, ServerError> {
        let cancel = CancellationToken::new();
        let mut local_addrs = Vec::new();
        let mut listeners = Vec::new();

        for addr in config.listen_addrs {
            let udp = UdpListener::bind(addr, Arc::clone(&pipeline), Arc::clone(&clock))
                .await
                .map_err(|e| match e {
                    ListenerError::Io(source) => ServerError::Bind { addr, source },
                    other => ServerError::Listener(other),
                })?;
            local_addrs.push(udp.bound_addr());

            let tcp = TcpListener::bind(
                addr,
                Arc::clone(&pipeline),
                Arc::clone(&clock),
                Some(config.tcp_idle_timeout),
            )
            .await
            .map_err(|e| match e {
                ListenerError::Io(source) => ServerError::Bind { addr, source },
                other => ServerError::Listener(other),
            })?;
            local_addrs.push(tcp.bound_addr());

            listeners.push(Self::spawn_udp_supervisor(udp, cancel.clone()));
            listeners.push(Self::spawn_tcp_supervisor(tcp, cancel.clone()));
        }

        Ok(Self {
            _pipeline: pipeline,
            _clock: clock,
            local_addrs,
            listeners,
            cancel,
        })
    }
}

impl<L, F, O, C, T> Server<L, F, O, C, T> {
    /// Returns the OS-assigned bound local addresses.
    #[must_use]
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.local_addrs.clone()
    }

    /// Signals cancellation to all listeners and awaits clean termination.
    ///
    /// # Errors
    /// Returns [`ServerError::Task`] if any background task join fails.
    pub async fn shutdown(&mut self) -> Result<(), ServerError> {
        self.cancel.cancel();
        for handle in self.listeners.drain(..) {
            match handle.await {
                Ok(res) => res?,
                Err(err) => return Err(ServerError::Task(err.to_string())),
            }
        }
        Ok(())
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
