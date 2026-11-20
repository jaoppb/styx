//! TOML configuration parsing for [`ServerConfig`].

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::domain::config::PoolConfig;
use crate::domain::error::ConfigError;
use crate::domain::limits::{
    ConcurrencyLimits, DEFAULT_MAX_IN_FLIGHT_QUERIES, DEFAULT_MAX_TCP_CONNECTIONS,
    MAX_IN_FLIGHT_PER_CONNECTION, TCP_WRITE_TIMEOUT,
};
use crate::domain::request::MaxResponseSize;
use crate::infrastructure::supervisor::{
    SupervisorBackoffPolicy, DEFAULT_HEALTHY_THRESHOLD_SECS, DEFAULT_INITIAL_BACKOFF_MS,
    DEFAULT_MAX_BACKOFF_SECS,
};
use crate::infrastructure::tcp::DEFAULT_TCP_IDLE_TIMEOUT;
use crate::infrastructure::udp_socket::default_socket_count;

use super::strays;

const DEFAULT_UDP_PAYLOAD_SIZE: u16 = 1232;
/// Must stay above `Timeouts::default()`'s longest member timeout, or a config that leaves every
/// timeout unset is rejected by `check_deadline_covers`.
const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 5;

fn default_listen_addrs() -> Vec<SocketAddr> {
    vec![SocketAddr::from(([127, 0, 0, 1], 53))]
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSupervisorConfig {
    pub(super) initial_backoff_ms: Option<u64>,
    pub(super) max_backoff_secs: Option<u64>,
    pub(super) healthy_threshold_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RawConfig {
    #[serde(default = "default_listen_addrs")]
    pub(super) listen_addrs: Vec<SocketAddr>,
    #[serde(default = "default_udp_size")]
    pub(super) udp_payload_size_default: u16,
    #[serde(default = "default_tcp_idle")]
    pub(super) tcp_idle_timeout_secs: u64,
    #[serde(default = "default_query_timeout")]
    pub(super) query_timeout_secs: u64,
    #[serde(default)]
    pub(super) max_in_flight_queries: Option<usize>,
    #[serde(default)]
    pub(super) max_tcp_connections: Option<usize>,
    #[serde(default)]
    pub(super) filter_aaaa: bool,
    #[serde(default)]
    pub(super) supervisor: Option<RawSupervisorConfig>,
    #[serde(default)]
    pub(super) upstream: Option<toml::Value>,
    /// Every other top-level key. Tables belong to other features' parsers.
    #[serde(flatten)]
    pub(super) other: toml::Table,
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
    /// Whether `AAAA` questions are answered NODATA without asking upstream.
    pub filter_aaaa: bool,
    /// Policy controlling supervisor retry backoff and healthy run reset.
    pub supervisor: SupervisorBackoffPolicy,
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
        strays::reject_stray_keys(&raw.other)?;
        if raw.listen_addrs.is_empty() {
            return Err(ConfigError::Invalid("listen_addrs cannot be empty".into()));
        }

        let supervisor = parse_supervisor_policy(raw.supervisor)?;
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
            filter_aaaa: raw.filter_aaaa,
            supervisor,
            upstream,
        };

        if let Some(pool) = &config.upstream {
            config.check_deadline_covers(pool)?;
        }

        Ok(config)
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

fn parse_supervisor_policy(
    raw: Option<RawSupervisorConfig>,
) -> Result<SupervisorBackoffPolicy, ConfigError> {
    let raw = raw.unwrap_or_default();
    let initial_ms = raw.initial_backoff_ms.unwrap_or(DEFAULT_INITIAL_BACKOFF_MS);
    let max_secs = raw.max_backoff_secs.unwrap_or(DEFAULT_MAX_BACKOFF_SECS);
    let healthy_secs = raw
        .healthy_threshold_secs
        .unwrap_or(DEFAULT_HEALTHY_THRESHOLD_SECS);

    if initial_ms == 0 {
        return Err(ConfigError::Invalid(
            "supervisor initial_backoff_ms must be greater than zero".into(),
        ));
    }
    let initial_backoff = Duration::from_millis(initial_ms);
    let max_backoff = Duration::from_secs(max_secs);
    if initial_backoff > max_backoff {
        return Err(ConfigError::Invalid(
            "supervisor initial_backoff must not exceed max_backoff".into(),
        ));
    }
    let healthy_threshold = Duration::from_secs(healthy_secs);
    Ok(SupervisorBackoffPolicy::new(
        initial_backoff,
        max_backoff,
        healthy_threshold,
    ))
}
