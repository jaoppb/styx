//! Pool and upstream configuration types, TOML parsing, and validation.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;
use styx_proto::{Name, RecordType};

use styx_core::UpstreamKind;

use crate::domain::circuit::CircuitConfig;
use crate::domain::edns::EdnsBufferSize;
use crate::domain::error::ConfigError;
use crate::domain::probe::{CanaryConfig, ProbeConfig};
use crate::domain::selection::StrategyName;
use crate::domain::weight::Weight;

/// Timeout budgets for an upstream provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// UDP query timeout.
    pub udp: Duration,
    /// TCP connection and query timeout.
    pub tcp: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            udp: Duration::from_secs(2),
            tcp: Duration::from_secs(3),
        }
    }
}

/// Description of a single upstream provider in configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    /// Human-readable provider name.
    pub name: String,
    /// Upstream kind (forwarder or recursor).
    pub kind: UpstreamKind,
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Relative selection weight.
    pub weight: Weight,
    /// Optional custom canary override.
    pub canary: Option<CanaryConfig>,
    /// Configured query timeouts.
    pub timeouts: Timeouts,
    /// Advertised EDNS buffer size.
    pub edns_buffer: EdnsBufferSize,
}

/// Top-level configuration for an upstream pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolConfig {
    /// Selection strategy across pool members.
    pub strategy: StrategyName,
    /// List of upstream member configurations.
    pub members: Vec<UpstreamConfig>,
    /// Probing configuration.
    pub probe: ProbeConfig,
    /// Circuit breaker policy configuration.
    pub circuit: CircuitConfig,
}

impl PoolConfig {
    /// Parses and validates a `PoolConfig` from a TOML string.
    ///
    /// # Errors
    /// Returns [`ConfigError`] on invalid syntax, empty pool, EDNS buffer size below floor,
    /// or recursor canary that does not require descent.
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        let raw: RawPoolConfig = toml::from_str(content)?;
        Self::from_raw(raw)
    }

    /// Parses and validates a `PoolConfig` from a TOML value.
    ///
    /// # Errors
    /// Returns [`ConfigError`] on invalid syntax, empty pool, EDNS buffer size below floor,
    /// or recursor canary that does not require descent.
    pub fn from_toml_value(val: toml::Value) -> Result<Self, ConfigError> {
        let raw: RawPoolConfig = val.try_into().map_err(ConfigError::from)?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawPoolConfig) -> Result<Self, ConfigError> {
        if raw.members.is_empty() {
            return Err(ConfigError::EmptyPool);
        }

        if raw.strategy == StrategyName::Race {
            tracing::warn!(
                "race selection configured; privacy hazard: every query is broadcast to all providers simultaneously"
            );
        }

        let mut members = Vec::with_capacity(raw.members.len());
        for m in raw.members {
            members.push(parse_member(m)?);
        }

        let probe = ProbeConfig {
            idle_window: Duration::from_secs(raw.probe.idle_window_secs.unwrap_or(60)),
            down_retry_interval: Duration::from_secs(raw.probe.down_retry_secs.unwrap_or(10)),
            tick: Duration::from_secs(raw.probe.tick_secs.unwrap_or(1)),
        };

        let circuit = CircuitConfig {
            failure_threshold: raw.circuit.failure_threshold.unwrap_or(3),
            open_cooldown: Duration::from_secs(raw.circuit.open_cooldown_secs.unwrap_or(30)),
            half_open_successes: raw.circuit.half_open_successes.unwrap_or(2),
        };

        Ok(Self {
            strategy: raw.strategy,
            members,
            probe,
            circuit,
        })
    }
}

fn parse_canary(kind: RawUpstreamKind, raw: RawCanaryConfig) -> Result<CanaryConfig, ConfigError> {
    let qname = Name::from_ascii(&raw.qname)
        .map_err(|e| ConfigError::Invalid(format!("invalid canary name: {e}")))?;
    let qtype = match raw.qtype.to_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "NS" => RecordType::NS,
        "TXT" => RecordType::TXT,
        other => {
            return Err(ConfigError::Invalid(format!(
                "unsupported canary qtype: {other}"
            )))
        }
    };
    let timeout = Duration::from_millis(raw.timeout_ms.unwrap_or(2000));
    let canary = CanaryConfig {
        qname,
        qtype,
        timeout,
    };

    if kind == RawUpstreamKind::Recursor
        && (canary.qname == Name::root() || canary.qname.labels().len() < 2)
    {
        return Err(ConfigError::CanaryNotDescending);
    }

    Ok(canary)
}

fn parse_member(m: RawUpstreamConfig) -> Result<UpstreamConfig, ConfigError> {
    let edns_octets = m.edns_buffer.unwrap_or(1232);
    let edns_buffer = EdnsBufferSize::new(edns_octets)?;

    let canary = match m.canary {
        Some(raw_c) => Some(parse_canary(m.kind, raw_c)?),
        None => None,
    };

    let timeouts = Timeouts {
        udp: Duration::from_millis(m.udp_timeout_ms.unwrap_or(2000)),
        tcp: Duration::from_millis(m.tcp_timeout_ms.unwrap_or(3000)),
    };

    let kind = match m.kind {
        RawUpstreamKind::Forwarder => UpstreamKind::Forwarder,
        RawUpstreamKind::Recursor => UpstreamKind::Recursor,
    };

    Ok(UpstreamConfig {
        name: m.name,
        kind,
        addr: m.addr,
        weight: Weight::new(m.weight.unwrap_or(1)),
        canary,
        timeouts,
        edns_buffer,
    })
}

#[derive(Debug, Deserialize)]
struct RawPoolConfig {
    strategy: StrategyName,
    #[serde(default)]
    members: Vec<RawUpstreamConfig>,
    #[serde(default)]
    probe: RawProbeConfig,
    #[serde(default)]
    circuit: RawCircuitConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RawUpstreamKind {
    Forwarder,
    Recursor,
}

#[derive(Debug, Deserialize)]
struct RawUpstreamConfig {
    name: String,
    kind: RawUpstreamKind,
    addr: SocketAddr,
    weight: Option<u32>,
    canary: Option<RawCanaryConfig>,
    edns_buffer: Option<u16>,
    udp_timeout_ms: Option<u64>,
    tcp_timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawCanaryConfig {
    qname: String,
    qtype: String,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct RawProbeConfig {
    idle_window_secs: Option<u64>,
    down_retry_secs: Option<u64>,
    tick_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct RawCircuitConfig {
    failure_threshold: Option<u32>,
    open_cooldown_secs: Option<u64>,
    half_open_successes: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pool_config_empty_fails() {
        let toml = r#"
            strategy = "ordered_failover"
            members = []
        "#;
        assert!(matches!(
            PoolConfig::from_toml_str(toml),
            Err(ConfigError::EmptyPool)
        ));
    }

    #[test]
    fn test_parse_pool_config_edns_floor() {
        let toml = r#"
            strategy = "round_robin"
            [[members]]
            name = "cf"
            kind = "forwarder"
            addr = "1.1.1.1:53"
            edns_buffer = 500
        "#;
        assert!(matches!(
            PoolConfig::from_toml_str(toml),
            Err(ConfigError::EdnsBufferTooSmall(500))
        ));
    }

    #[test]
    fn test_parse_pool_config_valid() {
        let toml = r#"
            strategy = "weighted"
            [[members]]
            name = "cf"
            kind = "forwarder"
            addr = "1.1.1.1:53"
            weight = 10
            edns_buffer = 1232

            [[members]]
            name = "quad9"
            kind = "forwarder"
            addr = "9.9.9.9:53"
            weight = 20
        "#;
        let pool = PoolConfig::from_toml_str(toml).expect("valid config");
        assert_eq!(pool.strategy, StrategyName::Weighted);
        assert_eq!(pool.members.len(), 2);
        assert_eq!(pool.members[0].weight.value(), 10);
        assert_eq!(pool.members[1].weight.value(), 20);
    }
}
