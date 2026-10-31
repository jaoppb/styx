//! The raw shape shared by the global `[recursion]` table and every
//! `[recursion.members.<name>]` table, and the merge that resolves one member.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::{
    InfraCapacity, RecursionConfig, DEFAULT_MAX_DELEGATIONS, DEFAULT_MAX_SERVERS,
    DEFAULT_TCP_TIMEOUT, DEFAULT_UDP_TIMEOUT,
};
use crate::domain::budget::{
    DescentLimits, DEFAULT_MAX_CNAME_CHAIN, DEFAULT_MAX_DEPTH, DEFAULT_MAX_OUTBOUND_QUERIES,
    DEFAULT_WALL_CLOCK,
};
use crate::domain::error::ConfigError;

/// Every key optional: an absent key falls through to the next layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSettings {
    pub(super) root_hints: Option<PathBuf>,
    pub(super) max_depth: Option<u8>,
    pub(super) max_outbound_queries: Option<u16>,
    pub(super) max_cname_chain: Option<u8>,
    pub(super) wall_clock_ms: Option<u64>,
    pub(super) udp_timeout_ms: Option<u64>,
    pub(super) tcp_timeout_ms: Option<u64>,
    pub(super) use_ipv6: Option<bool>,
    pub(super) max_delegations: Option<usize>,
    pub(super) max_servers: Option<usize>,
}

impl RawSettings {
    /// `self` where it sets a key, `defaults` where it does not.
    pub(super) fn over(&self, defaults: &Self) -> Self {
        Self {
            root_hints: self
                .root_hints
                .clone()
                .or_else(|| defaults.root_hints.clone()),
            max_depth: self.max_depth.or(defaults.max_depth),
            max_outbound_queries: self.max_outbound_queries.or(defaults.max_outbound_queries),
            max_cname_chain: self.max_cname_chain.or(defaults.max_cname_chain),
            wall_clock_ms: self.wall_clock_ms.or(defaults.wall_clock_ms),
            udp_timeout_ms: self.udp_timeout_ms.or(defaults.udp_timeout_ms),
            tcp_timeout_ms: self.tcp_timeout_ms.or(defaults.tcp_timeout_ms),
            use_ipv6: self.use_ipv6.or(defaults.use_ipv6),
            max_delegations: self.max_delegations.or(defaults.max_delegations),
            max_servers: self.max_servers.or(defaults.max_servers),
        }
    }

    /// The four descent bounds, built-in defaults filling the gaps.
    pub(super) fn limits(&self) -> Result<DescentLimits, ConfigError> {
        DescentLimits::new(
            self.max_depth.unwrap_or(DEFAULT_MAX_DEPTH),
            self.max_outbound_queries
                .unwrap_or(DEFAULT_MAX_OUTBOUND_QUERIES),
            self.max_cname_chain.unwrap_or(DEFAULT_MAX_CNAME_CHAIN),
            millis(self.wall_clock_ms, DEFAULT_WALL_CLOCK),
        )
    }

    /// The finished settings, built-in defaults filling the gaps.
    pub(super) fn resolve(&self) -> Result<RecursionConfig, ConfigError> {
        let root_hints = self
            .root_hints
            .clone()
            .ok_or(ConfigError::MissingRootHints)?;
        Ok(RecursionConfig {
            root_hints,
            limits: self.limits()?,
            udp_timeout: millis(self.udp_timeout_ms, DEFAULT_UDP_TIMEOUT),
            tcp_timeout: millis(self.tcp_timeout_ms, DEFAULT_TCP_TIMEOUT),
            use_ipv6: self.use_ipv6.unwrap_or(true),
            capacity: InfraCapacity {
                max_delegations: self.max_delegations.unwrap_or(DEFAULT_MAX_DELEGATIONS),
                max_servers: self.max_servers.unwrap_or(DEFAULT_MAX_SERVERS),
            },
        })
    }
}

fn millis(value: Option<u64>, default: Duration) -> Duration {
    value.map_or(default, Duration::from_millis)
}
