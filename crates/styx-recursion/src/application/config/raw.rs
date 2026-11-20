//! The raw shape shared by the global `[recursion]` table and every
//! `[recursion.members.<name>]` table, and its resolution into a member's settings.

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
use crate::domain::error::{ConfigError, MemberConfigError};

/// Every key optional: an absent key falls through to the next layer.
#[derive(Debug, Deserialize)]
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
    pub(super) fn resolve(self) -> Result<RecursionConfig, MemberConfigError> {
        let root_hints = self
            .root_hints
            .clone()
            .ok_or(MemberConfigError::MissingRootHints)?;
        let limits = self.limits().map_err(|error| match error {
            ConfigError::ZeroLimit(field) => MemberConfigError::ZeroLimit(field),
            other => MemberConfigError::Toml(other.to_string()),
        })?;
        Ok(RecursionConfig {
            root_hints,
            limits,
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
