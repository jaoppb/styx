//! The `[recursion]` section of the TOML file.
//!
//! The file owns infrastructure: root hints, budgets and timeouts are needed before
//! any database exists, so they live here and nowhere else. Changing them means
//! editing the file and restarting.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::domain::budget::{
    DescentLimits, DEFAULT_MAX_CNAME_CHAIN, DEFAULT_MAX_DEPTH, DEFAULT_MAX_OUTBOUND_QUERIES,
    DEFAULT_WALL_CLOCK,
};
use crate::domain::error::ConfigError;

/// Default per-query UDP timeout. Authoritative servers answer in tens of
/// milliseconds; 800 ms leaves room for a distant one while letting a descent try
/// several servers inside its wall-clock budget.
pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_millis(800);

/// Default per-query TCP timeout, longer than UDP for the handshake.
pub const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_millis(1500);

/// Default bound on cached delegations. A household resolves a few thousand
/// distinct zones a day; at a few hundred bytes each, 10 000 keeps this store
/// within a few megabytes on a Raspberry Pi.
pub const DEFAULT_MAX_DELEGATIONS: usize = 10_000;

/// Default bound on nameservers with metrics, sized like the delegation bound.
pub const DEFAULT_MAX_SERVERS: usize = 10_000;

/// Entry bounds for the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfraCapacity {
    /// Maximum delegations held.
    pub max_delegations: usize,
    /// Maximum nameservers with metrics held.
    pub max_servers: usize,
}

impl Default for InfraCapacity {
    fn default() -> Self {
        Self {
            max_delegations: DEFAULT_MAX_DELEGATIONS,
            max_servers: DEFAULT_MAX_SERVERS,
        }
    }
}

/// The recursor's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursionConfig {
    /// Path of the `named.root`-style root-hints file.
    pub root_hints: PathBuf,
    /// Denial-of-service bounds per client question.
    pub limits: DescentLimits,
    /// Per-query UDP timeout.
    pub udp_timeout: Duration,
    /// Per-query TCP timeout.
    pub tcp_timeout: Duration,
    /// Whether to query nameservers over IPv6. Off on a box with no IPv6 path, so
    /// AAAA glue is not tried at all rather than failing one timeout at a time.
    pub use_ipv6: bool,
    /// Bounds on the infrastructure cache.
    pub capacity: InfraCapacity,
}

#[derive(Debug, Deserialize)]
struct RawFile {
    recursion: Option<RawRecursion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecursion {
    root_hints: PathBuf,
    max_depth: Option<u8>,
    max_outbound_queries: Option<u16>,
    max_cname_chain: Option<u8>,
    wall_clock_ms: Option<u64>,
    udp_timeout_ms: Option<u64>,
    tcp_timeout_ms: Option<u64>,
    use_ipv6: Option<bool>,
    max_delegations: Option<usize>,
    max_servers: Option<usize>,
}

impl RecursionConfig {
    /// Reads the `[recursion]` section of a whole styx TOML file. `None` when the
    /// file has no such section, so no recursor is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Toml`] for malformed TOML or an unknown key, and
    /// [`ConfigError::ZeroLimit`] for a zero limit.
    pub fn from_toml_str(content: &str) -> Result<Option<Self>, ConfigError> {
        let file: RawFile =
            toml::from_str(content).map_err(|error| ConfigError::Toml(error.to_string()))?;
        let Some(raw) = file.recursion else {
            return Ok(None);
        };
        let millis =
            |value: Option<u64>, default: Duration| value.map_or(default, Duration::from_millis);
        let limits = DescentLimits::new(
            raw.max_depth.unwrap_or(DEFAULT_MAX_DEPTH),
            raw.max_outbound_queries
                .unwrap_or(DEFAULT_MAX_OUTBOUND_QUERIES),
            raw.max_cname_chain.unwrap_or(DEFAULT_MAX_CNAME_CHAIN),
            millis(raw.wall_clock_ms, DEFAULT_WALL_CLOCK),
        )?;
        Ok(Some(Self {
            root_hints: raw.root_hints,
            limits,
            udp_timeout: millis(raw.udp_timeout_ms, DEFAULT_UDP_TIMEOUT),
            tcp_timeout: millis(raw.tcp_timeout_ms, DEFAULT_TCP_TIMEOUT),
            use_ipv6: raw.use_ipv6.unwrap_or(true),
            capacity: InfraCapacity {
                max_delegations: raw.max_delegations.unwrap_or(DEFAULT_MAX_DELEGATIONS),
                max_servers: raw.max_servers.unwrap_or(DEFAULT_MAX_SERVERS),
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_section_is_optional_and_defaults_fill_the_gaps() {
        assert_eq!(
            RecursionConfig::from_toml_str("listen_addrs = []"),
            Ok(None)
        );
        let config =
            RecursionConfig::from_toml_str("[recursion]\nroot_hints = \"/etc/named.root\"\n")
                .unwrap()
                .unwrap();
        assert_eq!(config.limits, DescentLimits::default());
        assert!(config.use_ipv6);
    }

    #[test]
    fn zero_limits_and_unknown_keys_are_rejected() {
        let zero = "[recursion]\nroot_hints = \"x\"\nmax_depth = 0\n";
        assert_eq!(
            RecursionConfig::from_toml_str(zero),
            Err(ConfigError::ZeroLimit("max_depth"))
        );
        let typo = "[recursion]\nroot_hints = \"x\"\nmax_dept = 3\n";
        assert!(matches!(
            RecursionConfig::from_toml_str(typo),
            Err(ConfigError::Toml(_))
        ));
    }
}
