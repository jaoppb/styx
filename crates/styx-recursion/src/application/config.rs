//! The `[recursion]` section of the TOML file.
//!
//! The section holds the defaults every recursor member shares; a member's
//! `[recursion.members.<name>]` table overrides any of them, key by key. A member that
//! names its own `root_hints` needs no shared section at all.
//!
//! The file owns infrastructure: root hints, budgets and timeouts are needed before
//! any database exists, so they live here and nowhere else. Changing them means
//! editing the file and restarting.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use toml::{Table, Value};

use crate::application::recursor::RecursorSettings;
use crate::domain::budget::DescentLimits;
use crate::domain::error::ConfigError;
use raw::RawSettings;

mod raw;

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

/// One recursor member's settings, merged and validated.
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
    recursion: Option<Table>,
}

/// The `[recursion]` section as written: shared defaults and, per recursor member, the
/// keys its `[recursion.members.<name>]` table overrides. Nothing is merged until
/// [`Self::for_member`] asks for one member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecursionSection {
    defaults: RawSettings,
    overrides: BTreeMap<String, RawSettings>,
}

impl RecursionSection {
    /// Reads the `[recursion]` section of a whole styx TOML file. A file without one
    /// yields an empty section: no defaults and no overrides.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Toml`] for malformed TOML or an unknown key in the shared
    /// defaults, [`ConfigError::ZeroLimit`] for a zero limit there, and
    /// [`ConfigError::Member`] for an unknown key in a member's overrides.
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        let file: RawFile = toml::from_str(content).map_err(toml_error)?;
        let Some(mut table) = file.recursion else {
            return Ok(Self::default());
        };
        let members = match table.remove("members") {
            None => Table::new(),
            Some(Value::Table(members)) => members,
            Some(_) => {
                return Err(ConfigError::Toml(
                    "`members` must be a table of per-member overrides".to_owned(),
                ))
            }
        };
        let defaults: RawSettings = table.try_into().map_err(toml_error)?;
        defaults.limits()?;
        let overrides = members
            .into_iter()
            .map(|(member, value)| {
                let raw = value
                    .try_into()
                    .map_err(|error| ConfigError::member(&member, toml_error(error)))?;
                Ok((member, raw))
            })
            .collect::<Result<_, ConfigError>>()?;
        Ok(Self {
            defaults,
            overrides,
        })
    }

    /// The settings of the recursor member named `member`: its overrides, then the
    /// shared defaults, then the built-in defaults, key by key.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Member`] naming `member` when the merged settings name no
    /// root hints, hold a zero limit, or give a wall clock that does not end before
    /// `query_timeout`.
    pub fn for_member(
        &self,
        member: &str,
        query_timeout: Duration,
    ) -> Result<RecursionConfig, ConfigError> {
        let raw = self
            .overrides
            .get(member)
            .map_or_else(|| self.defaults.clone(), |own| own.over(&self.defaults));
        raw.resolve()
            .and_then(|config| config.check_deadline(query_timeout).map(|()| config))
            .map_err(|reason| ConfigError::member(member, reason))
    }

    /// Checks that every `[recursion.members.<name>]` table names one of `recursors`,
    /// so an override for a misspelt or non-recursor member cannot be silently unused.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::UnknownMember`] with the first name that is not a recursor.
    pub fn check_overrides(&self, recursors: &[&str]) -> Result<(), ConfigError> {
        match self
            .overrides
            .keys()
            .find(|name| !recursors.contains(&name.as_str()))
        {
            Some(name) => Err(ConfigError::UnknownMember(name.clone())),
            None => Ok(()),
        }
    }
}

impl RecursionConfig {
    /// The behaviour settings a [`crate::application::recursor::Recursor`] takes.
    #[must_use]
    pub const fn settings(&self) -> RecursorSettings {
        RecursorSettings {
            limits: self.limits,
            use_ipv6: self.use_ipv6,
        }
    }

    /// A descent that may outlast the whole-query deadline is cut off by it instead of
    /// failing on its own budget, so `wall_clock_ms` must end first.
    fn check_deadline(&self, query_timeout: Duration) -> Result<(), ConfigError> {
        let wall_clock = self.limits.wall_clock();
        if wall_clock < query_timeout {
            return Ok(());
        }
        Err(ConfigError::WallClockOutlastsDeadline {
            wall_clock,
            query_timeout,
        })
    }
}

fn toml_error(error: impl ToString) -> ConfigError {
    ConfigError::Toml(error.to_string())
}

#[cfg(test)]
mod schema_keys;

#[cfg(test)]
mod tests;
