//! The recursion crate's error types.

use std::time::Duration;

use styx_core::format_toml_key;
use thiserror::Error;

/// Which denial-of-service bound a descent ran into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetExceeded {
    /// Too many zone cuts descended, counting glue-resolving sub-descents.
    Depth,
    /// Too many outbound queries, counting glue-resolving sub-descents.
    OutboundQueries,
    /// Too many CNAME or DNAME links followed.
    CnameChain,
    /// The descent ran past its wall-clock limit.
    WallClock,
}

impl BudgetExceeded {
    /// Whether the bound belongs to one descent alone. A CNAME chain is followed
    /// by one descent, so a glue sub-descent that overruns it has failed to resolve
    /// that one name and nothing more. Depth, queries and time are spent from one
    /// budget shared with the parent, which has no allowance left either.
    #[must_use]
    pub const fn is_local_to_descent(self) -> bool {
        matches!(self, Self::CnameChain)
    }
}

/// Why a descent failed.
///
/// Converted to `UpstreamError` at the `Upstream` boundary and never seen beyond it.
/// Messages name the failure class, never a client, a zone or a server address:
/// those travel in `tracing` fields.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecursionError {
    /// Every candidate nameserver for a zone failed, was lame, or had no address.
    #[error("no reachable nameserver")]
    NoReachableNameserver {
        /// Whether the zone was the root: then the fault is this box's reach to the
        /// internet, not one domain's servers.
        at_root: bool,
    },
    /// A denial-of-service bound was hit.
    #[error("descent budget exceeded: {0:?}")]
    BudgetExceeded(BudgetExceeded),
    /// A CNAME or DNAME chain revisited a name.
    #[error("alias chain loops")]
    CnameLoop,
    /// A referral pointed at the zone being asked or above it.
    #[error("referral does not descend")]
    DelegationLoop,
    /// A server answered for a name it is not entitled to speak for.
    #[error("response out of bailiwick")]
    OutOfBailiwick,
    /// Every server of a delegation answered without authority.
    #[error("lame delegation")]
    LameDelegation,
    /// A response stayed truncated over TCP.
    #[error("response truncated over tcp")]
    Truncated,
    /// A response could not be used: undecodable, mismatched, or structurally wrong.
    #[error("malformed response")]
    Malformed,
    /// The caller's deadline passed.
    #[error("descent timed out")]
    Timeout,
}

/// Invalid recursion configuration, rejected at startup.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// A descent limit was zero, which would make every descent fail at once.
    #[error("descent limit `{0}` must be greater than zero")]
    ZeroLimit(&'static str),
    /// The root-hints file could not be read.
    #[error("root hints could not be read: {0}")]
    RootHintsUnreadable(String),
    /// The root-hints file contained a line that is not a root NS or address record.
    #[error("root hints line {line}: {reason}")]
    RootHintsInvalid {
        /// One-based line number.
        line: usize,
        /// What was wrong with it.
        reason: String,
    },
    /// The root hints named no root server with an address.
    #[error("root hints name no root server with an address")]
    RootHintsEmpty,
    /// The `[recursion]` TOML section did not parse.
    #[error("invalid [recursion] configuration: {0}")]
    Toml(String),
    /// A `[recursion.members.<name>]` table names no recursor member of the pool.
    #[error("{} names no recursor member of the pool", format_recursion_member_table(.0))]
    UnknownMember(String),
    /// A recursor member's longest per-exchange timeout does not fit inside the
    /// whole-query deadline. `wall_clock_ms` is not compared here (#146).
    #[error(
        "query_timeout ({}ms) must exceed recursor member `{member}`'s longest per-exchange \
         timeout ({}ms; only udp_timeout_ms and tcp_timeout_ms are checked, not \
         wall_clock_ms); raise query_timeout_secs or lower udp_timeout_ms / tcp_timeout_ms \
         under [recursion] or {}",
        .query_timeout.as_millis(),
        .timeout.as_millis(),
        format_recursion_member_table(.member)
    )]
    ExchangeTimeoutOutlastsDeadline {
        /// The pool member's name.
        member: String,
        /// The longer of its merged UDP and TCP timeouts.
        timeout: Duration,
        /// The server's whole-query deadline.
        query_timeout: Duration,
    },
    /// One recursor member's settings are invalid.
    #[error("recursor member `{member}`: {reason}")]
    Member {
        /// The pool member's name.
        member: String,
        /// What is wrong with its settings.
        reason: MemberConfigError,
    },
}

/// What can go wrong when parsing or resolving one recursor member's settings.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemberConfigError {
    /// An override table did not parse or named an unknown key.
    #[error("invalid configuration: {0}")]
    Toml(String),
    /// A descent limit was zero after merging.
    #[error("descent limit `{0}` must be greater than zero")]
    ZeroLimit(&'static str),
    /// Neither the member's overrides nor the shared `[recursion]` section name a
    /// root-hints file.
    #[error("no root_hints in [recursion] or in the member's overrides")]
    MissingRootHints,
}

impl ConfigError {
    /// Attributes `reason` to the recursor member named `member`.
    #[must_use]
    pub fn member(member: &str, reason: MemberConfigError) -> Self {
        Self::Member {
            member: member.to_owned(),
            reason,
        }
    }
}

/// Formats `[recursion.members.<name>]` as a valid TOML table header, quoting `member`
/// whenever it is not a TOML bare key.
fn format_recursion_member_table(member: &str) -> String {
    format!("[recursion.members.{}]", format_toml_key(member))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_cname_chain_bound_belongs_to_one_descent() {
        assert!(BudgetExceeded::CnameChain.is_local_to_descent());
        for shared in [
            BudgetExceeded::Depth,
            BudgetExceeded::OutboundQueries,
            BudgetExceeded::WallClock,
        ] {
            assert!(!shared.is_local_to_descent());
        }
    }

    #[test]
    fn unknown_member_quotes_non_bare_toml_keys() {
        assert_eq!(
            ConfigError::UnknownMember("recursor-v4".to_owned()).to_string(),
            "[recursion.members.recursor-v4] names no recursor member of the pool"
        );
        assert_eq!(
            ConfigError::UnknownMember("rec.v4".to_owned()).to_string(),
            r#"[recursion.members."rec.v4"] names no recursor member of the pool"#
        );
    }
}
