//! The recursion crate's error types.

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
}
