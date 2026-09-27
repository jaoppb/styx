//! Selection strategy port and candidate view projections.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::domain::circuit::CircuitState;
use crate::domain::upstream::{UpstreamId, UpstreamKind};
use crate::domain::weight::Weight;

/// Identifies the configured upstream selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyName {
    /// Try available upstreams in configured order.
    OrderedFailover,
    /// Round-robin across available upstreams.
    RoundRobin,
    /// Send query concurrently to all available upstreams.
    Race,
    /// Draw candidate upstream proportionally to its assigned weight.
    Weighted,
}

/// A read-only projection of a pool member presented to selection strategies.
///
/// Strategies observe only this sanitized projection and cannot mutate health
/// or access raw transport sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberView {
    /// Upstream identifier.
    pub id: UpstreamId,
    /// Architectural kind (forwarder or recursor).
    pub kind: UpstreamKind,
    /// Relative assigned weight.
    pub weight: Weight,
    /// Smoothed round-trip time EWMA, if observed.
    pub srtt: Option<Duration>,
    /// Current circuit breaker state.
    pub circuit: CircuitState,
    /// Whether the member is currently available to serve traffic.
    pub available: bool,
}

/// The decision produced by a selection strategy for a query dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Try the given upstream IDs in sequential order with fallback.
    Sequential(Vec<UpstreamId>),
    /// Fan out the query concurrently across all listed upstream IDs.
    Fanout(Vec<UpstreamId>),
    /// No upstream is currently available to service the query.
    NoneAvailable,
}

/// Pure port defining how candidates are selected for a query dispatch.
///
/// # Invariants
/// - Synchronous, pure function with no I/O.
/// - Does not mutate health or access upstreams directly.
pub trait SelectionStrategy: Send + Sync {
    /// Returns the strategy's identifying name.
    fn name(&self) -> StrategyName;

    /// Chooses one or more candidate upstreams to answer a query.
    fn select(&self, candidates: &[MemberView], now: Instant) -> Selection;
}
