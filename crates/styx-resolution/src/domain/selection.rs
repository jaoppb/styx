//! Selection strategy port and candidate view projections.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use styx_core::{UpstreamId, UpstreamKind};

use crate::domain::circuit::CircuitState;
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

/// Rotates candidate upstream views starting at offset `start` (wrapping around).
///
/// Returns an ordered list of [`UpstreamId`]s beginning from `start` (modulo `available.len()`)
/// through the end of `available`, followed by the elements preceding `start`.
#[must_use]
pub fn rotate(available: &[&MemberView], start: usize) -> Vec<UpstreamId> {
    let total = available.len();
    if total == 0 {
        return Vec::new();
    }
    let start = start.checked_rem(total).unwrap_or(0);
    let mut rotated = Vec::with_capacity(total);
    if let Some(slice_end) = available.get(start..) {
        for m in slice_end {
            rotated.push(m.id.clone());
        }
    }
    if let Some(slice_start) = available.get(..start) {
        for m in slice_start {
            rotated.push(m.id.clone());
        }
    }
    rotated
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_member(id: &str) -> MemberView {
        MemberView {
            id: UpstreamId::new(id),
            kind: UpstreamKind::Forwarder,
            weight: Weight::new(1),
            srtt: None,
            circuit: CircuitState::Closed,
            available: true,
        }
    }

    #[test]
    fn test_rotate_empty() {
        let rotated = rotate(&[], 0);
        assert!(rotated.is_empty());
    }

    #[test]
    fn test_rotate_wraps_and_orders() {
        let m1 = test_member("u1");
        let m2 = test_member("u2");
        let m3 = test_member("u3");
        let available = [&m1, &m2, &m3];

        let r0 = rotate(&available, 0);
        assert_eq!(
            r0,
            vec![
                UpstreamId::new("u1"),
                UpstreamId::new("u2"),
                UpstreamId::new("u3")
            ]
        );

        let r1 = rotate(&available, 1);
        assert_eq!(
            r1,
            vec![
                UpstreamId::new("u2"),
                UpstreamId::new("u3"),
                UpstreamId::new("u1")
            ]
        );

        let r2 = rotate(&available, 2);
        assert_eq!(
            r2,
            vec![
                UpstreamId::new("u3"),
                UpstreamId::new("u1"),
                UpstreamId::new("u2")
            ]
        );

        let r3 = rotate(&available, 4);
        assert_eq!(
            r3,
            vec![
                UpstreamId::new("u2"),
                UpstreamId::new("u3"),
                UpstreamId::new("u1")
            ]
        );
    }
}
