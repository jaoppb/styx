//! Ordered failover selection strategy.
//!
//! Tries upstreams sequentially in their configured definition order,
//! falling back to secondary providers only when primary members are down.

use std::time::Instant;

use crate::domain::selection::{MemberView, Selection, SelectionStrategy, StrategyName};

/// Selects candidate upstreams in strictly configured order.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrderedFailover;

impl OrderedFailover {
    /// Creates a new `OrderedFailover` strategy.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SelectionStrategy for OrderedFailover {
    fn name(&self) -> StrategyName {
        StrategyName::OrderedFailover
    }

    fn select(&self, candidates: &[MemberView], _now: Instant) -> Selection {
        let available_ids: Vec<_> = candidates
            .iter()
            .filter(|m| m.available)
            .map(|m| m.id.clone())
            .collect();

        if available_ids.is_empty() {
            Selection::NoneAvailable
        } else {
            Selection::Sequential(available_ids)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::domain::circuit::CircuitState;
    use crate::domain::weight::Weight;
    use styx_core::{UpstreamId, UpstreamKind};

    fn make_view(id: &str, available: bool) -> MemberView {
        MemberView {
            id: UpstreamId::new(id),
            kind: UpstreamKind::Forwarder,
            weight: Weight::new(1),
            srtt: Some(Duration::from_millis(10)),
            circuit: if available {
                CircuitState::Closed
            } else {
                CircuitState::Open {
                    since: Instant::now(),
                }
            },
            available,
        }
    }

    #[test]
    fn test_ordered_failover() {
        let strat = OrderedFailover::new();
        let now = Instant::now();

        // All available
        let list = vec![make_view("up1", true), make_view("up2", true)];
        assert_eq!(
            strat.select(&list, now),
            Selection::Sequential(vec![UpstreamId::new("up1"), UpstreamId::new("up2")])
        );

        // Primary down
        let list = vec![make_view("up1", false), make_view("up2", true)];
        assert_eq!(
            strat.select(&list, now),
            Selection::Sequential(vec![UpstreamId::new("up2")])
        );

        // All down
        let list = vec![make_view("up1", false), make_view("up2", false)];
        assert_eq!(strat.select(&list, now), Selection::NoneAvailable);
    }
}
