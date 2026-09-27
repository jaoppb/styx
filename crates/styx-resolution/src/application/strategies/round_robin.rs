//! Round-robin upstream selection strategy.
//!
//! Cycles evenly through available upstream members using an atomic cursor,
//! rotating candidate order so subsequent candidates serve as sequential fallbacks.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::domain::selection::{MemberView, Selection, SelectionStrategy, StrategyName};

/// Selects candidate upstreams rotating sequentially via an atomic cursor.
#[derive(Debug, Default)]
pub struct RoundRobin {
    cursor: AtomicUsize,
}

impl RoundRobin {
    /// Creates a new `RoundRobin` strategy starting at cursor 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cursor: AtomicUsize::new(0),
        }
    }
}

impl SelectionStrategy for RoundRobin {
    fn name(&self) -> StrategyName {
        StrategyName::RoundRobin
    }

    fn select(&self, candidates: &[MemberView], _now: Instant) -> Selection {
        let available: Vec<_> = candidates.iter().filter(|m| m.available).collect();
        let total = available.len();

        if total == 0 {
            return Selection::NoneAvailable;
        }

        let idx = self.cursor.fetch_add(1, Ordering::Relaxed);
        let start = idx.checked_rem(total).unwrap_or(0);

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

        Selection::Sequential(rotated)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::domain::circuit::CircuitState;
    use crate::domain::upstream::{UpstreamId, UpstreamKind};
    use crate::domain::weight::Weight;

    fn make_view(id: &str, available: bool) -> MemberView {
        MemberView {
            id: UpstreamId::new(id),
            kind: UpstreamKind::Forwarder,
            weight: Weight::new(1),
            srtt: Some(Duration::from_millis(10)),
            circuit: CircuitState::Closed,
            available,
        }
    }

    #[test]
    fn test_round_robin_rotation() {
        let strat = RoundRobin::new();
        let now = Instant::now();
        let candidates = vec![
            make_view("up1", true),
            make_view("up2", true),
            make_view("up3", true),
        ];

        let sel1 = strat.select(&candidates, now);
        let sel2 = strat.select(&candidates, now);
        let sel3 = strat.select(&candidates, now);

        assert_eq!(
            sel1,
            Selection::Sequential(vec![
                UpstreamId::new("up1"),
                UpstreamId::new("up2"),
                UpstreamId::new("up3")
            ])
        );
        assert_eq!(
            sel2,
            Selection::Sequential(vec![
                UpstreamId::new("up2"),
                UpstreamId::new("up3"),
                UpstreamId::new("up1")
            ])
        );
        assert_eq!(
            sel3,
            Selection::Sequential(vec![
                UpstreamId::new("up3"),
                UpstreamId::new("up1"),
                UpstreamId::new("up2")
            ])
        );
    }
}
