//! Race-all upstream selection strategy.
//!
//! # Privacy Warning
//! Race dispatch is a privacy hazard, not merely a performance optimization.
//! Every query is broadcast concurrently to every available upstream in the pool,
//! multiplying outbound queries and revealing all lookup traffic to multiple
//! third-party DNS providers simultaneously.

use std::time::Instant;

use crate::domain::selection::{MemberView, Selection, SelectionStrategy, StrategyName};

/// Selects all available upstreams concurrently via fan-out race.
#[derive(Debug, Clone, Copy, Default)]
pub struct RaceAll;

impl RaceAll {
    /// Creates a new `RaceAll` strategy.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SelectionStrategy for RaceAll {
    fn name(&self) -> StrategyName {
        StrategyName::Race
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
            Selection::Fanout(available_ids)
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
            circuit: CircuitState::Closed,
            available,
        }
    }

    #[test]
    fn test_race_all_fans_out_to_all_available() {
        let strat = RaceAll::new();
        let now = Instant::now();
        let candidates = vec![
            make_view("up1", true),
            make_view("up2", false),
            make_view("up3", true),
        ];

        let sel = strat.select(&candidates, now);
        assert_eq!(
            sel,
            Selection::Fanout(vec![UpstreamId::new("up1"), UpstreamId::new("up3")])
        );

        let none_avail = vec![make_view("up1", false)];
        assert_eq!(strat.select(&none_avail, now), Selection::NoneAvailable);
    }
}
