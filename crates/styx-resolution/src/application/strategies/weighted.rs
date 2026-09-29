//! Weighted upstream selection strategy.
//!
//! Draws an upstream candidate proportionally to its configured relative weight,
//! returning the selected winner first with the remaining available members
//! serving as sequential fallbacks.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use crate::domain::selection::{MemberView, Selection, SelectionStrategy, StrategyName};
use crate::domain::weight::Weight;

/// Selects candidate upstreams weighted by their configured relative weight.
#[derive(Debug, Default)]
pub struct Weighted {
    draw_counter: AtomicU64,
    rr_fallback_cursor: AtomicUsize,
}

impl Weighted {
    /// Creates a new `Weighted` strategy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            draw_counter: AtomicU64::new(0),
            rr_fallback_cursor: AtomicUsize::new(0),
        }
    }

    fn select_round_robin(&self, available: &[&MemberView]) -> Selection {
        let total = available.len();
        if total == 0 {
            return Selection::NoneAvailable;
        }

        let idx = self.rr_fallback_cursor.fetch_add(1, Ordering::Relaxed);
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

impl SelectionStrategy for Weighted {
    fn name(&self) -> StrategyName {
        StrategyName::Weighted
    }

    fn select(&self, candidates: &[MemberView], _now: Instant) -> Selection {
        let available: Vec<_> = candidates.iter().filter(|m| m.available).collect();
        if available.is_empty() {
            return Selection::NoneAvailable;
        }
        if available.len() == 1 {
            if let Some(first) = available.first() {
                return Selection::Sequential(vec![first.id.clone()]);
            }
        }

        let weights: Vec<Weight> = available.iter().map(|m| m.weight).collect();
        let total_weight = Weight::checked_sum(&weights).unwrap_or_else(|| Weight::new(0));

        if total_weight.value() == 0 {
            return self.select_round_robin(&available);
        }

        let draw_idx = self.draw_counter.fetch_add(1, Ordering::Relaxed);
        let draw_target = draw_idx
            .checked_rem(u64::from(total_weight.value()))
            .unwrap_or(0);

        let mut cumulative: u64 = 0;
        let mut winner_idx = 0;

        for (idx, member) in available.iter().enumerate() {
            cumulative = cumulative.saturating_add(u64::from(member.weight.value()));
            if cumulative > draw_target {
                winner_idx = idx;
                break;
            }
        }

        let mut ordered = Vec::with_capacity(available.len());
        if let Some(winner) = available.get(winner_idx) {
            ordered.push(winner.id.clone());
        }

        for (idx, member) in available.iter().enumerate() {
            if idx != winner_idx {
                ordered.push(member.id.clone());
            }
        }

        Selection::Sequential(ordered)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::domain::circuit::CircuitState;
    use styx_core::{UpstreamId, UpstreamKind};

    fn make_weighted_view(id: &str, weight: u32, available: bool) -> MemberView {
        MemberView {
            id: UpstreamId::new(id),
            kind: UpstreamKind::Forwarder,
            weight: Weight::new(weight),
            srtt: Some(Duration::from_millis(10)),
            circuit: CircuitState::Closed,
            available,
        }
    }

    #[test]
    fn test_weighted_degenerate_zero_weight_falls_back_to_round_robin() {
        let strat = Weighted::new();
        let now = Instant::now();
        let candidates = vec![
            make_weighted_view("up1", 0, true),
            make_weighted_view("up2", 0, true),
        ];

        let sel1 = strat.select(&candidates, now);
        let sel2 = strat.select(&candidates, now);
        assert_eq!(
            sel1,
            Selection::Sequential(vec![UpstreamId::new("up1"), UpstreamId::new("up2")])
        );
        assert_eq!(
            sel2,
            Selection::Sequential(vec![UpstreamId::new("up2"), UpstreamId::new("up1")])
        );
    }

    #[test]
    fn test_weighted_proportional_distribution() {
        let strat = Weighted::new();
        let now = Instant::now();
        let candidates = vec![
            make_weighted_view("heavy", 3, true),
            make_weighted_view("light", 1, true),
        ];

        let mut heavy_count = 0;
        let mut light_count = 0;

        for _ in 0..40 {
            let Selection::Sequential(ids) = strat.select(&candidates, now) else {
                continue;
            };
            match ids.first() {
                Some(id) if id == &UpstreamId::new("heavy") => heavy_count += 1,
                Some(id) if id == &UpstreamId::new("light") => light_count += 1,
                _ => {}
            }
        }

        assert_eq!(heavy_count, 30);
        assert_eq!(light_count, 10);
    }
}
