//! Static strategy dispatch wrapping the four concrete selection strategies.

use std::time::Instant;

use crate::application::strategies::{OrderedFailover, RaceAll, RoundRobin, Weighted};
use crate::domain::selection::{MemberView, Selection, SelectionStrategy, StrategyName};

/// Selection strategy enum dispatching statically across all four strategies.
#[derive(Debug)]
pub enum ConfiguredStrategy {
    /// Try available upstreams in configured order.
    OrderedFailover(OrderedFailover),
    /// Round-robin across available upstreams.
    RoundRobin(RoundRobin),
    /// Send query concurrently to all available upstreams.
    Race(RaceAll),
    /// Draw candidate upstream proportionally to its assigned weight.
    Weighted(Weighted),
}

impl ConfiguredStrategy {
    /// Constructs a `ConfiguredStrategy` from a [`StrategyName`].
    #[must_use]
    pub fn from_name(name: StrategyName) -> Self {
        match name {
            StrategyName::OrderedFailover => Self::OrderedFailover(OrderedFailover::new()),
            StrategyName::RoundRobin => Self::RoundRobin(RoundRobin::new()),
            StrategyName::Race => Self::Race(RaceAll::new()),
            StrategyName::Weighted => Self::Weighted(Weighted::new()),
        }
    }
}

impl SelectionStrategy for ConfiguredStrategy {
    fn name(&self) -> StrategyName {
        match self {
            Self::OrderedFailover(s) => s.name(),
            Self::RoundRobin(s) => s.name(),
            Self::Race(s) => s.name(),
            Self::Weighted(s) => s.name(),
        }
    }

    fn select(&self, candidates: &[MemberView], now: Instant) -> Selection {
        match self {
            Self::OrderedFailover(s) => s.select(candidates, now),
            Self::RoundRobin(s) => s.select(candidates, now),
            Self::Race(s) => s.select(candidates, now),
            Self::Weighted(s) => s.select(candidates, now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_name_names() {
        assert_eq!(
            ConfiguredStrategy::from_name(StrategyName::OrderedFailover).name(),
            StrategyName::OrderedFailover
        );
        assert_eq!(
            ConfiguredStrategy::from_name(StrategyName::RoundRobin).name(),
            StrategyName::RoundRobin
        );
        assert_eq!(
            ConfiguredStrategy::from_name(StrategyName::Race).name(),
            StrategyName::Race
        );
        assert_eq!(
            ConfiguredStrategy::from_name(StrategyName::Weighted).name(),
            StrategyName::Weighted
        );
    }
}
