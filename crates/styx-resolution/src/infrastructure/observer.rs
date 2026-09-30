//! No-op implementation of [`QueryObserver`].

use styx_proto::Question;

use crate::domain::answer::ResolutionOutcome;
use crate::domain::ports::observer::{QueryDetail, QueryObserver};
use crate::domain::request::ClientId;

/// No-op query observer that discards all telemetry and metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardObserver;

impl DiscardObserver {
    /// Creates a new `DiscardObserver`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl QueryObserver for DiscardObserver {
    fn record_outcome(
        &self,
        _client: &ClientId,
        _question: &Question,
        _outcome: &ResolutionOutcome,
    ) {
    }

    fn offer_detail(&self, _detail: QueryDetail) {}

    fn dropped_detail(&self) -> u64 {
        0
    }

    fn wants_detail(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discard_observer_does_not_want_detail() {
        let observer = DiscardObserver::new();
        assert!(!observer.wants_detail());
        assert_eq!(observer.dropped_detail(), 0);
    }
}
