//! The state machine behind a rate-limited warning that counts what it suppressed.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::infrastructure::admission::WARN_INTERVAL;

/// What a caller does with one occurrence of the warned-about event.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Log now, reporting how many occurrences were suppressed since the previous line.
    Emit { suppressed: u64 },
    /// Do not log. `flush` is `Some` for the first suppression of an interval, which must
    /// arrange to report the count once the interval closes.
    Suppressed { flush: Option<FlushPlan> },
}

/// When, and on behalf of which interval, a suppressed count is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlushPlan {
    epoch: Instant,
    after: Duration,
}

impl FlushPlan {
    /// How long to wait before calling [`WarnGate::flush`].
    pub(crate) const fn after(&self) -> Duration {
        self.after
    }

    /// The interval this plan reports, to be handed back to [`WarnGate::flush`].
    pub(crate) const fn epoch(&self) -> Instant {
        self.epoch
    }
}

#[derive(Debug, Default)]
struct GateState {
    last_emitted: Option<Instant>,
    suppressed: u64,
    flush_planned: bool,
}

/// Lets one line through per [`WARN_INTERVAL`] and counts the occurrences it held back.
///
/// An interval opens when a line is emitted. Occurrences inside it are only counted; the
/// first of them yields a [`FlushPlan`] so that the count is reported when the interval
/// closes even if no further occurrence ever arrives. A line emitted by a later occurrence
/// first takes the count itself, which supersedes the plan.
#[derive(Debug, Default)]
pub(crate) struct WarnGate {
    state: Mutex<GateState>,
}

impl WarnGate {
    /// Records one occurrence at `now`.
    pub(crate) fn record(&self, now: Instant) -> Verdict {
        let Ok(mut state) = self.state.lock() else {
            return Verdict::Suppressed { flush: None };
        };
        let elapsed = state
            .last_emitted
            .map(|previous| now.saturating_duration_since(previous));
        let Some(since_last) = elapsed.filter(|since| *since < WARN_INTERVAL) else {
            state.last_emitted = Some(now);
            state.flush_planned = false;
            return Verdict::Emit {
                suppressed: std::mem::take(&mut state.suppressed),
            };
        };
        state.suppressed = state.suppressed.saturating_add(1);
        let flush = Self::plan_flush(&mut state, since_last);
        Verdict::Suppressed { flush }
    }

    fn plan_flush(state: &mut GateState, since_last: Duration) -> Option<FlushPlan> {
        if state.flush_planned {
            return None;
        }
        let epoch = state.last_emitted?;
        state.flush_planned = true;
        Some(FlushPlan {
            epoch,
            after: WARN_INTERVAL.saturating_sub(since_last),
        })
    }

    /// Takes the count for the interval `epoch` opened, now that it has closed at `now`.
    ///
    /// Returns `None` when a later line already reported it, or when nothing was suppressed.
    /// Otherwise the report is itself a line, so it opens the next interval.
    pub(crate) fn flush(&self, epoch: Instant, now: Instant) -> Option<u64> {
        let mut state = self.state.lock().ok()?;
        if state.last_emitted != Some(epoch) {
            return None;
        }
        state.flush_planned = false;
        if state.suppressed == 0 {
            return None;
        }
        state.last_emitted = Some(now);
        Some(std::mem::take(&mut state.suppressed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn after(start: Instant, millis: u64) -> Instant {
        start.checked_add(Duration::from_millis(millis)).unwrap()
    }

    fn plan(verdict: Verdict) -> FlushPlan {
        match verdict {
            Verdict::Suppressed { flush: Some(plan) } => plan,
            other => panic!("expected a first suppression, got {other:?}"),
        }
    }

    #[test]
    fn first_occurrence_emits_with_nothing_suppressed() {
        let gate = WarnGate::default();
        assert_eq!(gate.record(Instant::now()), Verdict::Emit { suppressed: 0 });
    }

    #[test]
    fn only_the_first_suppression_of_an_interval_plans_a_flush() {
        let gate = WarnGate::default();
        let start = Instant::now();
        gate.record(start);

        let first = plan(gate.record(after(start, 100)));
        assert_eq!(first.after(), Duration::from_millis(900));
        assert_eq!(first.epoch(), start);
        assert_eq!(
            gate.record(after(start, 200)),
            Verdict::Suppressed { flush: None }
        );
    }

    #[test]
    fn flush_reports_the_count_and_opens_the_next_interval() {
        let gate = WarnGate::default();
        let start = Instant::now();
        gate.record(start);
        let flush = plan(gate.record(after(start, 100)));
        gate.record(after(start, 200));

        let closed = after(start, 1000);
        assert_eq!(gate.flush(flush.epoch(), closed), Some(2));
        assert_eq!(
            gate.record(after(start, 1100)),
            Verdict::Suppressed {
                flush: Some(FlushPlan {
                    epoch: closed,
                    after: Duration::from_millis(900),
                })
            }
        );
    }

    #[test]
    fn later_line_takes_the_count_and_supersedes_the_plan() {
        let gate = WarnGate::default();
        let start = Instant::now();
        gate.record(start);
        let stale = plan(gate.record(after(start, 100)));

        assert_eq!(
            gate.record(after(start, 1000)),
            Verdict::Emit { suppressed: 1 }
        );
        assert_eq!(gate.flush(stale.epoch(), after(start, 1000)), None);
    }

    #[test]
    fn superseded_plan_cannot_flush_a_newer_interval() {
        let gate = WarnGate::default();
        let start = Instant::now();
        gate.record(start);
        let stale = plan(gate.record(after(start, 100)));
        gate.record(after(start, 1000));
        let current = plan(gate.record(after(start, 1100)));

        assert_eq!(gate.flush(stale.epoch(), after(start, 1100)), None);
        assert_eq!(gate.flush(current.epoch(), after(start, 2000)), Some(1));
    }

    #[test]
    fn burst_within_one_interval_yields_one_line_and_one_flush() {
        let gate = WarnGate::default();
        let start = Instant::now();
        let mut emitted = 0_u32;
        let mut plans = Vec::new();
        for _ in 0..10_000 {
            match gate.record(after(start, 10)) {
                Verdict::Emit { .. } => emitted += 1,
                Verdict::Suppressed { flush: Some(plan) } => plans.push(plan),
                Verdict::Suppressed { flush: None } => {}
            }
        }
        // The first record at `start + 10ms` opens the interval, so 9 999 are suppressed.
        assert_eq!(emitted, 1);
        assert_eq!(plans.len(), 1);
        let flushed = plans
            .first()
            .and_then(|p| gate.flush(p.epoch(), after(start, 1010)));
        assert_eq!(flushed, Some(9_999));
    }
}
