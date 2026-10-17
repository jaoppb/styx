//! Admission of queries and probes against a member's circuit, and the half-open trial slot.

use std::time::Instant;

use crate::domain::circuit::{CircuitConfig, CircuitState, TrialId};
use crate::domain::health::HealthState;

/// What an admitted query or probe is allowed to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitAdmission {
    /// The circuit is closed: any number of queries may run and none holds a slot.
    Regular,
    /// The single half-open trial. It holds the slot until it records an outcome or
    /// is released with [`HealthState::release_trial`].
    Trial(TrialId),
}

impl HealthState {
    /// Attempts to admit a query for dispatch, taking the half-open trial slot if it is free.
    pub fn try_admit(&mut self, now: Instant, config: &CircuitConfig) -> Option<CircuitAdmission> {
        match self.circuit {
            CircuitState::Closed => Some(CircuitAdmission::Regular),
            CircuitState::HalfOpen { trial: Some(_) } => None,
            CircuitState::HalfOpen { trial: None } => Some(self.begin_trial(None)),
            CircuitState::Open { since } => {
                let elapsed = now.checked_duration_since(since).unwrap_or_default();
                (elapsed >= config.open_cooldown).then(|| self.begin_trial(None))
            }
        }
    }

    /// Attempts to admit a background health probe, taking the trial slot even before the cool-down.
    pub fn try_admit_probe(&mut self) -> Option<CircuitAdmission> {
        match self.circuit {
            CircuitState::Closed => Some(CircuitAdmission::Regular),
            CircuitState::HalfOpen { trial: Some(_) } => None,
            CircuitState::HalfOpen { trial: None } => Some(self.begin_trial(None)),
            CircuitState::Open { since } => Some(self.begin_trial(Some(since))),
        }
    }

    /// Gives the trial slot back without observing an outcome.
    ///
    /// For a trial that was cancelled before it reported: it says nothing about the
    /// upstream, so no failure is counted and no latency is sampled. Does nothing unless
    /// `trial` still holds the slot, so a trial that already recorded an outcome, or whose
    /// slot has since passed to a newer trial, is left alone.
    ///
    /// A probe that took the slot from `Open` puts the circuit back to that `Open`, so
    /// the cool-down it skipped is still owed rather than lost.
    pub fn release_trial(&mut self, trial: TrialId) {
        if self.circuit != (CircuitState::HalfOpen { trial: Some(trial) }) {
            return;
        }
        self.circuit = match self.probe_reopens_to.take() {
            Some(since) => CircuitState::Open { since },
            None => CircuitState::HalfOpen { trial: None },
        };
    }

    fn begin_trial(&mut self, reopens_to: Option<Instant>) -> CircuitAdmission {
        let trial = self.next_trial;
        self.next_trial = trial.next();
        self.probe_reopens_to = reopens_to;
        self.circuit = CircuitState::HalfOpen { trial: Some(trial) };
        CircuitAdmission::Trial(trial)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use styx_core::FailureClass;

    use super::*;
    use crate::domain::health::Outcome;

    fn config() -> CircuitConfig {
        CircuitConfig {
            failure_threshold: 1,
            open_cooldown: Duration::from_secs(5),
            half_open_successes: 1,
        }
    }

    fn fault() -> Outcome {
        Outcome::Failure {
            class: FailureClass::UpstreamFault,
            was_probe: false,
        }
    }

    /// An open member whose cool-down has elapsed at the returned instant.
    fn recovering() -> (HealthState, Instant) {
        let now = Instant::now();
        let mut health = HealthState::new();
        health.observe(fault(), now, &config());
        let later = now.checked_add(Duration::from_secs(6)).expect("advance");
        (health, later)
    }

    fn trial_of(admission: Option<CircuitAdmission>) -> TrialId {
        match admission {
            Some(CircuitAdmission::Trial(trial)) => trial,
            other => panic!("expected a trial, got {other:?}"),
        }
    }

    #[test]
    fn closed_admits_regular_queries_without_a_slot() {
        let mut health = HealthState::new();
        let now = Instant::now();

        assert_eq!(
            health.try_admit(now, &config()),
            Some(CircuitAdmission::Regular)
        );
        assert_eq!(
            health.try_admit(now, &config()),
            Some(CircuitAdmission::Regular)
        );
        assert_eq!(health.try_admit_probe(), Some(CircuitAdmission::Regular));
        assert_eq!(health.circuit(), CircuitState::Closed);
    }

    #[test]
    fn open_before_cooldown_admits_nothing() {
        let (mut health, _) = recovering();
        assert_eq!(health.try_admit(Instant::now(), &config()), None);
    }

    #[test]
    fn a_second_admission_is_refused_while_a_trial_holds_the_slot() {
        let (mut health, later) = recovering();

        let trial = trial_of(health.try_admit(later, &config()));

        assert_eq!(
            health.circuit(),
            CircuitState::HalfOpen { trial: Some(trial) }
        );
        assert!(!health.is_available(later, &config()));
        assert_eq!(health.try_admit(later, &config()), None);
        assert_eq!(health.try_admit_probe(), None);
    }

    #[test]
    fn each_trial_gets_a_distinct_identity() {
        let (mut health, later) = recovering();
        let first = trial_of(health.try_admit(later, &config()));
        health.release_trial(first);

        let second = trial_of(health.try_admit(later, &config()));

        assert_ne!(first, second);
    }

    #[test]
    fn releasing_the_trial_frees_the_slot_without_counting_a_fault() {
        let (mut health, later) = recovering();
        let trial = trial_of(health.try_admit(later, &config()));
        let failures = health.consecutive_failures();
        let srtt = health.srtt();
        let refused = health.refused_replies();

        health.release_trial(trial);

        assert_eq!(health.circuit(), CircuitState::HalfOpen { trial: None });
        assert!(health.is_available(later, &config()));
        assert_eq!(health.consecutive_failures(), failures);
        assert_eq!(health.srtt(), srtt);
        assert_eq!(health.refused_replies(), refused);
    }

    #[test]
    fn a_probe_takes_the_slot_while_the_circuit_is_still_cooling_down() {
        let (mut health, _) = recovering();

        let trial = trial_of(health.try_admit_probe());

        assert_eq!(
            health.circuit(),
            CircuitState::HalfOpen { trial: Some(trial) }
        );
        assert_eq!(health.try_admit_probe(), None);
    }

    #[test]
    fn a_cancelled_probe_puts_an_open_circuit_back_to_open() {
        let (mut health, _) = recovering();
        let open = health.circuit();

        let trial = trial_of(health.try_admit_probe());
        health.release_trial(trial);

        assert_eq!(health.circuit(), open);
    }

    #[test]
    fn releasing_a_trial_that_lost_the_slot_to_a_newer_one_is_a_no_op() {
        let (mut health, later) = recovering();
        let stale = trial_of(health.try_admit(later, &config()));
        health.observe(fault(), later, &config());
        let newer_time = later.checked_add(Duration::from_secs(6)).expect("advance");
        let newer = trial_of(health.try_admit(newer_time, &config()));

        health.release_trial(stale);

        assert_eq!(
            health.circuit(),
            CircuitState::HalfOpen { trial: Some(newer) }
        );
    }

    #[test]
    fn releasing_a_trial_that_already_recorded_an_outcome_is_a_no_op() {
        let (mut health, later) = recovering();
        let trial = trial_of(health.try_admit(later, &config()));
        health.observe(fault(), later, &config());
        let reopened = health.circuit();

        health.release_trial(trial);

        assert_eq!(health.circuit(), reopened);
        assert!(matches!(reopened, CircuitState::Open { .. }));
    }
}
