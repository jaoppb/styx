//! Gives a half-open trial's slot back when the trial is dropped before it reports.

use std::sync::RwLock;

use crate::domain::circuit::TrialId;
use crate::domain::health::{CircuitAdmission, HealthState};

/// Holds a member's half-open trial slot for as long as the trial is running.
///
/// A trial is dropped without reporting when a race winner aborts it, when the query
/// deadline drops the whole resolution, or when a probe is cancelled. Releasing on drop
/// keeps that from leaving the member unavailable forever. Dropping after the outcome was
/// recorded, or after a newer trial took the slot, releases nothing.
#[must_use = "dropping the guard releases the trial slot immediately"]
pub struct TrialGuard<'pool> {
    health: &'pool RwLock<HealthState>,
    trial: Option<TrialId>,
}

impl<'pool> TrialGuard<'pool> {
    pub(crate) const fn new(
        health: &'pool RwLock<HealthState>,
        admission: CircuitAdmission,
    ) -> Self {
        let trial = match admission {
            CircuitAdmission::Regular => None,
            CircuitAdmission::Trial(trial) => Some(trial),
        };
        Self { health, trial }
    }
}

impl Drop for TrialGuard<'_> {
    fn drop(&mut self) {
        let Some(trial) = self.trial else {
            return;
        };
        let mut health = match self.health.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        health.release_trial(trial);
    }
}
