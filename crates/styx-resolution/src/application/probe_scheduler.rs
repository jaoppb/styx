//! Background probe scheduler task.
//!
//! Manufactures resolution observations only where passive health is blind,
//! keeping standbys and recovering members measured without perturbing healthy paths.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use styx_core::{Clock, Upstream, UpstreamId};
use styx_proto::{Question, RecordClass};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::application::pool::{record_span_outcome, UpstreamPool};
use crate::domain::health::Outcome;
use crate::domain::selection::SelectionStrategy;

/// Background task that executes periodic canary probes against due pool members.
pub struct ProbeScheduler<S, U, C> {
    pool: Arc<UpstreamPool<S, U, C>>,
    clock: Arc<C>,
    tick: Duration,
    in_flight: Arc<Mutex<HashSet<UpstreamId>>>,
}

impl<S, U, C> ProbeScheduler<S, U, C>
where
    S: SelectionStrategy + 'static,
    U: Upstream + Clone + 'static,
    C: Clock,
{
    /// Creates a new `ProbeScheduler`.
    #[must_use]
    pub fn new(pool: Arc<UpstreamPool<S, U, C>>, clock: Arc<C>, tick: Duration) -> Self {
        Self {
            pool,
            clock,
            tick,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Runs the probe scheduler loop until the cancellation token triggers.
    pub async fn run(self, shutdown: CancellationToken) {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    tracing::debug!("probe scheduler received shutdown signal");
                    break;
                }
                () = tokio::time::sleep(self.tick) => {
                    self.tick_once().await;
                }
            }
        }
    }

    async fn tick_once(&self) {
        let due_ids = self.pool.due_for_probe();
        for id in due_ids {
            let mut guard = self.in_flight.lock().await;
            if guard.contains(&id) {
                continue;
            }
            guard.insert(id.clone());
            drop(guard);

            let pool = self.pool.clone();
            let clock = self.clock.clone();
            let in_flight = self.in_flight.clone();
            let probe_id = id.clone();

            tokio::spawn(async move {
                Self::execute_probe(&pool, &clock, &probe_id).await;
                let mut guard = in_flight.lock().await;
                guard.remove(&probe_id);
            });
        }
    }

    /// Directly probes a specific member once and records the outcome.
    pub async fn probe_once(&self, id: &UpstreamId) {
        Self::execute_probe(&self.pool, &self.clock, id).await;
    }

    async fn execute_probe(pool: &UpstreamPool<S, U, C>, clock: &C, id: &UpstreamId) {
        let Some(member) = pool.members().iter().find(|m| m.id == *id) else {
            return;
        };

        let span = tracing::info_span!(
            "upstream_probe",
            member_id = %id,
            strategy = "probe",
            outcome = tracing::field::Empty,
            elapsed_ms = tracing::field::Empty,
        );

        let question = Question::new(
            member.canary.qname.clone(),
            member.canary.qtype,
            RecordClass::In,
        );
        let start = clock.now_monotonic();
        let deadline = start.checked_add(member.canary.timeout).unwrap_or(start);

        let res = member
            .upstream
            .resolve(&question, deadline)
            .instrument(span.clone())
            .await;
        let elapsed = clock
            .now_monotonic()
            .checked_duration_since(start)
            .unwrap_or_default();

        let outcome = match res {
            Ok(_) => {
                record_span_outcome(&span, elapsed, None);
                Outcome::Success {
                    latency: elapsed,
                    was_probe: true,
                }
            }
            Err(err) => {
                let class = err.classify();
                record_span_outcome(&span, elapsed, Some(class));
                Outcome::Failure {
                    class,
                    was_probe: true,
                }
            }
        };

        pool.record(id, outcome);
    }
}
