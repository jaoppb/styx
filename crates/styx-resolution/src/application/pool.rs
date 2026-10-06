//! Upstream pool dispatch, member health ownership, and candidate selection.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use styx_core::{
    Clock, FailureClass, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse,
};
use styx_proto::Question;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::domain::circuit::{CircuitConfig, CircuitState};
use crate::domain::error::PoolError;
use crate::domain::health::{HealthState, Outcome};
use crate::domain::probe::{CanaryConfig, ProbePolicy};
use crate::domain::selection::{MemberView, Selection, SelectionStrategy};
use crate::domain::weight::Weight;

/// A single upstream member managed within a pool.
pub struct PoolMember<U> {
    /// Upstream identifier.
    pub id: UpstreamId,
    /// Upstream resolution implementation.
    pub upstream: U,
    /// Configured selection weight.
    pub weight: Weight,
    /// Health check canary configuration.
    pub canary: CanaryConfig,
    /// Thread-safe health state.
    pub health: RwLock<HealthState>,
}

impl<U: Upstream> PoolMember<U> {
    /// Creates a new `PoolMember` with cold-start health.
    #[must_use]
    pub fn new(id: UpstreamId, upstream: U, weight: Weight, canary: CanaryConfig) -> Self {
        Self {
            id,
            upstream,
            weight,
            canary,
            health: RwLock::new(HealthState::new()),
        }
    }
}

/// Upstream pool managing member lifecycle, selection, and health observation.
pub struct UpstreamPool<S, U, C> {
    members: Vec<PoolMember<U>>,
    strategy: S,
    clock: Arc<C>,
    circuit: CircuitConfig,
    probe_policy: ProbePolicy,
}

type FanoutTaskResult = (
    UpstreamId,
    UpstreamKind,
    Instant,
    Result<UpstreamResponse, UpstreamError>,
    tracing::Span,
);

impl<S, U, C> UpstreamPool<S, U, C>
where
    S: SelectionStrategy,
    U: Upstream + Clone + 'static,
    C: Clock,
{
    /// Creates a new `UpstreamPool`.
    #[must_use]
    pub fn new(
        members: Vec<PoolMember<U>>,
        strategy: S,
        clock: Arc<C>,
        circuit: CircuitConfig,
        probe_policy: ProbePolicy,
    ) -> Self {
        Self {
            members,
            strategy,
            clock,
            circuit,
            probe_policy,
        }
    }

    /// Returns a read-only snapshot projection of all pool members.
    #[must_use]
    pub fn snapshot(&self) -> Vec<MemberView> {
        let now = self.clock.now_monotonic();
        self.members
            .iter()
            .map(|m| {
                let health = match m.health.read() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                MemberView {
                    id: m.id.clone(),
                    kind: m.upstream.kind(),
                    weight: m.weight,
                    srtt: health.srtt(),
                    circuit: health.circuit(),
                    available: health.is_available(now, &self.circuit),
                }
            })
            .collect()
    }

    /// Records an outcome for an upstream member, updating its health fold.
    pub fn record(&self, id: &UpstreamId, outcome: Outcome) {
        let now = self.clock.now_monotonic();
        if let Some(member) = self.members.iter().find(|m| m.id == *id) {
            let mut health = match member.health.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let prev_circuit = health.circuit();
            health.observe(outcome, now, &self.circuit);
            let next_circuit = health.circuit();
            match (prev_circuit, next_circuit) {
                (
                    CircuitState::Closed | CircuitState::HalfOpen { .. },
                    CircuitState::Open { .. },
                ) => {
                    tracing::warn!(upstream = %id, "upstream circuit opened");
                }
                (
                    CircuitState::Open { .. } | CircuitState::HalfOpen { .. },
                    CircuitState::Closed,
                ) => {
                    tracing::warn!(upstream = %id, "upstream circuit closed");
                }
                _ => {}
            }
        }
    }

    /// Attempts to admit a query or probe on the specified member.
    #[must_use]
    pub fn try_admit(&self, id: &UpstreamId) -> bool {
        let Some(member) = self.members.iter().find(|m| m.id == *id) else {
            return false;
        };
        let mut health = match member.health.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        health.try_admit(self.clock.now_monotonic(), &self.circuit)
    }

    /// Attempts to admit a background health probe on the specified member.
    #[must_use]
    pub fn try_admit_probe(&self, id: &UpstreamId) -> bool {
        let Some(member) = self.members.iter().find(|m| m.id == *id) else {
            return false;
        };
        let mut health = match member.health.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        health.try_admit_probe()
    }

    /// Returns a list of upstream IDs due for active background probing.
    #[must_use]
    pub fn due_for_probe(&self) -> Vec<UpstreamId> {
        let now = self.clock.now_monotonic();
        let views = self.snapshot();
        let mut due = Vec::new();

        for (member, view) in self.members.iter().zip(views.iter()) {
            let health = match member.health.read() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if self.probe_policy.due(view, &health, now) {
                due.push(member.id.clone());
            }
        }

        due
    }

    /// Resolves a DNS query using the configured selection strategy.
    ///
    /// # Errors
    /// Returns [`PoolError::AllUpstreamsDown`] if no members are available,
    /// or [`PoolError::Exhausted`] if all attempted members fail.
    pub async fn resolve(
        &self,
        query: &Question,
        deadline: Instant,
    ) -> Result<UpstreamResponse, PoolError> {
        let views = self.snapshot();
        let now = self.clock.now_monotonic();
        let selection = self.strategy.select(&views, now);

        match selection {
            Selection::NoneAvailable => {
                tracing::warn!("all upstreams down in pool");
                Err(PoolError::AllUpstreamsDown)
            }
            Selection::Sequential(ids) => self.try_sequential(&ids, query, deadline).await,
            Selection::Fanout(ids) => self.try_fanout(&ids, query, deadline).await,
        }
    }

    async fn try_sequential(
        &self,
        ids: &[UpstreamId],
        query: &Question,
        deadline: Instant,
    ) -> Result<UpstreamResponse, PoolError> {
        let mut last_error = None;

        for id in ids {
            if self.clock.now_monotonic() >= deadline {
                break;
            }

            if !self.try_admit(id) {
                continue;
            }

            let Some(member) = self.members.iter().find(|m| m.id == *id) else {
                continue;
            };

            match self.dispatch_member(member, query, deadline).await {
                Ok(resp) => return Ok(resp),
                Err(err) => last_error = Some(err),
            }
        }

        Err(PoolError::Exhausted { last_error })
    }

    async fn dispatch_member(
        &self,
        member: &PoolMember<U>,
        query: &Question,
        deadline: Instant,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let strategy = self.strategy.name();
        let span = tracing::info_span!(
            "upstream_dispatch",
            member_id = %member.id,
            strategy = ?strategy,
            outcome = tracing::field::Empty,
            elapsed_ms = tracing::field::Empty,
        );

        let start = self.clock.now_monotonic();

        let res = member
            .upstream
            .resolve(query, deadline)
            .instrument(span.clone())
            .await;
        let elapsed = self
            .clock
            .now_monotonic()
            .checked_duration_since(start)
            .unwrap_or_default();

        match res {
            Ok(mut resp) => {
                record_span_outcome(&span, elapsed, None);
                self.record(
                    &member.id,
                    Outcome::Success {
                        latency: elapsed,
                        was_probe: false,
                    },
                );
                resp.answered_by = member.id.clone();
                resp.kind = member.upstream.kind();
                resp.elapsed = elapsed;
                resp.raced_count = 1;
                Ok(resp)
            }
            Err(err) => {
                let class = err.classify();
                record_span_outcome(&span, elapsed, Some(class));
                self.record(
                    &member.id,
                    Outcome::Failure {
                        class,
                        was_probe: false,
                    },
                );
                Err(err)
            }
        }
    }

    async fn try_fanout(
        &self,
        ids: &[UpstreamId],
        query: &Question,
        deadline: Instant,
    ) -> Result<UpstreamResponse, PoolError> {
        let mut set = JoinSet::new();
        let raced_count = u8::try_from(ids.len()).unwrap_or(u8::MAX);
        let strategy = self.strategy.name();

        for id in ids {
            if !self.try_admit(id) {
                continue;
            }

            let Some(member) = self.members.iter().find(|m| m.id == *id) else {
                continue;
            };

            let upstream = member.upstream.clone();
            let q = query.clone();
            let id_clone = member.id.clone();
            let kind = upstream.kind();
            let start = self.clock.now_monotonic();

            let span = tracing::info_span!(
                "upstream_dispatch",
                member_id = %id_clone,
                strategy = ?strategy,
                outcome = tracing::field::Empty,
                elapsed_ms = tracing::field::Empty,
            );

            set.spawn(async move {
                let res = upstream
                    .resolve(&q, deadline)
                    .instrument(span.clone())
                    .await;
                (id_clone, kind, start, res, span)
            });
        }

        self.collect_fanout_results(set, raced_count).await
    }

    async fn collect_fanout_results(
        &self,
        mut set: JoinSet<FanoutTaskResult>,
        raced_count: u8,
    ) -> Result<UpstreamResponse, PoolError> {
        let mut last_error = None;

        while let Some(join_res) = set.join_next().await {
            let (id, kind, start, result, span) = match join_res {
                Ok(tuple) => tuple,
                Err(_) => continue,
            };

            let elapsed = self
                .clock
                .now_monotonic()
                .checked_duration_since(start)
                .unwrap_or_default();

            match result {
                Ok(mut resp) => {
                    record_span_outcome(&span, elapsed, None);
                    self.record(
                        &id,
                        Outcome::Success {
                            latency: elapsed,
                            was_probe: false,
                        },
                    );
                    resp.answered_by = id;
                    resp.kind = kind;
                    resp.elapsed = elapsed;
                    resp.raced_count = raced_count;
                    set.abort_all();
                    return Ok(resp);
                }
                Err(err) => {
                    let class = err.classify();
                    record_span_outcome(&span, elapsed, Some(class));
                    self.record(
                        &id,
                        Outcome::Failure {
                            class,
                            was_probe: false,
                        },
                    );
                    last_error = Some(err);
                }
            }
        }

        Err(PoolError::Exhausted { last_error })
    }

    /// Accesses the underlying members slice.
    #[must_use]
    pub fn members(&self) -> &[PoolMember<U>] {
        &self.members
    }
}

pub(crate) fn record_span_outcome(
    span: &tracing::Span,
    elapsed: std::time::Duration,
    result_class: Option<FailureClass>,
) {
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    span.record("elapsed_ms", elapsed_ms);
    match result_class {
        None => span.record("outcome", "success"),
        Some(FailureClass::UpstreamFault) => span.record("outcome", "upstream_fault"),
        Some(FailureClass::AnswerFault) => span.record("outcome", "answer_fault"),
    };
}
