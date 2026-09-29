//! Upstream pool dispatch, member health ownership, and candidate selection.

use std::sync::{Arc, RwLock};

use styx_core::{Clock, Upstream, UpstreamId, UpstreamResponse};
use styx_proto::Question;
use tokio::task::JoinSet;

use crate::domain::circuit::CircuitConfig;
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
            health.observe(outcome, now, &self.circuit);
        }
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
    pub async fn resolve(&self, query: &Question) -> Result<UpstreamResponse, PoolError> {
        let views = self.snapshot();
        let now = self.clock.now_monotonic();
        let selection = self.strategy.select(&views, now);

        match selection {
            Selection::NoneAvailable => Err(PoolError::AllUpstreamsDown),
            Selection::Sequential(ids) => self.try_sequential(&ids, query).await,
            Selection::Fanout(ids) => self.try_fanout(&ids, query).await,
        }
    }

    async fn try_sequential(
        &self,
        ids: &[UpstreamId],
        query: &Question,
    ) -> Result<UpstreamResponse, PoolError> {
        let mut last_error = None;

        for id in ids {
            let Some(member) = self.members.iter().find(|m| m.id == *id) else {
                continue;
            };

            let start = self.clock.now_monotonic();
            let deadline = start.checked_add(member.canary.timeout).unwrap_or(start);

            match member.upstream.resolve(query, deadline).await {
                Ok(mut resp) => {
                    let elapsed = self
                        .clock
                        .now_monotonic()
                        .checked_duration_since(start)
                        .unwrap_or_default();
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
                    return Ok(resp);
                }
                Err(err) => {
                    self.record(
                        &member.id,
                        Outcome::Failure {
                            class: err.classify(),
                            was_probe: false,
                        },
                    );
                    last_error = Some(err);
                }
            }
        }

        Err(PoolError::Exhausted { last_error })
    }

    async fn try_fanout(
        &self,
        ids: &[UpstreamId],
        query: &Question,
    ) -> Result<UpstreamResponse, PoolError> {
        let mut set = JoinSet::new();
        let raced_count = u8::try_from(ids.len()).unwrap_or(u8::MAX);

        for id in ids {
            let Some(member) = self.members.iter().find(|m| m.id == *id) else {
                continue;
            };

            let upstream = member.upstream.clone();
            let q = query.clone();
            let id_clone = member.id.clone();
            let kind = upstream.kind();
            let start = self.clock.now_monotonic();
            let deadline = start.checked_add(member.canary.timeout).unwrap_or(start);

            set.spawn(async move {
                let res = upstream.resolve(&q, deadline).await;
                (id_clone, kind, start, res)
            });
        }

        let mut last_error = None;

        while let Some(join_res) = set.join_next().await {
            let (id, kind, start, result) = match join_res {
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
                    self.record(
                        &id,
                        Outcome::Failure {
                            class: err.classify(),
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
