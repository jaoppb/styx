//! `Recursor`: runs descents, and is an ordinary pool member behind `Upstream`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use styx_core::{Clock, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse};
use styx_proto::{Message, Question};

use crate::application::diagnostics::DiagnosticsState;
use crate::application::driver::DescentContext;
use crate::application::prime::PrimeJob;
use crate::application::priming::Priming;
use crate::application::single_flight::InFlight;
use crate::domain::budget::DescentLimits;
use crate::domain::error::RecursionError;
use crate::domain::ports::{ChainMaterialSink, DiagnosticsSink, InfraCache, Transport};
use crate::domain::root_hints::RootHints;

/// How often expired infrastructure-cache entries are swept.
pub const EVICTION_INTERVAL: Duration = Duration::from_secs(60);

/// How long without a single reply from any nameserver before a failed descent is
/// held against the recursor itself: past this, the network, not the name, is the
/// likelier culprit.
pub const NETWORK_SILENCE: Duration = Duration::from_secs(30);

/// The recursor's collaborators, injected by the composition root.
#[derive(Debug)]
pub struct RecursorPorts<C, T, D, M, I> {
    /// Every time read goes through this.
    pub clock: Arc<C>,
    /// Sends questions to nameservers.
    pub transport: Arc<T>,
    /// Receives diagnostics snapshots.
    pub diagnostics: Arc<D>,
    /// Receives collected DNSSEC chain material.
    pub chain_material: Arc<M>,
    /// The infrastructure cache.
    pub infra: Arc<I>,
}

/// Behaviour settings, from the `[recursion]` TOML section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursorSettings {
    /// Denial-of-service bounds per client question.
    pub limits: DescentLimits,
    /// Whether IPv6 nameserver addresses are queried.
    pub use_ipv6: bool,
}

/// Why a descent failed, and whether the recursor heard anything from the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescentFailure {
    /// What ended the descent.
    pub error: RecursionError,
    /// No nameserver answered anything for [`NETWORK_SILENCE`] before the failure.
    pub network_silent: bool,
}

/// A resolved answer and how it was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The response for the client's question.
    pub message: Message,
    /// Whether any reply the descent used arrived over TCP.
    pub via_tcp: bool,
}

/// An iterative resolver implementing `Upstream`.
#[derive(Debug)]
pub struct Recursor<C, T, D, M, I> {
    pub(crate) id: UpstreamId,
    pub(crate) settings: RecursorSettings,
    pub(crate) ports: RecursorPorts<C, T, D, M, I>,
    pub(crate) in_flight: InFlight,
    pub(crate) hints: RootHints,
    pub(crate) priming: Arc<Priming>,
    pub(crate) stats: Arc<DiagnosticsState>,
    pub(crate) last_eviction: Mutex<Option<Instant>>,
}

impl<C, T, D, M, I> Recursor<C, T, D, M, I>
where
    C: Clock,
    T: Transport + 'static,
    D: DiagnosticsSink,
    M: ChainMaterialSink,
    I: InfraCache + 'static,
{
    /// Builds a recursor seeded from `hints`. Sends nothing: priming is lazy.
    #[must_use]
    pub fn new(
        id: UpstreamId,
        settings: RecursorSettings,
        hints: &RootHints,
        ports: RecursorPorts<C, T, D, M, I>,
    ) -> Self {
        ports.infra.prime_from(hints, ports.clock.now_monotonic());
        let stats = DiagnosticsState::new();
        stats.set_root_servers(hints.seed());
        Self {
            id,
            settings,
            ports,
            in_flight: InFlight::new(),
            hints: hints.clone(),
            priming: Arc::new(Priming::new()),
            stats: Arc::new(stats),
            last_eviction: Mutex::new(None),
        }
    }

    /// Resolves `question` by iterative descent before `deadline`.
    ///
    /// # Errors
    ///
    /// Returns the [`RecursionError`] that ended the descent.
    pub async fn resolve_iteratively(
        &self,
        question: &Question,
        deadline: Instant,
    ) -> Result<Message, RecursionError> {
        self.resolve_detailed(question, deadline)
            .await
            .map(|resolution| resolution.message)
            .map_err(|failure| failure.error)
    }

    /// Like [`Self::resolve_iteratively`], and says whether the network was silent
    /// when the descent failed, which is what the pool needs to judge the recursor.
    ///
    /// # Errors
    ///
    /// Returns the [`DescentFailure`] that ended the descent.
    pub async fn resolve_detailed(
        &self,
        question: &Question,
        deadline: Instant,
    ) -> Result<Resolution, DescentFailure> {
        let now = self.ports.clock.now_monotonic();
        self.maintain(now);
        self.start_priming(now);

        let mut context = DescentContext::new(self.settings.limits, now, deadline);
        let result = self.descend(question.clone(), &mut context).await;
        let material = std::mem::take(&mut context.material);
        if !material.is_empty() {
            self.ports.chain_material.push(material);
        }
        self.stats
            .record_descent(result.is_err(), context.fallbacks);
        let finished = self.ports.clock.now_monotonic();
        if let Some(snapshot) = self.stats.snapshot_if_due(finished) {
            self.ports.diagnostics.publish(snapshot);
        }
        match result {
            Ok(message) => Ok(Resolution {
                message,
                via_tcp: context.used_tcp,
            }),
            Err(error) => Err(DescentFailure {
                error,
                network_silent: !self.stats.replied_within(finished, NETWORK_SILENCE),
            }),
        }
    }

    /// Starts priming in a task of its own if it is due. The descent that triggered
    /// it carries on with the hints and the cached root set, and the attempt has its
    /// own deadline, so neither the descent's budget nor a short caller deadline can
    /// spoil it.
    fn start_priming(&self, now: Instant) {
        let job = || PrimeJob {
            clock: Arc::clone(&self.ports.clock),
            transport: Arc::clone(&self.ports.transport),
            infra: Arc::clone(&self.ports.infra),
            stats: Arc::clone(&self.stats),
            use_ipv6: self.settings.use_ipv6,
            hints: self.hints.clone(),
        };
        let _detached = self.priming.trigger(now, || job().run());
    }

    fn maintain(&self, now: Instant) {
        let mut last = match self.last_eviction.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if last.is_some_and(|at| now.saturating_duration_since(at) < EVICTION_INTERVAL) {
            return;
        }
        *last = Some(now);
        drop(last);
        self.ports.infra.evict_expired(now);
    }
}

impl<C, T, D, M, I> Upstream for Recursor<C, T, D, M, I>
where
    C: Clock,
    T: Transport + 'static,
    D: DiagnosticsSink,
    M: ChainMaterialSink,
    I: InfraCache + 'static,
{
    fn id(&self) -> UpstreamId {
        self.id.clone()
    }

    fn kind(&self) -> UpstreamKind {
        UpstreamKind::Recursor
    }

    /// A full descent. For a pool probe, this is the canary: the correct test of a
    /// recursor is a whole descent, not a single query.
    async fn resolve(
        &self,
        query: &Question,
        deadline: Instant,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let start = self.ports.clock.now_monotonic();
        let resolution = self
            .resolve_detailed(query, deadline)
            .await
            .map_err(|failure| to_upstream_error(&failure))?;
        Ok(UpstreamResponse {
            message: resolution.message,
            answered_by: self.id.clone(),
            kind: UpstreamKind::Recursor,
            elapsed: self
                .ports
                .clock
                .now_monotonic()
                .saturating_duration_since(start),
            via_tcp: resolution.via_tcp,
            raced_count: 1,
        })
    }
}

/// The `Upstream` boundary: a descent failure becomes the pool's error, carrying no
/// zone, server or client detail.
///
/// What indicts the recursor is whether the network answered at all, not which
/// error ended this descent. A dead leaf zone, a lame or looping delegation, a
/// server returning undecodable replies and a spent wall clock all belong to one
/// name, and are answer faults that must not trip the circuit breaker — otherwise
/// repeated queries for one broken domain would take every other name down with it.
/// A recursor that has heard nothing from any nameserver, or whose root servers
/// cannot be used, is the one that is broken: its failures are upstream faults,
/// whatever form they take (a dead link burns the wall clock before it ever
/// reports an unreachable root).
#[must_use]
pub fn to_upstream_error(failure: &DescentFailure) -> UpstreamError {
    if failure.network_silent {
        return UpstreamError::Timeout;
    }
    let at_root = matches!(
        failure.error,
        RecursionError::NoReachableNameserver { at_root: true }
    );
    UpstreamError::ServerFailure {
        is_upstream: at_root,
    }
}
