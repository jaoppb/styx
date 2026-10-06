//! `Recursor`: runs descents, and is an ordinary pool member behind `Upstream`.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use styx_core::{Clock, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse};
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType, ResponseCode, Ttl};

use crate::application::diagnostics::DiagnosticsState;
use crate::application::driver::DescentContext;
use crate::application::priming::{PrimeOutcome, Priming};
use crate::application::single_flight::InFlight;
use crate::domain::budget::DescentLimits;
use crate::domain::error::{BudgetExceeded, RecursionError};
use crate::domain::metrics::MetricEvent;
use crate::domain::ports::{ChainMaterialSink, DiagnosticsSink, InfraCache, Transport};
use crate::domain::root_hints::RootHints;
use crate::domain::topology::{Delegation, GlueOrigin, Nameserver};

/// Root servers asked per priming attempt before giving up until the backoff ends.
pub const PRIMING_ATTEMPTS: usize = 3;

/// Longest a priming attempt may take, whatever the caller's deadline.
pub const PRIMING_DEADLINE: Duration = Duration::from_secs(2);

/// Shortest lifetime given to a primed root NS set, so a server returning a tiny
/// TTL cannot make every descent re-prime.
pub const PRIMING_MIN_TTL: Duration = Duration::from_secs(300);

/// How often expired infrastructure-cache entries are swept.
pub const EVICTION_INTERVAL: Duration = Duration::from_secs(60);

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

/// An iterative resolver implementing `Upstream`.
#[derive(Debug)]
pub struct Recursor<C, T, D, M, I> {
    pub(crate) id: UpstreamId,
    pub(crate) settings: RecursorSettings,
    pub(crate) ports: RecursorPorts<C, T, D, M, I>,
    pub(crate) in_flight: InFlight,
    pub(crate) priming: Priming,
    pub(crate) stats: DiagnosticsState,
    pub(crate) last_eviction: Mutex<Option<Instant>>,
}

impl<C, T, D, M, I> Recursor<C, T, D, M, I>
where
    C: Clock,
    T: Transport,
    D: DiagnosticsSink,
    M: ChainMaterialSink,
    I: InfraCache,
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
            priming: Priming::new(),
            stats,
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
        let now = self.ports.clock.now_monotonic();
        self.maintain(now);
        let prime_deadline = deadline.min(now.checked_add(PRIMING_DEADLINE).unwrap_or(now));
        self.priming
            .ensure(now, || self.prime_once(prime_deadline))
            .await;

        let mut context = DescentContext::new(self.settings.limits, now, deadline);
        let result = self.descend(question.clone(), &mut context).await;
        let material = std::mem::take(&mut context.material);
        if !material.is_empty() {
            self.ports.chain_material.push(material);
        }
        self.stats
            .record_descent(result.is_err(), context.fallbacks);
        if let Some(snapshot) = self.stats.snapshot_if_due(self.ports.clock.now_monotonic()) {
            self.ports.diagnostics.publish(snapshot);
        }
        result
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

    /// One priming attempt: ask up to [`PRIMING_ATTEMPTS`] root servers for the
    /// root NS set and install the first usable answer.
    async fn prime_once(&self, deadline: Instant) -> PrimeOutcome {
        let clock = &self.ports.clock;
        let started = clock.now_monotonic();
        let root = self
            .ports
            .infra
            .closest_enclosing_cut(&Name::root(), started);
        let question = Question::new(Name::root(), RecordType::NS, RecordClass::In);
        let candidates = root
            .nameservers
            .untried()
            .into_iter()
            .filter(|server| self.settings.use_ipv6 || server.ip().is_ipv4())
            .take(PRIMING_ATTEMPTS);
        for server in candidates {
            let sent_at = clock.now_monotonic();
            let edns = self.ports.infra.metrics(server, sent_at).edns(sent_at);
            let reply = self
                .ports
                .transport
                .query(server, &question, edns, deadline)
                .await;
            let now = clock.now_monotonic();
            let Ok(reply) = reply else {
                self.stats.record_root_contact(server.ip(), None, now);
                self.ports
                    .infra
                    .update_metrics(server, MetricEvent::Failure, now);
                continue;
            };
            let rtt = now.saturating_duration_since(sent_at);
            self.stats.record_root_contact(server.ip(), Some(rtt), now);
            self.ports
                .infra
                .update_metrics(server, MetricEvent::Success(rtt), now);
            let Some(delegation) = root_ns_set(&reply.message, now) else {
                continue;
            };
            let lifetime = ttl_duration(delegation.ttl()).max(PRIMING_MIN_TTL);
            self.stats.set_root_servers(delegation.nameservers());
            self.stats.record_priming(now);
            self.ports.infra.put_delegation(delegation);
            tracing::debug!(%server, "root NS set primed");
            return PrimeOutcome::Primed(now.checked_add(lifetime).unwrap_or(now));
        }
        tracing::warn!("priming failed: no root server answered; using root hints");
        PrimeOutcome::Failed
    }
}

impl<C, T, D, M, I> Upstream for Recursor<C, T, D, M, I>
where
    C: Clock,
    T: Transport,
    D: DiagnosticsSink,
    M: ChainMaterialSink,
    I: InfraCache,
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
        let message = self
            .resolve_iteratively(query, deadline)
            .await
            .map_err(to_upstream_error)?;
        Ok(UpstreamResponse {
            message,
            answered_by: self.id.clone(),
            kind: UpstreamKind::Recursor,
            elapsed: self
                .ports
                .clock
                .now_monotonic()
                .saturating_duration_since(start),
            via_tcp: false,
            raced_count: 1,
        })
    }
}

/// The `Upstream` boundary: a descent failure becomes the pool's error, carrying no
/// zone, server or client detail. Failures specific to one name — a lame or looping
/// delegation, a spent budget — are answer faults that must not trip the circuit
/// breaker; only an unreachable root or a timeout indicts the recursor itself.
#[must_use]
pub fn to_upstream_error(error: RecursionError) -> UpstreamError {
    match error {
        RecursionError::Timeout | RecursionError::BudgetExceeded(BudgetExceeded::WallClock) => {
            UpstreamError::Timeout
        }
        RecursionError::NoReachableNameserver { at_root } => UpstreamError::ServerFailure {
            is_upstream: at_root,
        },
        RecursionError::Truncated => UpstreamError::Truncated,
        RecursionError::Malformed => {
            UpstreamError::Malformed("unusable response during descent".into())
        }
        RecursionError::BudgetExceeded(_)
        | RecursionError::CnameLoop
        | RecursionError::DelegationLoop
        | RecursionError::OutOfBailiwick
        | RecursionError::LameDelegation => UpstreamError::ServerFailure { is_upstream: false },
    }
}

/// The root NS set from a priming response: the root's NS records, with addresses
/// from the additional section (the root may vouch for any name).
fn root_ns_set(message: &Message, now: Instant) -> Option<Delegation> {
    if message.header.rcode != ResponseCode::NOERROR {
        return None;
    }
    let ns: Vec<_> = message
        .answers
        .iter()
        .filter(|record| record.owner.is_root())
        .filter_map(|record| match &record.rdata {
            RData::Ns(target) => Some((target.clone(), record.ttl)),
            _ => None,
        })
        .collect();
    let ttl = ns.iter().map(|(_, ttl)| *ttl).min().unwrap_or(Ttl::ZERO);
    let servers: Vec<Nameserver> = ns
        .into_iter()
        .map(|(name, _)| Nameserver {
            addresses: addresses_of(message, &name),
            name,
            glue_origin: GlueOrigin::InBailiwickGlue,
        })
        .filter(|server| !server.addresses.is_empty())
        .collect();
    if servers.is_empty() {
        return None;
    }
    Some(Delegation::new(
        Name::root(),
        Name::root(),
        servers,
        ttl,
        now,
    ))
}

fn addresses_of(message: &Message, name: &Name) -> Vec<IpAddr> {
    message
        .additionals
        .iter()
        .filter(|record| record.owner == *name)
        .filter_map(|record| match record.rdata {
            RData::A(address) => Some(IpAddr::V4(address)),
            RData::Aaaa(address) => Some(IpAddr::V6(address)),
            _ => None,
        })
        .collect()
}

fn ttl_duration(ttl: Ttl) -> Duration {
    Duration::from_secs(u64::from(ttl.seconds()))
}
