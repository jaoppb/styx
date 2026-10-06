//! The descent driver: the loop that feeds `Descent` the world.
//!
//! `Descent` decides; this loop acts — choosing servers, sending through the
//! transport (single-flighted), timing, resolving glue with sub-descents that share
//! the parent's budget, following aliases from the infrastructure cache, and
//! applying what the descent learned. Each step is a named helper returning early,
//! so the loop reads as a sequence of calls rather than a match pyramid.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Instant;

use styx_core::Clock;
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType};
use tracing::Instrument;

use crate::application::recursor::Recursor;
use crate::application::selection::select_server;
use crate::application::single_flight::OutboundKey;
use crate::domain::budget::{DescentBudget, DescentLimits};
use crate::domain::chain_material::ChainMaterial;
use crate::domain::descent::{Descent, DescentAction, DescentEvent, Observation, QueryTarget};
use crate::domain::error::RecursionError;
use crate::domain::metrics::MetricEvent;
use crate::domain::ports::{
    ChainMaterialSink, DiagnosticsSink, EdnsObservation, InfraCache, Transport, TransportError,
    TransportReply,
};
use crate::domain::topology::NameserverAddr;

/// How deeply glue lookups may nest. A nameserver whose address needs a lookup
/// whose nameserver needs a lookup is already rare; past three levels the chain is
/// broken or hostile, and the shared budget would end it anyway, only later.
pub const MAX_GLUE_NESTING: usize = 3;

/// What one client question's descent shares with its glue sub-descents.
#[derive(Debug)]
pub(crate) struct DescentContext {
    pub(crate) budget: DescentBudget,
    pub(crate) deadline: Instant,
    pub(crate) glue_stack: Vec<Name>,
    pub(crate) material: ChainMaterial,
    pub(crate) fallbacks: u64,
}

impl DescentContext {
    pub(crate) fn new(limits: DescentLimits, now: Instant, deadline: Instant) -> Self {
        let budget = DescentBudget::new(limits, now);
        let deadline = deadline.min(budget.wall_clock_deadline());
        Self {
            budget,
            deadline,
            glue_stack: Vec::new(),
            material: ChainMaterial::default(),
            fallbacks: 0,
        }
    }
}

/// A boxed descent future. Boxing is required, not chosen: a glue sub-descent is a
/// descent, so the future is recursive and must have a known size.
type DescentFuture<'a> = Pin<Box<dyn Future<Output = Result<Message, RecursionError>> + Send + 'a>>;

impl<C, T, D, M, I> Recursor<C, T, D, M, I>
where
    C: Clock,
    T: Transport,
    D: DiagnosticsSink,
    M: ChainMaterialSink,
    I: InfraCache,
{
    /// Runs one descent for `question` within `context`'s shared budget.
    pub(crate) fn descend<'a>(
        &'a self,
        question: Question,
        context: &'a mut DescentContext,
    ) -> DescentFuture<'a> {
        let span =
            tracing::debug_span!("descent", qname = %question.qname, qtype = ?question.qtype);
        Box::pin(self.run(question, context).instrument(span))
    }

    async fn run(
        &self,
        question: Question,
        context: &mut DescentContext,
    ) -> Result<Message, RecursionError> {
        let now = self.ports.clock.now_monotonic();
        let cut = self.start_cut(&question.qname, question.qtype, now);
        let mut descent = Descent::new(question, cut, self.settings.limits.max_cname_chain());
        let mut action = descent.next_action();
        loop {
            self.apply_events(&mut descent, context);
            action = match action {
                DescentAction::Query(target) => {
                    self.query_step(&mut descent, target, context).await
                }
                DescentAction::ResolveGlue(name) => {
                    self.glue_step(&mut descent, name, context).await
                }
                DescentAction::FollowCname(target) => self.follow(&mut descent, &target),
                DescentAction::Answer(message) => {
                    return finish(&mut descent, context, Ok(message))
                }
                DescentAction::Fail(error) => return finish(&mut descent, context, Err(error)),
            };
        }
    }

    /// Where to start for `name`: its closest known cut — or, for a DS question,
    /// the closest cut above its parent, because the DS RRset lives on the parent
    /// side of the delegation.
    fn start_cut(
        &self,
        name: &Name,
        qtype: RecordType,
        now: Instant,
    ) -> crate::domain::topology::ZoneCut {
        let lookup = if qtype == RecordType::DS {
            name.parent().unwrap_or_else(Name::root)
        } else {
            name.clone()
        };
        self.ports.infra.closest_enclosing_cut(&lookup, now)
    }

    fn follow(&self, descent: &mut Descent, target: &Name) -> DescentAction {
        let now = self.ports.clock.now_monotonic();
        let cut = self.start_cut(target, descent.original().qtype, now);
        descent.restart_at(cut);
        descent.next_action()
    }

    async fn query_step(
        &self,
        descent: &mut Descent,
        target: QueryTarget,
        context: &mut DescentContext,
    ) -> DescentAction {
        let now = self.ports.clock.now_monotonic();
        if let Err(exceeded) = context.budget.elapsed(now) {
            return DescentAction::Fail(RecursionError::BudgetExceeded(exceeded));
        }
        if now >= context.deadline {
            return DescentAction::Fail(RecursionError::Timeout);
        }
        let server = match target {
            QueryTarget::SameServer(server) => server,
            QueryTarget::AnyServer => match self.choose(descent, now) {
                Some(server) => server,
                None => return descent.next_action(),
            },
        };
        // Every waiting descent is charged for a shared exchange: each descent's
        // bound must hold on its own, whoever happened to lead.
        if let Err(exceeded) = context.budget.charge_query() {
            return DescentAction::Fail(RecursionError::BudgetExceeded(exceeded));
        }
        let observation = self.send(descent, server, context.deadline, now).await;
        let finished = self.ports.clock.now_monotonic();
        descent.observe(observation, &mut context.budget, finished)
    }

    fn choose(&self, descent: &mut Descent, now: Instant) -> Option<NameserverAddr> {
        let choice = select_server(
            descent.current_cut(),
            self.ports.infra.as_ref(),
            now,
            self.settings.use_ipv6,
        );
        for skipped in choice.skipped {
            descent.skip_server(skipped);
        }
        choice.chosen
    }

    /// Composes the question through minimisation and sends it, single-flighted.
    async fn send(
        &self,
        descent: &mut Descent,
        server: NameserverAddr,
        deadline: Instant,
        sent_at: Instant,
    ) -> Observation {
        let metrics = self.ports.infra.metrics(server, sent_at);
        let sent = descent.compose(server, metrics.minimisation(sent_at));
        let zone = descent.current_cut().zone.clone();
        let span = tracing::debug_span!(
            "query",
            zone = %zone,
            sent = %sent.qname,
            sent_type = ?sent.qtype,
            %server,
        );
        let key = OutboundKey {
            server,
            as_sent: sent.clone(),
        };
        let transport = self.ports.transport.as_ref();
        let (outcome, role) = self
            .in_flight
            .exchange(key, || {
                transport.query(server, &sent, metrics.edns(), deadline)
            })
            .instrument(span.clone())
            .await;
        let finished = self.ports.clock.now_monotonic();
        let rtt = finished.saturating_duration_since(sent_at);
        tracing::debug!(parent: &span, ?role, answered = outcome.is_ok(), ?rtt, "exchange");
        self.record_exchange(server, &zone, &outcome, rtt, finished);
        match outcome {
            Ok(reply) => Observation::Reply(reply.message),
            Err(error) => Observation::Failed(error),
        }
    }

    fn record_exchange(
        &self,
        server: NameserverAddr,
        zone: &Name,
        outcome: &Result<TransportReply, TransportError>,
        rtt: std::time::Duration,
        now: Instant,
    ) {
        let answered = outcome.is_ok();
        if zone.is_root() {
            self.stats
                .record_root_contact(server.ip(), answered.then_some(rtt), now);
        } else if zone.label_count() == 1 {
            self.stats.record_tld_contact(zone, answered, now);
        }
        let Ok(reply) = outcome else {
            return;
        };
        let infra = &self.ports.infra;
        infra.update_metrics(server, MetricEvent::Success(rtt), now);
        match reply.edns {
            EdnsObservation::Supported(size) => {
                infra.update_metrics(server, MetricEvent::EdnsSupported(size), now);
            }
            EdnsObservation::Intolerant => {
                infra.update_metrics(server, MetricEvent::EdnsIntolerant, now);
            }
            EdnsObservation::Inconclusive => {}
        }
    }

    /// Looks up a glue-less nameserver's addresses with a sub-descent that spends
    /// from this descent's budget. A name already being looked up further up the
    /// stack is circular glue: it fails at once instead of looping.
    async fn glue_step(
        &self,
        descent: &mut Descent,
        name: Name,
        context: &mut DescentContext,
    ) -> DescentAction {
        let circular = context.glue_stack.contains(&name);
        if circular || context.glue_stack.len() >= MAX_GLUE_NESTING {
            tracing::debug!(nameserver = %name, circular, "glue lookup refused");
            return descent.next_action();
        }
        context.glue_stack.push(name.clone());
        let mut addresses = self.lookup_addresses(&name, RecordType::A, context).await;
        if self.settings.use_ipv6 && matches!(&addresses, Ok(found) if found.is_empty()) {
            addresses = self
                .lookup_addresses(&name, RecordType::AAAA, context)
                .await;
        }
        context.glue_stack.pop();
        match addresses {
            Ok(found) => {
                descent.provide_glue(&name, &found);
                descent.next_action()
            }
            Err(error @ (RecursionError::Timeout | RecursionError::BudgetExceeded(_))) => {
                DescentAction::Fail(error)
            }
            Err(_) => descent.next_action(),
        }
    }

    async fn lookup_addresses(
        &self,
        name: &Name,
        qtype: RecordType,
        context: &mut DescentContext,
    ) -> Result<Vec<IpAddr>, RecursionError> {
        let question = Question::new(name.clone(), qtype, RecordClass::In);
        let message = self.descend(question, context).await?;
        Ok(message
            .answers
            .iter()
            .filter_map(|record| match record.rdata {
                RData::A(address) => Some(IpAddr::V4(address)),
                RData::Aaaa(address) => Some(IpAddr::V6(address)),
                _ => None,
            })
            .collect())
    }

    fn apply_events(&self, descent: &mut Descent, context: &mut DescentContext) {
        let now = self.ports.clock.now_monotonic();
        for event in descent.drain_events() {
            match event {
                DescentEvent::Delegation(delegation) => self.ports.infra.put_delegation(delegation),
                DescentEvent::Metric(server, metric) => {
                    self.ports.infra.update_metrics(server, metric, now);
                }
                DescentEvent::MinimisationFallback => {
                    context.fallbacks = context.fallbacks.saturating_add(1);
                }
            }
        }
    }
}

/// Ends a descent: keeps the chain material it collected and returns its result.
fn finish(
    descent: &mut Descent,
    context: &mut DescentContext,
    result: Result<Message, RecursionError>,
) -> Result<Message, RecursionError> {
    context.material.extend(descent.take_chain_material());
    if let Err(error) = &result {
        tracing::debug!(%error, "descent failed");
    }
    result
}
