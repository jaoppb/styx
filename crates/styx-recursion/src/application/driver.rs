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
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_core::Clock;
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType};
use tracing::Instrument;

use crate::application::exchange::ExchangeJob;
use crate::application::recursor::Recursor;
use crate::application::selection::select_server;
use crate::application::single_flight::{FlightResult, OutboundKey};
use crate::domain::budget::{DescentBudget, DescentLimits};
use crate::domain::chain_material::ChainMaterial;
use crate::domain::descent::{Descent, DescentAction, DescentEvent, Observation, QueryTarget};
use crate::domain::error::{BudgetExceeded, RecursionError};
use crate::domain::ports::{ChainMaterialSink, DiagnosticsSink, InfraCache, Transport};
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
    pub(crate) used_tcp: bool,
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
            used_tcp: false,
        }
    }
}

/// Addresses a glue sub-descent found, and how long they may be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedAddresses {
    addresses: Vec<IpAddr>,
    /// The shortest TTL among the address records.
    lifetime: Duration,
}

/// A boxed descent future. Boxing is required, not chosen: a glue sub-descent is a
/// descent, so the future is recursive and must have a known size.
type DescentFuture<'a> = Pin<Box<dyn Future<Output = Result<Message, RecursionError>> + Send + 'a>>;

impl<C, T, D, M, I> Recursor<C, T, D, M, I>
where
    C: Clock,
    T: Transport + 'static,
    D: DiagnosticsSink,
    M: ChainMaterialSink,
    I: InfraCache + 'static,
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
        let mut descent = Descent::new(question, cut, self.settings.limits.max_cname_chain())
            .with_use_ipv6(self.settings.use_ipv6);
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
                    return self.finish(&mut descent, context, Ok(message));
                }
                DescentAction::Fail(error) => {
                    return self.finish(&mut descent, context, Err(error));
                }
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
        let sent = self.send(descent, server, now, context).await;
        let observation = match sent {
            Ok(observation) => observation,
            Err(exceeded) => return DescentAction::Fail(RecursionError::BudgetExceeded(exceeded)),
        };
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
    ///
    /// The exchange itself — sending, timing and recording the server's health —
    /// belongs to a task of its own (see [`ExchangeJob`]); this descent only waits
    /// for it, under its own deadline, and pays for the packets it cost.
    async fn send(
        &self,
        descent: &mut Descent,
        server: NameserverAddr,
        sent_at: Instant,
        context: &mut DescentContext,
    ) -> Result<Observation, BudgetExceeded> {
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
        let job = ExchangeJob {
            clock: Arc::clone(&self.ports.clock),
            transport: Arc::clone(&self.ports.transport),
            infra: Arc::clone(&self.ports.infra),
            stats: Arc::clone(&self.stats),
            server,
            sent,
            zone,
            edns: metrics.edns(sent_at),
        };
        let FlightResult { outcome, role } = self
            .in_flight
            .exchange(key, context.deadline, move || job.run())
            .instrument(span.clone())
            .await;
        let rtt = self
            .ports
            .clock
            .now_monotonic()
            .saturating_duration_since(sent_at);
        tracing::debug!(parent: &span, ?role, answered = outcome.is_ok(), ?rtt, "exchange");
        // The first exchange was charged before sending; every waiter pays for the
        // rest, so each descent's bound holds on its own, whoever happened to lead.
        let spent = match &outcome {
            Ok(reply) => reply.wire_exchanges,
            Err(failure) => failure.wire_exchanges,
        };
        context.budget.charge_extra(spent.saturating_sub(1))?;
        Ok(match outcome {
            Ok(reply) => {
                context.used_tcp |= reply.via_tcp;
                Observation::Reply(reply.message)
            }
            Err(failure) => Observation::Failed(failure.error),
        })
    }

    /// Looks up a glue-less nameserver's addresses with a sub-descent that spends
    /// from this descent's budget. A name already being looked up further up the
    /// stack is circular glue: it fails at once instead of looping.
    ///
    /// What the lookup finds is written back into the cached delegation, so the
    /// next descent under the same zone does not repeat it.
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
        if self.settings.use_ipv6 && matches!(&addresses, Ok(found) if found.addresses.is_empty()) {
            addresses = self
                .lookup_addresses(&name, RecordType::AAAA, context)
                .await;
        }
        context.glue_stack.pop();
        match addresses {
            Ok(found) => {
                self.remember_glue(descent, &name, &found);
                descent.provide_glue(&name, &found.addresses);
                descent.next_action()
            }
            Err(error) if is_fatal_to_parent(&error) => DescentAction::Fail(error),
            Err(_) => descent.next_action(),
        }
    }

    fn remember_glue(&self, descent: &Descent, name: &Name, found: &ResolvedAddresses) {
        if found.addresses.is_empty() || found.lifetime.is_zero() {
            return;
        }
        let now = self.ports.clock.now_monotonic();
        self.ports.infra.provide_addresses(
            &descent.current_cut().zone,
            name,
            &found.addresses,
            found.lifetime,
            now,
        );
    }

    async fn lookup_addresses(
        &self,
        name: &Name,
        qtype: RecordType,
        context: &mut DescentContext,
    ) -> Result<ResolvedAddresses, RecursionError> {
        let question = Question::new(name.clone(), qtype, RecordClass::In);
        // The nameserver's own zones are not the client's chain: their DS material
        // and transport belong to no validation or answer the client asked for.
        let outer_material = std::mem::take(&mut context.material);
        let outer_used_tcp = std::mem::replace(&mut context.used_tcp, false);
        let result = self.descend(question, context).await;
        context.material = outer_material;
        context.used_tcp = outer_used_tcp;
        let message = result?;
        let mut addresses = Vec::new();
        let mut shortest: Option<u32> = None;
        for record in &message.answers {
            let address = match record.rdata {
                RData::A(address) => IpAddr::V4(address),
                RData::Aaaa(address) => IpAddr::V6(address),
                _ => continue,
            };
            addresses.push(address);
            let seconds = record.ttl.seconds();
            shortest = Some(shortest.map_or(seconds, |current| current.min(seconds)));
        }
        Ok(ResolvedAddresses {
            addresses,
            lifetime: Duration::from_secs(u64::from(shortest.unwrap_or(0))),
        })
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

/// Whether a glue sub-descent's failure ends the parent too: its own timeout or a
/// bound the parent shares. A bound local to the sub-descent only means that one
/// nameserver name cannot be resolved, and the zone's other servers may still be.
fn is_fatal_to_parent(error: &RecursionError) -> bool {
    match error {
        RecursionError::Timeout => true,
        RecursionError::BudgetExceeded(bound) => !bound.is_local_to_descent(),
        _ => false,
    }
}

impl<C, T, D, M, I> Recursor<C, T, D, M, I>
where
    C: Clock,
    T: Transport + 'static,
    D: DiagnosticsSink,
    M: ChainMaterialSink,
    I: InfraCache + 'static,
{
    /// Ends a descent: applies the events its last step recorded — the loop only
    /// drains them at the top of an iteration, which a final step never reaches —
    /// keeps the chain material it collected, and returns its result.
    fn finish(
        &self,
        descent: &mut Descent,
        context: &mut DescentContext,
        result: Result<Message, RecursionError>,
    ) -> Result<Message, RecursionError> {
        self.apply_events(descent, context);
        context.material.extend(descent.take_chain_material());
        if let Err(error) = &result {
            tracing::debug!(%error, "descent failed");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::BudgetExceeded;

    #[test]
    fn only_a_shared_bound_or_the_deadline_ends_the_parent_descent() {
        assert!(is_fatal_to_parent(&RecursionError::Timeout));
        for shared in [
            BudgetExceeded::Depth,
            BudgetExceeded::OutboundQueries,
            BudgetExceeded::WallClock,
        ] {
            assert!(is_fatal_to_parent(&RecursionError::BudgetExceeded(shared)));
        }
        assert!(!is_fatal_to_parent(&RecursionError::BudgetExceeded(
            BudgetExceeded::CnameChain
        )));
        assert!(!is_fatal_to_parent(&RecursionError::LameDelegation));
        assert!(!is_fatal_to_parent(&RecursionError::CnameLoop));
    }
}
