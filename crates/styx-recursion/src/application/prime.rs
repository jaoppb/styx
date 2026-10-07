//! One priming attempt: ask root servers for the root NS set and install it.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_core::Clock;
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType, ResponseCode, Ttl};

use crate::application::diagnostics::DiagnosticsState;
use crate::application::priming::PrimeOutcome;
use crate::domain::metrics::MetricEvent;
use crate::domain::ports::{InfraCache, Transport};
use crate::domain::root_hints::RootHints;
use crate::domain::topology::{Delegation, GlueOrigin, Nameserver};

/// Root servers asked per priming attempt before giving up until the backoff ends.
pub const PRIMING_ATTEMPTS: usize = 3;

/// Longest a priming attempt may take, whatever any caller's deadline.
pub const PRIMING_DEADLINE: Duration = Duration::from_secs(2);

/// Shortest lifetime given to a primed root NS set, so a server returning a tiny
/// TTL cannot make every descent re-prime.
pub const PRIMING_MIN_TTL: Duration = Duration::from_secs(300);

/// The collaborators of one attempt, owned so the attempt runs as a task of its own.
pub(crate) struct PrimeJob<C, T, I> {
    pub(crate) clock: Arc<C>,
    pub(crate) transport: Arc<T>,
    pub(crate) infra: Arc<I>,
    pub(crate) stats: Arc<DiagnosticsState>,
    pub(crate) use_ipv6: bool,
    pub(crate) hints: RootHints,
}

impl<C: Clock, T: Transport, I: InfraCache> PrimeJob<C, T, I> {
    /// Asks up to [`PRIMING_ATTEMPTS`] root servers for the root NS set and installs
    /// the first usable answer, within [`PRIMING_DEADLINE`].
    pub(crate) async fn run(self) -> PrimeOutcome {
        let started = self.clock.now_monotonic();
        let deadline = started.checked_add(PRIMING_DEADLINE).unwrap_or(started);
        let root = self.infra.closest_enclosing_cut(&Name::root(), started);
        let question = Question::new(Name::root(), RecordType::NS, RecordClass::In);
        let candidates = root
            .nameservers
            .untried()
            .into_iter()
            .filter(|server| self.use_ipv6 || server.ip().is_ipv4())
            .take(PRIMING_ATTEMPTS);
        for server in candidates {
            if let Some(outcome) = self.ask(server, &question, deadline).await {
                return outcome;
            }
        }
        tracing::warn!("priming failed: no root server answered; using root hints");
        PrimeOutcome::Failed
    }

    /// Asks one root server; `Some` when it gave a usable root NS set.
    async fn ask(
        &self,
        server: crate::domain::topology::NameserverAddr,
        question: &Question,
        deadline: Instant,
    ) -> Option<PrimeOutcome> {
        let sent_at = self.clock.now_monotonic();
        let edns = self.infra.metrics(server, sent_at).edns(sent_at);
        let reply = self.transport.query(server, question, edns, deadline).await;
        let now = self.clock.now_monotonic();
        let Ok(reply) = reply else {
            self.stats.record_root_contact(server.ip(), None, now);
            self.infra.update_metrics(server, MetricEvent::Failure, now);
            return None;
        };
        let rtt = now.saturating_duration_since(sent_at);
        self.stats.record_root_contact(server.ip(), Some(rtt), now);
        self.stats.note_reply(now);
        self.infra
            .update_metrics(server, MetricEvent::Success(rtt), now);
        let live = root_ns_set(&reply.message, now)?;
        let delegation = union_with_hints(live, &self.hints.to_delegation(now));
        let lifetime = ttl_duration(delegation.ttl()).max(PRIMING_MIN_TTL);
        self.stats.set_root_servers(delegation.nameservers());
        self.stats.record_priming(now);
        self.infra.put_delegation(delegation);
        tracing::debug!(%server, "root NS set primed");
        Some(PrimeOutcome::Primed(
            now.checked_add(lifetime).unwrap_or(now),
        ))
    }
}

/// The root NS set from a priming response: the root's NS records, with addresses
/// from the additional section (the root may vouch for any name).
///
/// Only an authoritative, complete answer counts: the root set is installed without
/// an expiry, so a non-authoritative or truncated one — from a cache, a middlebox
/// or a forger — must not be able to replace it.
fn root_ns_set(message: &Message, now: Instant) -> Option<Delegation> {
    if message.header.rcode != ResponseCode::NOERROR
        || !message.header.authoritative
        || message.header.truncated
    {
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

/// The live root set with every hint server it lacks added back, and every hint
/// address a live server lacks added to it. A live answer that names few servers,
/// or only ones a forger controls, can then add to the root set but never shrink it
/// below the hints; a server IANA retires lingers until the hints file is updated.
fn union_with_hints(live: Delegation, hints: &Delegation) -> Delegation {
    let mut nameservers = live.nameservers().to_vec();
    for hinted in hints.nameservers() {
        match nameservers
            .iter_mut()
            .find(|member| member.name.eq_ignore_case(&hinted.name))
        {
            Some(member) => member.add_addresses(&hinted.addresses),
            None => nameservers.push(hinted.clone()),
        }
    }
    Delegation::new(
        Name::root(),
        Name::root(),
        nameservers,
        live.ttl(),
        live.learned_at(),
    )
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

#[cfg(test)]
#[path = "prime_tests.rs"]
mod tests;
