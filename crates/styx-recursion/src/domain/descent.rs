//! `Descent`: the I/O-free state machine for one client question.
//!
//! Fed the outcome of each query, it says what to do next. It never touches a
//! socket, a clock or a cache: time, the chosen server and that server's verdict
//! arrive as parameters, and what it learns leaves as [`DescentEvent`]s the driver
//! applies. That is what makes the resolver's correctness testable without a
//! network.

use std::time::{Duration, Instant};

use styx_proto::{
    Header, Message, MessageKind, Name, Opcode, Question, RData, RecordType, ResourceRecord,
    ResponseCode,
};

use crate::domain::bailiwick::is_in_bailiwick;
use crate::domain::budget::DescentBudget;
use crate::domain::chain_material::{ChainMaterial, SignedReferral};
use crate::domain::classify::{classify, AliasKind, AliasLink, ResponseKind};
use crate::domain::cname_chain::CnameChain;
use crate::domain::error::RecursionError;
use crate::domain::metrics::{MetricEvent, MinimisationVerdict};
use crate::domain::minimisation::{BadResponse, FallbackDecision, MinimisationState};
use crate::domain::ports::TransportError;
use crate::domain::topology::{Delegation, NameserverAddr, ZoneCut};

/// How long a `MishandlesMinimised` verdict lasts. Long enough that a broken server
/// is not re-tested on every query, short enough that a server that gets fixed
/// regains minimised queries within the hour.
pub const MINIMISATION_VERDICT_TTL: Duration = Duration::from_secs(3600);

/// How long a server stays marked lame for a zone. Fifteen minutes matches common
/// resolver practice: lameness is often a transient misconfiguration.
pub const LAME_TTL: Duration = Duration::from_secs(900);

/// Which server the next query must go to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryTarget {
    /// Any untried server of the current cut, chosen by the driver.
    AnyServer,
    /// This server again, with the next composed question.
    SameServer(NameserverAddr),
}

/// What the driver must do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescentAction {
    /// Compose a question with [`Descent::compose`] and send it.
    Query(QueryTarget),
    /// Look up this nameserver's addresses with a sub-descent sharing the budget,
    /// then report them with [`Descent::provide_glue`].
    ResolveGlue(Name),
    /// The descent was redirected to this name outside the current zone: find its
    /// closest known cut and continue with [`Descent::restart_at`].
    FollowCname(Name),
    /// The final response for the client.
    Answer(Message),
    /// The descent failed.
    Fail(RecursionError),
}

/// Something the descent learned, for the driver to apply to the infrastructure
/// cache and the diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescentEvent {
    /// A delegation learned from a referral.
    Delegation(Delegation),
    /// An observation about one nameserver.
    Metric(NameserverAddr, MetricEvent),
    /// The descent fell back to sending the full qname.
    MinimisationFallback,
}

/// The outcome of one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// A response arrived.
    Reply(Message),
    /// No usable response arrived.
    Failed(TransportError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Outstanding {
    server: NameserverAddr,
    sent: Question,
}

/// The state of one client question's descent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descent {
    original: Question,
    cut: ZoneCut,
    minimisation: MinimisationState,
    cname_chain: CnameChain,
    aliases: Vec<ResourceRecord>,
    collected: ChainMaterial,
    events: Vec<DescentEvent>,
    outstanding: Option<Outstanding>,
    last_error: Option<RecursionError>,
}

impl Descent {
    /// Starts a descent for `question` from `cut`.
    #[must_use]
    pub fn new(question: Question, cut: ZoneCut, max_cname_chain: u8) -> Self {
        let minimisation =
            MinimisationState::new(question.qname.clone(), question.qtype, &cut.zone);
        Self {
            cname_chain: CnameChain::new(question.qname.clone(), max_cname_chain),
            original: question,
            cut,
            minimisation,
            aliases: Vec::new(),
            collected: ChainMaterial::default(),
            events: Vec::new(),
            outstanding: None,
            last_error: None,
        }
    }

    /// The cut being asked.
    #[must_use]
    pub const fn current_cut(&self) -> &ZoneCut {
        &self.cut
    }

    /// The name being resolved now: the client's qname, or an alias target.
    #[must_use]
    pub const fn target(&self) -> &Name {
        self.minimisation.target()
    }

    /// The client's question.
    #[must_use]
    pub const fn original(&self) -> &Question {
        &self.original
    }

    /// Composes the question for `server`, whose verdict is `verdict`. Every
    /// outbound question goes through here, and so through minimisation.
    pub fn compose(&mut self, server: NameserverAddr, verdict: MinimisationVerdict) -> Question {
        let sent = self.minimisation.next_question(&self.cut.zone, verdict);
        self.outstanding = Some(Outstanding {
            server,
            sent: sent.clone(),
        });
        sent
    }

    /// Decides the next step when no query is outstanding: query an untried
    /// server, look up a nameserver's address, or give up.
    pub fn next_action(&mut self) -> DescentAction {
        if !self.cut.nameservers.untried().is_empty() {
            return DescentAction::Query(QueryTarget::AnyServer);
        }
        if let Some(name) = self.cut.nameservers.next_unresolved() {
            self.cut.nameservers.mark_lookup_attempted(&name);
            return DescentAction::ResolveGlue(name);
        }
        let fallback = RecursionError::NoReachableNameserver {
            at_root: self.cut.is_root,
        };
        DescentAction::Fail(self.last_error.take().unwrap_or(fallback))
    }

    /// Skips `server` without querying it — lame for this zone, say.
    pub fn skip_server(&mut self, server: NameserverAddr) {
        self.cut.nameservers.mark_tried(server);
    }

    /// Supplies addresses looked up for a glue-less nameserver.
    pub fn provide_glue(&mut self, name: &Name, addresses: &[std::net::IpAddr]) {
        self.cut.nameservers.provide_addresses(name, addresses);
    }

    /// Continues from `cut` after a [`DescentAction::FollowCname`].
    pub fn restart_at(&mut self, cut: ZoneCut) {
        self.minimisation.enter_cut(&cut.zone);
        self.cut = cut;
        self.last_error = None;
    }

    /// Takes the events recorded since the last call.
    pub fn drain_events(&mut self) -> Vec<DescentEvent> {
        std::mem::take(&mut self.events)
    }

    /// Takes the DNSSEC material collected so far.
    pub fn take_chain_material(&mut self) -> ChainMaterial {
        std::mem::take(&mut self.collected)
    }

    /// Feeds the outcome of the outstanding query and returns the next step.
    pub fn observe(
        &mut self,
        observation: Observation,
        budget: &mut DescentBudget,
        now: Instant,
    ) -> DescentAction {
        let Some(outstanding) = self.outstanding.take() else {
            return DescentAction::Fail(RecursionError::Malformed);
        };
        let message = match observation {
            Observation::Reply(message) => message,
            Observation::Failed(error) => return self.server_failed(&outstanding, error),
        };
        let intermediate = self.minimisation.is_intermediate(&outstanding.sent);
        let kind = classify(
            &self.cut.zone,
            &outstanding.sent,
            intermediate,
            &message,
            now,
        );
        let answered = matches!(
            kind,
            ResponseKind::Referral(_) | ResponseKind::AuthoritativeAnswer | ResponseKind::Alias(_)
        );
        if self.minimisation.fallback_proved_mishandling(answered) {
            let until = now.checked_add(MINIMISATION_VERDICT_TTL).unwrap_or(now);
            self.metric(outstanding.server, MetricEvent::MishandlesMinimised(until));
        }
        self.dispatch(kind, &outstanding, intermediate, &message, budget, now)
    }

    fn dispatch(
        &mut self,
        kind: ResponseKind,
        outstanding: &Outstanding,
        intermediate: bool,
        message: &Message,
        budget: &mut DescentBudget,
        now: Instant,
    ) -> DescentAction {
        let server = outstanding.server;
        match kind {
            ResponseKind::Referral(delegation) => {
                self.on_referral(server, delegation, intermediate, budget)
            }
            ResponseKind::AuthoritativeAnswer => {
                DescentAction::Answer(self.build_answer(message, ResponseCode::NOERROR))
            }
            ResponseKind::Alias(link) => self.on_alias(server, link, intermediate),
            ResponseKind::NoDataAtEmptyNonTerminal => {
                self.metric(server, MetricEvent::HandlesMinimised);
                self.minimisation.advance_past_empty_non_terminal();
                DescentAction::Query(QueryTarget::AnyServer)
            }
            ResponseKind::NameError => {
                let _ = self
                    .minimisation
                    .on_bad_response(BadResponse::NameError, &outstanding.sent);
                DescentAction::Answer(self.build_answer(message, ResponseCode::NXDOMAIN))
            }
            ResponseKind::MinimisationRefused => self.on_refused(outstanding),
            ResponseKind::ServerFailure => {
                self.minimisation
                    .on_bad_response(BadResponse::ServerFailure, &outstanding.sent);
                self.metric(server, MetricEvent::Failure);
                self.leave(server, None)
            }
            ResponseKind::Lame => {
                let until = now.checked_add(LAME_TTL).unwrap_or(now);
                self.metric(server, MetricEvent::LameFor(self.cut.zone.clone(), until));
                self.leave(server, Some(RecursionError::LameDelegation))
            }
            ResponseKind::Truncated => self.leave(server, Some(RecursionError::Truncated)),
            ResponseKind::Malformed => self.leave(server, Some(RecursionError::Malformed)),
        }
    }

    fn on_referral(
        &mut self,
        server: NameserverAddr,
        delegation: Delegation,
        intermediate: bool,
        budget: &mut DescentBudget,
    ) -> DescentAction {
        if let Err(exceeded) = budget.descend() {
            return DescentAction::Fail(RecursionError::BudgetExceeded(exceeded));
        }
        if intermediate {
            self.metric(server, MetricEvent::HandlesMinimised);
        }
        self.collected.push_referral(SignedReferral {
            parent_zone: self.cut.zone.clone(),
            child_zone: delegation.child_zone().clone(),
            ds_records: delegation.ds_records().to_vec(),
        });
        if self.original.qtype == RecordType::DS && delegation.child_zone() == self.target() {
            return DescentAction::Answer(self.ds_from_referral(&delegation));
        }
        self.cut = delegation.to_cut();
        self.minimisation.enter_cut(&self.cut.zone);
        self.last_error = None;
        self.events.push(DescentEvent::Delegation(delegation));
        self.next_action()
    }

    fn on_alias(
        &mut self,
        server: NameserverAddr,
        link: AliasLink,
        intermediate: bool,
    ) -> DescentAction {
        if intermediate && link.kind == AliasKind::Cname {
            // A CNAME at an intermediate label redirects only that name, not the
            // names below it: descend one more label, as for an empty non-terminal.
            self.minimisation.advance_past_empty_non_terminal();
            return DescentAction::Query(QueryTarget::AnyServer);
        }
        if intermediate {
            // A DNAME above the target redirects the whole subtree. This server is
            // authoritative for the zone holding the target, so asking it the full
            // question leaks nothing it was not already entitled to see.
            self.minimisation.advance_to_target();
            return DescentAction::Query(QueryTarget::SameServer(server));
        }
        if let Err(error) = self.cname_chain.push(link.target.clone()) {
            return DescentAction::Fail(error);
        }
        self.aliases.extend(link.records);
        self.minimisation
            .retarget(link.target.clone(), &self.cut.zone);
        DescentAction::FollowCname(link.target)
    }

    fn on_refused(&mut self, outstanding: &Outstanding) -> DescentAction {
        match self
            .minimisation
            .on_bad_response(BadResponse::Refused, &outstanding.sent)
        {
            FallbackDecision::RetryFullQnameSameServer => {
                self.events.push(DescentEvent::MinimisationFallback);
                DescentAction::Query(QueryTarget::SameServer(outstanding.server))
            }
            FallbackDecision::TryNextServer | FallbackDecision::AcceptAsGenuine => {
                self.leave(outstanding.server, None)
            }
        }
    }

    fn server_failed(&mut self, outstanding: &Outstanding, error: TransportError) -> DescentAction {
        self.minimisation
            .on_bad_response(BadResponse::ServerFailure, &outstanding.sent);
        let recorded = match error {
            TransportError::Timeout | TransportError::Unreachable(_) => {
                self.metric(outstanding.server, MetricEvent::Failure);
                None
            }
            TransportError::Malformed => Some(RecursionError::Malformed),
            TransportError::Truncated => Some(RecursionError::Truncated),
        };
        self.leave(outstanding.server, recorded)
    }

    /// Gives up on `server` for this cut, remembering why, and moves on.
    fn leave(&mut self, server: NameserverAddr, error: Option<RecursionError>) -> DescentAction {
        self.cut.nameservers.mark_tried(server);
        if error.is_some() {
            self.last_error = error;
        }
        self.next_action()
    }

    fn metric(&mut self, server: NameserverAddr, event: MetricEvent) {
        self.events.push(DescentEvent::Metric(server, event));
    }

    /// A DS question answered by the parent's referral, which carries the DS RRset
    /// (or, for an unsigned delegation, nothing: NODATA).
    fn ds_from_referral(&self, delegation: &Delegation) -> Message {
        let mut response = self.response_skeleton(ResponseCode::NOERROR);
        response.answers.extend(self.aliases.iter().cloned());
        response.answers.extend(
            delegation
                .ds_records()
                .iter()
                .filter(|record| matches!(record.rdata, RData::Ds(_)))
                .cloned(),
        );
        response
    }

    /// The client's response: the alias records followed, then the records for the
    /// final name that the answering server was entitled to give — and, only when
    /// there are none, the negative proof (SOA, NSEC/NSEC3 and their signatures)
    /// from its own zone. A positive answer carries no authority section: the
    /// answer cache admits nothing else there, and nothing else is needed.
    fn build_answer(&self, message: &Message, rcode: ResponseCode) -> Message {
        let target = self.target();
        let qtype = self.original.qtype;
        let mut response = self.response_skeleton(rcode);
        let records: Vec<ResourceRecord> = message
            .answers
            .iter()
            .filter(|record| record.owner == *target && answers_type(record, qtype))
            .filter(|record| is_in_bailiwick(&self.cut.zone, &record.owner))
            .cloned()
            .collect();
        if records.is_empty() {
            response.authorities = message
                .authorities
                .iter()
                .filter(|record| is_in_bailiwick(&self.cut.zone, &record.owner))
                .filter(|record| is_negative_proof(record))
                .cloned()
                .collect();
        }
        response.answers.extend(self.aliases.iter().cloned());
        response.answers.extend(records);
        response
    }

    fn response_skeleton(&self, rcode: ResponseCode) -> Message {
        let mut header = Header::new_query(0, Opcode::Query, true);
        header.kind = MessageKind::Response;
        header.recursion_available = true;
        header.rcode = rcode;
        let mut response = Message::new(header);
        response.questions.push(self.original.clone());
        response
    }
}

fn answers_type(record: &ResourceRecord, qtype: RecordType) -> bool {
    record.rtype == qtype
        || matches!(&record.rdata, RData::Rrsig(signature) if signature.type_covered() == qtype)
}

fn is_negative_proof(record: &ResourceRecord) -> bool {
    let proof = |rtype| {
        matches!(
            rtype,
            RecordType::SOA | RecordType::NSEC | RecordType::NSEC3
        )
    };
    match &record.rdata {
        RData::Rrsig(signature) => proof(signature.type_covered()),
        _ => proof(record.rtype),
    }
}

#[cfg(test)]
#[path = "descent_tests.rs"]
mod tests;
