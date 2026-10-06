use std::net::{IpAddr, Ipv4Addr};

use styx_proto::{RecordClass, Ttl};

use super::*;
use crate::domain::budget::DescentLimits;
use crate::domain::topology::{GlueOrigin, Nameserver, NsSet};

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn addr(last: u8) -> NameserverAddr {
    NameserverAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
}

fn cut(zone: &str, servers: &[u8]) -> ZoneCut {
    let members = servers
        .iter()
        .map(|last| Nameserver {
            name: name(&format!("ns{last}.{}", zone.trim_start_matches('.'))),
            addresses: vec![addr(*last).ip()],
            glue_origin: GlueOrigin::InBailiwickGlue,
        })
        .collect();
    ZoneCut::new(name(zone), NsSet::new(members))
}

fn record(owner: &str, rdata: RData) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        rdata.rtype(),
        RecordClass::In,
        Ttl::from_secs(300),
        rdata,
    )
}

fn reply(sent: &Question, rcode: ResponseCode, authoritative: bool) -> Message {
    let mut header = Header::new_query(1, Opcode::Query, false);
    header.kind = MessageKind::Response;
    header.rcode = rcode;
    header.authoritative = authoritative;
    let mut message = Message::new(header);
    message.questions.push(sent.clone());
    message
}

fn referral(sent: &Question, zone: &str, glue: u8) -> Message {
    let mut message = reply(sent, ResponseCode::NOERROR, false);
    let ns = format!("ns.{zone}");
    message.authorities.push(record(zone, RData::Ns(name(&ns))));
    message
        .additionals
        .push(record(&ns, RData::A(Ipv4Addr::new(192, 0, 2, glue))));
    message
}

struct Harness {
    descent: Descent,
    budget: DescentBudget,
    now: Instant,
}

impl Harness {
    fn new(qname: &str, qtype: RecordType, start: ZoneCut) -> Self {
        let now = Instant::now();
        let question = Question::new(name(qname), qtype, RecordClass::In);
        Self {
            descent: Descent::new(question, start, 8),
            budget: DescentBudget::new(DescentLimits::default(), now),
            now,
        }
    }

    fn send(&mut self, server: NameserverAddr) -> Question {
        self.descent.compose(server, MinimisationVerdict::Unknown)
    }

    fn observe(&mut self, observation: Observation) -> DescentAction {
        self.descent
            .observe(observation, &mut self.budget, self.now)
    }

    fn metric_events(&mut self) -> Vec<MetricEvent> {
        self.descent
            .drain_events()
            .into_iter()
            .filter_map(|event| match event {
                DescentEvent::Metric(_, metric) => Some(metric),
                _ => None,
            })
            .collect()
    }
}

#[test]
fn a_cold_descent_asks_each_zone_one_label_and_answers_from_the_last() {
    let mut harness = Harness::new("www.example.com.", RecordType::A, cut(".", &[1]));

    let first = harness.send(addr(1));
    assert_eq!(
        (first.qname.to_string(), first.qtype),
        ("com.".into(), RecordType::NS)
    );
    let action = harness.observe(Observation::Reply(referral(&first, "com.", 2)));
    assert_eq!(action, DescentAction::Query(QueryTarget::AnyServer));

    let second = harness.send(addr(2));
    assert_eq!(second.qname.to_string(), "example.com.");
    harness.observe(Observation::Reply(referral(&second, "example.com.", 3)));

    let last = harness.send(addr(3));
    assert_eq!(
        (last.qname.to_string(), last.qtype),
        ("www.example.com.".into(), RecordType::A)
    );
    let mut answer = reply(&last, ResponseCode::NOERROR, true);
    answer.answers.push(record(
        "www.example.com.",
        RData::A(Ipv4Addr::new(203, 0, 113, 1)),
    ));
    let DescentAction::Answer(response) = harness.observe(Observation::Reply(answer)) else {
        panic!("expected an answer");
    };
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.questions[0].qname, name("www.example.com."));
}

#[test]
fn a_refusal_retries_the_same_server_in_full_and_success_writes_a_verdict() {
    let mut harness = Harness::new("www.example.com.", RecordType::A, cut(".", &[1]));
    let minimised = harness.send(addr(1));
    let refused = reply(&minimised, ResponseCode::REFUSED, false);
    assert_eq!(
        harness.observe(Observation::Reply(refused)),
        DescentAction::Query(QueryTarget::SameServer(addr(1)))
    );
    assert!(harness
        .descent
        .drain_events()
        .contains(&DescentEvent::MinimisationFallback));

    let full = harness.send(addr(1));
    assert_eq!(full.qname, name("www.example.com."));
    harness.observe(Observation::Reply(referral(&full, "com.", 2)));
    assert!(harness
        .metric_events()
        .iter()
        .any(|event| matches!(event, MetricEvent::MishandlesMinimised(_))));
}

#[test]
fn a_timeout_moves_on_and_never_writes_a_verdict() {
    let mut harness = Harness::new("www.example.com.", RecordType::A, cut(".", &[1, 2]));
    harness.send(addr(1));
    assert_eq!(
        harness.observe(Observation::Failed(TransportError::Timeout)),
        DescentAction::Query(QueryTarget::AnyServer)
    );
    assert_eq!(
        harness.descent.current_cut().nameservers.untried(),
        vec![addr(2)]
    );
    let events = harness.metric_events();
    assert_eq!(events, vec![MetricEvent::Failure]);
}

#[test]
fn an_intermediate_nxdomain_is_the_answer_without_a_full_qname_query() {
    let mut harness = Harness::new("a.b.missing.com.", RecordType::A, cut("com.", &[2]));
    let sent = harness.send(addr(2));
    assert_eq!(sent.qname, name("missing.com."));
    let mut nxdomain = reply(&sent, ResponseCode::NXDOMAIN, true);
    nxdomain.authorities.push(record(
        "com.",
        RData::Soa(styx_proto::SoaRdata::new(
            name("a.com."),
            name("b.com."),
            1,
            2,
            3,
            4,
            5,
        )),
    ));
    let DescentAction::Answer(response) = harness.observe(Observation::Reply(nxdomain)) else {
        panic!("expected an answer");
    };
    assert_eq!(response.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(
        response.authorities.len(),
        1,
        "the SOA rides along for negative caching"
    );
}

#[test]
fn every_server_lame_fails_as_a_lame_delegation() {
    let mut harness = Harness::new(
        "www.example.com.",
        RecordType::A,
        cut("example.com.", &[3, 4]),
    );
    for server in [addr(3), addr(4)] {
        let sent = harness.send(server);
        let lame = reply(&sent, ResponseCode::NOERROR, false);
        let action = harness.observe(Observation::Reply(lame));
        if server == addr(4) {
            assert_eq!(action, DescentAction::Fail(RecursionError::LameDelegation));
        }
    }
}

#[test]
fn a_final_cname_follows_and_carries_the_alias_record() {
    let mut harness = Harness::new("www.example.com.", RecordType::A, cut("example.com.", &[3]));
    let sent = harness.send(addr(3));
    let mut alias = reply(&sent, ResponseCode::NOERROR, true);
    alias.answers.push(record(
        "www.example.com.",
        RData::Cname(name("edge.cdn.net.")),
    ));
    assert_eq!(
        harness.observe(Observation::Reply(alias)),
        DescentAction::FollowCname(name("edge.cdn.net."))
    );
    harness.descent.restart_at(cut("cdn.net.", &[5]));

    let next = harness.send(addr(5));
    assert_eq!(next.qname, name("edge.cdn.net."));
    let mut answer = reply(&next, ResponseCode::NOERROR, true);
    answer.answers.push(record(
        "edge.cdn.net.",
        RData::A(Ipv4Addr::new(203, 0, 113, 9)),
    ));
    let DescentAction::Answer(response) = harness.observe(Observation::Reply(answer)) else {
        panic!("expected an answer");
    };
    let owners: Vec<String> = response
        .answers
        .iter()
        .map(|r| r.owner.to_string())
        .collect();
    assert_eq!(owners, ["www.example.com.", "edge.cdn.net."]);
}

#[test]
fn a_glueless_cut_asks_for_glue_then_gives_up() {
    let glueless = ZoneCut::new(
        name("example.com."),
        NsSet::new(vec![Nameserver {
            name: name("ns.example.net."),
            addresses: Vec::new(),
            glue_origin: GlueOrigin::ResolvedSeparately,
        }]),
    );
    let mut harness = Harness::new("www.example.com.", RecordType::A, glueless);
    assert_eq!(
        harness.descent.next_action(),
        DescentAction::ResolveGlue(name("ns.example.net."))
    );
    assert_eq!(
        harness.descent.next_action(),
        DescentAction::Fail(RecursionError::NoReachableNameserver { at_root: false })
    );
}

#[test]
fn depth_runs_out() {
    let mut harness = Harness::new("a.b.c.example.", RecordType::A, cut(".", &[1]));
    harness.budget = DescentBudget::new(
        DescentLimits::new(1, 64, 8, Duration::from_secs(4)).unwrap(),
        harness.now,
    );
    let first = harness.send(addr(1));
    harness.observe(Observation::Reply(referral(&first, "example.", 2)));
    let second = harness.send(addr(2));
    assert_eq!(
        harness.observe(Observation::Reply(referral(&second, "c.example.", 3))),
        DescentAction::Fail(RecursionError::BudgetExceeded(
            crate::domain::error::BudgetExceeded::Depth
        ))
    );
}

#[test]
fn ds_material_arriving_unasked_in_a_referral_is_kept() {
    let mut harness = Harness::new("www.example.com.", RecordType::A, cut("com.", &[2]));
    let sent = harness.send(addr(2));
    let mut signed = referral(&sent, "example.com.", 3);
    let ds = styx_proto::DsRdata::new(12345, 13, 2, vec![0xAB; 32]);
    signed
        .authorities
        .push(record("example.com.", RData::Ds(ds)));
    harness.observe(Observation::Reply(signed));

    let material = harness.descent.take_chain_material();
    let referrals = material.referrals();
    assert_eq!(referrals.len(), 1);
    assert_eq!(referrals[0].parent_zone, name("com."));
    assert_eq!(referrals[0].child_zone, name("example.com."));
    assert_eq!(referrals[0].ds_records.len(), 1);
}

#[test]
fn a_positive_answer_carries_no_authority_section() {
    let mut harness = Harness::new("www.example.com.", RecordType::A, cut("example.com.", &[3]));
    let sent = harness.send(addr(3));
    let mut answer = reply(&sent, ResponseCode::NOERROR, true);
    answer.answers.push(record(
        "www.example.com.",
        RData::A(Ipv4Addr::new(203, 0, 113, 2)),
    ));
    answer
        .authorities
        .push(record("example.com.", RData::Ns(name("ns3.example.com."))));
    let DescentAction::Answer(response) = harness.observe(Observation::Reply(answer)) else {
        panic!("expected an answer");
    };
    assert!(response.authorities.is_empty());
}
