//! Issue #133's acceptance, over real sockets: a client asks a bound server whose cache
//! stage validates with `styx-dnssec` through the pool chain source, and a fake validating
//! forwarder serves a signed zone, `com.` under a test root anchor.
//!
//! A signed answer reaches the client with AD=1; a bogus one (signed by a key `com.` never
//! published) is SERVFAIL under `HardFail` and served with AD clear under `WarnOnly`; and a
//! forwarder that strips DNSSEC yields no AD and, under `HardFail`, SERVFAIL — never a reply
//! that passes for an unsigned zone.

use std::sync::Arc;
use std::time::Duration;

use styx_core::test_util::TestClock;
use styx_core::{SystemSleeper, UpstreamId};
use styx_dnssec::{FailureMode, ValidationPolicy};
use styx_proto::{Header, Message, Opcode, Opt, Question, RecordClass, RecordType, ResponseCode};
use styx_resolution::{
    AllowAllFilter, CacheStage, CanaryConfig, CircuitConfig, DiscardObserver, Do53Forwarder,
    EdnsBufferSize, NoLocalRecords, OrderedFailover, Pipeline, PoolMember, ProbeConfig,
    ProbePolicy, Server, ServerConfig, ShardedAnswerCache, UpstreamPool, Weight,
};
use styx_testkit::{DnsClient, FakeNameServer, FakeRole, ZoneScript};

use super::test_zone::{a_record, clock, name, nsec, ZoneKey};
use super::{DnssecValidator, PoolChainSource, PushedReferrals};

const SIGNED: &str = "www.com.";
const BOGUS: &str = "bogus.com.";

type Pool = UpstreamPool<OrderedFailover, Do53Forwarder<TestClock>, TestClock>;
type Validator = DnssecValidator<
    TestClock,
    PoolChainSource<OrderedFailover, Do53Forwarder<TestClock>, TestClock>,
>;
type Stage = CacheStage<
    ShardedAnswerCache<TestClock>,
    OrderedFailover,
    Do53Forwarder<TestClock>,
    TestClock,
    Validator,
>;
type TestServer = Server<NoLocalRecords, AllowAllFilter, DiscardObserver, TestClock, Stage>;

/// What a validating forwarder answers for a signed `com.` under `root`: the chain from the
/// root down, a signed `www.com.`, and `bogus.com.` signed by a key nobody published.
fn signed_world(root: &ZoneKey, com: &ZoneKey, stripped: bool) -> ZoneScript {
    let forger = ZoneKey::generate("com.");
    let www = name(SIGNED);
    let bogus = name(BOGUS);
    let not_a_cut = |owner: &str| {
        com.signed(vec![nsec(
            &name(owner),
            &name("zzz.com."),
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        )])
    };
    let mut script = ZoneScript::new()
        .origin("com.", 300)
        .denial(SIGNED, RecordType::DS, not_a_cut(SIGNED))
        .denial(BOGUS, RecordType::DS, not_a_cut(BOGUS))
        .answer(BOGUS, RecordType::A, forger.signed(vec![a_record(&bogus)]));
    let chain = [
        (".", RecordType::DNSKEY, root.dnskey_rrset()),
        ("com.", RecordType::DS, root.signed(vec![com.ds_record()])),
        ("com.", RecordType::DNSKEY, com.dnskey_rrset()),
        (SIGNED, RecordType::A, com.signed(vec![a_record(&www)])),
    ];
    for (owner, rtype, records) in chain {
        let records = if stripped {
            records
                .into_iter()
                .filter(|r| r.rtype != RecordType::RRSIG)
                .collect()
        } else {
            records
        };
        script = script.answer(owner, rtype, records);
    }
    script
}

fn pool_to(upstream: &FakeNameServer, clock: &Arc<TestClock>) -> Arc<Pool> {
    let id = UpstreamId::new("validating-forwarder");
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        Duration::from_millis(500),
        Duration::from_millis(500),
        Arc::clone(clock),
    );
    let canary = CanaryConfig {
        qname: name("canary.check."),
        qtype: RecordType::A,
        timeout: Duration::from_millis(500),
    };
    Arc::new(UpstreamPool::new(
        vec![PoolMember::new(id, forwarder, Weight::new(1), canary)],
        OrderedFailover::new(),
        Arc::clone(clock),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    ))
}

struct Fixture {
    upstream: FakeNameServer,
    server: TestServer,
}

impl Fixture {
    async fn boot(mode: FailureMode, stripped: bool) -> Self {
        let root = ZoneKey::generate(".");
        let com = ZoneKey::generate("com.");
        let upstream =
            FakeNameServer::start(FakeRole::Authoritative, signed_world(&root, &com, stripped))
                .await
                .unwrap();
        let clock = Arc::new(clock());
        let pool = pool_to(&upstream, &clock);
        let anchors = root.anchors();
        let policy = ValidationPolicy {
            failure_mode: mode,
            ..ValidationPolicy::default()
        };
        let source = PoolChainSource::new(
            Arc::clone(&pool),
            Arc::new(PushedReferrals::new(Arc::clone(&clock))),
            Arc::clone(&clock),
            Duration::from_secs(1),
            &anchors,
            policy.nsec3_max_iterations,
        );
        let validator = DnssecValidator::new(super::test_zone::clock(), policy, anchors, source);
        let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
        let stage = CacheStage::new(cache, pool, Arc::clone(&clock), Duration::from_secs(2))
            .with_validator(Arc::new(validator));
        let pipeline = Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            Arc::clone(&clock),
        )
        .with_terminal(Arc::new(stage));
        let config = ServerConfig::from_toml_str("listen_addrs = [\"127.0.0.1:0\"]").unwrap();
        let server = Server::bind(
            config,
            Arc::new(pipeline),
            clock,
            Arc::new(SystemSleeper::new()),
        )
        .await
        .unwrap();
        Self { upstream, server }
    }

    async fn ask(&self, qname: &str) -> Message {
        let mut query = Message::new(Header::new_query(0x5150, Opcode::Query, true));
        query
            .questions
            .push(Question::new(name(qname), RecordType::A, RecordClass::In));
        query.opt = Some(Opt::new(1232, 0, true, Vec::new()));
        let server = *self.server.local_addrs().first().unwrap();
        DnsClient::new().query_udp(server, &query).await.unwrap()
    }

    async fn shutdown(mut self) {
        self.server.shutdown().await.unwrap();
        self.upstream.shutdown();
    }
}

#[tokio::test]
async fn a_signed_answer_reaches_the_client_with_ad_set() {
    let fixture = Fixture::boot(FailureMode::HardFail, false).await;

    let reply = fixture.ask(SIGNED).await;

    assert_eq!(reply.header.rcode, ResponseCode::NOERROR);
    assert!(reply.header.authentic_data);
    assert!(reply
        .answers
        .iter()
        .any(|record| record.rtype == RecordType::RRSIG));
    fixture.shutdown().await;
}

#[tokio::test]
async fn a_bogus_answer_is_servfail_under_hard_fail() {
    let fixture = Fixture::boot(FailureMode::HardFail, false).await;

    let reply = fixture.ask(BOGUS).await;

    assert_eq!(reply.header.rcode, ResponseCode::SERVFAIL);
    assert!(reply.answers.is_empty());
    assert!(!reply.header.authentic_data);
    fixture.shutdown().await;
}

#[tokio::test]
async fn a_bogus_answer_is_served_with_ad_clear_under_warn_only() {
    let fixture = Fixture::boot(FailureMode::WarnOnly, false).await;

    let reply = fixture.ask(BOGUS).await;

    assert_eq!(reply.header.rcode, ResponseCode::NOERROR);
    assert!(!reply.header.authentic_data);
    assert!(reply
        .answers
        .iter()
        .any(|record| record.rtype == RecordType::A));
    fixture.shutdown().await;
}

/// 6d.3: a forwarder that strips DNSSEC is ChainMaterialUnavailable, Indeterminate, which
/// HardFail refuses; were it taken for an unsigned zone the answer would pass as Insecure.
#[tokio::test]
async fn a_dnssec_stripping_forwarder_never_passes_for_an_unsigned_zone() {
    let fixture = Fixture::boot(FailureMode::HardFail, true).await;

    let reply = fixture.ask(SIGNED).await;

    assert_eq!(reply.header.rcode, ResponseCode::SERVFAIL);
    assert!(!reply.header.authentic_data);
    fixture.shutdown().await;
}
