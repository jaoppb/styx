//! How the cache stage turns a DNSSEC verdict into a reply (Phase 06, 6d.5 and 6d.6).
//!
//! The validator is a test double returning a scripted verdict, so these tests pin the
//! stage's half of the contract — AD, SERVFAIL, CD, caching and the signature bound — over
//! real sockets, apart from whether any signature verifies.

// The helpers below sit outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

mod harness;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use harness::{DnsClient, TestClock, TestServer};
use styx_core::UpstreamId;
use styx_proto::{
    Header, Message, Name, Opcode, Opt, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, RrsigRdata, Ttl,
};
use styx_resolution::{
    AllowAllFilter, AnswerCache, CacheStage, CanaryConfig, CircuitConfig, ConditionalRoute,
    ConditionalRoutes, DiscardObserver, Do53Forwarder, EdnsBufferSize, NoLocalRecords,
    OrderedFailover, PoolMember, ProbeConfig, ProbePolicy, ResponseValidator, SecurityStatus,
    ShardedAnswerCache, UpstreamPool, Validation, Weight,
};
use styx_testkit::{FakeNameServer, FakeRole, ZoneScript};

const QNAME: &str = "www.example.com.";
const NOW: u64 = 1_700_000_000;
const RECORD_TTL: u32 = 300;

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

/// An A record and an RRSIG over it that expires `signed_for` seconds after [`NOW`].
fn signed_answer(signed_for: u32) -> Vec<ResourceRecord> {
    let owner = name(QNAME);
    let now = u32::try_from(NOW).expect("fits");
    let rrsig = RrsigRdata::new(
        RecordType::A,
        15,
        3,
        RECORD_TTL,
        now.checked_add(signed_for).expect("fits"),
        now.checked_sub(100).expect("fits"),
        4242,
        name("example.com."),
        vec![7; 64],
    );
    let record = |rtype, rdata| {
        ResourceRecord::new(
            owner.clone(),
            rtype,
            RecordClass::In,
            Ttl::from_secs(RECORD_TTL),
            rdata,
        )
    };
    vec![
        record(RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 1))),
        record(RecordType::RRSIG, RData::Rrsig(rrsig)),
    ]
}

/// The bits a client sets on its query.
#[derive(Clone, Copy)]
struct Asked {
    dnssec_ok: bool,
    authentic_data: bool,
    checking_disabled: bool,
}

/// A client that validates for itself: DO=1, the usual way to ask for AD.
const VALIDATING: Asked = Asked {
    dnssec_ok: true,
    authentic_data: false,
    checking_disabled: false,
};

fn query(asked: Asked) -> Message {
    let mut message = Message::new(Header::new_query(0x1357, Opcode::Query, true));
    message.header.authentic_data = asked.authentic_data;
    message.header.checking_disabled = asked.checking_disabled;
    message
        .questions
        .push(Question::new(name(QNAME), RecordType::A, RecordClass::In));
    message.opt = Some(Opt::new(1232, 0, asked.dnssec_ok, Vec::new()));
    message
}

/// Returns whatever verdict the test set, and counts the answers it was asked about.
struct ScriptedValidator {
    verdict: Mutex<Validation>,
    calls: AtomicUsize,
}

impl ScriptedValidator {
    fn new(verdict: Validation) -> Arc<Self> {
        Arc::new(Self {
            verdict: Mutex::new(verdict),
            calls: AtomicUsize::new(0),
        })
    }

    fn set(&self, verdict: Validation) {
        *self.verdict.lock().expect("verdict lock") = verdict;
    }
}

impl ResponseValidator for ScriptedValidator {
    async fn validate(&self, _question: &Question, _response: &Message) -> Validation {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.verdict.lock().expect("verdict lock")
    }
}

const SECURE: Validation = Validation {
    status: SecurityStatus::Secure,
    rejected: false,
};
const BOGUS_REJECTED: Validation = Validation {
    status: SecurityStatus::Bogus,
    rejected: true,
};
const BOGUS_WARNED: Validation = Validation {
    status: SecurityStatus::Bogus,
    rejected: false,
};

type Stage = CacheStage<
    ShardedAnswerCache<TestClock>,
    OrderedFailover,
    Do53Forwarder<TestClock>,
    TestClock,
    ScriptedValidator,
>;

struct Fixture {
    upstream: FakeNameServer,
    clock: Arc<TestClock>,
    cache: Arc<ShardedAnswerCache<TestClock>>,
    server: TestServer<NoLocalRecords, AllowAllFilter, DiscardObserver, TestClock, Stage>,
}

fn pool_of(
    upstream: &FakeNameServer,
    clock: &Arc<TestClock>,
) -> Arc<UpstreamPool<OrderedFailover, Do53Forwarder<TestClock>, TestClock>> {
    let id = UpstreamId::new("validated");
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        Duration::from_millis(500),
        Duration::from_millis(500),
        Arc::clone(clock),
    );
    let member = PoolMember::new(
        id,
        forwarder,
        Weight::new(1),
        CanaryConfig {
            qname: name("canary.check."),
            qtype: RecordType::A,
            timeout: Duration::from_millis(500),
        },
    );
    Arc::new(UpstreamPool::new(
        vec![member],
        OrderedFailover::new(),
        Arc::clone(clock),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    ))
}

impl Fixture {
    async fn boot(validator: Arc<ScriptedValidator>, signed_for: u32) -> Self {
        let script = ZoneScript::new().answer(QNAME, RecordType::A, signed_answer(signed_for));
        let upstream = FakeNameServer::start(FakeRole::Authoritative, script)
            .await
            .expect("fake upstream");
        let clock = Arc::new(TestClock::new());
        clock.set_utc(
            UNIX_EPOCH
                .checked_add(Duration::from_secs(NOW))
                .expect("fits"),
        );
        let pool = pool_of(&upstream, &clock);
        let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
        let stage = Arc::new(
            CacheStage::new(
                Arc::clone(&cache),
                pool,
                Arc::clone(&clock),
                Duration::from_secs(2),
            )
            .with_validator(validator),
        );
        let server = TestServer::boot_with_terminal_and_clock(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            stage,
            Arc::clone(&clock),
        )
        .await
        .expect("boot server");
        Self {
            upstream,
            clock,
            cache,
            server,
        }
    }

    async fn ask(&self, checking_disabled: bool) -> Message {
        self.ask_as(Asked {
            checking_disabled,
            ..VALIDATING
        })
        .await
    }

    async fn ask_as(&self, asked: Asked) -> Message {
        DnsClient::new()
            .query_udp(self.server.udp_addr(), &query(asked))
            .await
            .expect("reply")
    }

    fn upstream_queries(&self) -> usize {
        self.upstream.received().len()
    }

    async fn shutdown(mut self) {
        self.server.shutdown().await.expect("shutdown");
        self.upstream.shutdown();
    }
}

fn answer_ttls(message: &Message) -> Vec<u32> {
    message
        .answers
        .iter()
        .map(|record| record.ttl.seconds())
        .collect()
}

#[tokio::test]
async fn a_secure_answer_carries_ad_live_and_from_the_cache() {
    let fixture = Fixture::boot(ScriptedValidator::new(SECURE), 3600).await;

    let live = fixture.ask(false).await;
    let cached = fixture.ask(false).await;

    assert!(live.header.authentic_data);
    assert!(cached.header.authentic_data);
    assert_eq!(fixture.cache.stats().hits, 1);
    assert_eq!(fixture.upstream_queries(), 1);
    fixture.shutdown().await;
}

/// RFC 4035 §4.6: the upstream's AD means nothing to styx; only its own verdict sets AD.
#[tokio::test]
async fn an_unvalidated_answer_never_carries_ad() {
    let fixture = Fixture::boot(ScriptedValidator::new(Validation::UNVALIDATED), 3600).await;

    let reply = fixture.ask(false).await;

    assert_eq!(reply.header.rcode, ResponseCode::NOERROR);
    assert!(!reply.header.authentic_data);
    fixture.shutdown().await;
}

#[tokio::test]
async fn a_refused_verdict_is_servfail_and_is_not_cached() {
    let validator = ScriptedValidator::new(BOGUS_REJECTED);
    let fixture = Fixture::boot(Arc::clone(&validator), 3600).await;

    let first = fixture.ask(false).await;
    let second = fixture.ask(false).await;

    assert_eq!(first.header.rcode, ResponseCode::SERVFAIL);
    assert!(first.answers.is_empty());
    assert_eq!(second.header.rcode, ResponseCode::SERVFAIL);
    assert_eq!(fixture.upstream_queries(), 2);
    assert_eq!(validator.calls.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
}

/// RFC 4035 §3.2.2: a CD=1 client gets the data a CD=0 client would be refused, without
/// AD; it is still not cached, so a CD=0 client asking next is refused again.
#[tokio::test]
async fn a_cd1_client_gets_a_refused_answer_without_ad_and_it_is_not_cached() {
    let fixture = Fixture::boot(ScriptedValidator::new(BOGUS_REJECTED), 3600).await;

    let checking_disabled = fixture.ask(true).await;
    let checking_enabled = fixture.ask(false).await;

    assert_eq!(checking_disabled.header.rcode, ResponseCode::NOERROR);
    assert_eq!(checking_disabled.answers.len(), 2);
    assert!(!checking_disabled.header.authentic_data);
    assert!(checking_disabled.header.checking_disabled);
    assert_eq!(checking_enabled.header.rcode, ResponseCode::SERVFAIL);
    assert_eq!(fixture.upstream_queries(), 2);
    fixture.shutdown().await;
}

/// Under `WarnOnly` a Bogus verdict is logged, not enforced: served and cached, never AD.
#[tokio::test]
async fn a_warned_verdict_is_served_and_cached_without_ad() {
    let fixture = Fixture::boot(ScriptedValidator::new(BOGUS_WARNED), 3600).await;

    let live = fixture.ask(false).await;
    let cached = fixture.ask(false).await;

    assert_eq!(live.header.rcode, ResponseCode::NOERROR);
    assert!(!live.header.authentic_data);
    assert!(!cached.header.authentic_data);
    assert_eq!(fixture.upstream_queries(), 1);
    fixture.shutdown().await;
}

/// RFC 4035 §5.3.3: a Secure answer lives no longer than its earliest signature.
#[tokio::test]
async fn a_secure_answer_ttl_is_capped_at_its_signature_expiration() {
    let fixture = Fixture::boot(ScriptedValidator::new(SECURE), 120).await;

    let live = fixture.ask(false).await;

    assert_eq!(answer_ttls(&live), vec![120, 120]);
    fixture.shutdown().await;
}

/// 6d.6: once the signature has expired the entry is gone, so the answer is fetched and
/// validated again instead of being served from the cache with AD.
#[tokio::test]
async fn an_entry_whose_signature_expired_is_never_served_with_ad() {
    let validator = ScriptedValidator::new(SECURE);
    let fixture = Fixture::boot(Arc::clone(&validator), 120).await;
    assert!(fixture.ask(false).await.header.authentic_data);

    fixture.clock.advance(Duration::from_secs(121));
    validator.set(BOGUS_WARNED);
    let after_expiry = fixture.ask(false).await;

    assert!(!after_expiry.header.authentic_data);
    assert_eq!(fixture.cache.stats().hits, 0);
    assert_eq!(fixture.upstream_queries(), 2);
    assert_eq!(validator.calls.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
}

/// The cache's TTL floor (5 s by default) would keep an entry past a signature that has
/// less than that left, so such an answer is served but not cached.
#[tokio::test]
async fn an_answer_signed_for_less_than_the_ttl_floor_is_not_cached() {
    let fixture = Fixture::boot(ScriptedValidator::new(SECURE), 3).await;

    let first = fixture.ask(false).await;
    let second = fixture.ask(false).await;

    assert!(first.header.authentic_data);
    assert!(second.header.authentic_data);
    assert_eq!(fixture.cache.stats().hits, 0);
    assert_eq!(fixture.upstream_queries(), 2);
    fixture.shutdown().await;
}

/// Issue #122: a cache hit shows the stored verdict's AD only to a client that set DO or AD
/// (RFC 6840 §5.8); a client with neither gets AD=0 from the same entry.
#[tokio::test]
async fn a_secure_hit_shows_ad_only_to_a_client_that_set_do_or_ad() {
    let fixture = Fixture::boot(ScriptedValidator::new(SECURE), 3600).await;
    assert!(fixture.ask(false).await.header.authentic_data);

    let plain = fixture
        .ask_as(Asked {
            dnssec_ok: false,
            ..VALIDATING
        })
        .await;
    let ad_only = fixture
        .ask_as(Asked {
            dnssec_ok: false,
            authentic_data: true,
            checking_disabled: false,
        })
        .await;
    let dnssec_ok = fixture.ask_as(VALIDATING).await;

    assert_eq!(fixture.cache.stats().hits, 3);
    assert!(!plain.header.authentic_data);
    assert!(ad_only.header.authentic_data);
    assert!(dnssec_ok.header.authentic_data);
    fixture.shutdown().await;
}

/// Issue #122, CD=1: styx validates whatever CD says, so an entry admitted for a CD=0
/// client carries the same verdict to a CD=1 one; CD only lifts enforcement.
#[tokio::test]
async fn a_cd1_client_gets_the_same_verdict_from_an_entry_a_cd0_query_filled() {
    let fixture = Fixture::boot(ScriptedValidator::new(SECURE), 3600).await;
    assert!(fixture.ask(false).await.header.authentic_data);

    let checking_disabled = fixture.ask(true).await;

    assert_eq!(fixture.cache.stats().hits, 1);
    assert!(checking_disabled.header.checking_disabled);
    assert!(checking_disabled.header.authentic_data);
    fixture.shutdown().await;
}

/// A conditional route sends a local domain to a LAN server; validating its answer would
/// ask the main pool about that domain, so it is served unvalidated: no AD, never refused,
/// and the validator is not consulted.
#[tokio::test]
async fn an_answer_from_a_conditional_route_is_not_validated() {
    let local = "nas.lan.";
    let router_script = ZoneScript::new().answer(
        local,
        RecordType::A,
        vec![ResourceRecord::new(
            name(local),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(RECORD_TTL),
            RData::A(Ipv4Addr::new(192, 168, 1, 10)),
        )],
    );
    let router = FakeNameServer::start(FakeRole::Authoritative, router_script)
        .await
        .expect("router");
    let main = FakeNameServer::start(FakeRole::Authoritative, ZoneScript::new())
        .await
        .expect("main upstream");
    let clock = Arc::new(TestClock::new());
    let validator = ScriptedValidator::new(BOGUS_REJECTED);
    let stage = Arc::new(
        CacheStage::new(
            Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock))),
            pool_of(&main, &clock),
            Arc::clone(&clock),
            Duration::from_secs(2),
        )
        .with_validator(Arc::clone(&validator))
        .with_conditional(ConditionalRoutes::new(vec![ConditionalRoute {
            domains: vec![name("lan.")],
            target: pool_of(&router, &clock),
        }])),
    );
    let mut server = TestServer::boot_with_terminal_and_clock(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        stage,
        clock,
    )
    .await
    .expect("boot server");
    let mut asked = query(VALIDATING);
    if let Some(question) = asked.questions.first_mut() {
        question.qname = name(local);
    }

    let reply = DnsClient::new()
        .query_udp(server.udp_addr(), &asked)
        .await
        .expect("reply");

    assert_eq!(reply.header.rcode, ResponseCode::NOERROR);
    assert!(!reply.header.authentic_data);
    assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
    assert!(main.received().is_empty());
    server.shutdown().await.expect("shutdown");
    router.shutdown();
    main.shutdown();
}
