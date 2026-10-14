//! End-to-end tests for caching a forwarded CNAME chain (issue #77).
//!
//! A recursive upstream answers a CDN-fronted name with the whole chain in the answer
//! section and nothing in the authority section, so the bailiwick zone degenerates to
//! the qname. The cache must still serve the chain whole on a hit.

mod harness;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use harness::{
    DnsClient, FakeNameServer, FakeRole, HarnessError, TestClock, TestServer, ZoneScript,
};
use styx_core::UpstreamId;
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl,
};
use styx_resolution::{
    Admission, AllowAllFilter, AnswerCache, CacheStage, CanaryConfig, CircuitConfig,
    DiscardObserver, Do53Forwarder, EdnsBufferSize, NoLocalRecords, OrderedFailover, PoolMember,
    ProbeConfig, ProbePolicy, ShardedAnswerCache, TtlPolicy, UpstreamPool, Weight,
};

const QNAME: &str = "www.example.com.";
const TARGET: &str = "cdn.provider.net.";
const UNRELATED: &str = "unrelated.example.";

type Terminal =
    CacheStage<ShardedAnswerCache<TestClock>, OrderedFailover, Do53Forwarder<TestClock>, TestClock>;
type Stage = Arc<Terminal>;

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

fn record(owner: &str, rdata: RData) -> ResourceRecord {
    record_with_ttl(owner, rdata, 300)
}

fn record_with_ttl(owner: &str, rdata: RData, seconds: u32) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        rdata.rtype(),
        RecordClass::In,
        Ttl::from_secs(seconds),
        rdata,
    )
}

fn alias_record() -> ResourceRecord {
    record(QNAME, RData::Cname(name(TARGET)))
}

fn address_record(owner: &str, last_octet: u8) -> ResourceRecord {
    record(owner, RData::A(Ipv4Addr::new(192, 0, 2, last_octet)))
}

fn make_query(qname: &str, rtype: RecordType) -> Message {
    let mut msg = Message::new(Header::new_query(0x1234, Opcode::Query, true));
    msg.header.recursion_desired = true;
    msg.questions
        .push(Question::new(name(qname), rtype, RecordClass::In));
    msg
}

fn create_stage(
    cache: Arc<ShardedAnswerCache<TestClock>>,
    upstream: SocketAddr,
    clock: Arc<TestClock>,
) -> Stage {
    let id = UpstreamId::new("up1");
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream,
        EdnsBufferSize::default(),
        Duration::from_millis(500),
        Duration::from_millis(500),
        Arc::clone(&clock),
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
    let pool = Arc::new(UpstreamPool::new(
        vec![member],
        OrderedFailover::new(),
        Arc::clone(&clock),
        CircuitConfig {
            failure_threshold: 3,
            open_cooldown: Duration::from_secs(30),
            half_open_successes: 1,
        },
        ProbePolicy::new(ProbeConfig::default()),
    ));
    Arc::new(CacheStage::with_admission(
        cache,
        pool,
        Admission::new(TtlPolicy::default()),
        clock,
        Duration::from_secs(2),
    ))
}

/// Everything one test needs: a fake forwarder-style upstream answering `script`,
/// the cache in front of it, and a booted server to query.
struct Fixture {
    cache: Arc<ShardedAnswerCache<TestClock>>,
    upstream: FakeNameServer,
    server: TestServer<NoLocalRecords, AllowAllFilter, DiscardObserver, TestClock, Terminal>,
    client: DnsClient,
}

impl Fixture {
    async fn boot(script: ZoneScript) -> Result<Self, HarnessError> {
        let clock = Arc::new(TestClock::new());
        let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
        let upstream = FakeNameServer::start(FakeRole::Authoritative, script).await?;
        let stage = create_stage(Arc::clone(&cache), upstream.udp_addr(), Arc::clone(&clock));
        let server = TestServer::boot_with_terminal_and_clock(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            stage,
            clock,
        )
        .await?;
        Ok(Self {
            cache,
            upstream,
            server,
            client: DnsClient::new(),
        })
    }

    async fn ask(&self, qname: &str, rtype: RecordType) -> Result<Message, HarnessError> {
        self.client
            .query_udp(self.server.udp_addr(), &make_query(qname, rtype))
            .await
    }

    /// Number of queries for `qname` that reached the upstream.
    fn upstream_queries_for(&self, qname: &str) -> usize {
        let wanted = name(qname);
        self.upstream
            .received_queries()
            .iter()
            .filter(|question| question.qname == wanted)
            .count()
    }

    async fn shutdown(mut self) -> Result<(), HarnessError> {
        self.server.shutdown().await?;
        self.upstream.shutdown();
        Ok(())
    }
}

fn owners(message: &Message) -> Vec<String> {
    message
        .answers
        .iter()
        .map(|record| record.owner.to_string())
        .collect()
}

/// The bug: the second answer, served from cache, used to carry only the CNAME.
#[tokio::test]
async fn test_forwarded_cname_chain_is_served_whole_from_cache() {
    let script = ZoneScript::new().answer(
        QNAME,
        RecordType::A,
        vec![alias_record(), address_record(TARGET, 10)],
    );
    let fixture = Fixture::boot(script).await.expect("boot fixture");

    let first = fixture.ask(QNAME, RecordType::A).await.expect("query");
    assert_eq!(owners(&first), [QNAME, TARGET]);
    assert_eq!(fixture.upstream_queries_for(QNAME), 1);

    let second = fixture.ask(QNAME, RecordType::A).await.expect("query");
    assert_eq!(
        owners(&second),
        [QNAME, TARGET],
        "cache hit lost the target"
    );
    assert_eq!(fixture.upstream_queries_for(QNAME), 1, "second was a miss");
    assert_eq!(fixture.cache.stats().hits, 1);
    assert_eq!(fixture.cache.stats().rejected_out_of_bailiwick, 0);

    fixture.shutdown().await.expect("shutdown");
}

/// A record off the chain stays rejected, and only it, while the chain is cached.
#[tokio::test]
async fn test_record_off_the_chain_is_still_rejected() {
    let script = ZoneScript::new().answer(
        QNAME,
        RecordType::A,
        vec![
            alias_record(),
            address_record(TARGET, 10),
            address_record(UNRELATED, 66),
        ],
    );
    let fixture = Fixture::boot(script).await.expect("boot fixture");

    fixture.ask(QNAME, RecordType::A).await.expect("query");
    let second = fixture.ask(QNAME, RecordType::A).await.expect("query");

    assert_eq!(owners(&second), [QNAME, TARGET]);
    assert_eq!(fixture.upstream_queries_for(QNAME), 1);
    assert_eq!(fixture.cache.stats().rejected_out_of_bailiwick, 1);

    fixture.shutdown().await.expect("shutdown");
}

/// A chain that ends in neither the asked type nor a denial is a broken answer:
/// serving it from cache would hand stubs a CNAME with no address.
#[tokio::test]
async fn test_dangling_cname_chain_is_not_cached() {
    let script = ZoneScript::new().answer(QNAME, RecordType::A, vec![alias_record()]);
    let fixture = Fixture::boot(script).await.expect("boot fixture");

    fixture.ask(QNAME, RecordType::A).await.expect("query");
    fixture.ask(QNAME, RecordType::A).await.expect("query");

    assert_eq!(
        fixture.upstream_queries_for(QNAME),
        2,
        "dangling chain cached"
    );
    assert_eq!(fixture.cache.stats().hits, 0);
    assert_eq!(
        fixture.cache.stats().rejected_incomplete_chain,
        2,
        "one per refused answer"
    );

    fixture.shutdown().await.expect("shutdown");
}

/// Asking for the CNAME itself is complete with the CNAME alone.
#[tokio::test]
async fn test_cname_query_answered_by_bare_cname_is_cached() {
    let script = ZoneScript::new().answer(QNAME, RecordType::CNAME, vec![alias_record()]);
    let fixture = Fixture::boot(script).await.expect("boot fixture");

    fixture.ask(QNAME, RecordType::CNAME).await.expect("query");
    let second = fixture.ask(QNAME, RecordType::CNAME).await.expect("query");

    assert_eq!(owners(&second), [QNAME]);
    assert_eq!(fixture.upstream_queries_for(QNAME), 1);
    assert_eq!(fixture.cache.stats().hits, 1);

    fixture.shutdown().await.expect("shutdown");
}

/// Asks twice and asserts the answer was refused both times: nothing was stored, so
/// the upstream saw both queries, and each refusal counted once.
async fn assert_refused_as_incomplete(script: ZoneScript) -> Result<(), HarnessError> {
    let fixture = Fixture::boot(script).await?;

    fixture.ask(QNAME, RecordType::A).await?;
    fixture.ask(QNAME, RecordType::A).await?;

    assert_eq!(fixture.upstream_queries_for(QNAME), 2, "half chain cached");
    assert_eq!(fixture.cache.stats().hits, 0);
    assert_eq!(fixture.cache.stats().rejected_incomplete_chain, 2);

    fixture.shutdown().await
}

/// A zero-TTL link is dropped by admission after the chain looked complete: what is
/// left is an address whose owner is not the qname, and no alias to reach it.
#[tokio::test]
async fn test_zero_ttl_cname_leaves_no_half_cached_chain() {
    let script = ZoneScript::new().answer(
        QNAME,
        RecordType::A,
        vec![
            record_with_ttl(QNAME, RData::Cname(name(TARGET)), 0),
            address_record(TARGET, 10),
        ],
    );
    assert_refused_as_incomplete(script)
        .await
        .expect("refused twice");
}

/// The bug of #77 by another road: a zero-TTL terminal A leaves a bare CNAME.
#[tokio::test]
async fn test_zero_ttl_terminal_address_leaves_no_bare_cname() {
    let script = ZoneScript::new().answer(
        QNAME,
        RecordType::A,
        vec![
            alias_record(),
            record_with_ttl(TARGET, RData::A(Ipv4Addr::new(192, 0, 2, 10)), 0),
        ],
    );
    assert_refused_as_incomplete(script)
        .await
        .expect("refused twice");
}

/// A chain that loops back on itself leads nowhere however many records it carries.
#[tokio::test]
async fn test_cyclic_cname_chain_is_not_cached() {
    let script = ZoneScript::new()
        .answer(QNAME, RecordType::CNAME, vec![alias_record()])
        .answer(
            TARGET,
            RecordType::CNAME,
            vec![record(TARGET, RData::Cname(name(QNAME)))],
        );
    assert_refused_as_incomplete(script)
        .await
        .expect("refused twice");
}

/// An answer made only of records the chain has no standing to carry is refused as
/// both: forged records, and no answer at all.
#[tokio::test]
async fn test_answer_of_only_off_chain_records_counts_both_refusals() {
    let script =
        ZoneScript::new().answer(QNAME, RecordType::A, vec![address_record(UNRELATED, 66)]);
    let fixture = Fixture::boot(script).await.expect("boot fixture");

    fixture.ask(QNAME, RecordType::A).await.expect("query");

    assert_eq!(fixture.cache.stats().rejected_out_of_bailiwick, 1);
    assert_eq!(fixture.cache.stats().rejected_incomplete_chain, 1);

    fixture.shutdown().await.expect("shutdown");
}
