//! DNSSEC records between the forwarder and the client (issue #86).
//!
//! Every upstream query asks for DNSSEC records, whatever the client set, so the RRSIGs a
//! signed zone returns reach a DO=1 client; a DO=0 client never sees them, live or from a
//! cache entry a DO=1 query filled.

// The helpers below sit outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

mod harness;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use harness::{DnsClient, TestClock, TestServer};
use styx_core::UpstreamId;
use styx_proto::{
    Header, Message, Name, Opcode, Opt, Question, RData, RecordClass, RecordType, ResourceRecord,
    RrsigRdata, Ttl,
};
use styx_resolution::{
    AllowAllFilter, AnswerCache, CacheStage, CanaryConfig, CircuitConfig, DiscardObserver,
    Do53Forwarder, EdnsBufferSize, NoLocalRecords, OrderedFailover, PoolMember, ProbeConfig,
    ProbePolicy, ShardedAnswerCache, UpstreamPool, Weight,
};
use styx_testkit::{FakeNameServer, FakeRole, ZoneScript};

const SIGNED: &str = "www.example.com.";

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

fn signed_answer() -> Vec<ResourceRecord> {
    let owner = name(SIGNED);
    let rrsig = RrsigRdata::new(
        RecordType::A,
        15,
        3,
        300,
        1_700_000_200,
        1_700_000_000,
        4242,
        name("example.com."),
        vec![7; 64],
    );
    vec![
        ResourceRecord::new(
            owner.clone(),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ),
        ResourceRecord::new(
            owner,
            RecordType::RRSIG,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::Rrsig(rrsig),
        ),
    ]
}

fn query(dnssec_ok: Option<bool>) -> Message {
    let mut message = Message::new(Header::new_query(0x2468, Opcode::Query, true));
    message
        .questions
        .push(Question::new(name(SIGNED), RecordType::A, RecordClass::In));
    message.opt = dnssec_ok.map(|bit| Opt::new(1232, 0, bit, Vec::new()));
    message
}

fn rrsig_count(message: &Message) -> usize {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .filter(|record| record.rtype == RecordType::RRSIG)
        .count()
}

type Stage =
    CacheStage<ShardedAnswerCache<TestClock>, OrderedFailover, Do53Forwarder<TestClock>, TestClock>;

struct Fixture {
    upstream: FakeNameServer,
    cache: Arc<ShardedAnswerCache<TestClock>>,
    server: TestServer<NoLocalRecords, AllowAllFilter, DiscardObserver, TestClock, Stage>,
}

impl Fixture {
    async fn boot() -> Self {
        let script = ZoneScript::new().answer(SIGNED, RecordType::A, signed_answer());
        let upstream = FakeNameServer::start(FakeRole::Authoritative, script)
            .await
            .expect("fake upstream");
        let clock = Arc::new(TestClock::new());
        let id = UpstreamId::new("signed");
        let forwarder = Do53Forwarder::new(
            id.clone(),
            upstream.udp_addr(),
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
            CircuitConfig::default(),
            ProbePolicy::new(ProbeConfig::default()),
        ));
        let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
        let stage = Arc::new(CacheStage::new(
            Arc::clone(&cache),
            pool,
            Arc::clone(&clock),
            Duration::from_secs(2),
        ));
        let server = TestServer::boot_with_terminal_and_clock(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            stage,
            clock,
        )
        .await
        .expect("boot server");
        Self {
            upstream,
            cache,
            server,
        }
    }

    async fn ask(&self, dnssec_ok: Option<bool>) -> Message {
        DnsClient::new()
            .query_udp(self.server.udp_addr(), &query(dnssec_ok))
            .await
            .expect("reply")
    }

    async fn shutdown(mut self) {
        self.server.shutdown().await.expect("shutdown");
        self.upstream.shutdown();
    }
}

#[tokio::test]
async fn a_do1_query_reaches_the_upstream_with_do1_and_its_rrsigs_reach_the_client() {
    let fixture = Fixture::boot().await;

    let reply = fixture.ask(Some(true)).await;

    let received = fixture.upstream.received();
    assert_eq!(received.len(), 1);
    assert!(received.iter().all(|asked| asked.dnssec_ok));
    assert_eq!(rrsig_count(&reply), 1);
    assert!(reply.opt.is_some_and(|opt| opt.dnssec_ok()));
    fixture.shutdown().await;
}

/// The upstream is asked with DO=1 even for a client without DO; only the reply to the
/// client loses the records it did not ask for.
#[tokio::test]
async fn a_do0_client_gets_no_rrsig_although_the_upstream_was_asked_with_do1() {
    for client_do in [None, Some(false)] {
        let fixture = Fixture::boot().await;

        let reply = fixture.ask(client_do).await;

        assert!(fixture
            .upstream
            .received()
            .iter()
            .all(|asked| asked.dnssec_ok));
        assert_eq!(rrsig_count(&reply), 0);
        assert_eq!(reply.answers.len(), 1);
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn a_do0_client_gets_no_rrsig_from_an_entry_a_do1_query_filled() {
    let fixture = Fixture::boot().await;
    assert_eq!(rrsig_count(&fixture.ask(Some(true)).await), 1);

    let from_cache = fixture.ask(Some(false)).await;

    assert_eq!(fixture.cache.stats().hits, 1);
    assert_eq!(fixture.upstream.received().len(), 1);
    assert_eq!(rrsig_count(&from_cache), 0);
    assert_eq!(from_cache.answers.len(), 1);
    fixture.shutdown().await;
}
