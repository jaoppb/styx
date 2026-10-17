//! A cache hit and the live answer to the same query agree on every header flag and on the
//! question section, which carries the client's own casing (issue #81).

mod harness;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use harness::TestClock;
use styx_core::{Clock, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, SoaRdata, Ttl,
};
use styx_resolution::{
    AnswerCache, CacheStage, CanaryConfig, CircuitConfig, ClientId, MaxResponseSize,
    OrderedFailover, PipelineError, PoolMember, PoolTerminal, ProbeConfig, ProbePolicy,
    RequestContext, ResolutionResponse, ShardedAnswerCache, TerminalHandler, Transport,
    UpstreamPool, Weight,
};

const MIXED_CASE: &str = "WwW.ExAmPlE.CoM.";

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

fn ask(text: &str) -> Question {
    Question::new(name(text), RecordType::A, RecordClass::In)
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

fn soa() -> RData {
    RData::Soa(SoaRdata::new(
        name("ns.example.com."),
        name("hostmaster.example.com."),
        1,
        2,
        3,
        4,
        60,
    ))
}

/// The reply of an authoritative server that lowercases the name it echoes and sets AA, RD
/// and RA, the way a hickory fake server does.
fn authoritative_reply(rcode: ResponseCode, with_answer: bool) -> Message {
    let mut message = Message::response_to(0x1000, ask("www.example.com."));
    message.header.authoritative = true;
    message.header.recursion_desired = true;
    message.header.rcode = rcode;
    if with_answer {
        message.answers.push(record(
            "www.example.com.",
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
    } else {
        message.authorities.push(record("example.com.", soa()));
    }
    message
}

/// An upstream that answers every query with one canned message and counts the queries.
#[derive(Clone)]
struct ScriptedUpstream {
    reply: Message,
    queries: Arc<AtomicUsize>,
}

impl Upstream for ScriptedUpstream {
    fn id(&self) -> UpstreamId {
        UpstreamId::new("scripted")
    }

    fn kind(&self) -> UpstreamKind {
        UpstreamKind::Forwarder
    }

    fn resolve(
        &self,
        _query: &Question,
        _deadline: Instant,
    ) -> impl std::future::Future<Output = Result<UpstreamResponse, UpstreamError>> + Send {
        self.queries.fetch_add(1, Ordering::SeqCst);
        let message = self.reply.clone();
        async move {
            Ok(UpstreamResponse {
                message,
                answered_by: UpstreamId::new("scripted"),
                kind: UpstreamKind::Forwarder,
                elapsed: Duration::ZERO,
                via_tcp: false,
                raced_count: 1,
            })
        }
    }
}

type Pool = UpstreamPool<OrderedFailover, ScriptedUpstream, TestClock>;

struct Fixture {
    pool: Arc<Pool>,
    cache: Arc<ShardedAnswerCache<TestClock>>,
    clock: Arc<TestClock>,
}

fn fixture(reply: Message) -> Fixture {
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
    let upstream = ScriptedUpstream {
        reply,
        queries: Arc::new(AtomicUsize::new(0)),
    };
    let member = PoolMember::new(
        UpstreamId::new("scripted"),
        upstream,
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
    Fixture { pool, cache, clock }
}

impl Fixture {
    fn stage(
        &self,
    ) -> CacheStage<ShardedAnswerCache<TestClock>, OrderedFailover, ScriptedUpstream, TestClock>
    {
        CacheStage::new(
            Arc::clone(&self.cache),
            Arc::clone(&self.pool),
            Arc::clone(&self.clock),
            Duration::from_secs(2),
        )
    }

    fn context(&self, recursion_desired: bool, checking_disabled: bool) -> RequestContext {
        let mut header = Header::new_query(0x1234, Opcode::Query, recursion_desired);
        header.checking_disabled = checking_disabled;
        let mut query = Message::new(header);
        query.questions.push(ask(MIXED_CASE));
        RequestContext::new(
            query,
            ClientId::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Transport::Udp,
            MaxResponseSize::classic(),
            MaxResponseSize::classic(),
            self.clock.now_monotonic(),
        )
    }
}

/// The text of every question, case included (`Name` equality ignores case).
fn asked(response: &ResolutionResponse) -> Vec<String> {
    response
        .message()
        .questions
        .iter()
        .map(|question| question.qname.to_string())
        .collect()
}

/// Asks twice through the cache stage: the first answer is live, the second is a hit.
async fn live_then_hit(
    fixture: &Fixture,
    ctx: &RequestContext,
) -> Result<(ResolutionResponse, ResolutionResponse), PipelineError> {
    let stage = fixture.stage();
    let live = stage.handle_terminal(ctx).await?;
    let hit = stage.handle_terminal(ctx).await?;
    let stats = fixture.cache.stats();
    assert_eq!(
        stats.hits.saturating_add(stats.negative_hits),
        1,
        "the second answer is a hit"
    );
    Ok((live, hit))
}

fn assert_same_reply(live: &ResolutionResponse, hit: &ResolutionResponse) {
    assert_eq!(live.message().header, hit.message().header);
    assert_eq!(asked(live), asked(hit));
}

#[tokio::test]
async fn test_a_hit_and_the_live_answer_agree_on_a_mixed_case_rd_query() {
    let fixture = fixture(authoritative_reply(ResponseCode::NOERROR, true));
    let ctx = fixture.context(true, false);

    let (live, hit) = live_then_hit(&fixture, &ctx).await.expect("both answers");

    assert_same_reply(&live, &hit);
    assert_eq!(asked(&hit), vec![MIXED_CASE.to_string()]);
    assert!(hit.message().header.recursion_desired);
}

#[tokio::test]
async fn test_a_cached_nxdomain_is_not_authoritative() {
    let fixture = fixture(authoritative_reply(ResponseCode::NXDOMAIN, false));
    let ctx = fixture.context(true, false);

    let (live, hit) = live_then_hit(&fixture, &ctx).await.expect("both answers");

    assert_same_reply(&live, &hit);
    assert_eq!(hit.message().header.rcode, ResponseCode::NXDOMAIN);
    assert!(!hit.message().header.authoritative);
}

#[tokio::test]
async fn test_a_cached_nodata_is_not_authoritative() {
    let fixture = fixture(authoritative_reply(ResponseCode::NOERROR, false));
    let ctx = fixture.context(true, false);

    let (live, hit) = live_then_hit(&fixture, &ctx).await.expect("both answers");

    assert_same_reply(&live, &hit);
    assert!(!hit.message().header.authoritative);
}

#[tokio::test]
async fn test_a_cached_positive_answer_is_not_authoritative() {
    let fixture = fixture(authoritative_reply(ResponseCode::NOERROR, true));
    let ctx = fixture.context(true, false);

    let (live, hit) = live_then_hit(&fixture, &ctx).await.expect("both answers");

    assert!(!live.message().header.authoritative);
    assert!(!hit.message().header.authoritative);
}

#[tokio::test]
async fn test_a_query_without_rd_gets_rd_clear_live_and_cached() {
    let fixture = fixture(authoritative_reply(ResponseCode::NOERROR, true));
    let ctx = fixture.context(false, false);

    let (live, hit) = live_then_hit(&fixture, &ctx).await.expect("both answers");

    assert_same_reply(&live, &hit);
    assert!(!hit.message().header.recursion_desired);
}

#[tokio::test]
async fn test_a_query_with_cd_gets_cd_set_live_and_cached() {
    let fixture = fixture(authoritative_reply(ResponseCode::NOERROR, true));
    let ctx = fixture.context(true, true);

    let (live, hit) = live_then_hit(&fixture, &ctx).await.expect("both answers");

    assert_same_reply(&live, &hit);
    assert!(hit.message().header.checking_disabled);
}

#[tokio::test]
async fn test_the_pool_terminal_answers_with_the_clients_flags_and_question() {
    let fixture = fixture(authoritative_reply(ResponseCode::NXDOMAIN, false));
    let ctx = fixture.context(false, true);
    let terminal = PoolTerminal::new(
        Arc::clone(&fixture.pool),
        Arc::clone(&fixture.clock),
        Duration::from_secs(2),
    );

    let response = terminal.handle_terminal(&ctx).await.expect("answer");

    let header = &response.message().header;
    assert_eq!(header.id, 0x1234);
    assert!(!header.recursion_desired);
    assert!(header.checking_disabled);
    assert!(!header.authoritative);
    assert_eq!(asked(&response), vec![MIXED_CASE.to_string()]);
}
