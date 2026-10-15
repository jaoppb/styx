//! `CacheStage` refuses an upstream reply that does not answer the client's question,
//! on the cacheable path and on the meta-type path alike (issue #116).

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
    OrderedFailover, PipelineError, PoolMember, ProbeConfig, ProbePolicy, RequestContext,
    ShardedAnswerCache, TerminalHandler, Transport, UpstreamPool, Weight,
};

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

fn ask(text: &str, qtype: RecordType) -> Question {
    Question::new(name(text), qtype, RecordClass::In)
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

/// An upstream that answers every query with one canned message and counts the queries.
#[derive(Clone)]
struct ScriptedUpstream {
    reply: Message,
    queries: Arc<AtomicUsize>,
}

impl ScriptedUpstream {
    fn new(reply: Message) -> Self {
        Self {
            reply,
            queries: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
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

type Stage =
    CacheStage<ShardedAnswerCache<TestClock>, OrderedFailover, ScriptedUpstream, TestClock>;

struct Fixture {
    stage: Stage,
    cache: Arc<ShardedAnswerCache<TestClock>>,
    upstream: ScriptedUpstream,
    clock: Arc<TestClock>,
}

fn fixture(reply: Message) -> Fixture {
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
    let upstream = ScriptedUpstream::new(reply);
    let member = PoolMember::new(
        UpstreamId::new("scripted"),
        upstream.clone(),
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
    let stage = CacheStage::new(
        Arc::clone(&cache),
        pool,
        Arc::clone(&clock),
        Duration::from_secs(2),
    );
    Fixture {
        stage,
        cache,
        upstream,
        clock,
    }
}

fn context(fixture: &Fixture, question: &Question) -> RequestContext {
    let mut query = Message::new(Header::new_query(0x1234, Opcode::Query, true));
    query.questions.push(question.clone());
    RequestContext::new(
        query,
        ClientId::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Transport::Udp,
        MaxResponseSize::classic(),
        MaxResponseSize::classic(),
        fixture.clock.now_monotonic(),
    )
}

/// An address answer for `answered`, echoing `echoed` as its question section.
fn address_reply(answered: &Question, echoed: Vec<Question>) -> Message {
    let mut message = Message::response_to(0x1000, answered.clone());
    message.questions = echoed;
    message.answers.push(record(
        "www.example.com.",
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    message
}

fn assert_servfail(result: Result<styx_resolution::ResolutionResponse, PipelineError>) {
    let refused = result.err().map(|error| error.response_code());
    assert_eq!(
        refused,
        Some(ResponseCode::SERVFAIL),
        "a reply that does not answer the question is refused"
    );
}

#[tokio::test]
async fn test_a_matching_reply_is_served_and_then_cached() {
    let client = ask("www.example.com.", RecordType::A);
    let fixture = fixture(address_reply(&client, vec![client.clone()]));
    let ctx = context(&fixture, &client);

    let first = fixture.stage.handle_terminal(&ctx).await.expect("first");
    assert_eq!(first.message().answers.len(), 1);
    fixture.stage.handle_terminal(&ctx).await.expect("second");

    assert_eq!(fixture.upstream.queries(), 1);
    assert_eq!(fixture.cache.stats().hits, 1);
}

#[tokio::test]
async fn test_a_reply_echoing_another_question_is_servfail_and_stores_nothing() {
    let client = ask("www.example.com.", RecordType::A);
    let echoed = vec![ask("evil.example.net.", RecordType::A)];
    let fixture = fixture(address_reply(&client, echoed));
    let ctx = context(&fixture, &client);

    assert_servfail(fixture.stage.handle_terminal(&ctx).await);
    assert_servfail(fixture.stage.handle_terminal(&ctx).await);

    assert_eq!(
        fixture.upstream.queries(),
        2,
        "nothing was stored to answer from"
    );
    assert_eq!(fixture.cache.stats().rejected_question_mismatch, 2);
    assert_eq!(fixture.cache.stats().entries, 0);
}

#[tokio::test]
async fn test_a_reply_echoing_two_questions_is_servfail_and_stores_nothing() {
    let client = ask("www.example.com.", RecordType::A);
    let echoed = vec![client.clone(), ask("extra.example.com.", RecordType::A)];
    let fixture = fixture(address_reply(&client, echoed));
    let ctx = context(&fixture, &client);

    assert_servfail(fixture.stage.handle_terminal(&ctx).await);
    assert_servfail(fixture.stage.handle_terminal(&ctx).await);

    assert_eq!(fixture.upstream.queries(), 2);
    assert_eq!(fixture.cache.stats().rejected_multiple_questions, 2);
    assert_eq!(fixture.cache.stats().entries, 0);
}

#[tokio::test]
async fn test_a_denial_echoing_no_question_is_servfail_and_stores_nothing() {
    let client = ask("www.example.com.", RecordType::A);
    let mut reply = Message::response_to(0x1000, client.clone());
    reply.questions.clear();
    reply.authorities.push(record("example.com.", soa()));
    let fixture = fixture(reply);
    let ctx = context(&fixture, &client);

    assert_servfail(fixture.stage.handle_terminal(&ctx).await);
    assert_servfail(fixture.stage.handle_terminal(&ctx).await);

    assert_eq!(fixture.upstream.queries(), 2);
    assert_eq!(fixture.cache.stats().entries, 0);
}

#[tokio::test]
async fn test_a_meta_type_reply_echoing_another_question_is_servfail() {
    let client = ask("www.example.com.", RecordType::ANY);
    let echoed = vec![ask("evil.example.net.", RecordType::ANY)];
    let fixture = fixture(address_reply(&client, echoed));
    let ctx = context(&fixture, &client);

    assert_servfail(fixture.stage.handle_terminal(&ctx).await);
}

#[tokio::test]
async fn test_a_meta_type_reply_echoing_its_question_is_served() {
    let client = ask("www.example.com.", RecordType::ANY);
    let fixture = fixture(address_reply(&client, vec![client.clone()]));
    let ctx = context(&fixture, &client);

    let served = fixture.stage.handle_terminal(&ctx).await.expect("served");
    assert_eq!(served.message().answers.len(), 1);
    assert_eq!(fixture.cache.stats().entries, 0);
}

#[tokio::test]
async fn test_an_error_reply_with_records_is_served_but_never_stored() {
    let client = ask("www.example.com.", RecordType::A);
    let mut reply = address_reply(&client, vec![client.clone()]);
    reply.header.rcode = ResponseCode::SERVFAIL;
    let fixture = fixture(reply);
    let ctx = context(&fixture, &client);

    let first = fixture.stage.handle_terminal(&ctx).await.expect("first");
    assert_eq!(first.message().header.rcode, ResponseCode::SERVFAIL);
    fixture.stage.handle_terminal(&ctx).await.expect("second");

    assert_eq!(
        fixture.upstream.queries(),
        2,
        "a follow-up lookup must miss"
    );
    assert_eq!(fixture.cache.stats().entries, 0);
}
