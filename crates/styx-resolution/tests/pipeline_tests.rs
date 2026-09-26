//! Pipeline stage ordering, Clock injection, and forged answer safeguards.

mod harness;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harness::{DnsClient, TestServer};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, Ttl,
};
use styx_resolution::{
    AnswerSource, ClientId, FilterPolicy, FilterVerdict, LocalRecords, QueryDetail, QueryObserver,
    ResolutionOutcome,
};

fn make_query(name: &str, rtype: RecordType) -> Message {
    let qname = match Name::from_ascii(name) {
        Ok(q) => q,
        Err(_) => Name::root(),
    };
    let header = Header::new_query(0x2000, Opcode::Query, true);
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname, rtype, RecordClass::In));
    msg
}

struct StaticLocalRecords {
    name: String,
    ip: Ipv4Addr,
}

impl LocalRecords for StaticLocalRecords {
    fn lookup(&self, question: &Question) -> Option<Vec<ResourceRecord>> {
        if question.qname.to_string() == self.name {
            Some(vec![ResourceRecord::new(
                question.qname.clone(),
                RecordType::A,
                RecordClass::In,
                Ttl::from_secs(60),
                RData::A(self.ip),
            )])
        } else {
            None
        }
    }
}

struct SpyFilterPolicy {
    consulted: AtomicUsize,
    verdict: FilterVerdict,
}

impl FilterPolicy for SpyFilterPolicy {
    fn evaluate(&self, _client: &ClientId, _question: &Question) -> FilterVerdict {
        self.consulted.fetch_add(1, Ordering::SeqCst);
        self.verdict
    }
}

struct CountingObserver {
    outcomes: Mutex<Vec<ResolutionOutcome>>,
    details: Mutex<Vec<QueryDetail>>,
}

impl CountingObserver {
    fn new() -> Self {
        Self {
            outcomes: Mutex::new(Vec::new()),
            details: Mutex::new(Vec::new()),
        }
    }
}

impl QueryObserver for CountingObserver {
    fn record_outcome(
        &self,
        _client: &ClientId,
        _question: &Question,
        outcome: &ResolutionOutcome,
    ) {
        if let Ok(mut outcomes) = self.outcomes.lock() {
            outcomes.push(outcome.clone());
        }
    }

    fn offer_detail(&self, detail: QueryDetail) {
        if let Ok(mut details) = self.details.lock() {
            details.push(detail);
        }
    }

    fn dropped_detail(&self) -> u64 {
        0
    }
}

#[tokio::test]
async fn test_injected_clock_advancement() {
    let observer = Arc::new(CountingObserver::new());
    let mut server = TestServer::boot_with_collaborators(
        Arc::new(styx_resolution::NoLocalRecords::new()),
        Arc::new(styx_resolution::AllowAllFilter::new()),
        observer.clone(),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();
    let clock = server.clock();

    // Query at T0
    let q1 = make_query("t0.example.com.", RecordType::A);
    let _ = client
        .query_udp(server.udp_addr(), &q1)
        .await
        .expect("q1 query");
    let t0 = observer
        .details
        .lock()
        .expect("lock")
        .first()
        .expect("first detail")
        .at;

    // Advance clock by 10 days
    clock.advance(Duration::from_secs(10 * 86400));

    // Query at T1
    let q2 = make_query("t1.example.com.", RecordType::A);
    let _ = client
        .query_udp(server.udp_addr(), &q2)
        .await
        .expect("q2 query");
    let t1 = observer
        .details
        .lock()
        .expect("lock")
        .get(1)
        .expect("second detail")
        .at;

    let diff = match t1.duration_since(t0) {
        Ok(d) => d,
        Err(_) => Duration::ZERO,
    };
    assert!(
        diff >= Duration::from_secs(10 * 86400),
        "Clock advance must reflect in query timestamps"
    );

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_local_records_short_circuit_filter() {
    let local = Arc::new(StaticLocalRecords {
        name: "router.lan.".into(),
        ip: Ipv4Addr::new(192, 168, 1, 1),
    });
    let filter = Arc::new(SpyFilterPolicy {
        consulted: AtomicUsize::new(0),
        verdict: FilterVerdict::Block,
    });
    let observer = Arc::new(CountingObserver::new());

    let mut server = TestServer::boot_with_collaborators(local, filter.clone(), observer.clone())
        .await
        .expect("boot server");

    let client = DnsClient::new();
    let query = make_query("router.lan.", RecordType::A);
    let resp = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query");

    // 1. Local record answered NOERROR with forged answer honesty
    assert_eq!(resp.header.rcode, ResponseCode::NOERROR);
    assert!(
        !resp.header.authentic_data,
        "AD bit must be cleared on forged answer"
    );
    assert_eq!(resp.answers.len(), 1);

    // 2. Filter was NOT consulted (short-circuited at stage 1)
    assert_eq!(
        filter.consulted.load(Ordering::SeqCst),
        0,
        "Local records must short-circuit filter"
    );

    // 3. Observer recorded LocalRecord source and uncacheable
    let outcome = observer
        .outcomes
        .lock()
        .expect("lock")
        .first()
        .expect("outcome")
        .clone();
    assert_eq!(outcome.source(), AnswerSource::LocalRecord);
    assert!(!outcome.is_cacheable());
    assert!(outcome.is_forged());

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_filter_policy_block_honesty() {
    let local = Arc::new(styx_resolution::NoLocalRecords::new());
    let filter = Arc::new(SpyFilterPolicy {
        consulted: AtomicUsize::new(0),
        verdict: FilterVerdict::Block,
    });
    let observer = Arc::new(CountingObserver::new());

    let mut server = TestServer::boot_with_collaborators(local, filter.clone(), observer.clone())
        .await
        .expect("boot server");

    let client = DnsClient::new();
    let query = make_query("tracking.adserver.com.", RecordType::A);
    let resp = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query");

    assert_eq!(resp.header.rcode, ResponseCode::NXDOMAIN);
    assert!(
        !resp.header.authentic_data,
        "AD bit must be cleared on block"
    );
    assert!(resp.answers.is_empty(), "NXDOMAIN carries no answers");
    assert_eq!(filter.consulted.load(Ordering::SeqCst), 1);

    let outcome = observer
        .outcomes
        .lock()
        .expect("lock")
        .first()
        .expect("outcome")
        .clone();
    assert_eq!(outcome.source(), AnswerSource::Blocked);
    assert!(outcome.is_forged());
    assert!(!outcome.is_cacheable());

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_observer_records_every_query_path() {
    let observer = Arc::new(CountingObserver::new());
    let mut server = TestServer::boot_with_collaborators(
        Arc::new(styx_resolution::NoLocalRecords::new()),
        Arc::new(styx_resolution::AllowAllFilter::new()),
        observer.clone(),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();

    // 1. Normal query
    let _ = client
        .query_udp(server.udp_addr(), &make_query("valid.com.", RecordType::A))
        .await
        .expect("normal query");

    // 2. Malformed query (QDCOUNT = 0)
    let mut malformed = make_query("malformed.com.", RecordType::A);
    malformed.questions.clear();
    let _ = client
        .query_udp(server.udp_addr(), &malformed)
        .await
        .expect("malformed query");

    // 3. TCP query
    let _ = client
        .query_tcp(server.tcp_addr(), &make_query("tcp.com.", RecordType::A))
        .await
        .expect("tcp query");

    // Assert observer was notified for all 3 queries
    let count = observer.outcomes.lock().expect("lock").len();
    assert_eq!(
        count, 3,
        "Observer must record exactly once per query on every path"
    );

    server.shutdown().await.expect("shutdown");
}
