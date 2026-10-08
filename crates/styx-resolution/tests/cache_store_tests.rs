//! Store introspection, bailiwick enforcement, eviction, and concurrency tests.

mod harness;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use harness::{CommandableUpstream, DnsClient, TestClock, TestServer, UpstreamBehavior};
use styx_core::{Clock, UpstreamId};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, Ttl,
};
use styx_resolution::{
    Admission, AllowAllFilter, AnswerCache, AnswerSource, Bailiwick, CacheCapacity, CacheEntry,
    CacheKey, CacheStage, CircuitConfig, DiscardObserver, Do53Forwarder, EdnsBufferSize, HeapBytes,
    Lookup, NoLocalRecords, OrderedFailover, PoolMember, PositiveEntry, ProbeConfig, ProbePolicy,
    RejectReason, ShardedAnswerCache, TtlPolicy, UpstreamPool,
};

fn make_query(name: &str, rtype: RecordType) -> Message {
    let qname = Name::from_ascii(name).unwrap_or_else(|_| Name::root());
    let mut msg = Message::new(Header::new_query(0x3456, Opcode::Query, true));
    msg.header.recursion_desired = true;
    msg.questions
        .push(Question::new(qname, rtype, RecordClass::In));
    msg
}

fn create_member(
    id_str: &str,
    upstream: &CommandableUpstream,
    clock: Arc<TestClock>,
) -> PoolMember<Do53Forwarder<TestClock>> {
    let id = UpstreamId::new(id_str);
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        Duration::from_millis(500),
        Duration::from_millis(500),
        clock,
    );
    let canary = Name::from_ascii("canary.check.").unwrap_or_else(|_| Name::root());
    PoolMember::new(
        id,
        forwarder,
        styx_resolution::Weight::new(1),
        styx_resolution::CanaryConfig {
            qname: canary,
            qtype: RecordType::A,
            timeout: Duration::from_millis(500),
        },
    )
}

fn create_cache_stage(
    cache: Arc<ShardedAnswerCache<TestClock>>,
    upstream: &CommandableUpstream,
    clock: Arc<TestClock>,
) -> Arc<
    CacheStage<ShardedAnswerCache<TestClock>, OrderedFailover, Do53Forwarder<TestClock>, TestClock>,
> {
    let member = create_member("up1", upstream, Arc::clone(&clock));
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
    Arc::new(CacheStage::new(cache, pool, clock, Duration::from_secs(2)))
}

#[tokio::test]
async fn test_bailiwick_store_introspection_poisoned_records_absent() {
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
    let upstream = CommandableUpstream::start().await.expect("upstream start");

    // Configure upstream to answer for bank.example.com. but inject poisoned
    // target.evilcorp.com. record in Additional section
    upstream.set_behavior(UpstreamBehavior::PoisonedAdditional {
        answer_ip: Ipv4Addr::new(93, 184, 216, 34),
        poisoned_name: "target.evilcorp.com.".to_string(),
        poisoned_ip: Ipv4Addr::new(6, 6, 6, 6),
    });

    let stage = create_cache_stage(Arc::clone(&cache), &upstream, Arc::clone(&clock));
    let mut server = TestServer::boot_with_terminal_and_clock(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        stage,
        Arc::clone(&clock),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();
    let query = make_query("bank.example.com.", RecordType::A);

    let resp = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query");
    assert_eq!(resp.header.rcode, ResponseCode::NOERROR);
    assert_eq!(resp.answers.len(), 1);

    // 1. Legitimate in-bailiwick record MUST be present in cache
    let legitimate_q = Question::new(
        Name::from_ascii("bank.example.com.").expect("name"),
        RecordType::A,
        RecordClass::In,
    );
    let legitimate_key = CacheKey::from_question(&legitimate_q).expect("key");
    assert!(matches!(cache.lookup(&legitimate_key), Lookup::Hit(_)));

    // 2. Out-of-bailiwick poisoned record MUST be absent from cache
    let poisoned_q = Question::new(
        Name::from_ascii("target.evilcorp.com.").expect("name"),
        RecordType::A,
        RecordClass::In,
    );
    let poisoned_key = CacheKey::from_question(&poisoned_q).expect("key");
    assert!(matches!(cache.lookup(&poisoned_key), Lookup::Miss));

    // 3. Store-introspection: iterate all shards and prove poisoned key is absent
    for i in 0..cache.shard_count() {
        if let Some(shard) = cache.shard(i) {
            assert!(
                !shard.contains_key(&poisoned_key),
                "poisoned key found in cache store!"
            );
        }
    }

    // 4. Metrics reflection: rejection was accounted
    assert_eq!(cache.stats().rejected_out_of_bailiwick, 1);

    server.shutdown().await.expect("shutdown");
    upstream.shutdown();
}

fn make_test_key(name: &str) -> Option<CacheKey> {
    let qname = Name::from_ascii(name).ok()?;
    let q = Question::new(qname, RecordType::A, RecordClass::In);
    CacheKey::from_question(&q).ok()
}

#[tokio::test]
async fn test_capacity_eviction_expired_before_fresh_lru() {
    let clock = Arc::new(TestClock::new());
    // Single shard with capacity of 3 entries to deterministically exercise eviction
    let capacity = CacheCapacity::new(3, HeapBytes::new(1024 * 1024));
    let cache = ShardedAnswerCache::new(Arc::clone(&clock), capacity, TtlPolicy::default(), 1);
    let admission = Admission::new(TtlPolicy::default());

    // Helper to synthesize an upstream message and admit it
    let admit_record = |name: &str, ttl_secs: u32| {
        let qname = Name::from_ascii(name).expect("qname");
        let question = Question::new(qname.clone(), RecordType::A, RecordClass::In);
        let key = CacheKey::from_question(&question).expect("key");

        let mut msg = Message::response_to(0x1000, question.clone());
        msg.answers.push(ResourceRecord::new(
            qname,
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(ttl_secs),
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        ));

        let bailiwick = Bailiwick::of_response(&question, &msg);
        let outcome = admission.evaluate(
            &bailiwick,
            &msg,
            AnswerSource::Upstream,
            clock.now_monotonic(),
        );
        cache.admit(&key, outcome).expect("admit");
    };

    // 1. Populate with 3 entries: k1 (TTL 10), k2 (TTL 100), k3 (TTL 100)
    admit_record("k1.test.", 10);
    admit_record("k2.test.", 100);
    admit_record("k3.test.", 100);
    assert_eq!(cache.stats().entries, 3);

    // Advance clock by 20s: k1 expires, k2 and k3 remain fresh
    clock.advance(Duration::from_secs(20));

    // 2. Admit k4 (TTL 100): exceeds capacity 3, triggers eviction.
    // Expired entry (k1) MUST be reclaimed first, leaving fresh entries intact.
    admit_record("k4.test.", 100);
    assert_eq!(cache.stats().entries, 3);

    let k1_key = make_test_key("k1.test.").expect("key");
    assert!(matches!(
        cache.lookup(&k1_key),
        Lookup::Miss | Lookup::Expired
    ));

    let k2_key = make_test_key("k2.test.").expect("key");
    let k3_key = make_test_key("k3.test.").expect("key");
    let k4_key = make_test_key("k4.test.").expect("key");

    assert!(matches!(cache.lookup(&k2_key), Lookup::Hit(_)));
    assert!(matches!(cache.lookup(&k3_key), Lookup::Hit(_)));
    assert!(matches!(cache.lookup(&k4_key), Lookup::Hit(_)));

    // 3. Touch k2 to update recency (k3 is now oldest LRU)
    let _ = cache.lookup(&k2_key);

    // 4. Admit k5: all current entries (k2, k3, k4) are fresh. LRU entry (k3) MUST be evicted!
    admit_record("k5.test.", 100);
    assert_eq!(cache.stats().entries, 3);
    assert!(matches!(cache.lookup(&k3_key), Lookup::Miss));
    assert!(matches!(cache.lookup(&k2_key), Lookup::Hit(_)));
    assert!(matches!(cache.lookup(&k4_key), Lookup::Hit(_)));

    // Stats reflect both expired reclamation and fresh LRU eviction
    assert!(cache.stats().expired >= 1);
    assert!(cache.stats().evicted >= 1);
}

fn run_worker(c: Arc<ShardedAnswerCache<TestClock>>, clk: Arc<TestClock>, task_idx: u8) {
    let admission = Admission::new(TtlPolicy::default());
    for i in 0u8..50u8 {
        let bucket = i.rem_euclid(5);
        let name_str = format!("host-{task_idx}-{bucket}.test.");
        let Ok(qname) = Name::from_ascii(&name_str) else {
            continue;
        };
        let question = Question::new(qname.clone(), RecordType::A, RecordClass::In);
        let Ok(key) = CacheKey::from_question(&question) else {
            continue;
        };

        let mut msg = Message::response_to(0x1000, question.clone());
        msg.answers.push(ResourceRecord::new(
            qname,
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(60),
            RData::A(Ipv4Addr::new(10, 0, task_idx, i)),
        ));

        let bailiwick = Bailiwick::of_response(&question, &msg);
        let outcome = admission.evaluate(
            &bailiwick,
            &msg,
            AnswerSource::Upstream,
            clk.now_monotonic(),
        );
        let _ = c.admit(&key, outcome);
        let _ = c.lookup(&key);
    }
}

#[tokio::test]
async fn test_concurrent_admissions_safety() {
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(ShardedAnswerCache::new(
        Arc::clone(&clock),
        CacheCapacity::default(),
        TtlPolicy::default(),
        8,
    ));

    let mut handles = Vec::new();

    for task_idx in 0u8..20u8 {
        let c = Arc::clone(&cache);
        let clk = Arc::clone(&clock);
        handles.push(tokio::spawn(async move {
            run_worker(c, clk, task_idx);
        }));
    }

    for h in handles {
        h.await.expect("task join");
    }

    let stats = cache.stats();
    assert!(stats.admitted > 0);
    assert!(stats.hits > 0 || stats.misses > 0);

    let purged = cache.purge_all();
    assert_eq!(purged.count(), stats.entries);
    assert_eq!(cache.stats().entries, 0);
    assert_eq!(cache.stats().bytes, HeapBytes::zero());
}

/// ADR 0017: an answer record reached through an in-bailiwick CNAME chain is
/// admissible, so a cross-zone chain is cached whole — while an unrelated record
/// appended to the same answer section is still rejected.
#[test]
fn test_cross_zone_cname_chain_is_admitted_whole() {
    let clock = TestClock::new();
    let admission = Admission::new(TtlPolicy::default());
    let qname = Name::from_ascii("www.example.com.").expect("qname");
    let target = Name::from_ascii("x.cdn.net.").expect("target");
    let question = Question::new(qname.clone(), RecordType::A, RecordClass::In);

    let mut msg = Message::response_to(0x2000, question.clone());
    msg.answers.push(ResourceRecord::new(
        qname,
        RecordType::CNAME,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Cname(target.clone()),
    ));
    msg.answers.push(ResourceRecord::new(
        target,
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(Ipv4Addr::new(192, 0, 2, 7)),
    ));
    msg.answers.push(ResourceRecord::new(
        Name::from_ascii("evil.example.").expect("evil"),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(Ipv4Addr::new(6, 6, 6, 6)),
    ));

    let bailiwick = Bailiwick::of_response(&question, &msg);
    let outcome = admission.evaluate(
        &bailiwick,
        &msg,
        AnswerSource::Recursion,
        clock.now_monotonic(),
    );

    assert_eq!(outcome.admitted.len(), 1, "one composite entry");
    let Some(CacheEntry::Positive(PositiveEntry::Message(cached))) = outcome.admitted.first()
    else {
        panic!(
            "expected a composite message entry, got {:?}",
            outcome.admitted
        );
    };
    let owners: Vec<String> = cached
        .answer()
        .iter()
        .map(|rrset| rrset.owner().to_string())
        .collect();
    assert_eq!(owners, ["www.example.com.", "x.cdn.net."]);

    assert_eq!(outcome.rejected.len(), 1);
    let rejected = outcome.rejected.first().expect("one rejection");
    assert_eq!(rejected.reason, RejectReason::OutOfBailiwick);
    assert_eq!(rejected.owner.to_string(), "evil.example.");
}

/// A CNAME inside the zone that is not a link of the chain from the qname must not
/// let a record for an arbitrary foreign name into the cache.
#[test]
fn test_in_zone_cname_off_the_chain_cannot_poison_a_foreign_name() {
    let clock = TestClock::new();
    let admission = Admission::new(TtlPolicy::default());
    let qname = Name::from_ascii("www.example.com.").expect("qname");
    let question = Question::new(qname.clone(), RecordType::A, RecordClass::In);
    let record = |owner: &str, rdata: RData| {
        ResourceRecord::new(
            Name::from_ascii(owner).expect("owner"),
            rdata.rtype(),
            RecordClass::In,
            Ttl::from_secs(300),
            rdata,
        )
    };

    let mut msg = Message::response_to(0x2001, question.clone());
    msg.answers.push(record(
        "www.example.com.",
        RData::A(Ipv4Addr::new(192, 0, 2, 7)),
    ));
    msg.answers.push(record(
        "x.example.com.",
        RData::Cname(Name::from_ascii("www.bank.com.").expect("target")),
    ));
    msg.answers.push(record(
        "www.bank.com.",
        RData::A(Ipv4Addr::new(203, 0, 113, 66)),
    ));
    msg.authorities.push(record(
        "example.com.",
        RData::Ns(Name::from_ascii("ns.example.com.").expect("ns")),
    ));

    let bailiwick = Bailiwick::of_response(&question, &msg);
    let outcome = admission.evaluate(
        &bailiwick,
        &msg,
        AnswerSource::Recursion,
        clock.now_monotonic(),
    );

    assert!(outcome
        .rejected
        .iter()
        .any(|rejected| rejected.owner.to_string() == "www.bank.com."
            && rejected.reason == RejectReason::OutOfBailiwick));
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

fn chain_message(
    rcode: ResponseCode,
    soa_owner: &str,
    with_target_data: bool,
) -> (Question, Message) {
    let qname = name("www.example.com.");
    let question = Question::new(qname, RecordType::A, RecordClass::In);
    let record = |owner: &str, rdata: RData| {
        ResourceRecord::new(
            name(owner),
            rdata.rtype(),
            RecordClass::In,
            Ttl::from_secs(300),
            rdata,
        )
    };
    let mut msg = Message::response_to(0x2002, question.clone());
    msg.header.rcode = rcode;
    msg.answers.push(record(
        "www.example.com.",
        RData::Cname(name("www.bank.com.")),
    ));
    if with_target_data {
        msg.answers.push(record(
            "www.bank.com.",
            RData::A(Ipv4Addr::new(192, 0, 2, 9)),
        ));
    }
    let soa = styx_proto::SoaRdata::new(
        name("ns.bank.com."),
        name("hostmaster.bank.com."),
        1,
        2,
        3,
        4,
        120,
    );
    msg.authorities.push(record(soa_owner, RData::Soa(soa)));
    (question, msg)
}

fn evaluate_chain(
    question: &Question,
    msg: &Message,
) -> styx_resolution::domain::cache::AdmissionOutcome {
    let clock = TestClock::new();
    let admission = Admission::new(TtlPolicy::default());
    let bailiwick = Bailiwick::of_response(question, msg);
    admission.evaluate(
        &bailiwick,
        msg,
        AnswerSource::Recursion,
        clock.now_monotonic(),
    )
}

/// A cross-zone chain that ends in NXDOMAIN is cached whole, under the qname only:
/// the SOA of the zone the chain ends in rides inside the qname's composite entry
/// and never becomes a negative entry for the target name.
#[test]
fn test_cross_zone_chain_ending_in_nxdomain_is_cached_under_the_qname_only() {
    let (question, msg) = chain_message(ResponseCode::NXDOMAIN, "bank.com.", false);

    let outcome = evaluate_chain(&question, &msg);

    assert_eq!(
        outcome.admitted.len(),
        1,
        "one composite entry, nothing for the target"
    );
    let Some(CacheEntry::Positive(PositiveEntry::Message(cached))) = outcome.admitted.first()
    else {
        panic!("expected a composite entry, got {:?}", outcome.admitted);
    };
    assert_eq!(cached.rcode(), ResponseCode::NXDOMAIN);
    assert_eq!(cached.answer().len(), 1);
    let authority: Vec<String> = cached
        .authority()
        .iter()
        .map(|rrset| rrset.owner().to_string())
        .collect();
    assert_eq!(authority, ["bank.com."]);
    assert!(outcome.rejected.is_empty(), "{:?}", outcome.rejected);
}

/// The SOA must enclose the name the chain ends at: another zone's SOA does not close
/// the chain, so the answer is refused whole rather than cached without its ending,
/// and the foreign SOA is still reported as the out-of-bailiwick record it is.
#[test]
fn test_chain_denial_with_an_unrelated_soa_is_not_admitted() {
    let (question, msg) = chain_message(ResponseCode::NXDOMAIN, "attacker.org.", false);

    let outcome = evaluate_chain(&question, &msg);

    assert!(outcome.admitted.is_empty(), "{:?}", outcome.admitted);
    let reason_of = |owner: &str| {
        outcome
            .rejected
            .iter()
            .find(|rejected| rejected.owner.to_string() == owner)
            .map(|rejected| rejected.reason)
    };
    assert_eq!(
        reason_of("attacker.org."),
        Some(RejectReason::OutOfBailiwick)
    );
    assert_eq!(
        reason_of("www.example.com."),
        Some(RejectReason::IncompleteChain)
    );
}

/// An error response carries nothing to admit, and says nothing about alias chains:
/// it is not refused as an incomplete one.
#[test]
fn test_an_error_rcode_is_not_refused_as_an_incomplete_chain() {
    for rcode in [
        ResponseCode::SERVFAIL,
        ResponseCode::REFUSED,
        ResponseCode::FORMERR,
    ] {
        let question = Question::new(name("www.example.com."), RecordType::A, RecordClass::In);
        let mut msg = Message::response_to(0x2003, question.clone());
        msg.header.rcode = rcode;
        msg.authorities.push(ResourceRecord::new(
            name("example.com."),
            RecordType::NS,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::Ns(name("ns.example.com.")),
        ));

        let outcome = evaluate_chain(&question, &msg);

        assert!(outcome.admitted.is_empty(), "{rcode:?}");
        assert!(
            outcome.rejected.is_empty(),
            "{rcode:?}: {:?}",
            outcome.rejected
        );
    }
}

/// A response with no question cannot be shown to answer anything, so a dangling
/// alias in it is refused rather than admitted on the strength of the zone name.
#[test]
fn test_a_response_without_a_question_is_refused() {
    let (question, mut msg) = chain_message(ResponseCode::NOERROR, "bank.com.", false);
    msg.authorities.clear();
    msg.questions.clear();

    let outcome = evaluate_chain(&question, &msg);

    assert!(outcome.admitted.is_empty(), "{:?}", outcome.admitted);
    assert!(outcome
        .rejected
        .iter()
        .any(|rejected| rejected.reason == RejectReason::IncompleteChain));
}

/// An alias loop leads nowhere: data owned by a name inside the loop, or an SOA
/// beside it, does not make it an ending.
#[test]
fn test_a_cyclic_alias_chain_is_refused() {
    let question = Question::new(name("a.example.com."), RecordType::A, RecordClass::In);
    let record = |owner: &str, rdata: RData| {
        ResourceRecord::new(
            name(owner),
            rdata.rtype(),
            RecordClass::In,
            Ttl::from_secs(300),
            rdata,
        )
    };
    let mut msg = Message::response_to(0x2004, question.clone());
    msg.answers.push(record(
        "a.example.com.",
        RData::Cname(name("b.example.com.")),
    ));
    msg.answers.push(record(
        "b.example.com.",
        RData::Cname(name("a.example.com.")),
    ));
    msg.answers.push(record(
        "a.example.com.",
        RData::A(Ipv4Addr::new(192, 0, 2, 7)),
    ));

    let outcome = evaluate_chain(&question, &msg);

    assert!(outcome.admitted.is_empty(), "{:?}", outcome.admitted);
    assert!(outcome
        .rejected
        .iter()
        .all(|rejected| rejected.reason == RejectReason::IncompleteChain));
    assert_eq!(outcome.rejected.len(), 3);
}

/// A foreign SOA is a chain's ending only when the answer is a denial: beside real
/// data at the end of the chain it is out of bailiwick like any other.
#[test]
fn test_a_foreign_soa_beside_data_is_not_a_chain_ending() {
    let (question, msg) = chain_message(ResponseCode::NOERROR, "bank.com.", true);

    let outcome = evaluate_chain(&question, &msg);

    assert!(outcome
        .rejected
        .iter()
        .any(|rejected| rejected.owner.to_string() == "bank.com."
            && rejected.reason == RejectReason::OutOfBailiwick));
}
