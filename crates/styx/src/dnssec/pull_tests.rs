//! The pool chain source over real sockets: a fake upstream serves signed DS, DNSKEY and
//! NSEC records through a Do53 forwarder pool, the way a validating forwarder would.

use std::sync::Arc;
use std::time::Duration;

use styx_core::test_util::TestClock;
use styx_core::UpstreamId;
use styx_dnssec::{ChainSource, ChainSourceError, Delegation, Nsec3IterationsCap};
use styx_proto::{Name, RecordType};
use styx_recursion::domain::chain_material::{ChainMaterial, SignedReferral};
use styx_recursion::domain::ports::ChainMaterialSink;
use styx_resolution::{
    CanaryConfig, CircuitConfig, Do53Forwarder, EdnsBufferSize, OrderedFailover, PoolMember,
    ProbeConfig, ProbePolicy, UpstreamPool, Weight,
};
use styx_testkit::{FakeNameServer, FakeRole, ZoneScript};

use super::PoolChainSource;
use crate::dnssec::pushed::PushedReferrals;
use crate::dnssec::test_zone::{a_record, name, nsec, ZoneKey};

type Source = PoolChainSource<OrderedFailover, Do53Forwarder<TestClock>, TestClock>;

struct Fixture {
    upstream: FakeNameServer,
    pushed: Arc<PushedReferrals<TestClock>>,
    source: Source,
}

impl Fixture {
    async fn boot(script: ZoneScript, anchor: &ZoneKey) -> Self {
        let upstream = FakeNameServer::start(FakeRole::Authoritative, script)
            .await
            .unwrap();
        let clock = Arc::new(TestClock::new());
        let id = UpstreamId::new("validating-forwarder");
        let forwarder = Do53Forwarder::new(
            id.clone(),
            upstream.udp_addr(),
            EdnsBufferSize::default(),
            Duration::from_millis(500),
            Duration::from_millis(500),
            Arc::clone(&clock),
        );
        let canary = CanaryConfig {
            qname: name("canary.check."),
            qtype: RecordType::A,
            timeout: Duration::from_millis(500),
        };
        let pool = Arc::new(UpstreamPool::new(
            vec![PoolMember::new(id, forwarder, Weight::new(1), canary)],
            OrderedFailover::new(),
            Arc::clone(&clock),
            CircuitConfig::default(),
            ProbePolicy::new(ProbeConfig::default()),
        ));
        let pushed = Arc::new(PushedReferrals::new(Arc::clone(&clock)));
        let source = PoolChainSource::new(
            pool,
            Arc::clone(&pushed),
            clock,
            Duration::from_secs(1),
            &anchor.anchors(),
            Nsec3IterationsCap::DEFAULT,
        );
        Self {
            upstream,
            pushed,
            source,
        }
    }

    fn asked(&self) -> Vec<(String, RecordType)> {
        self.upstream
            .received()
            .into_iter()
            .map(|query| (query.question.qname.to_string(), query.question.qtype))
            .collect()
    }
}

fn delegation_script(root: &ZoneKey, com: &ZoneKey) -> ZoneScript {
    ZoneScript::new()
        .answer(".", RecordType::DNSKEY, root.dnskey_rrset())
        .answer("com.", RecordType::DS, root.signed(vec![com.ds_record()]))
        .answer("com.", RecordType::DNSKEY, com.dnskey_rrset())
}

#[tokio::test]
async fn an_anchored_zone_is_an_apex_with_its_signed_dnskey_rrset() {
    let root = ZoneKey::generate(".");
    let fixture = Fixture::boot(delegation_script(&root, &ZoneKey::generate("com.")), &root).await;

    let material = fixture.source.material_for(&Name::root()).await.unwrap();

    let Delegation::Apex { dnskey } = material.delegation else {
        panic!("expected an apex, got {:?}", material.delegation);
    };
    assert_eq!(dnskey.records.len(), 1);
    assert_eq!(dnskey.signatures.len(), 1);
    assert!(fixture
        .upstream
        .received()
        .iter()
        .all(|query| query.dnssec_ok));
}

#[tokio::test]
async fn a_signed_ds_rrset_makes_a_secure_delegation_with_the_child_dnskey() {
    let root = ZoneKey::generate(".");
    let com = ZoneKey::generate("com.");
    let fixture = Fixture::boot(delegation_script(&root, &com), &root).await;

    let material = fixture.source.material_for(com.zone()).await.unwrap();

    let Delegation::Signed { ds, dnskey } = material.delegation else {
        panic!(
            "expected a signed delegation, got {:?}",
            material.delegation
        );
    };
    assert_eq!(ds.records, vec![com.ds_record()]);
    assert_eq!(ds.signatures.len(), 1);
    assert_eq!(dnskey.signatures.len(), 1);
}

/// 6d.2: a DS RRset a recursor's referral carried is used as is; only the DNSKEY is asked.
#[tokio::test]
async fn a_pushed_ds_rrset_saves_the_ds_query() {
    let root = ZoneKey::generate(".");
    let com = ZoneKey::generate("com.");
    let fixture = Fixture::boot(delegation_script(&root, &com), &root).await;
    let mut material = ChainMaterial::default();
    material.push_referral(SignedReferral {
        parent_zone: Name::root(),
        child_zone: com.zone().clone(),
        ds_records: root.signed(vec![com.ds_record()]),
    });
    fixture.pushed.push(material);

    let material = fixture.source.material_for(com.zone()).await.unwrap();

    assert!(matches!(material.delegation, Delegation::Signed { .. }));
    assert_eq!(
        fixture.asked(),
        vec![("com.".to_string(), RecordType::DNSKEY)]
    );
}

#[tokio::test]
async fn the_parents_signed_nsec_without_ds_makes_an_unsigned_delegation() {
    let root = ZoneKey::generate(".");
    let insecure = name("insecure.");
    let proof = root.signed(vec![nsec(
        &insecure,
        &name("zzz."),
        &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
    )]);
    let script = ZoneScript::new()
        .origin(".", 300)
        .denial("insecure.", RecordType::DS, proof);
    let fixture = Fixture::boot(script, &root).await;

    let material = fixture.source.material_for(&insecure).await.unwrap();

    let Delegation::Unsigned { signatures, .. } = material.delegation else {
        panic!(
            "expected an unsigned delegation, got {:?}",
            material.delegation
        );
    };
    assert_eq!(signatures.len(), 1);
}

#[tokio::test]
async fn a_name_whose_nsec_lists_no_ns_is_not_a_zone_cut() {
    let root = ZoneKey::generate(".");
    let com = ZoneKey::generate("com.");
    let www = name("www.com.");
    let proof = com.signed(vec![nsec(
        &www,
        &name("zzz.com."),
        &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
    )]);
    let script = ZoneScript::new()
        .answer("www.com.", RecordType::A, vec![a_record(&www)])
        .origin("com.", 300)
        .denial("www.com.", RecordType::DS, proof);
    let fixture = Fixture::boot(script, &root).await;

    let material = fixture.source.material_for(&www).await.unwrap();

    assert_eq!(material.delegation, Delegation::NotACut);
}

/// 6d.3: a forwarder that strips DNSSEC records gives no chain material, which the validator
/// turns into Indeterminate — never an unsigned (Insecure) zone.
#[tokio::test]
async fn a_reply_stripped_of_dnssec_records_is_an_error_not_an_unsigned_zone() {
    let root = ZoneKey::generate(".");
    let com = ZoneKey::generate("com.");
    let unsigned_ds = vec![com.ds_record()];
    let script = ZoneScript::new()
        .answer("com.", RecordType::DS, unsigned_ds)
        .origin(".", 300);
    let fixture = Fixture::boot(script, &root).await;

    let ds_without_rrsig = fixture.source.material_for(com.zone()).await;
    let nodata_without_nsec = fixture.source.material_for(&name("org.")).await;
    let dnskey_without_rrsig = fixture.source.material_for(&Name::root()).await;

    for result in [ds_without_rrsig, nodata_without_nsec, dnskey_without_rrsig] {
        assert!(
            matches!(result, Err(ChainSourceError::Unavailable(_))),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn fetched_material_is_kept_for_the_next_validation() {
    let root = ZoneKey::generate(".");
    let com = ZoneKey::generate("com.");
    let fixture = Fixture::boot(delegation_script(&root, &com), &root).await;

    let first = fixture.source.material_for(com.zone()).await.unwrap();
    let second = fixture.source.material_for(com.zone()).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(fixture.upstream.received().len(), 2);
}
