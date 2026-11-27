use std::sync::Arc;
use std::time::Duration;

use styx_core::test_util::TestClock;
use styx_proto::Name;
use styx_recursion::domain::chain_material::{ChainMaterial, SignedReferral};
use styx_recursion::domain::ports::ChainMaterialSink;

use super::PushedReferrals;
use crate::dnssec::test_zone::{name, ZoneKey};

fn referral(parent: &ZoneKey, child: &ZoneKey) -> SignedReferral {
    SignedReferral {
        parent_zone: parent.zone().clone(),
        child_zone: child.zone().clone(),
        ds_records: parent.signed(vec![child.ds_record()]),
    }
}

fn push(store: &PushedReferrals<TestClock>, referral: SignedReferral) {
    let mut material = ChainMaterial::default();
    material.push_referral(referral);
    store.push(material);
}

fn store() -> (Arc<TestClock>, PushedReferrals<TestClock>) {
    let clock = Arc::new(TestClock::new());
    (Arc::clone(&clock), PushedReferrals::new(clock))
}

#[test]
fn a_parent_signed_ds_rrset_is_kept_for_its_child() {
    let (_, store) = store();
    let com = ZoneKey::generate("com.");
    let example = ZoneKey::generate("example.com.");

    push(&store, referral(&com, &example));

    let ds = store.ds_for(&name("EXAMPLE.com.")).expect("pushed DS");
    assert_eq!(ds.records, vec![example.ds_record()]);
    assert_eq!(ds.signatures.len(), 1);
}

#[test]
fn a_child_not_below_the_referring_zone_is_dropped() {
    let (_, store) = store();
    let org = ZoneKey::generate("org.");
    let example = ZoneKey::generate("example.com.");

    push(&store, referral(&org, &example));

    assert_eq!(store.ds_for(example.zone()), None);
}

/// A server for `com.` cannot vouch for `example.com.`'s DS with another zone's signature,
/// nor slip in a DS record owned by some other name.
#[test]
fn records_outside_the_parent_and_child_are_dropped() {
    let (_, store) = store();
    let com = ZoneKey::generate("com.");
    let other = ZoneKey::generate("other.com.");
    let example = ZoneKey::generate("example.com.");

    push(
        &store,
        SignedReferral {
            parent_zone: com.zone().clone(),
            child_zone: example.zone().clone(),
            ds_records: other.signed(vec![example.ds_record()]),
        },
    );
    push(
        &store,
        SignedReferral {
            parent_zone: com.zone().clone(),
            child_zone: example.zone().clone(),
            ds_records: com.signed(vec![other.ds_record()]),
        },
    );

    assert_eq!(store.ds_for(example.zone()), None);
}

#[test]
fn a_pushed_ds_rrset_lasts_its_ttl() {
    let (clock, store) = store();
    let root = ZoneKey::generate(".");
    let com = ZoneKey::generate("com.");
    push(&store, referral(&root, &com));

    clock.advance(Duration::from_secs(299));
    assert!(store.ds_for(&Name::root()).is_none());
    assert!(store.ds_for(com.zone()).is_some());
    clock.advance(Duration::from_secs(1));
    assert!(store.ds_for(com.zone()).is_none());
}
