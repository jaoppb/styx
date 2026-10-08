use std::net::{IpAddr, Ipv4Addr};

use styx_proto::Ttl;

use super::*;
use crate::domain::topology::{GlueOrigin, Nameserver};

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn delegation(zone: &str, ttl: u32, at: Instant) -> Delegation {
    let server = Nameserver {
        name: name(&format!("ns.{zone}")),
        addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        glue_origin: GlueOrigin::InBailiwickGlue,
    };
    let parent = name(zone).parent().unwrap();
    Delegation::new(parent, name(zone), vec![server], Ttl::from_secs(ttl), at)
}

#[test]
fn the_closest_unexpired_cut_wins_and_expiry_falls_back_up_the_tree() {
    let now = Instant::now();
    let cache = MemoryInfraCache::default();
    cache.put_delegation(delegation("com.", 600, now));
    cache.put_delegation(delegation("example.com.", 60, now));

    let warm = cache.closest_enclosing_cut(&name("www.example.com."), now);
    assert_eq!(warm.zone, name("example.com."));
    let later = now + Duration::from_secs(61);
    let colder = cache.closest_enclosing_cut(&name("www.example.com."), later);
    assert_eq!(colder.zone, name("com."));
    let unknown = cache.closest_enclosing_cut(&name("example.org."), now);
    assert!(unknown.is_root);
}

#[test]
fn the_bound_evicts_the_soonest_to_expire() {
    let now = Instant::now();
    let cache = MemoryInfraCache::new(InfraCapacity {
        max_delegations: 2,
        max_servers: 2,
    });
    cache.put_delegation(delegation("a.example.", 600, now));
    cache.put_delegation(delegation("b.example.", 60, now));
    cache.put_delegation(delegation("c.example.", 600, now));
    assert_eq!(cache.delegation_count(), 2);
    assert!(cache.get_delegation(&name("b.example."), now).is_none());
    assert!(cache.get_delegation(&name("a.example."), now).is_some());
}

#[test]
fn metrics_accumulate_per_server_and_idle_ones_are_dropped() {
    let now = Instant::now();
    let cache = MemoryInfraCache::default();
    let server = NameserverAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
    cache.update_metrics(server, MetricEvent::Success(Duration::from_millis(40)), now);
    assert_eq!(
        cache.metrics(server, now).srtt().smoothed(),
        Duration::from_millis(40)
    );
    cache.evict_expired(now + METRICS_IDLE_EXPIRY);
    assert_eq!(cache.metrics(server, now).srtt().smoothed(), Duration::ZERO);
}

#[test]
fn resolved_glue_is_kept_in_the_delegation_and_can_only_shorten_its_life() {
    let now = Instant::now();
    let cache = MemoryInfraCache::default();
    let glueless = Nameserver {
        name: name("ns.example.org."),
        addresses: Vec::new(),
        glue_origin: GlueOrigin::OutOfBailiwickDiscarded,
    };
    cache.put_delegation(Delegation::new(
        name("org."),
        name("example.org."),
        vec![glueless],
        Ttl::from_secs(600),
        now,
    ));
    let found = [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))];

    cache.provide_addresses(
        &name("example.org."),
        &name("ns.example.org."),
        &found,
        Duration::from_secs(120),
        now,
    );

    let cut = cache.closest_enclosing_cut(&name("www.example.org."), now);
    let member = cut.nameservers.members().first().unwrap();
    assert_eq!(member.addresses, found);
    assert_eq!(member.glue_origin, GlueOrigin::ResolvedSeparately);
    let after = now + Duration::from_secs(121);
    assert!(cache.get_delegation(&name("example.org."), after).is_none());

    cache.put_delegation(delegation("example.net.", 60, now));
    cache.provide_addresses(
        &name("example.net."),
        &name("ns.example.net."),
        &found,
        Duration::from_secs(3600),
        now,
    );
    let almost = now + Duration::from_secs(59);
    assert!(cache
        .get_delegation(&name("example.net."), almost)
        .is_some());
    let past = now + Duration::from_secs(61);
    assert!(cache.get_delegation(&name("example.net."), past).is_none());
}
