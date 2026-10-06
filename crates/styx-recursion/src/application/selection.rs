//! Choosing which nameserver of a cut to ask.

use std::time::Instant;

use crate::domain::ports::InfraCache;
use crate::domain::topology::{NameserverAddr, ZoneCut};

/// The outcome of choosing a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerChoice {
    /// The server to ask, if any remains.
    pub chosen: Option<NameserverAddr>,
    /// Untried servers excluded outright — lame for this zone, or of a disabled
    /// address family — for the descent to mark tried.
    pub skipped: Vec<NameserverAddr>,
}

/// Chooses the untried server of `cut` with the lowest SRTT, preferring servers not
/// in failure backoff. Servers lame for the zone, and IPv6 servers when IPv6 is
/// off, are never chosen. A server in backoff is still chosen when nothing else
/// remains: a slow answer beats none.
pub fn select_server<I: InfraCache>(
    cut: &ZoneCut,
    infra: &I,
    now: Instant,
    use_ipv6: bool,
) -> ServerChoice {
    let mut skipped = Vec::new();
    let mut best = None;
    for server in cut.nameservers.untried() {
        let metrics = infra.metrics(server, now);
        if (server.ip().is_ipv6() && !use_ipv6) || metrics.is_lame_for(&cut.zone, now) {
            skipped.push(server);
            continue;
        }
        let rank = (metrics.in_backoff(now), metrics.srtt());
        if best.as_ref().is_none_or(|(best_rank, _)| rank < *best_rank) {
            best = Some((rank, server));
        }
    }
    ServerChoice {
        chosen: best.map(|(_, server)| server),
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use styx_proto::Name;

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::domain::metrics::{MetricEvent, NameserverMetrics};
    use crate::domain::root_hints::RootHints;
    use crate::domain::topology::{Delegation, GlueOrigin, Nameserver, NsSet};

    /// Metrics only: selection reads nothing else from the cache.
    #[derive(Default)]
    struct MetricsOnly(Mutex<HashMap<NameserverAddr, NameserverMetrics>>);

    impl InfraCache for MetricsOnly {
        fn get_delegation(&self, _zone: &Name, _now: Instant) -> Option<Delegation> {
            None
        }
        fn put_delegation(&self, _delegation: Delegation) {}
        fn closest_enclosing_cut(&self, _name: &Name, _now: Instant) -> ZoneCut {
            ZoneCut::new(Name::root(), NsSet::default())
        }
        fn metrics(&self, server: NameserverAddr, now: Instant) -> NameserverMetrics {
            self.0
                .lock()
                .unwrap()
                .get(&server)
                .cloned()
                .unwrap_or_else(|| NameserverMetrics::new(now))
        }
        fn update_metrics(&self, server: NameserverAddr, event: MetricEvent, now: Instant) {
            self.0
                .lock()
                .unwrap()
                .entry(server)
                .or_insert_with(|| NameserverMetrics::new(now))
                .apply(event, now);
        }
        fn provide_addresses(
            &self,
            _zone: &Name,
            _nameserver: &Name,
            _addresses: &[IpAddr],
            _lifetime: std::time::Duration,
            _now: Instant,
        ) {
        }
        fn prime_from(&self, _hints: &RootHints, _now: Instant) {}
        fn evict_expired(&self, _now: Instant) {}
    }

    fn server(last: u8) -> NameserverAddr {
        NameserverAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
    }

    fn cut(addresses: Vec<IpAddr>) -> ZoneCut {
        ZoneCut::new(
            Name::from_ascii("example.").unwrap(),
            NsSet::new(vec![Nameserver {
                name: Name::from_ascii("ns.example.").unwrap(),
                addresses,
                glue_origin: GlueOrigin::InBailiwickGlue,
            }]),
        )
    }

    #[test]
    fn the_fastest_healthy_server_is_chosen_and_lame_ones_skipped() {
        let now = Instant::now();
        let infra = MetricsOnly::default();
        infra.update_metrics(
            server(1),
            MetricEvent::Success(Duration::from_millis(90)),
            now,
        );
        infra.update_metrics(
            server(2),
            MetricEvent::Success(Duration::from_millis(10)),
            now,
        );
        let lame_until = now + Duration::from_secs(60);
        let zone = Name::from_ascii("example.").unwrap();
        infra.update_metrics(server(3), MetricEvent::LameFor(zone, lame_until), now);
        let cut = cut(vec![server(1).ip(), server(2).ip(), server(3).ip()]);

        let choice = select_server(&cut, &infra, now, true);
        assert_eq!(choice.chosen, Some(server(2)));
        assert_eq!(choice.skipped, vec![server(3)]);
    }

    #[test]
    fn ipv6_servers_are_skipped_when_ipv6_is_off() {
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let choice = select_server(
            &cut(vec![v6]),
            &MetricsOnly::default(),
            Instant::now(),
            false,
        );
        assert_eq!(choice.chosen, None);
        assert_eq!(choice.skipped, vec![NameserverAddr::new(v6)]);
    }
}
