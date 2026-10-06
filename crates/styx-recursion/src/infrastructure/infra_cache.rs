//! The in-memory infrastructure cache.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use styx_proto::Name;

use crate::application::config::InfraCapacity;
use crate::domain::metrics::{MetricEvent, NameserverMetrics};
use crate::domain::ports::InfraCache;
use crate::domain::root_hints::RootHints;
use crate::domain::topology::{Delegation, NameserverAddr, NsSet, ZoneCut};

/// Longest a delegation is kept, whatever its NS TTL says: a day bounds how long a
/// hijacked or stale delegation can outlive a fix upstream.
pub const MAX_DELEGATION_LIFETIME: Duration = Duration::from_secs(86_400);

/// Metrics for a server not seen for this long are dropped: RTT and capabilities
/// are learned behaviour, and stale behaviour is worse than none.
pub const METRICS_IDLE_EXPIRY: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
struct Stored {
    delegation: Delegation,
    expires: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    root: Option<Delegation>,
    delegations: HashMap<Name, Stored>,
    metrics: HashMap<NameserverAddr, NameserverMetrics>,
}

/// Delegations by zone and metrics by nameserver, in memory, bounded by entry
/// counts with expired-first, then soonest-to-expire (delegations) or
/// least-recently-seen (servers) eviction.
#[derive(Debug, Default)]
pub struct MemoryInfraCache {
    inner: Mutex<Inner>,
    capacity: InfraCapacity,
}

impl MemoryInfraCache {
    /// An empty cache with the given bounds.
    #[must_use]
    pub fn new(capacity: InfraCapacity) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            capacity,
        }
    }

    /// Delegations currently held, the root excluded.
    #[must_use]
    pub fn delegation_count(&self) -> usize {
        self.lock().delegations.len()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl InfraCache for MemoryInfraCache {
    fn get_delegation(&self, zone: &Name, now: Instant) -> Option<Delegation> {
        let inner = self.lock();
        if zone.is_root() {
            return inner.root.clone();
        }
        inner
            .delegations
            .get(zone)
            .filter(|stored| stored.expires > now)
            .map(|stored| stored.delegation.clone())
    }

    fn put_delegation(&self, delegation: Delegation) {
        let mut inner = self.lock();
        if delegation.child_zone().is_root() {
            inner.root = Some(delegation);
            return;
        }
        let lifetime =
            Duration::from_secs(u64::from(delegation.ttl().seconds())).min(MAX_DELEGATION_LIFETIME);
        let learned_at = delegation.learned_at();
        let expires = learned_at.checked_add(lifetime).unwrap_or(learned_at);
        let zone = delegation.child_zone().clone();
        if !inner.delegations.contains_key(&zone)
            && inner.delegations.len() >= self.capacity.max_delegations
        {
            evict_one_delegation(&mut inner.delegations, learned_at);
        }
        inner.delegations.insert(
            zone,
            Stored {
                delegation,
                expires,
            },
        );
    }

    fn closest_enclosing_cut(&self, name: &Name, now: Instant) -> ZoneCut {
        let inner = self.lock();
        let mut current = Some(name.clone());
        while let Some(zone) = current.filter(|zone| !zone.is_root()) {
            if let Some(stored) = inner.delegations.get(&zone).filter(|s| s.expires > now) {
                return stored.delegation.to_cut();
            }
            current = zone.parent();
        }
        // The root never expires out of the cache: a stale root NS set is still the
        // best place to start, and re-priming refreshes it.
        inner.root.as_ref().map_or_else(
            || ZoneCut::new(Name::root(), NsSet::default()),
            Delegation::to_cut,
        )
    }

    fn metrics(&self, server: NameserverAddr, now: Instant) -> NameserverMetrics {
        self.lock()
            .metrics
            .get(&server)
            .cloned()
            .unwrap_or_else(|| NameserverMetrics::new(now))
    }

    fn update_metrics(&self, server: NameserverAddr, event: MetricEvent, now: Instant) {
        let mut inner = self.lock();
        if !inner.metrics.contains_key(&server) && inner.metrics.len() >= self.capacity.max_servers
        {
            evict_one_server(&mut inner.metrics);
        }
        inner
            .metrics
            .entry(server)
            .or_insert_with(|| NameserverMetrics::new(now))
            .apply(event, now);
    }

    fn prime_from(&self, hints: &RootHints, now: Instant) {
        let mut inner = self.lock();
        if inner.root.is_none() {
            inner.root = Some(hints.to_delegation(now));
        }
    }

    fn evict_expired(&self, now: Instant) {
        let mut inner = self.lock();
        inner.delegations.retain(|_, stored| stored.expires > now);
        inner.metrics.retain(|_, metrics| {
            now.saturating_duration_since(metrics.last_seen()) < METRICS_IDLE_EXPIRY
        });
    }
}

/// Evicts an expired delegation if there is one, else the one expiring soonest.
fn evict_one_delegation(delegations: &mut HashMap<Name, Stored>, now: Instant) {
    let victim = delegations
        .iter()
        .min_by_key(|(_, stored)| (stored.expires > now, stored.expires))
        .map(|(zone, _)| zone.clone());
    if let Some(zone) = victim {
        delegations.remove(&zone);
    }
}

/// Evicts the server seen least recently.
fn evict_one_server(metrics: &mut HashMap<NameserverAddr, NameserverMetrics>) {
    let victim = metrics
        .iter()
        .min_by_key(|(_, metrics)| metrics.last_seen())
        .map(|(server, _)| *server);
    if let Some(server) = victim {
        metrics.remove(&server);
    }
}

#[cfg(test)]
#[path = "infra_cache_tests.rs"]
mod tests;
