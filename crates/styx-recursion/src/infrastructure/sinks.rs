//! Adapters for the two publication ports.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use styx_core::UpstreamId;

use crate::domain::chain_material::ChainMaterial;
use crate::domain::diagnostics::RecursionDiagnostics;
use crate::domain::ports::{ChainMaterialSink, DiagnosticsSink};

/// Discards chain material. Wired until the DNSSEC validator replaces it.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardChainMaterial;

impl ChainMaterialSink for DiscardChainMaterial {
    fn push(&self, _material: ChainMaterial) {}
}

/// Holds each recursor member's latest diagnostics snapshot for the admin/web layer to
/// read, keyed by the member's [`UpstreamId`] so several recursors sharing one store do
/// not overwrite each other.
///
/// Publication swaps an `Arc` under a lock held only for the map insert, and a reader
/// clones the `Arc` the same way; neither ever waits on a descent.
#[derive(Debug, Default)]
pub struct DiagnosticsStore {
    latest: Mutex<HashMap<UpstreamId, Arc<RecursionDiagnostics>>>,
}

impl DiagnosticsStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The latest snapshot `upstream` published, if it has published one.
    #[must_use]
    pub fn snapshot(&self, upstream: &UpstreamId) -> Option<Arc<RecursionDiagnostics>> {
        self.with_map(|map| map.get(upstream).cloned())
    }

    fn with_map<R>(
        &self,
        f: impl FnOnce(&mut HashMap<UpstreamId, Arc<RecursionDiagnostics>>) -> R,
    ) -> R {
        let mut guard = match self.latest.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }
}

impl DiagnosticsSink for DiagnosticsStore {
    fn publish(&self, snapshot: RecursionDiagnostics) {
        let upstream = snapshot.upstream.clone();
        let snapshot = Arc::new(snapshot);
        self.with_map(|map| {
            let _previous = map.insert(upstream, snapshot);
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn snapshot_of(upstream: &str, descents_total: u64) -> RecursionDiagnostics {
        RecursionDiagnostics {
            upstream: UpstreamId::new(upstream),
            roots: Vec::new(),
            tlds: Vec::new(),
            last_successful_priming: None,
            descents_total,
            descents_failed: 0,
            minimisation_fallbacks: 0,
            observed_at: Instant::now(),
        }
    }

    #[test]
    fn each_recursor_keeps_its_own_latest_snapshot() {
        let store = DiagnosticsStore::new();
        store.publish(snapshot_of("recursor-a", 1));
        store.publish(snapshot_of("recursor-b", 7));
        store.publish(snapshot_of("recursor-a", 2));

        let a = store.snapshot(&UpstreamId::new("recursor-a")).unwrap();
        let b = store.snapshot(&UpstreamId::new("recursor-b")).unwrap();
        assert_eq!(a.descents_total, 2);
        assert_eq!(b.descents_total, 7);
        assert_eq!(store.snapshot(&UpstreamId::new("forwarder")), None);
    }
}
