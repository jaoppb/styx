//! Adapters for the two publication ports.

use std::sync::{Arc, Mutex};

use crate::domain::chain_material::ChainMaterial;
use crate::domain::diagnostics::RecursionDiagnostics;
use crate::domain::ports::{ChainMaterialSink, DiagnosticsSink};

/// Discards chain material. Wired until the DNSSEC validator replaces it.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardChainMaterial;

impl ChainMaterialSink for DiscardChainMaterial {
    fn push(&self, _material: ChainMaterial) {}
}

/// Holds the latest diagnostics snapshot for the admin/web layer to read.
///
/// Publication swaps an `Arc` under a lock held only for the pointer swap, and a
/// reader clones the `Arc` the same way; neither ever waits on a descent.
#[derive(Debug, Default)]
pub struct DiagnosticsStore {
    latest: Mutex<Option<Arc<RecursionDiagnostics>>>,
}

impl DiagnosticsStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The latest snapshot, if one has been published.
    #[must_use]
    pub fn snapshot(&self) -> Option<Arc<RecursionDiagnostics>> {
        match self.latest.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl DiagnosticsSink for DiagnosticsStore {
    fn publish(&self, snapshot: RecursionDiagnostics) {
        let snapshot = Some(Arc::new(snapshot));
        match self.latest.lock() {
            Ok(mut guard) => *guard = snapshot,
            Err(poisoned) => *poisoned.into_inner() = snapshot,
        }
    }
}
