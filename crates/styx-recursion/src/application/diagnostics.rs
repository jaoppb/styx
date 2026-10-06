//! Assembling `RecursionDiagnostics` from what descents observe.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use styx_proto::Name;

use crate::domain::diagnostics::{
    ContactOutcome, RecursionDiagnostics, RootServerStatus, TldStatus,
};
use crate::domain::topology::Nameserver;

/// Snapshots are published at most this often: publication must stay off the
/// critical path of individual descents, and the admin page needs nothing fresher.
pub const PUBLISH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct State {
    roots: HashMap<IpAddr, RootServerStatus>,
    tlds: HashMap<Name, TldStatus>,
    last_successful_priming: Option<Instant>,
    descents_total: u64,
    descents_failed: u64,
    minimisation_fallbacks: u64,
    last_published: Option<Instant>,
    last_reply: Option<Instant>,
}

/// The running totals and per-server observations behind the read model.
#[derive(Debug, Default)]
pub struct DiagnosticsState {
    state: Mutex<State>,
}

impl DiagnosticsState {
    /// Nothing observed yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Lists the current root servers, keeping what is known about each.
    pub fn set_root_servers(&self, servers: &[Nameserver]) {
        let mut state = self.lock();
        let mut roots = HashMap::new();
        let addresses = servers.iter().flat_map(|server| {
            server
                .addresses
                .iter()
                .map(move |address| (&server.name, address))
        });
        for (name, address) in addresses {
            let status = state.roots.remove(address).unwrap_or(RootServerStatus {
                name: name.clone(),
                address: *address,
                last_outcome: ContactOutcome::NeverContacted,
                last_rtt: None,
                last_contact: None,
            });
            roots.insert(*address, status);
        }
        state.roots = roots;
    }

    /// Records a query to a root server.
    pub fn record_root_contact(&self, address: IpAddr, rtt: Option<Duration>, now: Instant) {
        let mut state = self.lock();
        if let Some(status) = state.roots.get_mut(&address) {
            status.last_outcome = outcome(rtt);
            status.last_rtt = rtt.or(status.last_rtt);
            status.last_contact = Some(now);
        }
    }

    /// Records a query to a server of a top-level domain.
    pub fn record_tld_contact(&self, tld: &Name, answered: bool, now: Instant) {
        let entry = TldStatus {
            tld: tld.clone(),
            last_outcome: if answered {
                ContactOutcome::Answered
            } else {
                ContactOutcome::Failed
            },
            last_contact: Some(now),
        };
        self.lock().tlds.insert(tld.clone(), entry);
    }

    /// Records that some nameserver answered something at `now`.
    pub fn note_reply(&self, now: Instant) {
        self.lock().last_reply = Some(now);
    }

    /// Whether any nameserver answered within `window` before `now`. A recursor for
    /// which this is false has heard nothing from the network.
    #[must_use]
    pub fn replied_within(&self, now: Instant, window: Duration) -> bool {
        self.lock()
            .last_reply
            .is_some_and(|at| now.saturating_duration_since(at) <= window)
    }

    /// Records a successful priming query.
    pub fn record_priming(&self, now: Instant) {
        self.lock().last_successful_priming = Some(now);
    }

    /// Records one finished client descent.
    pub fn record_descent(&self, failed: bool, fallbacks: u64) {
        let mut state = self.lock();
        state.descents_total = state.descents_total.saturating_add(1);
        if failed {
            state.descents_failed = state.descents_failed.saturating_add(1);
        }
        state.minimisation_fallbacks = state.minimisation_fallbacks.saturating_add(fallbacks);
    }

    /// A snapshot as of `now`, or `None` if one was taken within
    /// [`PUBLISH_INTERVAL`].
    pub fn snapshot_if_due(&self, now: Instant) -> Option<RecursionDiagnostics> {
        let mut state = self.lock();
        let due = state
            .last_published
            .is_none_or(|last| now.saturating_duration_since(last) >= PUBLISH_INTERVAL);
        if !due {
            return None;
        }
        state.last_published = Some(now);
        Some(snapshot(&state, now))
    }
}

fn outcome(rtt: Option<Duration>) -> ContactOutcome {
    if rtt.is_some() {
        ContactOutcome::Answered
    } else {
        ContactOutcome::Failed
    }
}

fn snapshot(state: &State, now: Instant) -> RecursionDiagnostics {
    let mut roots: Vec<RootServerStatus> = state.roots.values().cloned().collect();
    roots.sort_by_key(|status| status.name.to_string());
    let mut tlds: Vec<TldStatus> = state.tlds.values().cloned().collect();
    tlds.sort_by_key(|status| status.tld.to_string());
    RecursionDiagnostics {
        roots,
        tlds,
        last_successful_priming: state.last_successful_priming,
        descents_total: state.descents_total,
        descents_failed: state.descents_failed,
        minimisation_fallbacks: state.minimisation_fallbacks,
        observed_at: now,
    }
}
