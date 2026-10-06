//! Sharing one outbound exchange among concurrent descents that would send the
//! identical question to the identical server.
//!
//! When a page load fires fifteen lookups under one cold zone, or every device in
//! the house wakes at once, each cache miss starts its own descent. Without this,
//! every one of them would ask the root and the TLD the same question — N times
//! the traffic to third parties. With it, the first caller leads the exchange and
//! the others await its result.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use styx_proto::Question;
use tokio::sync::OnceCell;

use crate::domain::ports::{TransportError, TransportReply};
use crate::domain::topology::NameserverAddr;

/// One exchange's identity: the server and the question exactly as sent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutboundKey {
    /// The nameserver asked.
    pub server: NameserverAddr,
    /// The question as it went on the wire, minimised or full.
    pub as_sent: Question,
}

/// Whether a caller sent the exchange or awaited another caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightRole {
    /// Created the entry; performs the send unless dropped first.
    Leader,
    /// Joined an entry already in flight.
    Follower,
}

type Outcome = Result<TransportReply, TransportError>;

/// The map of exchanges in flight.
///
/// The lock guards only map insertion and removal and is never held across an
/// `.await`. A follower awaits the shared cell; if the leader's future is dropped
/// before it finishes, a waiting follower runs its own send in the leader's place.
/// The entry is removed as soon as the exchange completes — success or failure —
/// so a failure is shared only with the callers already waiting on it.
#[derive(Debug, Default)]
pub struct InFlight {
    pending: Mutex<HashMap<OutboundKey, Arc<OnceCell<Outcome>>>>,
}

impl InFlight {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Joins the exchange for `key` if one is in flight, or leads a new one.
    fn join_or_lead(&self, key: &OutboundKey) -> (Arc<OnceCell<Outcome>>, FlightRole) {
        let mut pending = match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(cell) = pending.get(key) {
            return (Arc::clone(cell), FlightRole::Follower);
        }
        let cell = Arc::new(OnceCell::new());
        pending.insert(key.clone(), Arc::clone(&cell));
        (cell, FlightRole::Leader)
    }

    /// Runs `send` for `key`, or awaits the identical exchange already in flight.
    pub async fn exchange<F, Fut>(&self, key: OutboundKey, send: F) -> (Outcome, FlightRole)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Outcome>,
    {
        let (cell, role) = self.join_or_lead(&key);
        let outcome = cell.get_or_init(send).await.clone();
        let mut pending = match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if pending
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &cell))
        {
            pending.remove(&key);
        }
        (outcome, role)
    }

    /// Exchanges currently in flight.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.pending.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Whether nothing is in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
