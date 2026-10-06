//! Sharing one outbound exchange among concurrent descents that would send the
//! identical question to the identical server.
//!
//! When a page load fires fifteen lookups under one cold zone, or every device in
//! the house wakes at once, each cache miss starts its own descent. Without this,
//! every one of them would ask the root and the TLD the same question — N times
//! the traffic to third parties. With it, the first caller leads the exchange and
//! the others await its result.
//!
//! The exchange belongs to no caller. The leader hands it to a detached task, so a
//! caller that is cancelled — the pipeline's timeout, the pool aborting a losing
//! race — neither strands the followers nor leaves an entry behind; and each caller
//! waits under its own deadline, so a follower is never cut short by the leader's.

use std::collections::HashMap;
use std::future::Future;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use styx_proto::Question;
use tokio::sync::watch;

use crate::domain::ports::{TransportError, TransportFailure, TransportReply};
use crate::domain::topology::NameserverAddr;

/// One exchange's identity: the server and the question exactly as sent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutboundKey {
    /// The nameserver asked.
    pub server: NameserverAddr,
    /// The question as it went on the wire, minimised or full.
    pub as_sent: Question,
}

/// Whether a caller started the exchange or awaited another caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightRole {
    /// Created the entry and handed the send to its task.
    Leader,
    /// Joined an entry already in flight.
    Follower,
}

/// How one exchange ended.
pub type Outcome = Result<TransportReply, TransportFailure>;

/// What a caller gets back from [`InFlight::exchange`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightResult {
    /// The shared outcome, or a timeout if the caller's own deadline came first.
    pub outcome: Outcome,
    /// Whether this caller led or followed.
    pub role: FlightRole,
}

#[derive(Debug)]
struct Flight {
    result: watch::Sender<Option<Outcome>>,
}

type Pending = Mutex<HashMap<OutboundKey, Arc<Flight>>>;

fn lock(pending: &Pending) -> MutexGuard<'_, HashMap<OutboundKey, Arc<Flight>>> {
    match pending.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Removes an exchange's entry when dropped, so the entry goes whether the task
/// finishes, panics or is torn down with the runtime.
struct EntryGuard {
    pending: Arc<Pending>,
    key: OutboundKey,
    flight: Arc<Flight>,
}

impl Drop for EntryGuard {
    fn drop(&mut self) {
        let mut pending = lock(&self.pending);
        let ours = pending
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.flight));
        if ours {
            pending.remove(&self.key);
        }
    }
}

/// The map of exchanges in flight.
///
/// The lock guards only map insertion and removal and is never held across an
/// `.await`. The entry is removed before the result is published, so a failure is
/// shared only with the callers already waiting on it; a later caller starts a
/// fresh exchange.
#[derive(Debug, Default)]
pub struct InFlight {
    pending: Arc<Pending>,
}

impl InFlight {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Joins the exchange for `key` if one is in flight, or leads a new one by
    /// handing `send()` to a detached task.
    fn join_or_lead<F, Fut>(
        &self,
        key: OutboundKey,
        send: F,
    ) -> (watch::Receiver<Option<Outcome>>, FlightRole)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Outcome> + Send + 'static,
    {
        let mut pending = lock(&self.pending);
        if let Some(flight) = pending.get(&key) {
            return (flight.result.subscribe(), FlightRole::Follower);
        }
        let (result, receiver) = watch::channel(None);
        let flight = Arc::new(Flight { result });
        pending.insert(key.clone(), Arc::clone(&flight));
        drop(pending);

        let guard = EntryGuard {
            pending: Arc::clone(&self.pending),
            key,
            flight: Arc::clone(&flight),
        };
        let exchange = send();
        tokio::spawn(async move {
            let outcome = exchange.await;
            drop(guard);
            flight.result.send_replace(Some(outcome));
        });
        (receiver, FlightRole::Leader)
    }

    /// Runs `send` for `key`, or awaits the identical exchange already in flight,
    /// for at most until `deadline`.
    ///
    /// `send` runs only for the leader, and its future must not borrow from the
    /// caller: it outlives the caller if the caller is cancelled.
    pub async fn exchange<F, Fut>(
        &self,
        key: OutboundKey,
        deadline: Instant,
        send: F,
    ) -> FlightResult
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Outcome> + Send + 'static,
    {
        let (mut receiver, role) = self.join_or_lead(key, send);
        let waiting = receiver.wait_for(Option::is_some);
        let until = tokio::time::Instant::from_std(deadline);
        let outcome = match tokio::time::timeout_at(until, waiting).await {
            Ok(Ok(shared)) => match &*shared {
                Some(outcome) => outcome.clone(),
                None => Err(failure(TransportError::Unreachable(ErrorKind::Interrupted))),
            },
            Ok(Err(_)) => Err(failure(TransportError::Unreachable(ErrorKind::Interrupted))),
            Err(_) => Err(failure(TransportError::Timeout)),
        };
        FlightResult { outcome, role }
    }

    /// Exchanges currently in flight.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.pending).len()
    }

    /// Whether nothing is in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A failure that cost the caller one exchange: it was charged for the send.
const fn failure(error: TransportError) -> TransportFailure {
    TransportFailure {
        error,
        wire_exchanges: 1,
    }
}

#[cfg(test)]
#[path = "single_flight_tests.rs"]
mod tests;
