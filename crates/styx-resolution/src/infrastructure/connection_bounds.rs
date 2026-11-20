//! Per-connection bounds shared by stream transports (TCP, DoT, and DoH): in-flight
//! concurrency slots, per-connection query ceilings, and idle detection.

use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

/// The outstanding queries of one connection, counted by semaphore slots.
///
/// A query holds its slot from admission until its response is written, so the
/// connection is idle exactly when every slot is free.
#[derive(Debug)]
pub struct ConnectionInFlight {
    slots: Arc<Semaphore>,
    capacity: NonZeroUsize,
    released: Arc<Notify>,
}

impl ConnectionInFlight {
    /// Creates a tracker allowing `capacity` outstanding queries.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(capacity.get())),
            capacity,
            released: Arc::new(Notify::new()),
        }
    }

    /// Waits for a free slot; `None` only if the tracker has been closed.
    pub async fn track(&self) -> Option<InFlightSlot> {
        let permit = Arc::clone(&self.slots).acquire_owned().await.ok()?;
        Some(InFlightSlot {
            permit: Some(permit),
            released: Arc::clone(&self.released),
        })
    }

    /// Returns `true` when no query is outstanding.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.slots.available_permits() == self.capacity.get()
    }

    /// Resolves once no query is outstanding.
    pub async fn idle(&self) {
        loop {
            let notified = self.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_idle() {
                return;
            }
            notified.await;
        }
    }
}

/// One outstanding query on a connection; frees its slot when dropped.
#[derive(Debug)]
pub struct InFlightSlot {
    permit: Option<OwnedSemaphorePermit>,
    released: Arc<Notify>,
}

impl Drop for InFlightSlot {
    fn drop(&mut self) {
        // Release before notifying, so a woken `idle()` sees the freed slot.
        drop(self.permit.take());
        self.released.notify_waiters();
    }
}

/// Outcome of spending one query against a connection's ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Spend {
    /// Under the ceiling; keep accepting queries.
    Within,
    /// The query that spent the ceiling; answer it, then close the connection.
    Last,
    /// Past the ceiling; refuse the query.
    Over,
}

/// Copyable policy configuring a connection's [`QueryCeiling`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct QueryLimit(Option<NonZeroU64>);

impl QueryLimit {
    /// No per-connection query cap (plaintext TCP).
    pub(crate) const fn unlimited() -> Self {
        Self(None)
    }

    /// Caps a connection at `max` queries before closing.
    pub(crate) const fn limited(max: NonZeroU64) -> Self {
        Self(Some(max))
    }

    /// Instantiates a fresh counter for one accepted connection.
    pub(crate) fn ceiling(self) -> QueryCeiling {
        match self.0 {
            Some(max) => QueryCeiling::limited(max),
            None => QueryCeiling::unlimited(),
        }
    }
}

/// Per-connection query counter enforcing a configured ceiling.
#[derive(Debug)]
pub(crate) struct QueryCeiling {
    max: Option<NonZeroU64>,
    spent: AtomicU64,
}

impl QueryCeiling {
    /// A ceiling that never trips while still counting admitted queries for idle checks.
    pub(crate) fn unlimited() -> Self {
        Self {
            max: None,
            spent: AtomicU64::new(0),
        }
    }

    /// A ceiling allowing `max` queries before closing.
    pub(crate) fn limited(max: NonZeroU64) -> Self {
        Self {
            max: Some(max),
            spent: AtomicU64::new(0),
        }
    }

    /// Records one query against the ceiling.
    pub(crate) fn spend(&self) -> Spend {
        let current = self.spent.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let Some(max) = self.max else {
            return Spend::Within;
        };
        if current > max.get() {
            Spend::Over
        } else if current == max.get() {
            Spend::Last
        } else {
            Spend::Within
        }
    }

    /// Total queries admitted so far on this connection.
    pub(crate) fn seen(&self) -> u64 {
        self.spent.load(Ordering::Relaxed)
    }
}

/// Combined in-flight, query-ceiling, and idle tracker for one accepted connection.
#[derive(Debug)]
pub(crate) struct ConnectionLimiter {
    in_flight: ConnectionInFlight,
    ceiling: QueryCeiling,
    budget_spent: Notify,
    idle_timeout: Duration,
}

impl ConnectionLimiter {
    /// Creates a limiter with `max_in_flight` slots, `ceiling`, and `idle_timeout`.
    pub(crate) fn new(
        max_in_flight: NonZeroUsize,
        ceiling: QueryCeiling,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            in_flight: ConnectionInFlight::new(max_in_flight),
            ceiling,
            budget_spent: Notify::new(),
            idle_timeout,
        }
    }

    /// Waits for an in-flight concurrency slot.
    pub(crate) async fn track(&self) -> Option<InFlightSlot> {
        self.in_flight.track().await
    }

    /// Spends one query against the ceiling and wakes [`Self::budget_spent`] on the last.
    pub(crate) fn spend(&self) -> Spend {
        let outcome = self.ceiling.spend();
        if outcome == Spend::Last {
            self.budget_spent.notify_one();
        }
        outcome
    }

    /// Total queries admitted so far.
    pub(crate) fn seen(&self) -> u64 {
        self.ceiling.seen()
    }

    /// Resolves once the connection has spent its per-connection query ceiling.
    pub(crate) async fn budget_spent(&self) {
        self.budget_spent.notified().await;
    }

    /// Resolves once the connection has had nothing in flight and no new query for a whole
    /// idle timeout.
    pub(crate) async fn idle_expired(&self) {
        loop {
            self.in_flight.idle().await;
            let seen = self.ceiling.seen();
            tokio::time::sleep(self.idle_timeout).await;
            if self.in_flight.is_idle() && self.ceiling.seen() == seen {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_tracks_outstanding_slots() {
        let in_flight = ConnectionInFlight::new(NonZeroUsize::new(2).unwrap());
        assert!(in_flight.is_idle());
        let slot = in_flight.track().await.unwrap();
        assert!(!in_flight.is_idle());

        let waiter = async { in_flight.idle().await };
        let release = async {
            tokio::task::yield_now().await;
            drop(slot);
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(waiter, release);
        })
        .await
        .unwrap();
        assert!(in_flight.is_idle());
    }

    #[tokio::test]
    async fn track_blocks_at_capacity() {
        let in_flight = ConnectionInFlight::new(NonZeroUsize::MIN);
        let _held = in_flight.track().await.unwrap();
        let blocked = tokio::time::timeout(Duration::from_millis(50), in_flight.track()).await;
        assert!(blocked.is_err());
    }

    #[test]
    fn query_ceiling_transitions_within_last_over() {
        let ceiling = QueryCeiling::limited(NonZeroU64::new(2).unwrap());
        assert_eq!(ceiling.spend(), Spend::Within);
        assert_eq!(ceiling.spend(), Spend::Last);
        assert_eq!(ceiling.spend(), Spend::Over);
        assert_eq!(ceiling.seen(), 3);

        let unlimited = QueryCeiling::unlimited();
        for _ in 0..5 {
            assert_eq!(unlimited.spend(), Spend::Within);
        }
        assert_eq!(unlimited.seen(), 5);
    }
}
