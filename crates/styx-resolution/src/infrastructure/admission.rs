//! Admission control shared by every listener: the query budget, the TCP connection
//! budget, and the collaborators each listener is constructed from.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::application::terminal::RefusedTerminal;
use crate::application::Pipeline;

/// Minimum spacing between two rate-limited warnings from one listener.
const WARN_INTERVAL: Duration = Duration::from_secs(1);

/// The one process-wide budget of concurrently processed queries.
///
/// A clone shares the same permits, so every UDP and TCP listener on every address
/// draws from one ceiling.
#[derive(Debug, Clone)]
pub struct QueryBudget {
    permits: Arc<Semaphore>,
    capacity: NonZeroUsize,
}

impl QueryBudget {
    /// Creates a budget of `capacity` concurrent queries.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(capacity.get())),
            capacity,
        }
    }

    /// Waits for a permit; `None` once the budget has been closed for shutdown.
    pub async fn acquire(&self) -> Option<QueryPermit> {
        let permit = Arc::clone(&self.permits).acquire_owned().await.ok()?;
        Some(QueryPermit { _permit: permit })
    }

    /// Returns `true` when every permit is held, so the next acquire will wait.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.permits.available_permits() == 0
    }

    /// Returns the configured number of permits.
    #[must_use]
    pub fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    /// Closes the budget: every pending and future acquire returns `None`.
    pub fn close(&self) {
        self.permits.close();
    }
}

/// One admitted query; the permit returns to the budget when this is dropped.
#[derive(Debug)]
pub struct QueryPermit {
    _permit: OwnedSemaphorePermit,
}

/// The one process-wide budget of open TCP connections.
#[derive(Debug, Clone)]
pub struct ConnectionBudget {
    permits: Arc<Semaphore>,
}

impl ConnectionBudget {
    /// Creates a budget of `capacity` open connections.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(capacity.get())),
        }
    }

    /// Admits one connection without waiting; `None` when the cap is reached.
    #[must_use]
    pub fn try_admit(&self) -> Option<ConnectionPermit> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok()?;
        Some(ConnectionPermit { _permit: permit })
    }
}

/// One admitted connection; the slot frees when this is dropped.
#[derive(Debug)]
pub struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
}

/// The collaborators every listener is constructed from.
pub struct ListenerShared<L, F, O, C, T = RefusedTerminal> {
    /// The resolution pipeline every query is dispatched to.
    pub pipeline: Arc<Pipeline<L, F, O, C, T>>,
    /// The injected clock.
    pub clock: Arc<C>,
    /// The process-wide query budget.
    pub budget: QueryBudget,
    /// Tracks every task spawned below a listener, for shutdown.
    pub tasks: TaskTracker,
    /// Cancelled by shutdown once the drain grace period has expired.
    pub abort: CancellationToken,
    /// Per-query deadline handed to [`Pipeline::handle_within`].
    pub query_timeout: Duration,
}

impl<L, F, O, C, T> Clone for ListenerShared<L, F, O, C, T> {
    fn clone(&self) -> Self {
        Self {
            pipeline: Arc::clone(&self.pipeline),
            clock: Arc::clone(&self.clock),
            budget: self.budget.clone(),
            tasks: self.tasks.clone(),
            abort: self.abort.clone(),
            query_timeout: self.query_timeout,
        }
    }
}

/// Lets a repeated warning through at most once per second.
#[derive(Debug, Default)]
pub(crate) struct WarnLimiter {
    last: Mutex<Option<Instant>>,
}

impl WarnLimiter {
    /// Returns `true` when a warning may be emitted at `now`, and records it.
    pub(crate) fn allow(&self, now: Instant) -> bool {
        let Ok(mut last) = self.last.lock() else {
            return false;
        };
        let due = match *last {
            Some(previous) => now.saturating_duration_since(previous) >= WARN_INTERVAL,
            None => true,
        };
        if due {
            *last = Some(now);
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two() -> NonZeroUsize {
        NonZeroUsize::new(2).unwrap()
    }

    #[tokio::test]
    async fn query_budget_exhausts_and_refills_on_drop() {
        let budget = QueryBudget::new(two());
        let first = budget.acquire().await.unwrap();
        let _second = budget.acquire().await.unwrap();
        assert!(budget.is_exhausted());
        drop(first);
        assert!(!budget.is_exhausted());
    }

    #[tokio::test]
    async fn closed_query_budget_yields_none() {
        let budget = QueryBudget::new(two());
        budget.close();
        assert!(budget.acquire().await.is_none());
    }

    #[test]
    fn connection_budget_refuses_past_the_cap() {
        let budget = ConnectionBudget::new(two());
        let first = budget.try_admit().unwrap();
        let _second = budget.try_admit().unwrap();
        assert!(budget.try_admit().is_none());
        drop(first);
        assert!(budget.try_admit().is_some());
    }

    #[test]
    fn warn_limiter_spaces_warnings_one_second_apart() {
        let limiter = WarnLimiter::default();
        let start = Instant::now();
        assert!(limiter.allow(start));
        assert!(!limiter.allow(start.checked_add(Duration::from_millis(500)).unwrap()));
        assert!(limiter.allow(start.checked_add(Duration::from_secs(1)).unwrap()));
    }
}
