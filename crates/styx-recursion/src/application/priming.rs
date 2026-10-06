//! Lazy, background, single-flighted priming of the root NS set.
//!
//! The box boots before its WAN link, so nothing here may block startup: the
//! recursor is built from root hints alone and serves at once. The first descent
//! starts a priming query in a task of its own and carries on with the hints; no
//! other descent starts a second one while it runs; a failed prime is retried with
//! backoff while descents keep using the hints; and the prime repeats when the live
//! root NS set's TTL runs out.

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

/// First retry delay after a failed prime.
pub const PRIMING_INITIAL_BACKOFF: Duration = Duration::from_secs(5);

/// Longest retry delay after repeated failures: a WAN outage of hours should still
/// be noticed within minutes of recovery.
pub const PRIMING_MAX_BACKOFF: Duration = Duration::from_secs(300);

/// What the last priming attempt achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimeOutcome {
    /// The live root NS set was installed and holds until the instant given.
    Primed(Instant),
    /// No root server gave a usable answer.
    Failed,
}

#[derive(Debug)]
struct State {
    fresh_until: Option<Instant>,
    retry_at: Option<Instant>,
    backoff: Duration,
    running: bool,
}

/// The priming schedule. The attempt runs as a task of its own, so no descent
/// waits for it and no caller's deadline can cut it short or fail it.
#[derive(Debug)]
pub struct Priming {
    state: Mutex<State>,
}

impl Default for Priming {
    fn default() -> Self {
        Self::new()
    }
}

/// Settles the schedule when the attempt's task ends, even by panic or teardown,
/// so a lost attempt counts as a failed one rather than blocking priming forever.
struct Settle {
    priming: Arc<Priming>,
    started: Instant,
    outcome: Option<PrimeOutcome>,
}

impl Drop for Settle {
    fn drop(&mut self) {
        let outcome = self.outcome.unwrap_or(PrimeOutcome::Failed);
        self.priming.settle(outcome, self.started);
    }
}

impl Priming {
    /// Never primed: the first descent primes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                fresh_until: None,
                retry_at: None,
                backoff: PRIMING_INITIAL_BACKOFF,
                running: false,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Starts `prime` in the background if a prime is due at `now` and none is
    /// running, and returns its task. Returns `None`, doing nothing, when the root
    /// NS set is fresh, a failed prime is still backing off, or one is running.
    pub fn trigger<F, Fut>(self: &Arc<Self>, now: Instant, prime: F) -> Option<JoinHandle<()>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = PrimeOutcome> + Send + 'static,
    {
        if !self.begin(now) {
            return None;
        }
        let settle = Settle {
            priming: Arc::clone(self),
            started: now,
            outcome: None,
        };
        let attempt = prime();
        Some(tokio::spawn(async move {
            // Moved whole, so it drops with the task rather than field by field.
            let mut settle = settle;
            settle.outcome = Some(attempt.await);
        }))
    }

    /// Marks an attempt as running if one is due.
    fn begin(&self, now: Instant) -> bool {
        let mut state = self.lock();
        let waiting = state.fresh_until.is_some_and(|until| until > now)
            || state.retry_at.is_some_and(|at| at > now);
        if state.running || waiting {
            return false;
        }
        state.running = true;
        true
    }

    fn settle(&self, outcome: PrimeOutcome, started: Instant) {
        let mut state = self.lock();
        state.running = false;
        match outcome {
            PrimeOutcome::Primed(until) => {
                state.fresh_until = Some(until);
                state.retry_at = None;
                state.backoff = PRIMING_INITIAL_BACKOFF;
            }
            PrimeOutcome::Failed => {
                state.retry_at = started.checked_add(state.backoff);
                state.backoff = state.backoff.saturating_mul(2).min(PRIMING_MAX_BACKOFF);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    async fn run<F, Fut>(priming: &Arc<Priming>, now: Instant, prime: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = PrimeOutcome> + Send + 'static,
    {
        if let Some(task) = priming.trigger(now, prime) {
            task.await.unwrap();
        }
    }

    async fn failing(attempts: Arc<AtomicUsize>) -> PrimeOutcome {
        attempts.fetch_add(1, Ordering::SeqCst);
        PrimeOutcome::Failed
    }

    #[tokio::test]
    async fn a_failure_backs_off_and_a_success_holds_until_its_ttl() {
        let priming = Arc::new(Priming::new());
        let attempts = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let fail = || failing(Arc::clone(&attempts));
        run(&priming, start, fail).await;
        run(&priming, start + Duration::from_secs(1), fail).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "backing off");

        let retry = start + PRIMING_INITIAL_BACKOFF;
        let until = retry + Duration::from_secs(100);
        let counted = Arc::clone(&attempts);
        run(&priming, retry, || async move {
            counted.fetch_add(1, Ordering::SeqCst);
            PrimeOutcome::Primed(until)
        })
        .await;
        run(&priming, retry + Duration::from_secs(50), fail).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "fresh");
        run(&priming, until, fail).await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "expired, so primes again"
        );
    }

    #[tokio::test]
    async fn triggering_returns_at_once_and_a_running_prime_is_not_doubled() {
        let priming = Arc::new(Priming::new());
        let now = Instant::now();
        let until = now + Duration::from_secs(300);
        let first = priming.trigger(now, || async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            PrimeOutcome::Primed(until)
        });
        assert!(first.is_some(), "the descent was not made to wait");
        assert!(
            priming
                .trigger(now, || async { PrimeOutcome::Failed })
                .is_none(),
            "one is already running"
        );
        first.unwrap().await.unwrap();
    }

    #[tokio::test]
    async fn a_panicking_attempt_counts_as_a_failure_and_unblocks_priming() {
        let priming = Arc::new(Priming::new());
        let now = Instant::now();
        let task = priming
            .trigger(now, || async { panic!("prime exploded") })
            .unwrap();
        assert!(task.await.is_err());
        assert!(priming
            .trigger(now, || async { PrimeOutcome::Failed })
            .is_none());
        let later = now + PRIMING_INITIAL_BACKOFF;
        let again = priming.trigger(later, || async { PrimeOutcome::Failed });
        assert!(again.is_some(), "retried after the backoff");
    }
}
