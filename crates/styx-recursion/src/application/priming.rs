//! Lazy, non-blocking, single-flighted priming of the root NS set.
//!
//! The box boots before its WAN link, so nothing here may block startup: the
//! recursor is built from root hints alone and serves at once. The first descent
//! triggers a priming query; concurrent descents join it rather than sending their
//! own; a failed prime is retried with backoff while descents keep using the hints;
//! and the prime repeats when the live root NS set's TTL runs out.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::sync::OnceCell;

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
    attempt: Option<Arc<OnceCell<PrimeOutcome>>>,
}

/// The priming schedule. Holds no lock across an `.await`: the lock guards the
/// schedule; the attempt itself is a shared cell that joiners await.
#[derive(Debug)]
pub struct Priming {
    state: Mutex<State>,
}

impl Default for Priming {
    fn default() -> Self {
        Self::new()
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
                attempt: None,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Primes via `prime` if a prime is due at `now`, joining one already in
    /// flight. Returns at once when the root NS set is fresh or a failed prime is
    /// still backing off.
    pub async fn ensure<F, Fut>(&self, now: Instant, prime: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = PrimeOutcome>,
    {
        let Some(attempt) = self.due(now) else {
            return;
        };
        let outcome = *attempt.get_or_init(prime).await;
        self.settle(&attempt, outcome, now);
    }

    fn due(&self, now: Instant) -> Option<Arc<OnceCell<PrimeOutcome>>> {
        let mut state = self.lock();
        if let Some(attempt) = &state.attempt {
            return Some(Arc::clone(attempt));
        }
        if state.fresh_until.is_some_and(|until| until > now)
            || state.retry_at.is_some_and(|at| at > now)
        {
            return None;
        }
        let attempt = Arc::new(OnceCell::new());
        state.attempt = Some(Arc::clone(&attempt));
        Some(attempt)
    }

    fn settle(&self, attempt: &Arc<OnceCell<PrimeOutcome>>, outcome: PrimeOutcome, now: Instant) {
        let mut state = self.lock();
        let current = state
            .attempt
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, attempt));
        if !current {
            return;
        }
        state.attempt = None;
        match outcome {
            PrimeOutcome::Primed(until) => {
                state.fresh_until = Some(until);
                state.retry_at = None;
                state.backoff = PRIMING_INITIAL_BACKOFF;
            }
            PrimeOutcome::Failed => {
                state.retry_at = now.checked_add(state.backoff);
                state.backoff = state.backoff.saturating_mul(2).min(PRIMING_MAX_BACKOFF);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn a_failure_backs_off_and_a_success_holds_until_its_ttl() {
        let priming = Priming::new();
        let attempts = AtomicUsize::new(0);
        let start = Instant::now();
        let fail = || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            PrimeOutcome::Failed
        };
        priming.ensure(start, fail).await;
        priming.ensure(start + Duration::from_secs(1), fail).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "backing off");

        let retry = start + PRIMING_INITIAL_BACKOFF;
        let until = retry + Duration::from_secs(100);
        priming
            .ensure(retry, || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                PrimeOutcome::Primed(until)
            })
            .await;
        priming.ensure(retry + Duration::from_secs(50), fail).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "fresh");
        priming.ensure(until, fail).await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "expired, so primes again"
        );
    }
}
