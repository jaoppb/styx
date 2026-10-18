//! Test sleeper driven by a [`TestClock`].

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::domain::clock::Clock;
use crate::domain::sleeper::Sleeper;
use crate::test_util::clock::TestClock;

/// Controllable test double implementing [`Sleeper`].
///
/// A sleep completes when the shared [`TestClock`] has been advanced by at least the requested
/// duration, so a test moves the gate's clock and every pending sleep in one call.
#[derive(Debug, Clone)]
pub struct TestSleeper {
    clock: Arc<TestClock>,
}

impl TestSleeper {
    /// Creates a sleeper that measures time on `clock`.
    #[must_use]
    pub fn new(clock: Arc<TestClock>) -> Self {
        Self { clock }
    }
}

impl Sleeper for TestSleeper {
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        let clock = Arc::clone(&self.clock);
        // The deadline is fixed when `sleep` is called, not when the future is first polled, so
        // a test that advances the clock before the task is scheduled still releases it.
        let deadline = clock.now_monotonic().checked_add(duration);
        async move {
            if let Some(deadline) = deadline {
                wait_until(&clock, deadline).await;
            }
        }
    }
}

async fn wait_until(clock: &TestClock, deadline: Instant) {
    loop {
        let advanced = clock.advanced();
        let mut advanced = std::pin::pin!(advanced);
        advanced.as_mut().enable();
        if clock.now_monotonic() >= deadline {
            return;
        }
        advanced.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::time::timeout;

    const SLEEP: Duration = Duration::from_secs(1);
    const REAL_TIME_BUDGET: Duration = Duration::from_millis(500);

    #[tokio::test]
    async fn sleep_stays_pending_until_the_clock_reaches_the_deadline() {
        let clock = Arc::new(TestClock::new());
        let sleeper = TestSleeper::new(Arc::clone(&clock));

        let sleeping = tokio::spawn(async move { sleeper.sleep(SLEEP).await });
        tokio::task::yield_now().await;
        clock.advance(Duration::from_millis(999));
        tokio::task::yield_now().await;
        assert!(!sleeping.is_finished());

        clock.advance(Duration::from_millis(1));
        let finished = timeout(REAL_TIME_BUDGET, sleeping).await;
        assert!(finished.is_ok());
    }

    #[tokio::test]
    async fn sleep_started_after_an_advance_measures_from_the_new_now() {
        let clock = Arc::new(TestClock::new());
        let sleeper = TestSleeper::new(Arc::clone(&clock));
        clock.advance(Duration::from_secs(60));

        let sleeping = tokio::spawn(async move { sleeper.sleep(SLEEP).await });
        tokio::task::yield_now().await;
        assert!(!sleeping.is_finished());

        clock.advance(SLEEP);
        let finished = timeout(REAL_TIME_BUDGET, sleeping).await;
        assert!(finished.is_ok());
    }
}
