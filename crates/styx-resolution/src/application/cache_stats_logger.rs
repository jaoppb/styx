//! Background task that periodically logs answer cache counters at `debug`.

use std::sync::Arc;
use std::time::Duration;

use styx_core::Sleeper;
use tokio_util::sync::CancellationToken;

use crate::domain::cache::error::CacheError;
use crate::domain::cache::port::AnswerCache;

/// Periodically snapshots [`AnswerCache::stats`] and logs it at `debug` until shutdown.
pub struct CacheStatsLogger<A, S> {
    cache: Arc<A>,
    sleeper: Arc<S>,
    interval: Duration,
}

impl<A, S> CacheStatsLogger<A, S>
where
    A: AnswerCache,
    S: Sleeper,
{
    /// Creates a new `CacheStatsLogger` that logs `cache.stats()` every `interval`.
    ///
    /// # Errors
    /// Returns [`CacheError::ZeroStatsInterval`] when `interval` is zero.
    pub fn new(cache: Arc<A>, sleeper: Arc<S>, interval: Duration) -> Result<Self, CacheError> {
        if interval.is_zero() {
            return Err(CacheError::ZeroStatsInterval);
        }
        Ok(Self {
            cache,
            sleeper,
            interval,
        })
    }

    /// Runs the logging loop until `shutdown` is cancelled.
    pub async fn run(self, shutdown: CancellationToken) {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = self.sleeper.sleep(self.interval) => {
                    tracing::debug!(stats = ?self.cache.stats(), "answer cache stats");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use styx_core::{Sleeper, TestClock, TestSleeper};
    use tokio::sync::Notify;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;
    use tracing::field::{Field, Visit};
    use tracing::instrument::WithSubscriber;
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::Layer;

    use super::CacheStatsLogger;
    use crate::domain::cache::admission_outcome::AdmissionOutcome;
    use crate::domain::cache::bytes::HeapBytes;
    use crate::domain::cache::error::CacheError;
    use crate::domain::cache::key::CacheKey;
    use crate::domain::cache::port::{AdmittedCount, AnswerCache, Lookup, PurgedCount};
    use crate::domain::cache::stats::{AtomicCacheCounters, CacheStats};

    const INTERVAL: Duration = Duration::from_secs(60);
    const REAL_TIME_BUDGET: Duration = Duration::from_millis(500);

    #[derive(Default)]
    struct SpyCache {
        stats_calls: AtomicUsize,
    }

    impl AnswerCache for SpyCache {
        fn lookup(&self, _key: &CacheKey) -> Lookup {
            Lookup::Miss
        }

        fn admit(&self, _outcome: AdmissionOutcome) -> Result<AdmittedCount, CacheError> {
            Ok(AdmittedCount::new(0))
        }

        fn purge_all(&self) -> PurgedCount {
            PurgedCount::new(0)
        }

        fn stats(&self) -> CacheStats {
            self.stats_calls.fetch_add(1, Ordering::SeqCst);
            AtomicCacheCounters::default().snapshot(0, HeapBytes::zero())
        }
    }

    /// A [`TestSleeper`] that signals each time a sleep is armed, so the test advances the
    /// clock only once the logger's next deadline is fixed.
    struct ArmedSleeper {
        inner: TestSleeper,
        armed: Notify,
    }

    impl Sleeper for ArmedSleeper {
        fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
            let sleeping = self.inner.sleep(duration);
            self.armed.notify_one();
            sleeping
        }
    }

    #[derive(Default)]
    struct StatsMessageVisitor {
        matched: bool,
    }

    impl Visit for StatsMessageVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" && format!("{value:?}").contains("answer cache stats") {
                self.matched = true;
            }
        }
    }

    /// Counts the stats events once they are emitted, and signals after each one.
    #[derive(Default)]
    struct StatsEvents {
        count: AtomicUsize,
        emitted: Notify,
    }

    struct StatsEventLayer(Arc<StatsEvents>);

    impl<S: Subscriber> Layer<S> for StatsEventLayer {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            let mut visitor = StatsMessageVisitor::default();
            event.record(&mut visitor);
            if visitor.matched {
                self.0.count.fetch_add(1, Ordering::SeqCst);
                self.0.emitted.notify_one();
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn logs_after_each_interval_and_stops_on_cancellation() {
        let clock = Arc::new(TestClock::new());
        let sleeper = Arc::new(ArmedSleeper {
            inner: TestSleeper::new(Arc::clone(&clock)),
            armed: Notify::new(),
        });
        let cache = Arc::new(SpyCache::default());
        let shutdown = CancellationToken::new();
        let events = Arc::new(StatsEvents::default());
        let subscriber = tracing_subscriber::registry().with(
            StatsEventLayer(Arc::clone(&events)).with_filter(LevelFilter::from_level(Level::DEBUG)),
        );

        let logger = CacheStatsLogger::new(Arc::clone(&cache), Arc::clone(&sleeper), INTERVAL)
            .expect("non-zero interval");
        let handle = tokio::spawn(logger.run(shutdown.clone()).with_subscriber(subscriber));

        for interval in 1..=3 {
            timeout(REAL_TIME_BUDGET, sleeper.armed.notified())
                .await
                .expect("logger waits for the next interval");
            assert_eq!(events.count.load(Ordering::SeqCst), interval - 1);

            clock.advance(INTERVAL);
            timeout(REAL_TIME_BUDGET, events.emitted.notified())
                .await
                .expect("stats logged once the interval elapses");
            assert_eq!(cache.stats_calls.load(Ordering::SeqCst), interval);
            assert_eq!(events.count.load(Ordering::SeqCst), interval);
        }

        shutdown.cancel();
        timeout(REAL_TIME_BUDGET, handle)
            .await
            .expect("logger stops on cancel")
            .expect("logger task join");
    }

    #[test]
    fn a_zero_interval_is_refused() {
        let clock = Arc::new(TestClock::new());
        let sleeper = Arc::new(TestSleeper::new(clock));
        let result = CacheStatsLogger::new(Arc::new(SpyCache::default()), sleeper, Duration::ZERO);
        assert!(matches!(result, Err(CacheError::ZeroStatsInterval)));
    }
}
