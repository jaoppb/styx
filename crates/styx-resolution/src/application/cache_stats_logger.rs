//! Background task that periodically logs answer cache counters at `debug`.

use std::sync::Arc;
use std::time::Duration;

use styx_core::Sleeper;
use tokio_util::sync::CancellationToken;

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
    #[must_use]
    pub fn new(cache: Arc<A>, sleeper: Arc<S>, interval: Duration) -> Self {
        Self {
            cache,
            sleeper,
            interval,
        }
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use styx_core::{TestClock, TestSleeper};
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

    struct SpyCache {
        stats_calls: AtomicUsize,
        logged: Notify,
    }

    impl SpyCache {
        fn new() -> Self {
            Self {
                stats_calls: AtomicUsize::new(0),
                logged: Notify::new(),
            }
        }
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
            self.logged.notify_one();
            AtomicCacheCounters::default().snapshot(0, HeapBytes::zero())
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

    struct DebugEventCounter(Arc<AtomicUsize>);

    impl<S: Subscriber> Layer<S> for DebugEventCounter {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = StatsMessageVisitor::default();
            event.record(&mut visitor);
            if visitor.matched {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[tokio::test]
    async fn logs_after_each_interval_and_stops_on_cancellation() {
        let clock = Arc::new(TestClock::new());
        let sleeper = Arc::new(TestSleeper::new(Arc::clone(&clock)));
        let cache = Arc::new(SpyCache::new());
        let shutdown = CancellationToken::new();
        let debug_events = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(
            DebugEventCounter(Arc::clone(&debug_events))
                .with_filter(LevelFilter::from_level(Level::DEBUG)),
        );

        let logger = CacheStatsLogger::new(Arc::clone(&cache), sleeper, INTERVAL);
        let handle = tokio::spawn(logger.run(shutdown.clone()).with_subscriber(subscriber));

        tokio::task::yield_now().await;
        assert_eq!(cache.stats_calls.load(Ordering::SeqCst), 0);
        assert_eq!(debug_events.load(Ordering::SeqCst), 0);

        clock.advance(INTERVAL);
        timeout(REAL_TIME_BUDGET, cache.logged.notified())
            .await
            .expect("first stats log");
        assert_eq!(cache.stats_calls.load(Ordering::SeqCst), 1);
        assert_eq!(debug_events.load(Ordering::SeqCst), 1);

        shutdown.cancel();
        timeout(REAL_TIME_BUDGET, handle)
            .await
            .expect("logger stops on cancel")
            .expect("logger task join");
    }
}
