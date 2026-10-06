//! Listener supervisor backoff policy and execution loop.

use std::sync::Arc;
use std::time::Duration;

use styx_core::Clock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::application::terminal::TerminalHandler;
use crate::domain::error::ListenerError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::infrastructure::tcp::TcpListener;
use crate::infrastructure::udp::UdpListener;

/// Default initial backoff in milliseconds.
pub const DEFAULT_INITIAL_BACKOFF_MS: u64 = 50;

/// Default maximum backoff cap in seconds.
pub const DEFAULT_MAX_BACKOFF_SECS: u64 = 2;

/// Default healthy running duration in seconds required to reset backoff.
pub const DEFAULT_HEALTHY_THRESHOLD_SECS: u64 = 60;

/// Default initial backoff before retrying a crashed listener.
pub const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(DEFAULT_INITIAL_BACKOFF_MS);

/// Default maximum backoff cap for crashed listener retries.
pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(DEFAULT_MAX_BACKOFF_SECS);

/// Default healthy running duration required to reset the retry backoff.
pub const DEFAULT_HEALTHY_THRESHOLD: Duration = Duration::from_secs(DEFAULT_HEALTHY_THRESHOLD_SECS);

/// Policy controlling supervisor retry backoff and healthy run reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorBackoffPolicy {
    /// Initial backoff delay on listener crash.
    pub initial_backoff: Duration,
    /// Maximum backoff delay cap.
    pub max_backoff: Duration,
    /// Duration a listener must run continuously to reset backoff.
    pub healthy_threshold: Duration,
}

impl Default for SupervisorBackoffPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
            healthy_threshold: DEFAULT_HEALTHY_THRESHOLD,
        }
    }
}

impl SupervisorBackoffPolicy {
    /// Creates a new `SupervisorBackoffPolicy`.
    #[must_use]
    pub const fn new(
        initial_backoff: Duration,
        max_backoff: Duration,
        healthy_threshold: Duration,
    ) -> Self {
        Self {
            initial_backoff,
            max_backoff,
            healthy_threshold,
        }
    }
}

/// State tracker managing exponential backoff and reset transitions for a supervised listener.
#[derive(Debug, Clone)]
pub struct SupervisorBackoff {
    policy: SupervisorBackoffPolicy,
    current: Duration,
}

impl SupervisorBackoff {
    /// Creates a new `SupervisorBackoff` initialized to the policy's initial backoff.
    #[must_use]
    pub const fn new(policy: SupervisorBackoffPolicy) -> Self {
        Self {
            current: policy.initial_backoff,
            policy,
        }
    }

    /// Resets backoff to the initial delay if the elapsed run duration meets or exceeds the healthy threshold.
    pub fn record_run(&mut self, elapsed: Duration) {
        if elapsed >= self.policy.healthy_threshold {
            self.current = self.policy.initial_backoff;
        }
    }

    /// Records a crash: returns the current backoff delay to wait, and advances the next backoff.
    pub fn on_crash(&mut self) -> Duration {
        let delay = self.current;
        self.current = self.current.saturating_mul(2).min(self.policy.max_backoff);
        delay
    }

    /// Returns the current backoff delay.
    #[must_use]
    pub const fn current(&self) -> Duration {
        self.current
    }
}

/// Trait implemented by transport listeners managed by a supervisor loop.
pub trait SupervisedListener: Send + 'static {
    /// Returns human-readable transport name for logging (e.g. "UDP" or "TCP").
    fn transport_name(&self) -> &'static str;

    /// Runs the listener until cancelled or a fatal error occurs.
    fn run(
        &self,
        cancel: CancellationToken,
    ) -> impl std::future::Future<Output = Result<(), ListenerError>> + Send;
}

impl<L, F, O, C, T> SupervisedListener for UdpListener<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    fn transport_name(&self) -> &'static str {
        "UDP"
    }

    fn run(
        &self,
        cancel: CancellationToken,
    ) -> impl std::future::Future<Output = Result<(), ListenerError>> + Send {
        self.run(cancel)
    }
}

impl<L, F, O, C, T> SupervisedListener for TcpListener<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    fn transport_name(&self) -> &'static str {
        "TCP"
    }

    fn run(
        &self,
        cancel: CancellationToken,
    ) -> impl std::future::Future<Output = Result<(), ListenerError>> + Send {
        self.run(cancel)
    }
}

/// Spawns a supervisor task for a listener.
pub(crate) fn spawn_listener_supervisor<L, C>(
    listener: L,
    clock: Arc<C>,
    policy: SupervisorBackoffPolicy,
    cancel: CancellationToken,
) -> JoinHandle<Result<(), ListenerError>>
where
    L: SupervisedListener,
    C: Clock + Send + Sync + 'static,
{
    tokio::spawn(run_listener_supervisor(listener, clock, policy, cancel))
}

/// Runs the supervisor loop for a listener using an injected clock.
///
/// # Errors
/// Returns [`ListenerError`] if supervisor execution encounters an unrecoverable failure.
pub async fn run_listener_supervisor<L, C>(
    listener: L,
    clock: Arc<C>,
    policy: SupervisorBackoffPolicy,
    cancel: CancellationToken,
) -> Result<(), ListenerError>
where
    L: SupervisedListener,
    C: Clock + Send + Sync + 'static,
{
    let mut backoff = SupervisorBackoff::new(policy);
    while !cancel.is_cancelled() {
        let started_at = clock.now_monotonic();
        let Err(err) = listener.run(cancel.clone()).await else {
            break;
        };
        let elapsed = clock
            .now_monotonic()
            .checked_duration_since(started_at)
            .unwrap_or_default();
        backoff.record_run(elapsed);

        if handle_listener_crash(listener.transport_name(), err, &mut backoff, &cancel).await {
            break;
        }
    }
    Ok(())
}

async fn handle_listener_crash(
    kind: &'static str,
    err: ListenerError,
    backoff: &mut SupervisorBackoff,
    cancel: &CancellationToken,
) -> bool {
    if cancel.is_cancelled() {
        return true;
    }
    let delay = backoff.on_crash();
    tracing::error!(
        %err,
        delay_ms = delay.as_millis(),
        "{kind} listener crashed; retrying after backoff"
    );
    tokio::select! {
        () = cancel.cancelled() => true,
        () = tokio::time::sleep(delay) => cancel.is_cancelled(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_doubles_up_to_max() {
        let policy = SupervisorBackoffPolicy::new(
            Duration::from_millis(50),
            Duration::from_millis(200),
            Duration::from_secs(60),
        );
        let mut backoff = SupervisorBackoff::new(policy);

        assert_eq!(backoff.on_crash(), Duration::from_millis(50));
        assert_eq!(backoff.current(), Duration::from_millis(100));

        assert_eq!(backoff.on_crash(), Duration::from_millis(100));
        assert_eq!(backoff.current(), Duration::from_millis(200));

        assert_eq!(backoff.on_crash(), Duration::from_millis(200));
        assert_eq!(backoff.current(), Duration::from_millis(200));
    }

    #[test]
    fn test_short_run_does_not_reset_backoff() {
        let policy = SupervisorBackoffPolicy::default();
        let mut backoff = SupervisorBackoff::new(policy);

        assert_eq!(backoff.on_crash(), Duration::from_millis(50));
        assert_eq!(backoff.current(), Duration::from_millis(100));

        backoff.record_run(Duration::from_secs(59));
        assert_eq!(backoff.current(), Duration::from_millis(100));
        assert_eq!(backoff.on_crash(), Duration::from_millis(100));
        assert_eq!(backoff.current(), Duration::from_millis(200));
    }

    #[test]
    fn test_healthy_run_resets_backoff_to_initial() {
        let policy = SupervisorBackoffPolicy::default();
        let mut backoff = SupervisorBackoff::new(policy);

        assert_eq!(backoff.on_crash(), Duration::from_millis(50));
        assert_eq!(backoff.on_crash(), Duration::from_millis(100));
        assert_eq!(backoff.current(), Duration::from_millis(200));

        // Healthy run: >= 60 seconds
        backoff.record_run(Duration::from_secs(60));
        assert_eq!(backoff.current(), Duration::from_millis(50));
        assert_eq!(backoff.on_crash(), Duration::from_millis(50));
        assert_eq!(backoff.current(), Duration::from_millis(100));
    }
}
