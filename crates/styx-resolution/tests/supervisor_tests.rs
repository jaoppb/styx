//! Listener supervisor backoff and healthy run reset integration tests.

mod harness;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use harness::TestClock;
use styx_resolution::{
    run_listener_supervisor, ConfigError, ListenerError, ServerConfig, SupervisedListener,
    SupervisorBackoffPolicy,
};
use tokio_util::sync::CancellationToken;

struct ScriptedListener {
    clock: Arc<TestClock>,
    run_count: Arc<AtomicUsize>,
    run_timestamps: Arc<tokio::sync::Mutex<Vec<tokio::time::Instant>>>,
    run_2_advance: Duration,
    cancel: CancellationToken,
}

impl SupervisedListener for ScriptedListener {
    fn transport_name(&self) -> &'static str {
        "TEST"
    }

    async fn run(&self, _cancel: CancellationToken) -> Result<(), ListenerError> {
        let count = self.run_count.fetch_add(1, Ordering::SeqCst);
        let mut timestamps = self.run_timestamps.lock().await;
        timestamps.push(tokio::time::Instant::now());
        drop(timestamps);

        match count {
            0 => {
                // First crash: immediate crash
                Err(ListenerError::Io(std::io::Error::other("crash 1")))
            }
            1 => {
                // Second run: advance injected clock, then crash
                self.clock.advance(self.run_2_advance);
                Err(ListenerError::Io(std::io::Error::other("crash 2")))
            }
            _ => {
                // Third run: stop supervisor
                self.cancel.cancel();
                Ok(())
            }
        }
    }
}

#[tokio::test]
async fn test_supervisor_backoff_resets_after_healthy_run() {
    let clock = Arc::new(TestClock::new());
    let cancel = CancellationToken::new();
    let run_count = Arc::new(AtomicUsize::new(0));
    let run_timestamps = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let listener = ScriptedListener {
        clock: Arc::clone(&clock),
        run_count: Arc::clone(&run_count),
        run_timestamps: Arc::clone(&run_timestamps),
        run_2_advance: Duration::from_secs(60), // Healthy run: 1 minute
        cancel: cancel.clone(),
    };

    let policy = SupervisorBackoffPolicy::default();
    let supervisor_handle = tokio::spawn(run_listener_supervisor(listener, clock, policy, cancel));

    supervisor_handle
        .await
        .expect("supervisor task joins")
        .expect("supervisor completes");

    assert_eq!(run_count.load(Ordering::SeqCst), 3);

    let timestamps = run_timestamps.lock().await;
    assert_eq!(timestamps.len(), 3);

    // Wait between crash 1 and run 2 should be ~50 ms (initial backoff)
    let wait_1 = timestamps[1].duration_since(timestamps[0]);
    assert!(
        wait_1 >= Duration::from_millis(40) && wait_1 < Duration::from_millis(90),
        "wait_1 expected ~50ms, was {wait_1:?}"
    );

    // Because run 2 ran for 60s (healthy run), backoff reset to initial (50 ms).
    // If it had NOT reset, wait_2 would have doubled to 100 ms.
    let wait_2 = timestamps[2].duration_since(timestamps[1]);
    assert!(
        wait_2 >= Duration::from_millis(40) && wait_2 < Duration::from_millis(90),
        "wait_2 expected reset to ~50ms after 1 min healthy run, was {wait_2:?}"
    );
}

#[tokio::test]
async fn test_supervisor_backoff_doubles_without_healthy_run() {
    let clock = Arc::new(TestClock::new());
    let cancel = CancellationToken::new();
    let run_count = Arc::new(AtomicUsize::new(0));
    let run_timestamps = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let listener = ScriptedListener {
        clock: Arc::clone(&clock),
        run_count: Arc::clone(&run_count),
        run_timestamps: Arc::clone(&run_timestamps),
        run_2_advance: Duration::from_secs(10), // Unhealthy run: 10 seconds (< 60s)
        cancel: cancel.clone(),
    };

    let policy = SupervisorBackoffPolicy::default();
    let supervisor_handle = tokio::spawn(run_listener_supervisor(listener, clock, policy, cancel));

    supervisor_handle
        .await
        .expect("supervisor task joins")
        .expect("supervisor completes");

    assert_eq!(run_count.load(Ordering::SeqCst), 3);

    let timestamps = run_timestamps.lock().await;
    assert_eq!(timestamps.len(), 3);

    // Wait between crash 1 and run 2: ~50 ms
    let wait_1 = timestamps[1].duration_since(timestamps[0]);
    assert!(
        wait_1 >= Duration::from_millis(40) && wait_1 < Duration::from_millis(90),
        "wait_1 expected ~50ms, was {wait_1:?}"
    );

    // Run 2 was only 10s (unhealthy), so backoff doubled: ~100 ms
    let wait_2 = timestamps[2].duration_since(timestamps[1]);
    assert!(
        wait_2 >= Duration::from_millis(90) && wait_2 < Duration::from_millis(150),
        "wait_2 expected ~100ms when run is shorter than healthy threshold, was {wait_2:?}"
    );
}

#[tokio::test]
async fn test_supervisor_cancellation_during_backoff_sleep_exits_promptly() {
    let clock = Arc::new(TestClock::new());
    let cancel = CancellationToken::new();

    struct CrashingListener;
    impl SupervisedListener for CrashingListener {
        fn transport_name(&self) -> &'static str {
            "CRASH"
        }
        async fn run(&self, _cancel: CancellationToken) -> Result<(), ListenerError> {
            Err(ListenerError::Io(std::io::Error::other("immediate crash")))
        }
    }

    let policy = SupervisorBackoffPolicy::new(
        Duration::from_secs(5), // 5 seconds backoff
        Duration::from_secs(10),
        Duration::from_secs(60),
    );

    let cancel_clone = cancel.clone();
    let supervisor_handle = tokio::spawn(run_listener_supervisor(
        CrashingListener,
        clock,
        policy,
        cancel,
    ));

    // Allow the listener to crash and enter the 5s backoff sleep
    tokio::time::sleep(Duration::from_millis(30)).await;

    let cancel_start = tokio::time::Instant::now();
    cancel_clone.cancel();

    // Supervisor should exit promptly without sleeping the full 5 seconds
    tokio::time::timeout(Duration::from_millis(200), supervisor_handle)
        .await
        .expect("supervisor exits promptly upon cancellation")
        .expect("supervisor joins")
        .expect("supervisor completes");

    assert!(
        cancel_start.elapsed() < Duration::from_millis(100),
        "cancellation should break immediately"
    );
}

#[test]
fn test_supervisor_config_toml_parsing() {
    // Default parsing
    let default_cfg = ServerConfig::from_toml_str("").unwrap();
    assert_eq!(
        default_cfg.supervisor.initial_backoff,
        Duration::from_millis(50)
    );
    assert_eq!(default_cfg.supervisor.max_backoff, Duration::from_secs(2));
    assert_eq!(
        default_cfg.supervisor.healthy_threshold,
        Duration::from_secs(60)
    );

    // Custom [supervisor] table
    let toml = r#"
        [supervisor]
        initial_backoff_ms = 100
        max_backoff_secs = 5
        healthy_threshold_secs = 120
    "#;
    let custom_cfg = ServerConfig::from_toml_str(toml).unwrap();
    assert_eq!(
        custom_cfg.supervisor.initial_backoff,
        Duration::from_millis(100)
    );
    assert_eq!(custom_cfg.supervisor.max_backoff, Duration::from_secs(5));
    assert_eq!(
        custom_cfg.supervisor.healthy_threshold,
        Duration::from_secs(120)
    );

    // Invalid: initial_backoff_ms = 0
    let zero_initial = r#"
        [supervisor]
        initial_backoff_ms = 0
    "#;
    assert!(matches!(
        ServerConfig::from_toml_str(zero_initial),
        Err(ConfigError::Invalid(_))
    ));

    // Invalid: initial_backoff > max_backoff
    let initial_exceeds_max = r#"
        [supervisor]
        initial_backoff_ms = 3000
        max_backoff_secs = 2
    "#;
    assert!(matches!(
        ServerConfig::from_toml_str(initial_exceeds_max),
        Err(ConfigError::Invalid(_))
    ));
}
