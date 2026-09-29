//! Integration tests for Clock implementations (SystemClock and TestClock).

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use styx_core::{Clock, SystemClock, TestClock};

#[test]
fn test_system_clock() {
    let clock = SystemClock::new();
    let sys_now = SystemTime::now();
    let clock_now = clock.now_utc();
    let diff = clock_now
        .duration_since(sys_now)
        .unwrap_or_else(|_| sys_now.duration_since(clock_now).unwrap_or(Duration::ZERO));
    assert!(diff < Duration::from_secs(1));

    let mono_now = Instant::now();
    let clock_mono = clock.now_monotonic();
    let mono_diff = clock_mono
        .checked_duration_since(mono_now)
        .unwrap_or_else(|| {
            mono_now
                .checked_duration_since(clock_mono)
                .unwrap_or(Duration::ZERO)
        });
    assert!(mono_diff < Duration::from_secs(1));
}

#[test]
fn test_test_clock_advance() {
    let clock = TestClock::new();
    let start_utc = clock.now_utc();
    let start_mono = clock.now_monotonic();

    let advance_duration = Duration::from_secs(42);
    clock.advance(advance_duration);

    let end_utc = clock.now_utc();
    let end_mono = clock.now_monotonic();

    assert_eq!(
        end_utc.duration_since(start_utc).unwrap_or(Duration::ZERO),
        advance_duration
    );
    assert_eq!(
        end_mono
            .checked_duration_since(start_mono)
            .unwrap_or(Duration::ZERO),
        advance_duration
    );
}

#[test]
fn test_test_clock_set_utc() {
    let clock = TestClock::default();
    let start_mono = clock.now_monotonic();

    let custom_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    clock.set_utc(custom_time);

    assert_eq!(clock.now_utc(), custom_time);
    assert_eq!(clock.now_monotonic(), start_mono);
}

#[test]
fn test_test_clock_concurrency() {
    let clock = Arc::new(TestClock::new());
    let start_mono = clock.now_monotonic();
    let mut handles = Vec::new();

    for _ in 0..4 {
        let c = Arc::clone(&clock);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                c.advance(Duration::from_millis(5));
                let _ = c.now_utc();
                let _ = c.now_monotonic();
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let total_elapsed = clock
        .now_monotonic()
        .checked_duration_since(start_mono)
        .unwrap_or(Duration::ZERO);
    assert_eq!(total_elapsed, Duration::from_millis(2000));
}
