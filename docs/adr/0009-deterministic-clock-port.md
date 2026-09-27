# ADR 0009 — Deterministic Clock port abstraction

- **Status**: accepted
- **Date**: 2026-09-26
- **Phase**: 2 — Server loop and test harness

## Context

DNS resolution is fundamentally bound to time across multiple operational layers:

- **DNSSEC validation (Phase 6)**: RRSIG resource records carry cryptographic
  validity intervals (`inception` and `expiration` fields, RFC 4034 §3.1.5).
  Recorded test fixtures and signed zones have fixed expiration dates. If the
  resolver reads system time directly, recorded tests fail the moment real-world
  calendar time advances beyond the signature window.
- **Answer cache (Phase 4)**: Cached resource records require TTL decrement and
  eviction based on elapsed time.
- **Upstream resilience (Phase 3)**: Circuit breaker cool-down timers, passive
  EWMA latency decay, and background probe intervals rely on monotonic elapsed
  intervals.

In asynchronous systems, relying on `std::time::SystemTime::now()` or
`tokio::time::sleep` in test suites leads to slow, flaky test execution, race
conditions, and vulnerability to system clock drift or NTP adjustments. More
critically, retrofitting time injection into a DNSSEC validator, resolver cache,
and server loop after they are written is an invasive rewrite.

Furthermore, wall-clock time and monotonic time serve distinct domain purposes:
wall-clock time is required for calendar timestamps and protocol signatures but
can step backwards, whereas monotonic time is required for elapsed durations,
timeouts, and rate tracking.

## Decision

**Abstract all time access behind an injectable `Clock` port in `domain`, separating
monotonic instant from wall-clock time, backed by a deterministic test double.**

- **Port definition**: `styx_resolution::domain::ports::Clock` declares:
  - `fn now_monotonic(&self) -> Instant`: returns a monotonically increasing
    time point for measuring durations, timeouts, and state transitions.
  - `fn now_utc(&self) -> SystemTime`: returns UTC wall-clock time for
    timestamp recording, log telemetry, and DNSSEC signature validity checks.
- **Production adapter**: `styx_resolution::infrastructure::SystemClock` implements
  `Clock` using the standard library's real system clocks.
- **Test double**: `TestClock` in `tests/harness/clock.rs` provides deterministic,
  programmatic time control with `advance(Duration)` and `set_utc(SystemTime)`.
  Tests step time forward instantaneously without sleeping or calling
  `tokio::time::sleep`.
- **Static dispatch**: Pipeline and pool components accept time via generic
  type parameter (`<C: Clock>`) to ensure zero heap allocation or dynamic dispatch
  overhead on the resolution hot path.

## Consequences

- Test suites execute deterministically in milliseconds at socket level while
  simulating hours or days of elapsed cache expiration, circuit breaker resets,
  and DNSSEC validation intervals.
- Wall-clock time and monotonic intervals cannot be accidentally conflated at
  call sites.
- Production code is barred from calling `std::time::Instant::now()` or
  `SystemTime::now()` directly, requiring the injected clock to be threaded
  through domain services.
