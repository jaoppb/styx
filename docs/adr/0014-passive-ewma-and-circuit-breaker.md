# ADR 0014 — Passive integer EWMA latency tracking and three-state circuit breaker

- **Status**: accepted
- **Date**: 2026-09-27
- **Phase**: 3 — Upstream pool and Do53 forwarder

## Context

When routing DNS queries among multiple upstream servers, responsiveness and
resilience depend on detecting degraded or unresponsive servers rapidly:

1. **Latency estimation**: Selection strategies (e.g. weighted or lowest-latency
   routing) need an accurate, smoothed measurement of upstream round-trip time.
   Active synthetic pinging is wasteful and does not reflect real query payload
   performance.
2. **Computational overhead**: Latency tracking executes on every query response
   on the hot path. Using floating-point math introduces unnecessary overhead,
   can produce non-deterministic precision issues, and violates styx's zero-cost
   posture on low-power hardware.
3. **Failure isolation**: When an upstream becomes unreachable or drops packets,
   inbound queries directed to it stall until network timeouts expire (typically
   2–5 seconds). Repeatedly hitting dead upstreams degrades client perceived
   performance across the entire network.

## Decision

**Implement passive smoothed round-trip time (SRTT) tracking using fixed-point
integer EWMA, coupled with a three-state saturating circuit breaker.**

- **Fixed-point integer EWMA (`HealthState`)**:
  - Upstream latency is tracked passively from actual query completion times.
  - The smoothed round-trip time (SRTT) is updated using an Exponentially
    Weighted Moving Average with decay $\alpha = \frac{1}{8}$ (RFC 6298 TCP
    standard).
  - Calculations use strictly checked integer arithmetic and bitwise shifts:
    `new_srtt = (7 * old_srtt + sample_rtt) >> 3`.
  - Floating-point arithmetic is forbidden; calculations operate on nanoseconds
    via `Duration::from_nanos`.
  - Cold-start handling: the very first successful query sample initializes
    the SRTT baseline directly without requiring smoothing warm-up.
- **Three-state saturating circuit breaker (`CircuitState`)**:
  - Governed by `CircuitConfig { failure_threshold, open_cooldown, half_open_successes }`.
  - `Closed`: Upstream is healthy and accepts regular traffic. Every
    `UpstreamFault` increments a saturating consecutive failure counter.
  - `Open`: Tripped when consecutive failures reach `failure_threshold`
    (default 3). The pool immediately bypasses this upstream for a configured
    cool-down duration (`open_cooldown`, default 30s), eliminating timeout
    stalls for client queries.
  - `HalfOpen`: Entered after the cool-down expires. Permits a single probe query
    or trial request at a time (`in_flight: true`). Consecutive successful trials
    must reach `half_open_successes` (default 2) to transition the breaker back
    to `Closed` (resetting the failure count); any trial failure immediately
    re-arms `Open { since: now }` for another cool-down period.

## Consequences

- Degraded or dead upstreams are rapidly taken out of rotation after minimal
  failures, shielding downstream users from cumulative timeout delays.
- Latency estimation on the hot path uses integer bitwise operations with zero
  floating-point calculations and zero heap allocations.
- Health recovery is cautious and self-healing: dead upstreams are retested with
  controlled trial traffic without risking full traffic brownouts.
- Upstreams with transient packet drops that stay below the threshold retain
  smoothed latency measurements without abrupt circuit flaps.
