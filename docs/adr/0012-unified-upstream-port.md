# ADR 0012 — Unified Upstream trait port for forwarding and recursion

- **Status**: accepted
- **Date**: 2026-09-27
- **Phase**: 3 — Upstream pool and Do53 forwarder

## Context

`styx` requires two distinct operational modes for resolving non-cached queries:

1. **Forwarding (Phase 3 & 7)**: Sending queries across Do53 (UDP/TCP), DoT, or
   DoH to configured external upstream resolvers.
2. **Iterative recursion (Phase 5)**: Resolving queries from the DNS root zone
   (`.`) downward through TLD and authoritative nameservers, validating
   referrals and delegations independently.

From the architectural perspective of the resolution server loop, answer cache,
telemetry recorder, and health monitoring pool, the resolution backend is a
black box: given an inbound DNS query `Message` and client context, it returns an
authenticated or authoritative response `Message`, or reports a resolution error.

If forwarding and recursion exposed distinct traits or separate execution paths
within the request pipeline, the server would require duplicate caching logic,
divergent telemetry hooks, and fragmented health and failover orchestration.

## Decision

**Define a single unified `Upstream` trait port in `styx-core` that abstracts
both forwarding and recursive resolution backends.**

- **Port definition**: `styx_core::domain::upstream::Upstream` specifies:
  - `fn id(&self) -> &UpstreamId`: identifies the upstream instance for metrics,
    logging, and health state mapping.
  - `fn kind(&self) -> UpstreamKind`: distinguishes `UpstreamKind::Forwarder`
    from `UpstreamKind::Recursor`.
  - `async fn resolve(&self, query: &Message, cx: &RequestContext) -> Result<UpstreamResponse, UpstreamError>`:
    executes resolution and returns the response message along with measured
    round-trip latency (`Duration`).
- **Generic pool orchestration**: `UpstreamPool<U: Upstream, ...>` manages
  selection strategies, concurrency fanout, circuit breaking, and passive health
  tracking uniformly across any implementation of `Upstream`.
- **Implementation decoupling**: `Do53Forwarder` implements `Upstream` using
  standard UDP/TCP sockets in Phase 3; Phase 5 implements `Upstream` for the
  iterative recursion engine without modifying the pool or pipeline.

## Consequences

- The server loop and request pipeline remain agnostic of whether an answer was
  obtained via upstream Do53 forwarding, DoT/DoH transport, or full root-down
  iterative recursion.
- Caching, telemetry, and rate-limiting wrappers operate identically across all
  upstream types.
- The test harness easily injects dynamic test doubles (`CommandableUpstream`) to
  simulate specific network fault scenarios (delays, timeouts, truncation, ID
  mismatches) without touching network sockets.
- Recursive resolution mechanics (referral chasing, bailiwick checks, DS/DNSKEY
  queries) remain private internal details of the recursor implementation.
