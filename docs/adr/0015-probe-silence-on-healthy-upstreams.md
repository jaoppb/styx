# ADR 0015 — Background probe scheduler with absolute silence on healthy upstreams

- **Status**: accepted
- **Date**: 2026-09-27
- **Phase**: 3 — Upstream pool and Do53 forwarder

## Context

Many network systems employ background canary probing to monitor server
reachability. In a home network DNS resolver, however, continuously transmitting
unconditional synthetic probes to all upstream servers introduces several
operational drawbacks:

1. **Traffic amplification and resource consumption**: On low-power appliances
   (e.g. Raspberry Pi) or metered links, continuous background polling emits
   unnecessary network packets, prevents network hardware from entering low-power
   states, and consumes outbound bandwidth.
2. **Upstream abuse and rate-limiting**: Public DNS providers (Quad9, Cloudflare,
   Google) or ISP nameservers may rate-limit or flag repetitive synthetic canary
   queries originating from single home IPs.
3. **Redundant signal and false positives**: When an upstream is actively handling
   hundreds of real client queries per minute with low latency and zero errors,
   the live traffic stream already provides continuous, high-fidelity proof of
   health. Generating artificial canary probes adds zero informational value and
   creates artificial risk of tripping alarms if a synthetic probe drops.

Conversely, completely omitting background probing leaves tripped upstreams
(`Open` or `HalfOpen`) or idle standby upstreams in failover configurations
unmonitored, forcing real client queries to absorb probe failures when an upstream
comes back online or when failover is triggered.

## Decision

**Establish the core invariant: absolute probe silence on healthy active upstreams,
restricting background probing to recovery and standby states.**

- **Architectural invariant**: A healthy upstream (`Closed` circuit state) that is
  actively servicing live traffic is deemed verified by that traffic; background
  canary probes are strictly suppressed.
- **Probe scope**: `styx_resolution::application::ProbeScheduler` probes an
  upstream only under two specific conditions:
  1. **Recovery probing**: The upstream's circuit breaker is in `Open` (cool-down
     expired) or `HalfOpen`, requiring a canary to test whether the upstream has
     recovered without exposing end-user queries to potential timeouts.
  2. **Standby probing**: The upstream is in a secondary or idle role (such as a
     standby server in `OrderedFailover`) and has received no live traffic within
     the configured standby probe interval.
- **In-flight deduplication and bounded overhead**: Probes are scheduled via a
  dedicated supervised background task (`ProbeScheduler`). In-flight probes are
  deduplicated per upstream, ensuring at most one probe is outstanding at any
  moment.
- **Canary query shape**: Configured via `CanaryConfig`. Default canaries depend
  on upstream kind: forwarders use `probe.canary.invalid.` with type `A` (2-second
  timeout), whereas recursors use `root-canary.iana.org.` with type `NS` (5-second
  timeout). Individual pool members may override these with custom canary domains.

## Consequences

- Zero background probe traffic is emitted during normal steady-state operation
  when active upstreams are healthy and processing user traffic.
- Recovering and idle standby upstreams are monitored unobtrusively in the
  background, ensuring warm failover readiness.
- Spurious circuit flaps from dropped canary packets are eliminated on active
  channels.
- The invariant is mechanically verified by socket-level unit and integration
  tests using `TestClock` asserting zero probe packets sent when upstreams are
  healthy.
