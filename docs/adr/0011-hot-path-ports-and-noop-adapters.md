# ADR 0011 — Hot-path seams declared ahead of features via generic trait ports

- **Status**: accepted
- **Date**: 2026-09-26
- **Phase**: 2 — Server loop and test harness

## Context

`styx` enforces architectural decoupling between feature domains (ADR 0001):
feature crates (`styx-resolution`, `styx-filtering`, storage, telemetry) must never
depend on each other directly. Cross-feature integration is achieved exclusively
through ports declared in the consumer's `domain` and adapters wired at the
composition root (`crates/styx/src/main.rs`).

Several core features reside directly on the resolution request path:

- **Filter policy (Phase 8)**: Per-client blocklist evaluation.
- **Local records (Phase 9)**: Authoritative custom records and overrides.
- **Query logging observer (Phase 10)**: Synchronous atomic counter rollups and
  asynchronous ring-buffer event capture.

If the resolution engine were implemented without these seams in Phase 2,
introducing each feature in later phases would necessitate breaking changes to
the core request pipeline, function signatures, and existing test suites.

Conversely, introducing traditional dynamic dispatch abstractions (`dyn Port` /
`Arc<dyn Port>`) across every stage would introduce heap allocation, cache
invalidation, and pointer indirection overhead on the performance-critical
packet processing path.

## Decision

**Declare all hot-path domain trait ports in Phase 2 with zero-cost default no-op
adapters, wired via generic static dispatch.**

- **Port contracts in `domain/ports/`**:
  - `FilterPolicy`: evaluates queries and returns `FilterVerdict::Allow` or
    `FilterVerdict::Block`.
  - `LocalRecords`: searches memory/storage for configured domain mappings.
  - `QueryObserver`: receives lifecycle hooks for query admission and completion.
- **Default no-op adapters in `infrastructure/`**:
  - `AllowAllFilter`: unconditionally allows all queries.
  - `NoLocalRecords`: unconditionally returns no match.
  - `DiscardObserver`: drops query telemetry events without overhead.
- **Static dispatch**: The resolution pipeline is generic over its ports:
  `Pipeline<L: LocalRecords, F: FilterPolicy, O: QueryObserver, C: Clock, T: TerminalHandler = RefusedTerminal>`.
  Upstream resolution is decoupled from `Pipeline` itself; queries reaching the end
  of the pipeline delegate to `T: TerminalHandler`. In production, the composition root
  wires `CacheStage` (wrapping the answer cache and upstream pool) as `T`, while standalone
  resolution defaults to `RefusedTerminal`.
- **Composition root**: `crates/styx/src/main.rs` instantiates the default no-op
  adapters and injects them by value into `Pipeline` at boot time. Later phases
  substitute concrete implementations without modifying the resolution crate.

## Consequences

- The pipeline structure and type contracts are stabilized in Phase 2; subsequent
  phases implement product logic behind existing trait boundaries without
  disrupting the resolution core.
- Static dispatch enables full compiler inlining and monomorphization, eliminating
  virtual function table calls and allocations on the request hot path.
- Unit and integration tests can substitute focused mock or test adapters
  (e.g., test clocks, simulated block policies) cleanly.
- Generic type signatures in `Pipeline` and `Server` are more verbose, managed via
  type aliases and constructor helpers.
