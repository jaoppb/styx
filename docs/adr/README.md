# Architecture Decision Records (ADRs)

Architecture Decision Records (ADRs) document load-bearing architectural choices,
their context, and their accepted consequences.

As defined in [`AGENTS.md`](../../AGENTS.md):
> An architecture decision record explains why a past decision was made and is
> never edited except by superseding it; `AGENTS.md` explains how code is written
> going forward and is revised in place as conventions are learned.

## Index of Records

| ADR | Title | Phase | Date | Status |
|---|---|---|---|---|
| [0001](0001-layering-and-arch-lint.md) | Layering, and how arch-lint is made to enforce it | Phase 0 — Foundation and gates | 2026-09-22 | Accepted |
| [0002](0002-hickory-proto-exception.md) | `hickory-proto` as the test oracle | Phase 0 — Foundation and gates | 2026-09-22 | Accepted |
| [0003](0003-pinned-trust-anchor.md) | Pinned trust anchor and local key rollover | Phase 0 — Foundation and gates | 2026-09-22 | Accepted |
| [0004](0004-owned-decoded-domain-types.md) | Decoded domain types are owned, not zero-copy borrowed views | Phase 1 — Wire codec | 2026-09-26 | Accepted |
| [0005](0005-pointer-expansion-budget.md) | Compression pointer cycle detection and expansion budget | Phase 1 — Wire codec | 2026-09-26 | Accepted |
| [0006](0006-edns-opt-first-class-field.md) | EDNS(0) OPT pseudo-RR as a first-class Message field | Phase 1 — Wire codec | 2026-09-26 | Accepted |
| [0007](0007-name-case-preservation-and-canonical-form.md) | Name case preservation and RFC 4034 canonical form | Phase 1 — Wire codec | 2026-09-26 | Accepted |
| [0008](0008-cursor-bounds-checked-primitive.md) | Centralized checked slice traversal via Cursor primitive | Phase 1 — Wire codec | 2026-09-26 | Accepted |
| [0009](0009-deterministic-clock-port.md) | Deterministic Clock port abstraction | Phase 2 — Server loop and test harness | 2026-09-26 | Accepted |
| [0010](0010-pipeline-ordering-and-dnssec-honesty.md) | Request pipeline ordering and DNSSEC honesty for forged answers | Phase 2 — Server loop and test harness | 2026-09-26 | Accepted |
| [0011](0011-hot-path-ports-and-noop-adapters.md) | Hot-path seams declared ahead of features via generic trait ports | Phase 2 — Server loop and test harness | 2026-09-26 | Accepted |
| [0012](0012-unified-upstream-port.md) | Unified Upstream trait port for forwarding and recursion | Phase 3 — Upstream pool and Do53 forwarder | 2026-09-27 | Accepted |
| [0013](0013-failure-classification-isolating-authoritative-answers.md) | Upstream fault isolation from authoritative negative answers | Phase 3 — Upstream pool and Do53 forwarder | 2026-09-27 | Accepted |
| [0014](0014-passive-ewma-and-circuit-breaker.md) | Passive integer EWMA latency tracking and three-state circuit breaker | Phase 3 — Upstream pool and Do53 forwarder | 2026-09-27 | Accepted |
| [0015](0015-probe-silence-on-healthy-upstreams.md) | Background probe scheduler with absolute silence on healthy upstreams | Phase 3 — Upstream pool and Do53 forwarder | 2026-09-27 | Accepted |
| [0016](0016-answer-cache-global-key-and-egress-filtering.md) | Answer cache global key and egress filtering | Phase 4 — Answer cache | 2026-09-27 | Accepted |
| [0017](0017-admission-time-bailiwick-validation-and-forgery-refusal.md) | Admission-time bailiwick validation and forgery refusal | Phase 4 — Answer cache | 2026-09-27 | Accepted |
| [0018](0018-sharded-in-memory-concurrency-and-checked-heapbytes-accounting.md) | Sharded in-memory concurrency and checked heapbytes accounting | Phase 4 — Answer cache | 2026-09-27 | Accepted |
| [0019](0019-rfc2308-negative-caching-with-soa-ttl.md) | RFC 2308 negative caching with SOA TTL | Phase 4 — Answer cache | 2026-09-27 | Accepted |
