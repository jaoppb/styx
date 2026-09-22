# SPDD Analysis: Phase 2 — Server loop and test harness (styx)

> Project: **styx** — a filtering DNS resolver written from scratch in Rust, replacing
> Pi-hole's role on a home network (recursive/forwarding resolution, per-client blocking
> policy, Leptos admin UI). Single process, single binary, one box.
>
> This analysis is **self-contained**. It carries forward the project decisions,
> accepted consequences, non-goals and risks that bear on this phase, together with
> the reasoning behind each, so no other document is needed to implement the phase.

---

## Original Business Requirement

The following is the phase specification, reproduced verbatim.

```markdown
# Phase 2 — Server loop and test harness

> Part of [ROADMAP.md](../../ROADMAP.md) · Previous: [Phase 1 — Wire codec](01-wire-codec.md) · Next: [Phase 3 — Upstream pool](03-upstream-pool.md)

## Scope

- UDP and TCP listeners on an ephemeral port, TC bit and TCP fallback, the request
  pipeline skeleton.
- The injectable `Clock` of decision 37. It cannot be retrofitted later.
- **The harness itself**: in-process fake root, TLD and authoritative servers built
  on `hickory-proto`, driven over real sockets.
- **Declare the hot-path ports now, with no-op implementations** — `FilterPolicy`
  (decision 31), a `LocalRecords` lookup consulted ahead of the cache and ahead of
  any upstream (decision 13), and the query-log observer that decision 25 needs
  for synchronous rollup counters. All three live on the resolution hot path, so
  their shape must exist before the product half is written, or the product half
  rewrites the hot path. Their implementations land in
  [phase 8](08-filtering.md) and [phase 9](09-storage.md).
- **Fix the pipeline order now**, since it is a correctness property and not a
  detail: local records → filter → cache → upstream. Local records and blocks are
  both forged answers, so both clear AD, forge no signature, and never enter the
  answer cache.

## Exit criteria

Socket-level tests green against the fakes; `dig @127.0.0.1 -p <port>` works by
hand.
```

### Inlined decisions referenced by the phase spec

The phase spec above cites decisions by number. Their full text and rationale,
inlined here so this document stands alone:

- **The injectable `Clock` (cited as "decision 37")** — *TDD cycles run at socket
  level by default.* Feature tests drive real UDP/TCP against an ephemeral-port
  server, with in-process fake root and authoritative servers, and an injectable
  `Clock` — **because RRSIGs carry inception and expiration timestamps, so any
  recorded signature fixture expires on a date you did not choose. Time injection
  cannot be retrofitted into a validator; it is a rewrite.**

- **`FilterPolicy` as a port (cited as "decision 31")** — *Feature crates never
  depend on each other.* Cross-feature needs are expressed as a port in the
  consumer's `domain`, implemented by an adapter in the binary — e.g.
  `styx-resolution` declares a `FilterPolicy` port and the `styx` binary wires
  `styx-filtering` into it. `styx-web` may depend on a feature's `application`
  layer, because it is presentation, not a peer.

- **`LocalRecords` (cited as "decision 13")** — *Local records are answered before
  the cache and are always Insecure.* A/AAAA/CNAME/PTR rows in Turso, editable in
  the UI, matched ahead of the answer cache and ahead of any upstream. They never
  enter the answer cache and never reach the validator: **AD cleared, no forged
  signature, same honesty rule as a blocked reply.** This is what the
  zone-serving non-goal means by "resolution concern". *Accepted consequence:* a
  local name under a signed public zone (`nas.example.com` where `example.com` is
  signed) is unprovable and validating clients may SERVFAIL it — the documented
  guidance is to keep local names under an unsigned or internal suffix. This is
  precisely the failure reported as pi-hole#2686.

- **The query-log observer (cited as "decision 25")** — *Split write paths.*
  Rollup counters increment **synchronously via atomics on the response path** —
  never queued, never dropped, so every dashboard number is always exact. Only raw
  rows and the live ring go through a bounded channel, which drops when full and
  exposes a visible `dropped_detail` counter. **Dashboards cannot lie; detail
  degrades gracefully.**

- **`hickory-proto` as the harness oracle (project decision on test dependencies)**
  — *`hickory-proto` is the test oracle, `[dev-dependencies]` only.* The fake
  root/TLD/authoritative servers and the expected-byte fixtures have to encode DNS
  wire format; **if our own codec encodes them, the resolver and its oracle share
  every bug and a green suite proves only self-consistency.** The from-scratch ban
  is on shipping code, not the test rig. A CI check asserts `hickory-proto`
  appears in no normal or build dependency path, or the exception rots into a real
  dependency.

### Phase position in the build order

| Depends on (must exist first) | This phase | Depended on by |
|---|---|---|
| **Phase 0 — Foundation and gates**: git, Cargo workspace, a working (syn-engine) `arch-lint.toml`, the independent `cargo tree --edges normal` layering gate, the `hickory-dev-only` check, `clippy.toml` with the 15 denied lints, lefthook, GitHub Actions, and the `just gate` target. | **Phase 2 — Server loop and test harness** | **Phase 3 — `Upstream` port, forwarding, pool** (needs the listeners, the harness fakes and the injected `Clock` to prove circuit open/close); **Phase 4 — Answer cache** (needs injected time for TTL expiry and the pipeline slot after filter); **Phase 5 — Recursion** (needs fake root/TLD/auth servers over real sockets); **Phase 6 — DNSSEC** (needs the injected `Clock` for RRSIG inception/expiration); **Phase 7 — Encrypted inbound** (DoT/DoH listeners reuse the listener and request-pipeline shape); **Phase 8 — Filtering** (implements `FilterPolicy` behind the port declared here); **Phase 9 — Storage** (backs `LocalRecords`); **Phase 10 — Query log pipeline** (implements the observer declared here). |
| **Phase 1 — Wire codec (`styx-proto`)**: header, question, RR, RDATA for every v1 rrtype, name compression on both encode and decode, compression-pointer loop detection, EDNS(0) OPT — all under `indexing_slicing = deny` and `arithmetic_side_effects = deny`, fuzzed. `styx-proto` is shared foundation, not a feature crate: every crate parses through the wire codec, so the "feature crates never depend on each other" rule explicitly does not reach it, and `[[restrict-use]]` must be written so as not to forbid it. | | |

---

## Domain Concept Identification

### Codebase context

**Greenfield, no existing implementation.** The repository at the time of analysis
contains only `SPEC.md`, `ROADMAP.md`, `docs/specs/` and a placeholder
`arch-lint.toml` (the upstream Kotlin template, replaced in phase 0). There is no
git repository, no Cargo workspace, no `.rs` file, no migration, no build manifest
and no prior `spdd/` artefact. Every concept below is therefore **new**, and the
analysis is grounded in the project's recorded architectural decisions rather than
in existing code. The stack is fixed by those decisions: Rust, single binary,
async tasks, traits as ports, `thiserror` error enums, `tracing` for
observability, Turso for storage (not on the hot path), Leptos for the UI (a
compile-time Cargo feature, out of scope here).

### Existing Concepts (from codebase)

*None in code.* The following exist as **committed architectural commitments** from
prior phases and constrain this phase's shape:

- **`styx-proto` (phase 1, exists by the time this phase starts)**: the wire codec —
  message encode/decode, name compression both ways, compression-pointer loop
  detection, EDNS(0) OPT. Shared foundation; every crate in the workspace parses
  through it, including this phase's listeners and request pipeline. It is the one
  explicit exception to the "feature crates never depend on each other" rule.
- **Workspace layering convention (phase 0)**: one crate per feature, with
  `domain` / `application` / `infrastructure` as **modules inside that crate**.
  Cargo enforces feature-to-feature isolation; arch-lint enforces layering within a
  crate, by path glob, on the syn engine. Ports are declared in a consumer crate's
  `domain`; adapters are wired in the `styx` binary.
- **The gate (phase 0)**: formatting, 15 denied clippy lints workspace-wide (notably
  `indexing_slicing`, `arithmetic_side_effects`, `panic`, and no-unwrap/expect
  outside tests), `arch-lint check`, the `cargo tree` layering gate, the
  `hickory-dev-only` check, socket-level tests, and the `--no-default-features`
  headless build. Everything this phase produces must pass it.

### New Concepts Required

#### Transport and server loop

- **UDP listener**: business purpose — accept datagram queries on a configured
  address, the overwhelming majority of real DNS traffic. Relates to the request
  pipeline as its producer, and to the TC bit as the reason a response may not fit.
- **TCP listener**: business purpose — accept stream queries (two-byte length
  prefix per message), serving both clients that start on TCP and clients
  retrying after a truncated UDP answer. Peer of the UDP listener; both feed one
  pipeline.
- **Truncation / TC-bit policy**: business purpose — when a response exceeds the
  advertised UDP payload size (EDNS(0) OPT if present, else the 512-byte classic
  limit), emit a truncated response with TC set so the client retries over TCP.
  This is the *server* half of TCP fallback and the only part of fallback styx
  owns on the inbound side; the client's retry is the other half and is what the
  socket tests must exercise.
- **Listener set / bind configuration**: business purpose — listen addresses come
  from the TOML file, never from the database, because **config has two stores with
  a hard boundary: the file owns infrastructure, the DB owns policy.** The file
  owns everything needed before the DB exists or in order to reach it — listen
  addresses, upstreams and pools, selection strategy, TLS material, trust anchor,
  DB path, log mode. No overlap means no precedence rule, and it structurally
  guarantees that a dead DB cannot touch resolution. For this phase the practical
  consequence is that a listener must be bindable on an **ephemeral port** so tests
  can run many servers concurrently without port collisions.
- **Request context**: business purpose — the per-query unit of work that travels
  the pipeline: the decoded query, the client identity (source address; **clients
  are identified by IP plus optional manual naming**, since a DHCP server is a
  non-goal and styx never owns the lease table), the transport it arrived on, the
  maximum response size that transport and EDNS allow, and the accumulating
  decision record that the query-log observer will read. Owns the lifecycle of one
  query from accept to response-written.
- **Resolution decision / answer provenance**: business purpose — records *which
  pipeline stage produced the answer* (local record, block, cache hit, upstream)
  and therefore whether the answer is forged. This is what makes "clear AD, forge
  no signature, never cache" enforceable at one place rather than scattered
  across four future call sites. It is also the field the query-log rollups bucket
  on.
- **Supervised task model**: business purpose — listeners and background work run as
  async tasks that are supervised rather than fire-and-forget, because in a single
  process a panic anywhere can take DNS down for the whole house. The lint
  (`panic = "deny"`) helps; the real mitigations are a supervised task model and a
  `catch_unwind` boundary around the web layer — and the `catch_unwind` boundary
  is phase 12, so **everything before it relies on the lint and on task
  supervision**.

#### Time

- **`Clock` port**: business purpose — every place that reads "now" does so through
  an injected abstraction: TTL arithmetic and expiry in the answer cache, SRTT
  decay and circuit-breaker timing in the upstream pool, idle-window probe
  decisions, RRSIG inception/expiration comparison in the validator, rollup bucket
  boundaries in the query log, and timeouts in the server loop itself. Relates to
  everything downstream; **it is introduced in this phase precisely because it
  cannot be added later.** Two implementations: a system clock for production and a
  controllable test clock for the harness.

#### Hot-path ports (declared now, implemented later)

- **`FilterPolicy` port**: business purpose — answers "for this client and this
  question, is the verdict allow or block, and under which blocked-reply mode".
  Declared in the resolution crate's `domain`; the concrete matcher lands in
  **phase 8 — Filtering** and is wired by an adapter in the `styx` binary. Declared
  now because the cross-feature rule forbids `styx-resolution` from naming
  `styx-filtering`, and because a port bolted onto a finished hot path is a
  rewrite of that hot path.
- **`LocalRecords` port**: business purpose — answers "is there an operator-defined
  A/AAAA/CNAME/PTR record for this name", consulted **ahead of the answer cache and
  ahead of any upstream**. Backed by Turso rows in **phase 9 — Storage**, editable
  in the UI in phase 11. Its answers are forged, so they clear AD, carry no
  signature, and never enter the answer cache.
- **Query-log observer port**: business purpose — receives the outcome of every
  query on the response path. Splits into two obligations that must not be
  conflated: **rollup counters incremented synchronously via atomics** (never
  queued, never dropped — exactness is the point), and **raw rows plus the live
  ring pushed through a bounded channel** that drops when full and exposes
  `dropped_detail`. Implemented in **phase 10 — Query log pipeline**; the shape has
  to exist now because the synchronous half sits *on* the response path, not beside
  it.
- **No-op implementations of all three**: business purpose — the resolver must be
  fully runnable and fully testable in this phase with nothing behind the ports.
  `FilterPolicy` returns "allow" for every question; `LocalRecords` returns "no
  local record"; the observer discards. They are the default wiring until phases 8,
  9 and 10 replace them, and they are what makes the socket tests in phases 3–7
  possible before the product half exists.

#### Test harness

- **Fake authoritative server**: business purpose — an in-process DNS server,
  **encoding its responses with `hickory-proto`**, bound to an ephemeral port and
  driven over a real socket. It serves a scripted zone so tests can assert exact
  wire behaviour.
- **Fake root and fake TLD servers**: business purpose — the same machinery
  configured to return **referrals** rather than answers, so that phase 5's
  recursive descent has a delegation chain to walk. Declared and built now, even
  though nothing in this phase descends, because the harness is the deliverable
  that phases 3 through 7 are written against.
- **Test clock**: business purpose — the controllable `Clock` implementation the
  harness hands to the server under test, allowing time to be advanced
  deterministically. Non-negotiable for phase 4's TTL expiry, phase 3's circuit
  open/close, and phase 6's signature validity windows.
- **Ephemeral-port server fixture**: business purpose — boot a full styx server on
  port 0, hand the test its actual bound address, run real UDP/TCP against it, and
  tear it down. This is the shape of *every* feature test in the project.

### Conceptual Relationships

- One **listener set** (UDP + TCP) produces **request contexts**; one **request
  pipeline** consumes them and produces responses; the listener writes the response
  back over the transport it came in on.
- The pipeline consults, **in this fixed order**: `LocalRecords` → `FilterPolicy` →
  answer cache → upstream. The first three are short-circuits; only the last does
  I/O over the network.
- The **`Clock`** is a dependency of the pipeline and of everything the pipeline
  later grows (cache, pool, validator). It is injected at construction, never read
  from a global.
- The **query-log observer** is consulted at the *end* of the pipeline, on the
  response path, and reads the **resolution decision** recorded by whichever stage
  answered.
- The **harness** owns the fakes and the test clock, and boots the real server as a
  black box: it never reaches inside. Tests assert on bytes over sockets, not on
  internal state.
- **Ownership boundary**: the resolution crate owns the pipeline, the request
  context and the three port *declarations*. The `styx` binary owns the wiring —
  it is the only place that knows both a port and its implementation. The harness
  lives in test code and is the only place `hickory-proto` may appear.

### Key Business Rules

- **Pipeline order is fixed and is a correctness property, not a detail**: local
  records → filter → cache → upstream. It governs the request pipeline, `LocalRecords`,
  `FilterPolicy` and the answer cache. *Why this order:* local records must win over
  everything so an operator's override of a public name actually takes effect;
  filtering must precede the cache because the cache is **global, keyed
  `(qname, qtype, qclass)`, with group policy applied as a filter over the
  resolution result on the way out** — there are no per-group cache namespaces,
  since N groups would multiply memory and shred the hit rate the cache exists to
  provide; and both short-circuits must precede the upstream so a blocked or
  locally-answered name never generates outbound traffic.
- **Filtering is applied before validation, and a block is not a validation
  verdict.** This governs the interaction between `FilterPolicy` and the future
  validator. *Why:* the validator hard-fails bogus answers with SERVFAIL, and if a
  block were allowed to look like a validation outcome the two would be
  indistinguishable to a client. Pi-hole never resolved this interaction and ships
  the breakage as bug reports.
- **Forged answers clear AD and forge no signature, ever.** Governs local records
  and all five future blocked-reply modes (`NXDOMAIN` — the default here —, `NULL`
  i.e. `0.0.0.0`/`::` which is Pi-hole's default, `NODATA`, `IP`, and
  `IP-NODATA-AAAA`). *Why:* setting AD on a fabricated answer, or forging an RRSIG,
  is lying to a validating client in a way it cannot detect. *Accepted
  consequence, taken with eyes open:* a client validating with CD=0 gets an
  unsigned answer for a signed name. **That is a deliberate lie, and it is
  documented as one.**
- **Forged answers never enter the answer cache.** Governs `LocalRecords`,
  `FilterPolicy` and the cache. *Why:* the cache is global and shared across all
  clients and groups, so admitting a per-client block verdict or a local override
  into it would leak one client's policy into another client's answers.
- **The hot path touches no I/O.** Governs the whole pipeline. Matcher state is in
  memory, built at boot and on reload; Turso holds config, adlist definitions,
  clients/groups and history only. *Why:* **a DB outage must degrade logging and
  admin, never resolution.** For this phase the rule is enforced structurally — the
  no-op ports do nothing at all — and by the `no-sync-io` arch-lint rule from phase 0.
- **Rollup counters are synchronous and exact; detail is bounded and droppable.**
  Governs the observer port's shape: it must have a synchronous, infallible
  counter-increment obligation and a separate, lossy detail obligation. *Why:* if
  the dashboard's numbers can be dropped, the dashboard can lie, and there is no
  way for a reader to tell. The bounded detail channel's `dropped_detail` counter
  makes the lossy half honest about its losses.
- **Time is read only through the injected `Clock`.** Governs every component from
  this phase forward. *Why:* RRSIGs carry inception and expiration timestamps, so a
  recorded signature fixture expires on a date nobody chose; without injected time
  the DNSSEC suite rots and starts failing for calendar reasons. Retrofitting time
  injection into a validator is a rewrite, not a refactor.
- **`hickory-proto` is `[dev-dependencies]` only.** Governs the harness. *Why:* if
  styx's own codec encodes the fixtures, the resolver and its oracle share every
  bug and a green suite proves only self-consistency. A CI check asserts it appears
  in no normal or build dependency path.
- **Feature crates never name each other.** Governs the three port declarations:
  each is declared in the consumer's `domain` module and implemented by an adapter
  in the `styx` binary. `styx-proto` is the single explicit exception, since every
  crate parses through the wire codec.
- **Client identity is by source IP, best-effort.** Governs the request context.
  *Why:* a DHCP server is a non-goal; styx never owns the lease table. *Accepted
  consequence:* per-client groups keyed on IP will silently misattribute after a
  lease change. Manual naming and a visible "last seen" are mitigations, not fixes.

### Non-goals that bear on this phase

- **DoQ (DNS-over-QUIC, RFC 9250)**, inbound or outbound — so the listener
  abstraction needs to accommodate UDP, TCP and (in phase 7) TLS/HTTP-2, but not
  QUIC.
- **EDNS Client Subnet (RFC 7871)** — deliberately omitted; it leaks client
  topology. The EDNS(0) OPT handling in this phase must not grow an ECS option.
- **Authoritative zone serving** — local records and per-zone overrides are
  resolution/filtering concerns, not a zone-file server. This is what bounds
  `LocalRecords` to a lookup port over A/AAAA/CNAME/PTR rather than a zone engine.
- **Multi-node or replicated deployment** — one box, one binary, local DB file. No
  clustering concerns in the listener or state model.
- **Multi-user admin, roles, audit trail** — irrelevant to this phase except that
  the query-log observer has no actor field to carry.

---

## Strategic Approach

### Solution Direction

Build the **skeleton that every later phase is written against**, and deliberately
leave it hollow. Concretely, three things ship together and only make sense
together:

1. **A running server.** UDP and TCP listeners bound on a configurable (and, for
   tests, ephemeral) address, decoding with `styx-proto`, assembling a request
   context, running it through a pipeline whose stage order is fixed and
   asserted, and writing a response back on the arrival transport with correct
   truncation behaviour. The pipeline terminates in a stub where the upstream will
   later be, so the phase can answer *something* by hand for `dig` to see.

2. **Three declared ports with no-op bodies, plus an injected `Clock`.** The seams
   that cannot be cut later. The `Clock` because time injection into a validator is
   a rewrite; the three hot-path ports because each of them sits *on* the hot path,
   and a port introduced after four more phases have been built on top of the
   pipeline means rewriting the pipeline, the cache interaction and the response
   path at once. Their cost now is a trait, a no-op struct and a wiring line; their
   cost later is the product half rewriting the resolution half.

3. **The harness.** In-process fake root, TLD and authoritative servers, built on
   `hickory-proto`, bound to ephemeral ports, driven over **real sockets** — not
   in-memory channels. Plus the controllable test clock and the
   boot-a-server-on-port-0 fixture. This is the deliverable that phases 3 through 7
   actually consume; the running server is almost a side effect of being able to
   test one.

Data flow, in the project's idiom: *socket → decode (`styx-proto`) → request
context → `LocalRecords` (no-op) → `FilterPolicy` (no-op) → cache slot (absent
until phase 4) → upstream slot (absent until phase 3) → response assembly with
AD/TC/size rules → query-log observer (no-op) → encode → socket.* Errors are
`thiserror` enums returned as `Result<T, E>` and mapped to DNS RCODEs at the
pipeline boundary; there is no unwinding path, because `panic` is a denied lint
and its real `catch_unwind` mitigation does not arrive until phase 12.

Conventions leveraged: the crate-per-feature layout with `domain` /`application` /
`infrastructure` as **modules inside the crate**; traits as ports declared in the
consumer's `domain`; adapters wired only in the `styx` binary; `thiserror` error
enums; `tracing` for structured logging; async tasks under supervision; and the
phase 0 gate (15 denied clippy lints, arch-lint's syn engine, the `cargo tree`
layering gate, the `hickory-dev-only` check, the `--no-default-features` headless
build) as the definition of "done" for every commit.

### Key Design Decisions

- **Introduce the `Clock` as an injected port now rather than when the validator
  needs it.** *Trade-offs:* it threads an extra dependency through every
  constructor from day one, and production code pays an indirection to read a
  timestamp. Against that, it is the only thing that makes TTL expiry, circuit
  breakers and signature-validity tests deterministic. → **Recommendation: do it
  now, unconditionally.** RRSIGs carry inception and expiration timestamps, so any
  recorded signature fixture expires on a date nobody chose; without injected time
  the DNSSEC suite rots on the calendar. Retrofitting time injection into a
  validator is a rewrite, and by phase 6 the validator is the most intricate code
  in the project — the worst possible place to attempt one.

- **Declare `FilterPolicy`, `LocalRecords` and the query-log observer now, with
  no-op implementations, even though nothing implements them for six more phases.**
  *Trade-offs:* three traits whose real requirements are not fully known yet, which
  risks guessing a shape that phases 8–10 want to change; and six phases of dead
  code that the lint gate still has to be happy with. Against that: all three sit
  **on** the hot path, not beside it. → **Recommendation: declare all three.** The
  alternative is that the product half rewrites the resolution half — a port added
  after the cache, the pool, the recursor and the validator have been layered onto
  the pipeline means touching all of them. The shape risk is real but small,
  because the *obligations* are already pinned by decisions: `FilterPolicy` returns
  a verdict per (client, question); `LocalRecords` returns an optional forged
  answer; the observer has one synchronous exact-counter obligation and one bounded
  lossy-detail obligation.

- **Fix the pipeline order as a tested property, not a convention.** *Trade-offs:*
  asserting stage order in tests constrains later refactoring, and with no-op
  ports the assertions have to be about observable effects (e.g. no outbound
  traffic, nothing cached) rather than about calls. → **Recommendation: fix it and
  test it.** The order local records → filter → cache → upstream is what makes the
  cache safe to keep global: policy is applied on the way out, so no group's
  verdict is ever stored. Get the order wrong and the bug is a cross-client policy
  leak that no unit test will catch.

- **Give forged answers a single construction point that clears AD, forges no
  signature and marks the answer uncacheable.** *Trade-offs:* a small amount of
  indirection for what looks like two lines of flag-setting. → **Recommendation: do
  it.** There will eventually be **six** forged-answer paths — local records plus
  five blocked-reply modes — and each must be proven to clear AD and forge no
  signature. Five blocking modes multiply the validator interaction surface;
  **this is exactly the kind of plural that hides an untested combination.** One
  construction point turns six proofs into one plus five thin ones.

- **Drive the harness over real sockets rather than in-memory transports.**
  *Trade-offs:* slower tests, ephemeral-port management, occasional flakiness from
  the OS network stack, and the need to bind in CI. → **Recommendation: real
  sockets.** In-memory transports silently skip the parts most likely to be wrong:
  datagram size limits, truncation and TCP fallback, the TCP length prefix, partial
  reads and connection reuse. The exit criterion — "`dig @127.0.0.1 -p <port>`
  works by hand" — is only meaningful if the test path and the `dig` path are the
  same path.

- **Encode all harness fixtures with `hickory-proto`, and keep it out of the
  shipping dependency graph by CI check.** *Trade-offs:* a second DNS
  implementation in the dev tree, and the discipline of never letting it leak.
  → **Recommendation: keep it, and enforce the boundary mechanically.** If styx's
  own codec encodes the fixtures, the resolver and its oracle share every bug and a
  green suite proves only self-consistency. The `hickory-dev-only` check exists
  because an exception that is only a convention rots into a real dependency.

- **Build fake root and TLD servers now, before anything descends.** *Trade-offs:*
  building referral machinery that nothing in this phase exercises. →
  **Recommendation: build them now.** They are the reason this phase is called "and
  test harness". Phase 5's recursion is written against them, and discovering in
  phase 5 that the harness cannot express a delegation stalls the hardest phase in
  the project on tooling work.

- **Structure the server as supervised async tasks from the start.** *Trade-offs:*
  more machinery than a bare accept loop needs today. → **Recommendation: do it.**
  In a single process, a panic in one task can take DNS down for the whole house,
  and the `catch_unwind` boundary that really mitigates this is phase 12 —
  everything before it relies on the `panic = "deny"` lint plus task supervision.
  Retrofitting supervision after seven phases of tasks have accumulated is the
  expensive version.

- **Keep listen addresses in the TOML file, never in the database.** *Trade-offs:*
  changing a listener requires SSH and a restart. → **Recommendation: file only.**
  The file owns infrastructure, the DB owns policy, and there is no overlap — so
  there is no precedence rule to get wrong, and a dead DB structurally cannot touch
  resolution because nothing resolution needs lives there. *Accepted consequence,
  recorded at project level:* changing an upstream requires SSH and a restart,
  which is the thing people most want to do from the UI.

### Alternatives Considered

- **Add the `Clock` when the cache or the validator needs it (phase 4 or 6).**
  Rejected: time injection cannot be retrofitted into a validator; it is a rewrite,
  and it would be attempted inside the fiddliest code in the project.
- **Add `FilterPolicy` in phase 8 and `LocalRecords` in phase 9, where they are
  implemented.** Rejected: both sit on the hot path. Introducing them after the
  cache, pool, recursor and validator are layered on means the product half
  rewrites the resolution half — the exact failure the phase spec names.
- **Let `styx-resolution` depend on `styx-filtering` directly instead of declaring a
  port.** Rejected: feature crates never depend on each other. Cross-feature needs
  are ports in the consumer's `domain`, wired by an adapter in the binary; Cargo
  enforces the isolation and arch-lint's `[[restrict-use]]` enforces the naming.
- **Per-group answer caches, which would remove the need to apply policy on the way
  out.** Rejected at project level: N groups multiply memory and shred the hit rate
  the cache exists to provide. The cache stays global, keyed
  `(qname, qtype, qclass)`, and policy is a filter over the result — which is
  precisely why filter must sit *before* cache in the pipeline order fixed here.
- **In-memory / channel-based test transport instead of real sockets.** Rejected:
  it skips truncation, TCP fallback, the TCP length prefix and datagram limits —
  the behaviours this phase exists to get right.
- **Encode harness fixtures with styx's own codec, avoiding the `hickory-proto` dev
  dependency.** Rejected: the resolver and its oracle would share every bug, and the
  suite would prove only self-consistency.
- **Defer the fake root/TLD servers to phase 5, building only a fake authoritative
  server now.** Rejected: it moves harness work into the recursion phase, which is
  already one of the two hardest phases.
- **Skip the no-op implementations and leave the ports unimplemented until phase
  8.** Rejected: the server would not run or be testable in phases 2–7, which is
  the entire point of the harness.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **"The request pipeline skeleton" — how much of the pipeline exists?** The spec
  fixes the *order* of four stages but three of them are no-ops and the fourth (the
  upstream) does not exist until phase 3. Needs clarification: what does the server
  actually answer during this phase so that the "`dig` works by hand" exit
  criterion is satisfiable? A hard-coded stub answer and/or an explicit
  `REFUSED`/`SERVFAIL` terminal are the candidates; the choice must be made
  explicitly because the socket tests assert on it.
- **The `Clock`'s granularity and surface are unspecified.** Whether it exposes
  wall-clock time (needed for RRSIG inception/expiration comparison), monotonic
  time (needed for SRTT and circuit timers), or both, is not stated. Getting this
  wrong is the one way the "cannot be retrofitted" risk still bites: a `Clock` that
  exposes only one of the two will be widened in phase 6 anyway.
- **The query-log observer's two halves are not separated in the phase spec.** The
  requirement says "the query-log observer that decision 25 needs for synchronous
  rollup counters", but that decision has two distinct obligations — synchronous
  exact atomics, and a bounded lossy detail channel. Whether the port is one trait
  with two methods or two ports is undecided, and it determines whether the
  "never dropped" guarantee is expressible in the type.
- **`FilterPolicy`'s verdict vocabulary is not fixed here.** Whether the port
  returns a plain allow/block or a fully-formed blocked reply is undecided.
  Phase 8's blocked-reply construction — five modes, NODATA for non-A/AAAA qtypes,
  short TTL — has to land somewhere, and the split between "the filter decides" and
  "the pipeline forges" determines whether the AD-clearing proof lives in one place
  or five.
- **Client identification detail.** The request context carries a source IP, but
  what happens for an unknown client is explicitly undefined at project level:
  *client lifecycle is undefined — nothing says how a client comes into existence
  (auto-discovered on first query vs. added by hand), what group an unknown client
  lands in, or what happens to history rows when a client or group is deleted.* It
  is settled in phase 9 because it is schema, but this phase must choose a
  placeholder representation that phase 9 will not have to break.
- **Listener configuration shape.** The spec says "ephemeral port" for tests but
  does not state how many listeners, on how many addresses, are supported in
  production (one per address? dual-stack? a list?). It comes from TOML, but the
  structure is unspecified.
- **EDNS(0) handling depth.** `styx-proto` provides OPT, and truncation depends on
  the advertised UDP payload size, but whether this phase honours a client's
  advertised size, echoes an OPT, or handles EDNS version negotiation (BADVERS) is
  unstated.

### Edge Cases

- **A response that exceeds the advertised UDP payload size.** The TC bit must be
  set and the response trimmed to something legal — which raises "trimmed how":
  question-only, or answer-section-truncated. This is the core behaviour of the
  phase and is not spelled out.
- **A client that sends a query over TCP without ever trying UDP.** Must work
  identically; TCP is not merely a fallback path.
- **A TCP connection carrying multiple queries, or a partial length-prefixed read
  split across packets.** The two-byte length prefix means stream framing, which is
  a class of bug that in-memory transports never surface.
- **A malformed or truncated query.** `styx-proto` returns an error; the pipeline
  must map it to `FORMERR` and still answer, because a client that gets no answer
  retries and amplifies the problem. Under `indexing_slicing = deny` and
  `arithmetic_side_effects = deny` every offset is checked, so the error path is
  well-populated and must be exercised.
- **A query with an unsupported opcode, class, or a qtype styx does not know.**
  `NOTIMP` versus `REFUSED` versus pass-through is a choice with client-visible
  consequences.
- **A query with QDCOUNT of 0 or greater than 1.** Real resolvers see both from
  scanners.
- **EDNS(0) present with a payload size below 512, or absent entirely.** The
  truncation threshold differs and both must be tested.
- **A local record that would also be blocked.** With local records first, the local
  record wins and the filter never runs — this is a direct consequence of the fixed
  order and should be asserted, not assumed.
- **A local name under a signed public zone.** *Accepted project-level consequence:*
  `nas.example.com` where `example.com` is signed is unprovable, and validating
  clients may SERVFAIL it. The documented guidance is to keep local names under an
  unsigned or internal suffix. This is precisely the failure reported as
  pi-hole#2686, and the expectation recorded at project level is to **diagnose it at
  least once on your own network**, because the mitigation is documentation and
  documentation only helps people who read it.
- **Concurrent queries arriving faster than the pipeline drains.** Bounded channels
  and task supervision have to behave; the observer's detail channel is explicitly
  allowed to drop, but the synchronous counters are not.
- **Server shutdown with in-flight queries.** Listener teardown must not hang, or
  every test that boots an ephemeral server leaks one.
- **Two tests binding servers at the same moment.** Ephemeral ports make this safe
  only if the fixture reads back the *actual* bound address rather than guessing.

### Technical Risks

- **The `Clock` surface is the one irreversible decision in this phase.** *Impact:*
  a `Clock` that models only monotonic or only wall-clock time gets widened in
  phase 6, which is the retrofit this phase exists to prevent. *Mitigation
  direction:* model both explicitly from the start, and have the test clock control
  both independently.

- **The three port shapes are guessed six phases ahead of their implementations.**
  *Impact:* phases 8–10 want a different signature and the hot path changes anyway.
  *Mitigation direction:* keep each port's obligation minimal and grounded in an
  already-settled decision (verdict per client+question; optional forged answer;
  exact-counter + lossy-detail), and treat any widening as a signal to re-check the
  pipeline order rather than as routine.

- **Phase 0's gate may be silently inert.** *Impact:* every lint and layering rule
  this phase relies on could be checking nothing. The committed `arch-lint.toml` is
  the upstream Kotlin template: it contains `[[layers]]`, which routes arch-lint to
  its tree-sitter engine; that engine ships exactly one grammar
  (`tree-sitter-kotlin-ng`) and filters discovery to `.kt`/`.kts`, so **on a Rust
  repo it analyses zero files and exits 0** — silently disabling AL001–AL013 as
  well. Without `[[layers]]` the syn engine runs AL001–AL013 plus `[[scopes]]`,
  `[[deny-scope-dep]]` and `[[restrict-use]]`, which enforce layering on Rust by
  path glob. *Mitigation direction:* phase 0 replaces the file and pairs it with an
  independent `cargo tree` gate (arch-lint reads source text, `cargo tree` reads the
  link graph), and verifies with a **deliberate violation** — because **an inert
  config looks identical to a passing one.** This phase should not assume the gate
  is live without having seen a deliberate violation fail.

- **`panic = "deny"` is load-bearing and its real mitigation arrives in phase 12.**
  *Impact:* in a single process, a panic in any task can take DNS down for the whole
  house, and the `catch_unwind` boundary is ten phases away. *Mitigation direction:*
  supervised tasks from this phase forward; no `unwrap`/`expect` outside tests
  (enforced by arch-lint's `no-unwrap-expect` with `allow_in_tests = true`); every
  fallible path an explicit `Result` with a `thiserror` enum.

- **Hand-written wire handling under `indexing_slicing = deny` and
  `arithmetic_side_effects = deny`.** *Impact:* every offset and every TTL
  decrement becomes a checked operation, making the code verbose and the error
  surface wide. That is the intended tax, but it lands in this phase too — the TCP
  length prefix and the truncation size arithmetic are both affected. *Mitigation
  direction:* centralise the size arithmetic at the response-assembly point rather
  than spreading it through the listeners.

- **Socket-level tests are inherently slower and occasionally flaky.** *Impact:*
  the per-push gate includes socket tests, so flakiness there erodes the gate's
  credibility. *Mitigation direction:* ephemeral ports read back from the OS,
  bounded timeouts driven by the injected clock where possible, loopback only, and
  no reliance on external network (the live-internet differential run is a
  per-phase gate for recursion and DNSSEC, deliberately never a per-push one —
  *real DNS changes underneath the corpus, so it will sometimes fail for reasons
  that are not a bug, and a genuine regression can hide behind a shrug*).

- **`hickory-proto` leaking into the shipping graph.** *Impact:* the from-scratch
  commitment is quietly broken and the oracle stops being independent. *Mitigation
  direction:* the `hickory-dev-only` CI check from phase 0, asserting it appears in
  no normal or build dependency path.

- **The `--no-default-features` headless build.** *Impact:* the web UI is a
  compile-time Cargo feature (`web`, default on) so a headless resolver can be
  built; **CI builds and tests `--no-default-features` on every commit, or the
  headless build rots within a month.** Anything this phase adds must compile in
  both configurations.

- **No feedback loop for this phase or the six after it.** *Impact:* **phases 1
  through 7 produce nothing a human can look at except `dig` output**, and because
  the cutover is last, nobody is waiting on it either — the scope risk is
  concentrated into one long stretch with neither visible progress nor external
  pressure. *Mitigation direction:* the exit criterion "`dig @127.0.0.1 -p <port>`
  works by hand" is the only human-visible artefact this phase produces and should
  be treated as a real deliverable, not a formality. This is the accepted cost of
  not doing a live migration under two hand-written security-critical subsystems.

- **Harness expressiveness may fall short of phase 5.** *Impact:* recursion stalls
  on tooling. *Mitigation direction:* build the referral path (root → TLD → auth) in
  this phase and prove at least one hand-driven delegation walk over sockets, even
  though nothing in styx descends yet. Note also that *in-process fakes only prove
  the resolver does what we think delegation means* — the live differential run
  against `unbound` is the only gate that catches a shared misreading, and it is a
  per-phase gate for phases 5 and 6, not this one.

### Acceptance Criteria Coverage

The phase spec states two exit criteria. They are decomposed below against the
scope bullets they must cover.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | **Socket-level tests green against the fakes** — UDP and TCP listeners on an ephemeral port, TC bit and TCP fallback, request pipeline skeleton, exercised over real sockets against in-process fake root/TLD/authoritative servers built on `hickory-proto`. | Yes | Requires deciding what the pipeline answers while the upstream stage does not exist (phase 3). Truncation semantics (how a too-large response is trimmed) and EDNS(0) payload-size honouring must be pinned before the tests can assert. |
| 2 | **`dig @127.0.0.1 -p <port>` works by hand** — a human can query a running styx and get a well-formed response. | Yes | Same dependency as AC1: there must be *something* to answer. Also implies the production (non-test) bind path from TOML works, not just the port-0 test fixture. This is the only human-visible output of the phase. |
| 3 | *(implicit in scope)* **The injectable `Clock` exists and the harness can control time.** | Yes | Not stated as an exit criterion but explicitly "cannot be retrofitted later". Recommend an explicit criterion: a socket test whose outcome depends on advancing the test clock. Otherwise the `Clock` can ship unexercised and its inadequacy (wall-clock vs monotonic) is discovered in phase 6. |
| 4 | *(implicit in scope)* **`FilterPolicy`, `LocalRecords` and the query-log observer are declared with no-op implementations, in the consumer's `domain`, wired in the `styx` binary.** | Partial | No exit criterion asserts them. Recommend: arch-lint/`cargo tree` prove no feature-crate cross-dependency, plus a test that swaps a no-op for a test double and observes the pipeline honour it — which also proves the ports are genuinely injectable rather than decorative. |
| 5 | *(implicit in scope)* **Pipeline order local records → filter → cache → upstream is fixed and enforced.** | Partial | Stated as a correctness property with no criterion attached. With no-op ports, order must be asserted via observable effects: a test double at the local-records seat short-circuits before the filter double is consulted, and nothing produced by either seat is cached or carries AD. Recommend making this an explicit exit criterion. |
| 6 | *(implicit in scope)* **Forged answers clear AD, forge no signature, never enter the answer cache.** | Partial | The cache does not exist until phase 4 and the validator until phase 6, so this can only be established as a *structural* property here — one forged-answer construction point, asserted to clear AD and attach no RRSIG, and marked uncacheable. The five blocked-reply modes are proven against it in phase 8; the validator interaction in phase 6. Recommend asserting the construction point now, since five modes later is exactly where an untested combination hides. |
| 7 | *(implicit, inherited)* **Everything passes `just gate`**: formatting, the 15 denied clippy lints, `arch-lint check`, the `cargo tree` layering gate, the `hickory-dev-only` check, socket tests, and the `--no-default-features` headless build. | Yes | Depends on phase 0 having replaced the inert `arch-lint.toml` and verified it with a deliberate violation. If that verification was skipped, this AC is vacuous. |

**Coverage summary:** 2 stated exit criteria, both addressable; 5 further scope
commitments are implicit and 4 of them (3, 4, 5, 6) currently have **no criterion
attached**. The recommendation carried into the REASONS Canvas is to promote those
four into explicit, testable safeguards, because each one is an
irreversible-if-wrong property — injected time, hot-path port shape, pipeline
order, and forged-answer honesty — and all four are cheap to assert now and
expensive to discover later.
