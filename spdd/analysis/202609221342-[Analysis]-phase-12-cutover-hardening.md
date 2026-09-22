# SPDD Analysis: Phase 12 — Cutover hardening

> **Self-contained document.** The design record this analysis was derived from,
> and the per-phase specification files alongside it, are being retired once it is
> written. Every decision, rationale, accepted consequence, non-goal and risk that
> bears on this phase is reproduced here in full. Nothing in this document defers
> to an external file.

---

## Project Context (carried forward, verbatim in substance)

**styx** is a filtering DNS resolver written from scratch in Rust. It replaces
Pi-hole's role on a home network: recursive/forwarding resolution, per-client
blocking policy, and a Leptos admin UI.

It is explicitly a build-it-properly project, not a ship-it-this-quarter project.
v1 contains two hand-written security-critical subsystems (a recursive resolver
and a DNSSEC validator), so the repo optimises for a long correctness grind:
spec-first, socket-level behaviour tests, aggressive lints, CI from the first
commit.

**Codebase state: greenfield, no existing implementation.** At the time of this
analysis the repository contains no git history, no Cargo workspace, no
`Cargo.toml`, and no Rust source of any kind. The only tracked artefacts are the
specification documents and an `arch-lint.toml` that is the upstream Kotlin
template and enforces nothing (its `[[layers]]` key routes arch-lint to a
tree-sitter engine that ships only a Kotlin grammar, therefore discovers zero
`.rs` files, and exits green having checked nothing). Replacing that file is the
job of Phase 0. Consequently, every statement below about "existing concepts",
architecture conventions and layering is grounded in the project's recorded
design decisions rather than in read source code, and is flagged as such.

### Phase position and dependencies

Phase 12 is the **last** phase of twelve. The full ordering is:

| # | Phase | Delivers |
|---|-------|----------|
| 0 | Foundation and gates | Workspace, working arch-lint, CI, the `just gate` target |
| 1 | Wire codec | `styx-proto` — encode/decode, fuzzed |
| 2 | Server loop and test harness | UDP/TCP listeners, fake root/TLD/auth servers, injectable `Clock`, hot-path ports |
| 3 | `Upstream` port, forwarding, pool | Do53 forwarder, `HealthState`, all four selection strategies |
| 4 | Answer cache | Global RRset/message cache, negative caching, bailiwick rules |
| 5 | Recursion | `styx-recursion` — descent with relaxed QNAME minimisation |
| 6 | DNSSEC | `styx-dnssec` — positive chains, NSEC/NSEC3 denial, hard-fail |
| 7 | Encrypted inbound | DoT and DoH listeners, operator-supplied certs |
| 8 | Filtering | Matcher, allow/block precedence, blocked replies, adlist ingestion |
| 9 | Storage | Turso schema — policy only, designed once |
| 10 | Query log pipeline | Exact rollups, bounded detail channel, privacy modes |
| 11 | Web UI | `styx-web` — auth, dashboard, groups, adlists |
| **12** | **Cutover hardening** | **Panic boundary, musl artifacts, then the household** |

**Phase 12 depends directly on:**

- **Phase 0 — Foundation and gates.** Supplies the Cargo workspace shape; the
  working syn-engine `arch-lint.toml` with `[[scopes]]` per feature crate ×
  `domain`/`application`/`infrastructure`, `[[deny-scope-dep]]` layering rules
  and `[[restrict-use]]` isolation rules; the independent `cargo tree` layering
  gate; the 15 denied clippy lints workspace-wide (including the deny-level panic
  lint this phase finally backs with a runtime mitigation); the 4
  `allow-*-in-tests` entries in `clippy.toml`; lefthook pre-commit/pre-push; the
  GitHub Actions workflow whose release job this phase extends; the `just gate`
  target; and the `--no-default-features` headless build CI runs on every commit.
- **Phase 2 — Server loop and test harness.** Supplies the UDP and TCP listeners
  whose task lifetimes the supervisor must own, the in-process fake root/TLD/
  authoritative servers, the injectable `Clock`, and the socket-level test
  harness this phase uses to prove DNS keeps serving through an induced web
  panic.
- **Phase 11 — Web UI.** Supplies `styx-web`, the Leptos SSR crate whose request
  handlers are the panic source this phase must contain. Its server functions,
  session/origin checks and dashboard are the surface a `catch_unwind` boundary
  wraps. It also fixes the shape of the compile-time `web` Cargo feature, so the
  boundary must be correct in both the feature-on and feature-off builds.
- **Every phase 1 through 10, transitively.** The soak is not a unit test of this
  phase's code — it is the first sustained exercise of the whole binary: codec,
  listeners, upstream pool, answer cache, recursion, DNSSEC validation, encrypted
  inbound, matcher, storage, query-log pipeline and UI running together under
  real household traffic patterns.

**Phases that depend on Phase 12:** none. This is the terminal phase. Its output
is not consumed by a later phase; it is consumed by the household.

### Why this phase exists at the end, and what that costs

**The cutover is last.** styx runs on a dev box until everything in the
specification works; the household's resolver stays on Pi-hole until v1 is
complete. The reasoning: nothing mid-build has to be shippable, breaking changes
stay free, and phases are ordered by dependency and risk rather than usability.
**Accepted consequence: no operational feedback — cache behaviour, odd client
queries, DHCP churn — until the end, when it is most expensive to act on.**

That consequence compounds with the project's other ordering decision,
resolution-before-product. **Resolution-first plus a last cutover removes every
feedback loop.** Phases 1 through 7 produce nothing a human can look at except
`dig` output, and because the cutover is last, nobody is waiting on it either.
The already-large v1 scope risk is therefore concentrated into one long stretch
with neither visible progress nor external pressure. **This is the accepted cost
of not doing a live migration under two hand-written security-critical
subsystems.**

Both of those consequences come due *in this phase*. Everything the project chose
not to learn along the way — how the cache behaves under a real household's query
mix, which clients emit strange queries, how client identity survives DHCP churn
— arrives at once, in the soak, at the single moment when acting on it is most
expensive. Phase 12's design must therefore treat the soak not as a rubber stamp
but as the project's only integration feedback channel, and must make it cheap to
observe and cheap to abort.

---

## Original Business Requirement

Reproduced verbatim from the phase specification, with cross-document decision
references stripped (the decisions themselves are inlined in full immediately
below).

```markdown
# Phase 12 — Cutover hardening

The last phase, and the first moment the household's DNS depends on styx.

## Scope

- A `catch_unwind` boundary around the web layer and a supervised task model. In a
  single process a panic in a Leptos handler takes DNS down for the whole house.
- musl release artifacts for `x86_64` and `aarch64` on `v*` tags.
- Soak on one machine — **then** point the household at it.

## Exit criteria

A panic induced in a web handler leaves DNS serving; both musl artifacts build and
run on their targets; and a soak on one machine runs without intervention for long
enough to trust it. Only then does the household's resolver change.
```

### Governing decisions referenced above, inlined in full

These are the project-level decisions this phase implements or is constrained by.
They are reproduced here because the document that recorded them is being
deleted.

**Single process, single binary.** DNS listeners, Leptos SSR and background
workers share state via `Arc`. The web UI is a compile-time Cargo feature
(`web`, default on) so a headless resolver can be built. CI builds and tests
`--no-default-features` on every commit, or the headless build rots within a
month.

> This is the decision that creates this phase's central problem. Because
> everything is one process sharing state through `Arc`, there is no operating
> system boundary between the admin UI and the resolver. A panic in a Leptos
> request handler unwinds a task in the same process that owns the UDP and TCP
> listeners — and takes DNS down for the whole house.

**`panic = "deny"` is load-bearing.** In a single process, a panic in a Leptos
request handler takes DNS down for the whole house. **The lint helps; a
`catch_unwind` boundary around the web layer and a supervised task model are the
real mitigation.** Those two mitigations land in *this* phase, which means every
phase before it relies on the deny-level panic lint alone.

**One crate per feature; `domain`/`application`/`infrastructure` are modules
inside it.** Cargo enforces feature-to-feature isolation; arch-lint enforces
layering within a crate.

**Feature crates never depend on each other.** Cross-feature needs are expressed
as a port in the consumer's `domain`, implemented by an adapter in the binary.
`styx-web` may depend on a feature's `application` layer, because it is
presentation, not a peer.

**Lint policy as specified** — 15 denied clippy lints workspace-wide, 4
`allow-*-in-tests` entries in `clippy.toml`. All 15 names verified against rustc
1.96.0.

**CI on GitHub Actions**: quality gates on every push/PR; **release artifacts for
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` published on `v*`
tags.** Building the release artifacts is the mechanical half of this phase.

**TDD cycles run at socket level by default.** Feature tests drive real UDP/TCP
against an ephemeral-port server, with in-process fake root and authoritative
servers, and an injectable `Clock` — because RRSIGs carry inception and
expiration timestamps, so any recorded signature fixture expires on a date you
did not choose. Time injection cannot be retrofitted into a validator; it is a
rewrite.

**Acceptance runs in two tiers.** Per push, hermetic and fast: socket tests,
fuzzing, and the full lint/arch gate. Per phase, non-hermetic: a corpus of real
domains resolved through both styx and a local `unbound`, diffing RCODE, AD bit
and rrset contents. In-process fakes only prove the resolver does what we *think*
delegation means; the differential run is the only gate that catches a shared
misreading. It depends on the live internet and is flaky by nature, so it gates a
phase and never a push.

**The hot path touches no I/O.** Matcher state is in memory, built at boot and on
reload. The database holds config, adlist definitions, clients/groups and history
only. A database outage degrades logging and admin, never resolution.

> This is the property that makes a staged cutover survivable. A supervised model
> may restart the storage, query-log or web tasks without interrupting
> resolution, because resolution does not read the database on the hot path.

**Split write paths.** Rollup counters increment synchronously via atomics on the
response path — never queued, never dropped, so every dashboard number is always
exact. Only raw rows and the live ring go through a bounded channel, which drops
when full and exposes a visible `dropped_detail` counter. Dashboards cannot lie;
detail degrades gracefully.

**The root trust anchor is pinned, overridable by a file path in config.** A
compiled-in IANA anchor with a `trust-anchor` config override, behind a
`TrustAnchorSource` port. Automated RFC 5011 rollover needs state that survives
restarts, which would drag the storage layer into the validator phase for a
rollover that is pre-announced months ahead. **Accepted consequence: a KSK roll
needs a release or a file edit, and missing one SERVFAILs every lookup — this is
a monitoring obligation, not code.** RFC 5011 automated trust anchor rollover is
an explicit v1 non-goal; the `TrustAnchorSource` port is the seam it slots into
later.

> This is a standing operational obligation that this phase is the last chance to
> document, because after the cutover the household is exposed to it. A missed
> KSK roll does not degrade styx — it SERVFAILs every lookup on the network.

**Local records are answered before the cache and are always Insecure.**
A/AAAA/CNAME/PTR rows in the database, editable in the UI, matched ahead of the
answer cache and ahead of any upstream. They never enter the answer cache and
never reach the validator: AD cleared, no forged signature, same honesty rule as
a blocked reply. **Accepted consequence: a local name under a signed public zone
(`nas.example.com` where `example.com` is signed) is unprovable and validating
clients may SERVFAIL it — the documented guidance is to keep local names under an
unsigned or internal suffix.** This is precisely the failure reported as
pi-hole#2686. The mitigation is documentation, **which is a mitigation only for
people who read it.** Expect to diagnose this at least once on your own network.

**Multi-node or replicated deployment is an explicit v1 non-goal.** One box, one
binary, local database file. There is no failover peer, no second resolver to
take over during a restart, and no replication of policy state. Every availability
property this phase can offer must therefore come from within the single process:
supervision, restart, and a panic boundary. The rollback plan is not "fail over"
— it is "point the router back at Pi-hole".

**Config has two stores with a hard boundary: file owns infrastructure, database
owns policy.** A TOML file owns everything needed before the database exists or in
order to reach it — listen addresses, upstreams and pools, selection strategy,
TLS material, trust anchor, database path, log mode. The database owns everything
a human edits at runtime. The UI can change only database-backed things; file
changes need a restart. **Accepted consequence: changing an upstream requires SSH
and a restart, which is the thing people most want to do from the UI.** During a
cutover, that means every corrective action on infrastructure config is a restart,
and every restart is a DNS outage for the household.

**DoT/DoH certificates are operator-supplied, with a self-signed fallback.** The
TOML points at a cert/key path. If absent, styx generates a self-signed cert at
first boot and prints the SPKI pin once to the log. styx owns no PKI and
implements no ACME client. Accepted consequence: self-signed is usable for `curl`
and DoH clients that accept a pin, and largely unusable for DoT clients like
Android Private DNS, which want a publicly-valid name.

**Admin auth is a single password**, hashed with Argon2id in the database, seeded
from an environment variable or a generated first-boot secret printed once to the
log; signed, HttpOnly, `SameSite=Strict` session cookie plus an origin check. The
UI refuses to serve until a credential exists. Accepted consequence: no audit
trail; you can never tell who disabled blocking.

**DHCP is a v1 non-goal.** Clients are identified by IP plus optional manual
naming. styx never owns the lease table, so client identity is best-effort and
breaks on DHCP churn. Per-client groups keyed on IP will silently misattribute
after a lease change. Manual naming and a visible "last seen" are mitigations,
not fixes. This is one of the three named categories of operational feedback the
last-cutover decision deferred to this phase.

---

## Domain Concept Identification

### Existing Concepts

From prior phases. The project is greenfield, so "existing" here means
"specified and built by phases 0–11, not yet written".

- **The single process** — one binary containing DNS listeners, Leptos SSR and
  background workers, sharing state via `Arc`. It is the unit of failure this
  phase is hardening. It has no internal isolation boundary today; creating one
  is the phase's main work.
- **DNS listeners (UDP and TCP)** — from Phase 2. Long-lived async tasks bound to
  the configured listen addresses. They are the tasks whose survival defines
  "DNS is still serving". Their lifetimes currently belong to whatever spawned
  them; the supervisor must take ownership.
- **Encrypted inbound listeners (DoT and DoH)** — from Phase 7. Additional
  long-lived listener tasks with TLS state, operator-supplied or self-signed
  certificates. They are resolution-critical in the same sense as UDP/TCP and
  belong in the same supervision tier.
- **`styx-web` / Leptos SSR handlers** — from Phase 11. Request-scoped work,
  compiled in behind the default-on `web` Cargo feature. This is the panic source
  the boundary exists to contain. Presentation-tier: it may depend on feature
  crates' `application` layers, but nothing depends on it.
- **Background workers** — adlist ingestion (staged fetch, sanity checks,
  last-known-good retention, matcher rebuild and `ArcSwap` swap), the query-log
  detail-channel drain, rollup flushing, upstream health probing against idle or
  down members. All are restartable without interrupting resolution.
- **The answer cache and the infrastructure cache** — in-memory state shared via
  `Arc`. A restarted worker must not invalidate them; a restarted process loses
  them, which is an observable cold-start cost the soak must measure.
- **The matcher** — immutable, replaced wholesale via `ArcSwap`. Survives worker
  restarts by construction.
- **The exact rollup counters and the `dropped_detail` counter** — from Phase 10.
  Atomics on the response path plus a bounded channel. These are the phase's
  ready-made soak instrumentation: exact query counts and a visible drop count,
  already required to be truthful.
- **`just gate`** — from Phase 0. Formatting, the 15 denied clippy lints,
  `arch-lint check`, the `cargo tree` layering gate, the `hickory-dev-only`
  check, socket-level tests, and the `--no-default-features` headless build.
- **The GitHub Actions workflow** — from Phase 0. Quality gates on push/PR, and
  the release job that this phase must extend with the two musl targets.
- **The differential acceptance run** — a corpus of real domains resolved through
  both styx and a local `unbound`, diffing RCODE, AD bit and rrset contents.
  Non-hermetic, phase-gating. This phase runs it one final time, against the
  actual release artifact, as a pre-cutover check.
- **The injectable `Clock`** — from Phase 2. Needed here so restart backoff and
  soak-window logic are testable without waiting in real time.

### New Concepts Required (introduced by this phase)

- **Supervisor** — the component that owns the lifetime of every long-lived task
  in the process, observes each one's termination (normal return, error return,
  or panic), and applies a restart policy. It is the structural answer to "one
  process, no OS boundary": supervision is the isolation the operating system is
  not providing. It belongs in the binary crate, because it is composition — it
  wires tasks from multiple feature crates and is therefore the one place allowed
  to know about all of them.
- **Task classification / criticality tier** — the distinction between tasks whose
  death means the process is useless (the DNS listeners) and tasks whose death
  degrades a non-resolution function (web, query-log drain, adlist ingestion,
  health probing). The tier decides the restart policy and decides whether a
  repeated failure escalates to process exit. This concept only exists because
  the hot path touches no I/O: without that property, every task would be
  resolution-critical and there would be nothing to degrade to.
- **Restart policy** — how many times, how fast, and what happens when the budget
  is exhausted. It needs a backoff shape and a failure-count window, or a task
  that panics on every request becomes a restart loop that starves the runtime.
  Exhaustion has two possible terminal behaviours (shed the task and keep serving
  DNS, or exit the process) and the choice differs by tier.
- **Panic boundary (`catch_unwind` wrapper around the web layer)** — the
  per-request containment that stops a Leptos handler panic from unwinding past
  the request. Distinct from supervision: supervision catches a *task* dying,
  the boundary stops a *request* from killing anything. Both are named as the
  real mitigation; neither is sufficient alone. It must be
  `AssertUnwindSafe`-aware, must map a caught unwind to an HTTP 500 rather than a
  silent success, and must emit a `tracing` event loud enough that a soak notices.
- **Poisoned-state detection** — the reason a caught panic cannot simply be
  swallowed. A panic that unwinds through shared state can leave a `Mutex`
  poisoned or an invariant half-applied. The boundary has to distinguish "the
  request failed, state is fine" from "shared state may be inconsistent", because
  only the latter justifies escalating.
- **Shutdown coordination** — a cancellation signal and a drain deadline, so a
  supervised restart or a deliberate stop does not abandon in-flight queries,
  leave the bounded detail channel unread, or lose unflushed rollups. Required by
  the exact-counters rule: a rollup number that is lost on shutdown makes a
  dashboard lie.
- **Release target matrix** — the two musl targets, `x86_64-unknown-linux-musl`
  and `aarch64-unknown-linux-musl`, built on `v*` tags. The concept carries more
  than two triples: static linking against musl changes the allocator, the DNS
  resolver stub, and TLS behaviour, and aarch64 needs cross-compilation or a
  native runner. "Built" and "runs on its target" are two different assertions
  and the exit criterion demands both.
- **Artifact verification step** — the executable half of "both musl artifacts
  build *and run* on their targets". A cross-compiled binary that links is not a
  binary that resolves a name. The verification is a smoke run on each
  architecture: start, answer a query, exit cleanly.
- **Soak run and soak checklist** — a sustained single-machine run under
  representative traffic, with an explicit, written list of what is being watched
  and what constitutes "without intervention". Without a checklist, "long enough
  to trust it" has no content. The checklist is where the deferred operational
  feedback — cache behaviour, odd client queries, DHCP churn — is finally
  collected.
- **Cutover procedure and rollback** — the ordered steps that point the household
  at styx, and the single action that points it back at Pi-hole. Because
  multi-node deployment is a non-goal, rollback is the only availability
  mechanism above the process level, and it must be fast, documented and
  rehearsed before it is needed.
- **Standing operational obligations document** — the written record of the
  things that will bite after the cutover and that no code prevents: the pinned
  trust anchor and missed-KSK-roll failure mode, local names under signed public
  zones, and infrastructure config changes needing SSH plus a restart.

### Key Business Rules

- **DNS serving is the invariant.** A panic anywhere in the web layer must leave
  the UDP, TCP, DoT and DoH listeners answering queries. This is the phase's
  single non-negotiable property and the first exit criterion states it directly.
- **The panic boundary wraps the web layer, not the resolver.** Wrapping
  resolution in `catch_unwind` would convert a resolver bug into a silently
  wrong answer; the project's posture is that a bogus DNSSEC answer SERVFAILs
  rather than being papered over. The boundary's scope is presentation only.
- **A caught panic is never silent.** It produces an HTTP 500 and a `tracing`
  event at error level. Swallowing it defeats the soak, which is the project's
  only integration feedback channel.
- **The deny-level panic lint stays.** The boundary is a safety net, not a
  licence to panic. Both mitigations are additive: the lint prevents panics being
  written, the boundary and supervisor contain the ones that are written anyway
  (arithmetic overflow, slicing, third-party crates, allocator failure).
- **Supervision is tiered by whether resolution depends on the task.** Listener
  death is fatal to the process's purpose; web, query-log, adlist and probe task
  death is degradation. That tiering is only legitimate because the hot path
  touches no I/O — a database or query-log failure genuinely cannot reach
  resolution.
- **Restart must be bounded.** Unbounded restart of a deterministically-panicking
  task is a livelock that consumes the runtime the listeners need.
- **Rollup counters must survive a supervised restart and a clean shutdown.**
  They are specified as exact and never dropped; a restart that loses unflushed
  counts breaks that guarantee.
- **The headless build must still work.** The `web` feature is default-on but
  removable, and CI builds `--no-default-features` on every commit. The panic
  boundary and the supervisor must both compile and behave correctly with the web
  layer absent — the supervisor simply has no web tier to supervise.
- **Both release artifacts must build and run.** Not "build". The exit criterion
  is explicit that they run on their targets.
- **The soak precedes the cutover, and the cutover is the last action.** "Soak on
  one machine — **then** point the household at it." The ordering is the whole
  point of the phase; reversing it converts a private failure into a household
  outage.
- **"Without intervention" is the soak's pass condition.** Any manual restart,
  config edit or process kill during the window resets it. Without this, a soak
  that was nursed through its failures proves nothing.
- **Rollback is a documented single action.** Because there is no replica, the
  only recovery from a bad cutover is returning the household's resolver setting
  to Pi-hole. It must be written down before the cutover, not improvised during
  an outage with no DNS.

---

## Strategic Approach

### Solution Direction

Phase 12 is three separable workstreams with one hard ordering constraint between
them. It is deliberately *not* a feature phase: it adds no resolution behaviour,
no policy semantics and no UI. It adds a failure-containment structure, a release
pipeline, and a procedure.

**Workstream A — containment (code).** Introduce a supervisor in the binary crate
that owns every long-lived task, plus a `catch_unwind` panic boundary around the
web layer. The supervisor is composition-tier by definition: it is the only
component that legitimately knows about tasks from every feature crate, which is
exactly what the binary is for under the rule that feature crates never depend on
each other. Tasks are registered with a criticality tier and a restart policy;
the supervisor awaits their join handles, classifies termination (returned
cleanly, returned an error, panicked, cancelled), and acts per policy. The panic
boundary is a thin layer in or immediately around `styx-web`'s request path,
mapping a caught unwind to a 500 plus an error-level `tracing` event. Errors are
`thiserror` enums returned as `Result<T, E>`; the boundary is the only place that
converts a panic into an error value, and it does so explicitly.

**Workstream B — release (CI).** Extend the existing GitHub Actions release job
with a target matrix for `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`, triggered on `v*` tags, followed by a per-target
smoke run that starts the binary, resolves a name, and exits — because the exit
criterion says the artifacts must run, not merely link.

**Workstream C — cutover (procedure).** A written soak checklist, a soak run on
one machine, a final differential acceptance run against the actual release
artifact, a cutover procedure, a rollback procedure, and a standing-obligations
document covering the trust anchor, local names under signed zones, and
config-change-needs-restart.

**The ordering constraint:** A and B must both be complete and green before C's
soak starts, and C's soak must pass before the household's resolver changes.
Soaking a binary without the panic boundary measures the wrong system; cutting
over without a soak converts the project's accumulated, unvalidated integration
risk directly into a household outage.

**Data-flow direction for the code half:** binary `main` builds configuration and
shared `Arc` state → registers listener tasks (critical tier) and worker tasks
(degradable tier) with the supervisor → spawns the web layer wrapped in the panic
boundary (degradable tier) → supervisor awaits all handles → on termination,
classify, log via `tracing`, apply restart policy → on budget exhaustion, either
shed the task or initiate coordinated shutdown depending on tier.

### Key Design Decisions

- **Supervisor lives in the binary crate, not a feature crate.**
  Trade-offs: a feature crate would make it unit-testable in isolation and
  reusable, but it would need to know about every other feature crate's task
  types, which violates the rule that feature crates never depend on each other,
  and it would need an abstraction over "a task" broad enough to be meaningless.
  → **Recommendation: binary crate.** Supervision is wiring, and wiring is the
  binary's job under this architecture. Testability is recovered by making the
  supervisor generic over a task description rather than over concrete crates, and
  by driving it in integration tests with deliberately-panicking stub tasks.

- **Two supervision tiers, not one policy and not per-task bespoke policy.**
  Trade-offs: one uniform policy is simplest but forces a choice between "restart
  the listeners forever" (hides a real fault) and "exit on any task death" (a
  transient adlist fetch panic takes DNS down — the exact outcome this phase
  exists to prevent). Fully per-task policy is maximally flexible and maximally
  untestable.
  → **Recommendation: two tiers — resolution-critical and degradable — with a
  per-task restart budget inside each.** The tiering is licensed by the hot path
  touching no I/O: a degradable task genuinely cannot affect resolution
  correctness. Critical-tier exhaustion escalates to coordinated process exit
  (better a clean exit that a supervisor or the operator notices than a process
  that is up but answering nothing); degradable-tier exhaustion sheds the task,
  logs at error level, and leaves DNS serving.

- **`catch_unwind` at the request boundary, not at the task boundary alone.**
  Trade-offs: task-level supervision alone would let a panicking handler kill the
  whole web server task and restart it — losing every concurrent request,
  including unrelated ones, and cycling the listener socket. Request-level
  catching keeps the blast radius to one request, which is what a user would
  expect from any web framework.
  → **Recommendation: both, layered.** `catch_unwind` per request contains the
  common case; the supervisor catches the case where the panic happens outside a
  request scope (accept loop, TLS handshake, background render) or where the
  boundary itself is bypassed. The specification names both, and they cover
  disjoint failure modes.

- **A caught panic returns 500 and does not attempt to continue.**
  Trade-offs: returning a partial page or a cached response would be friendlier
  but risks serving state mutated halfway through an aborted handler.
  → **Recommendation: 500 plus a loud `tracing` error event.** Admin UI
  availability is explicitly the degradable tier; correctness and visibility beat
  friendliness. Visibility matters disproportionately here because the soak is
  the project's only integration feedback channel.

- **Poisoned shared state escalates; a clean request failure does not.**
  Trade-offs: treating every caught panic as poisoning would make the boundary
  useless (every handler panic restarts things). Treating none as poisoning risks
  serving from inconsistent state indefinitely.
  → **Recommendation: make the distinction explicit and narrow.** Shared state
  reachable from web handlers is either immutable-behind-`Arc` (the matcher via
  `ArcSwap`, config) or atomics (rollup counters) — neither of which a panic can
  poison. Lock-guarded state touched by handlers is the small set that needs
  poison handling, and that set should be minimised as part of this phase rather
  than papered over by the boundary.

- **Coordinated shutdown with a drain deadline, not abrupt exit.**
  Trade-offs: abrupt exit is simpler; a drain adds a cancellation token, a
  deadline, and a path for every task to honour it.
  → **Recommendation: coordinated shutdown.** The exact-rollup rule makes lost
  unflushed counters a correctness bug, not a cosmetic one, and abandoning
  in-flight queries during a restart shows up to the household as intermittent
  SERVFAILs — precisely the symptom that erodes trust during a fresh cutover. The
  deadline bounds it so shutdown cannot hang.

- **Release matrix with a per-target smoke run.**
  Trade-offs: building both targets is cheap; *running* aarch64 requires either a
  native ARM runner or emulation, both of which add CI cost and flake surface.
  → **Recommendation: build both, and run both.** The exit criterion says "build
  and run on their targets". A statically-linked musl binary differs from a glibc
  dev build in allocator behaviour, thread stack sizes and TLS/certificate store
  discovery — differences that surface only at runtime, and the dev box is not
  musl. Skipping the run would leave the only untested dimension untested.

- **The soak runs the actual release artifact, not a `cargo run` debug build.**
  Trade-offs: the dev build is more convenient and has better diagnostics.
  → **Recommendation: the musl artifact.** Soaking a binary that is not the one
  being deployed measures a different program. This also gives the musl artifact
  its long-duration exercise for free.

- **The soak checklist is written before the soak starts.**
  Trade-offs: writing it up front risks watching the wrong things; writing it
  afterwards is not a checklist, it is a summary of whatever happened.
  → **Recommendation: write it first, derived from the deferred-feedback list.**
  The last-cutover decision named exactly what would go unobserved until now —
  cache behaviour, odd client queries, DHCP churn — so those three are the
  checklist's mandatory items, alongside memory growth, `dropped_detail`,
  rollup/raw-row agreement, upstream health flapping, adlist staleness, and any
  caught panic at all.

- **The final differential acceptance run gates the cutover, not the merge.**
  Trade-offs: it is flaky by construction because real DNS changes underneath the
  corpus, so wiring it into the push gate would poison the gate.
  → **Recommendation: run it once against the release artifact as a pre-cutover
  check, with a human reading the diff.** A genuine regression can hide behind a
  shrug about flakiness, so the diff needs reading, not just a green tick.

- **Rollback is a documented procedure, not a feature.**
  Trade-offs: an automated fallback (styx forwarding to Pi-hole on failure) would
  be smoother but is effectively a second resolver in the deployment, which
  collides with the one-box-one-binary non-goal and adds a failure mode of its
  own.
  → **Recommendation: document a manual rollback — return the router's or
  clients' DNS setting to Pi-hole — and keep the Pi-hole instance running,
  unconfigured-away, through the soak and the first period after cutover.** The
  cheapest insurance available given no replication.

### Alternatives Considered

- **Process-level isolation (separate resolver and web processes).** Would make
  the panic boundary unnecessary by construction — the operating system would be
  the isolation. Rejected: it contradicts single process, single binary, which
  the whole architecture is built on (shared `Arc` state, a compile-time `web`
  feature, one deployable file). Reintroducing IPC to solve a panic-containment
  problem is a much larger change than a `catch_unwind` boundary, and it would
  have had to be decided in Phase 0, not Phase 12.
- **`panic = "abort"` in the release profile.** Would make every panic a clean,
  immediately-visible process death instead of a corrupted-state risk. Rejected:
  it makes `catch_unwind` impossible, and the failure mode it produces is exactly
  the one this phase exists to prevent — a panic in an admin page taking DNS down
  for the house. The project's posture is containment, not fail-fast, for the web
  tier specifically.
- **Relying on an external supervisor (systemd `Restart=always`) instead of an
  in-process one.** Rejected as the primary mechanism: a process restart loses
  the answer cache, the infrastructure cache and the matcher, causing a cold-start
  latency spike across the whole household, and it cannot express "restart the
  adlist worker but leave DNS untouched". It remains valuable as the outermost
  net, and the deployment should have it, but it is not a substitute for
  in-process supervision.
- **Rolling the cutover out gradually — a few clients first, then the house.**
  Genuinely attractive, and worth doing if the network permits per-client DNS
  assignment. Rejected as the *primary* plan because client identity is
  IP-keyed with DHCP as a non-goal, so a partial rollout mixes populations in a
  way that makes per-client policy and history harder to interpret during exactly
  the window when interpreting them matters. Recommended as an optional
  soak-extension step rather than a replacement for the single-machine soak.
- **Skipping the aarch64 runtime verification and shipping it build-only.**
  Rejected: the aarch64 artifact is the one most likely to be the actual
  deployment target (a Raspberry Pi is the stated memory-budget reference point),
  and it is the one the dev box cannot incidentally test.
- **Treating the soak as a fixed-duration timer.** Rejected in favour of a
  checklist with a duration floor. "Long enough to trust it" is about what was
  observed, not elapsed time; a week in which nothing was watched is worth less
  than two days with the checklist.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **"long enough to trust it" is undefined.** The exit criterion sets no
  duration. It needs a concrete floor and a set of conditions. Recommended
  resolution: a minimum of several consecutive days covering at least one full
  weekly traffic cycle and at least one adlist ingestion cycle, with the checklist
  clean — and an explicit rule that any intervention restarts the clock.
- **"without intervention" is not defined.** Does editing a blocklist in the UI
  count? Recommended resolution: normal in-UI policy use is *not* intervention
  (it is the product working); anything requiring SSH, a process restart, a TOML
  edit or a manual recovery action *is*, and resets the window.
- **"a panic induced in a web handler" — how is it induced?** A test-only
  injection endpoint is the obvious mechanism, but a panic endpoint compiled into
  a release binary reachable from the LAN is a denial-of-service primitive.
  Recommended resolution: the injection point exists only under a test cfg or a
  dev-only feature, is exercised by an integration test in CI, and is verifiably
  absent from the release artifact.
- **Scope of the panic boundary is stated as "around the web layer" but not
  delimited.** Does it cover Leptos server functions only, or also SSR rendering,
  static asset serving, the session/origin middleware and the accept loop?
  Recommended resolution: the whole `styx-web` request path including middleware,
  plus supervisor coverage for the accept loop, which is outside any request.
- **The restart policy has no specified parameters.** Nothing states how many
  restarts, over what window, with what backoff, or what happens at exhaustion.
  These are implementation-level and decidable at the keyboard, but they must be
  decided and written down, not defaulted silently.
- **"both musl artifacts build and run on their targets" — what does "run" prove?**
  Minimum viable: process starts, binds, answers one query correctly over UDP,
  exits cleanly on signal. Recommended resolution: state the smoke assertion
  explicitly so the CI step is not reduced to `--version`.
- **Whether the cutover is router-level or per-client is unspecified.** The
  phrase is "point the household at it". This determines the rollback speed and
  the blast radius, and should be decided before the soak, not during it.
- **Nothing states whether Pi-hole is kept running after cutover.** Given no
  replication and manual rollback, it should be — but this is an assumption, not
  a recorded decision, and it needs recording.

### Edge Cases

- **A panic during a supervised restart.** The task's startup itself panics, so
  the supervisor restarts it, and it panics again. Matters because this is the
  livelock case the restart budget exists for, and the most likely shape is a
  configuration or state problem that will not fix itself.
- **A panic outside any request scope.** TLS handshake failure in the DoH accept
  loop, a background SSR prerender, a panic inside the `catch_unwind` closure's
  own error path. The request boundary cannot see these; only supervision can.
- **A panic while holding a lock over shared state.** Poisons the lock; subsequent
  handlers fail. Matters because a boundary that returns 500 and forgets makes
  this an indefinite silent degradation rather than a visible fault.
- **Abort-not-unwind panics.** A double panic, a panic in a `Drop` impl during
  unwinding, or an allocation failure aborts the process regardless of
  `catch_unwind`. Matters because it bounds what this phase can honestly claim:
  the boundary contains *most* panics, not all, and the external supervisor is
  the only net under this case.
- **The DNS listeners themselves panic.** The exit criterion only covers a web
  panic. Critical-tier restart behaviour needs deciding and testing too — a
  listener that dies silently leaves a process that is up and answering nothing,
  the worst possible state because no monitoring notices.
- **Coordinated shutdown races an in-flight recursion.** A full recursive descent
  with DNSSEC validation can take seconds. The drain deadline must accommodate it
  or restarts produce SERVFAILs.
- **musl-specific runtime divergence.** Static musl builds differ from glibc in
  allocator behaviour under fragmentation (musl's allocator is markedly less
  aggressive about returning memory), default thread stack size (which matters for
  a recursive descent), and root-certificate discovery for DoH outbound and DoT
  inbound. Matters because the dev box is glibc and the deployment is musl, so
  this divergence is invisible until the artifact runs.
- **Cold start after any full-process restart.** Empty answer cache, empty
  infrastructure cache, matcher rebuild from lists. The household sees a latency
  spike. Matters for the cutover plan: do the cutover from an already-warm process.
- **First-boot artefacts firing during the cutover.** A generated admin password
  printed once to the log, a self-signed certificate generated at first boot with
  its SPKI pin printed once. If the cutover machine is freshly provisioned, these
  one-shot outputs happen in the middle of the cutover and are easy to miss.
- **A KSK roll during or shortly after the soak.** The trust anchor is pinned and
  compiled in, RFC 5011 rollover is a non-goal, and a missed roll SERVFAILs every
  lookup. Matters enormously: this is the one failure mode that takes the whole
  household off the internet with no partial degradation, and no code in the
  project prevents it.
- **A local record under a signed public zone.** A local A record for
  `nas.example.com` where `example.com` is DNSSEC-signed is unprovable —
  answered Insecure with AD cleared and no forged signature — and a validating
  client may SERVFAIL it. Matters because it looks exactly like a styx bug during
  a fresh cutover, and the only mitigation is documentation that someone has to
  read.
- **DHCP churn reassigning an IP during the soak.** Per-client groups keyed on IP
  silently misattribute after a lease change; history rows land on the wrong
  client. Matters because this is one of the three named categories of deferred
  operational feedback, and the soak is the first chance to see its real
  frequency on this network.
- **An adlist ingest failing mid-soak.** Last-known-good is retained and the list
  is marked stale with a reason. Matters because "keep last known good" means a
  dead list blocks forever, and the only signal is a staleness badge nobody is
  looking at — during a soak, somebody must be.
- **`race` selection left enabled at cutover.** It multiplies outbound QPS and
  shows every domain to every provider in the pool; in a mixed pool containing the
  recursor, the privacy posture changes per query non-deterministically. Matters
  because the moment it starts mattering is the moment real household traffic
  arrives.
- **The headless `--no-default-features` build.** With the web layer compiled out,
  the panic boundary has nothing to wrap and the supervisor has no web tier. Both
  must still compile and behave. Matters because CI builds this on every commit
  and the supervisor is the most likely place to accidentally require the `web`
  feature.
- **Rollup counters unflushed at shutdown.** Dashboards are specified as always
  exact; a shutdown that loses counts breaks a stated guarantee, and the first
  place anyone would look after a cutover is the dashboard.

### Technical Risks

- **`catch_unwind` and `UnwindSafe` friction.** Most realistic handler state is
  not `UnwindSafe`, so the boundary will need `AssertUnwindSafe`. Impact: the
  assertion is exactly where correctness is being asserted without a compiler
  check, so the set of state crossing the boundary must be small and reviewed.
  Mitigation direction: keep the boundary thin, keep web-reachable mutable state
  minimal (`ArcSwap` and atomics rather than locks), and document each
  `AssertUnwindSafe` use with what makes it sound.
- **`catch_unwind` around async code does not work the way it looks like it
  does.** It cannot wrap an `await` — the future must be polled inside the
  catching frame, which means wrapping the future's `poll`, not wrapping an
  `async` block. Impact: a naively-written boundary compiles, passes a synchronous
  test, and silently fails to catch panics that occur after the first suspension
  point — which is most of them. Mitigation direction: implement the boundary as a
  future wrapper whose `poll` is the catching frame, and test it with a panic
  induced *after* an `await`, not before.
- **Restart storms starving the runtime.** A deterministically-panicking task
  restarting without backoff consumes scheduler capacity the listeners need.
  Impact: DNS latency degrades even though the listeners never died. Mitigation
  direction: bounded budget plus exponential backoff, with the budget window
  driven by the injectable `Clock` so it is testable in milliseconds.
- **The deny-level panic lint's false sense of security.** The lint denies
  explicit panics, but arithmetic overflow, slicing, `unwrap` in a dependency and
  allocation failure all still panic. Impact: the real panic surface is wider than
  the lint's coverage, which is precisely why the boundary is called the real
  mitigation. Mitigation direction: treat the boundary as the primary control and
  the lint as defence in depth, and test the boundary against a panic the lint
  would not have caught.
- **aarch64 CI cost and flake.** Emulated runners are slow; native ARM runners may
  not be available. Impact: the release job becomes the slowest and least reliable
  part of CI, and the temptation is to weaken the runtime check. Mitigation
  direction: keep the smoke run minimal and hermetic — no live internet, a
  forwarder pointed at an in-process fake — so the only thing under test is "this
  binary runs on this architecture".
- **The soak is the project's first and only integration feedback.** Everything
  the last-cutover decision deferred — cache behaviour under a real query mix,
  odd client queries, DHCP churn — arrives here at once, at the point where acting
  on it is most expensive. Impact: the soak may surface design-level problems in
  phases 4, 8 or 9 at the moment the project wants to be finishing. Mitigation
  direction: accept it explicitly, budget time for a soak that fails and is rerun,
  and treat a soak finding as a legitimate reason to reopen an earlier phase
  rather than to shrug and cut over anyway.
- **No replication means no failover.** Multi-node deployment is an explicit
  non-goal — one box, one binary, local database file. Impact: every second of
  process downtime is a second of no DNS for the household, and the only recovery
  is manual rollback. Mitigation direction: keep Pi-hole alive and reachable
  through the soak and beyond; make the rollback a single documented action that
  works without DNS resolution being available to the person performing it (so:
  written down on paper or on a device with a cached copy, using IP addresses,
  not hostnames).
- **Infrastructure config changes require SSH and a restart.** The file/database
  config boundary means listen addresses, upstreams, pools, selection strategy,
  TLS material and the trust anchor are all file-owned. Impact: during the cutover,
  the corrections most likely to be needed (change an upstream, adjust the trust
  anchor) are exactly the ones that cost a restart and therefore a household DNS
  gap. Mitigation direction: settle infrastructure config before the soak begins
  and treat any change to it as a soak-restarting event.
- **Missed trust anchor rollover.** The root anchor is pinned and compiled in,
  with only a file-path override; RFC 5011 rollover is a non-goal. Impact: a KSK
  roll that passes unnoticed SERVFAILs every lookup on the network — total outage,
  no partial degradation, and the cause is entirely non-obvious from inside the
  network. Mitigation direction: this is a monitoring obligation, not code —
  record it in the standing-obligations document with the IANA source to watch, a
  calendar reminder, and the exact file-override procedure to apply under
  time pressure.
- **Local names under signed public zones.** Unprovable by construction, and
  validating clients may SERVFAIL them. Impact: presents as an intermittent,
  client-dependent styx bug during the fresh-cutover window when trust is
  lowest. Mitigation direction: documented guidance to keep local names under an
  unsigned or internal suffix — a mitigation only for people who read it — so it
  belongs in the standing-obligations document and ideally as inline guidance in
  the local-records UI.
- **Single-password admin auth with no audit trail.** You can never tell who
  disabled blocking. Impact: during soak triage, an unexplained behaviour change
  cannot be attributed. Mitigation direction: note it in the soak checklist so
  "did someone change something" is asked explicitly rather than assumed away.
- **Self-signed DoT is largely unusable for clients like Android Private DNS.**
  Impact: a cutover plan that assumes all household clients can use DoT will fail
  for exactly those clients. Mitigation direction: decide the certificate story
  before the cutover, not during it.

### Acceptance Criteria Coverage

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | A panic induced in a web handler leaves DNS serving | Yes | Needs a test-cfg-only induction point that is provably absent from the release artifact. The test must induce the panic *after* an `await` — a boundary that only catches pre-suspension panics passes a naive test and fails in production. Verified at socket level: drive a real UDP/TCP query before, during and after the induced panic and assert correct answers throughout. |
| 2 | Both musl artifacts build on their targets | Yes | A `v*`-tagged release matrix over `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`. Mechanically straightforward; the aarch64 build needs cross-compilation or a native runner. |
| 3 | Both musl artifacts **run** on their targets | Partial | "Run" is undefined and must be pinned to a concrete smoke assertion (start, bind, answer one query correctly, exit cleanly on signal). aarch64 execution needs emulation or a native ARM runner; this is the most likely AC to be quietly weakened to a build-only check. Keep the smoke run hermetic so it is not also a network test. |
| 4 | A soak on one machine runs without intervention for long enough to trust it | Partial | Both "long enough" and "without intervention" are undefined and must be given concrete definitions before the soak starts (duration floor covering a full weekly cycle and at least one adlist ingestion; intervention = anything needing SSH, a restart, a TOML edit or manual recovery, and it resets the clock). Also needs a written checklist, or "trust" has no content. |
| 5 | Only then does the household's resolver change | Yes | An ordering constraint on the procedure, not on code. Enforceable only by writing the cutover procedure with the soak as an explicit precondition, and by documenting the rollback before the cutover rather than during it. |
| — | Implicit: the supervised task model | Yes | Named in scope but absent from the exit criteria. Needs its own verification: induce a panic in a degradable worker and assert DNS is unaffected; induce one in a listener and assert the critical-tier policy fires; exhaust a restart budget and assert the documented terminal behaviour. Without this, the supervisor ships untested. |
| — | Implicit: the headless build still passes | Yes | Inherited from the standing rule that CI builds `--no-default-features` on every commit. The supervisor and the boundary must both compile and behave with the web layer compiled out. |
| — | Implicit: exact rollups survive restart and shutdown | Partial | Not mentioned in this phase's criteria but required by the standing guarantee that every dashboard number is always exact. Coordinated shutdown with a drain deadline is the mechanism; it needs a test that asserts no counts are lost across a supervised restart. |

---

## Non-goals that bear on this phase

- **Multi-node or replicated deployment.** One box, one binary, local database
  file. There is no failover target, so every availability property must come
  from within the process, and rollback to Pi-hole is the only recovery above
  process level.
- **RFC 5011 automated trust anchor rollover.** The anchor is pinned and compiled
  in with a file-path override behind a `TrustAnchorSource` port, which is the
  seam a future implementation slots into. Until then, a KSK roll needs a release
  or a file edit, and missing one SERVFAILs every lookup. A monitoring
  obligation, not code.
- **Authoritative zone serving.** Local records are a resolution concern, not a
  zone-file server — which is why a local name under a signed public zone is
  unprovable rather than something styx could sign its way out of.
- **DHCP server.** Clients are identified by IP plus optional manual naming;
  styx never owns the lease table, so client identity is best-effort and breaks on
  lease churn. This is one of the three deferred-feedback categories the soak must
  watch.
- **Multi-user admin, roles, audit trail.** Single Argon2id-hashed password, no
  attribution of changes — relevant to soak triage.
- **EDNS Client Subnet and DNS-over-QUIC.** Neither ships in v1; neither affects
  this phase beyond bounding what the cutover delivers.

---

## Summary

Phase 12 is the project's terminal phase and the first moment the household's DNS
depends on styx. It contains three things: the runtime containment that the
single-process architecture has been deferring since Phase 0 (a `catch_unwind`
boundary around the Leptos web layer plus a supervised, tiered task model), the
release pipeline that produces and verifies static musl artifacts for
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` on `v*` tags, and
the procedure — soak, then cutover, with a documented rollback — that turns a
working binary into the household's resolver.

Its defining tension is that it carries the bill for two earlier ordering
decisions. Because the cutover is last and resolution came before product, no
operational feedback of any kind has been collected: cache behaviour under a real
query mix, odd client queries and DHCP churn all arrive for the first time in this
phase's soak, at the point where acting on them is most expensive, and with
neither visible progress nor external pressure having applied along the way. That
was accepted deliberately, as the cost of not doing a live migration underneath
two hand-written security-critical subsystems — but it means the soak is not a
formality. It is the only integration feedback channel the project has, and the
design must make it cheap to observe and cheap to abort.

The second defining property is that the mitigation this phase delivers is the one
every prior phase has been living without. In a single process sharing state via
`Arc`, a panic in a Leptos request handler takes DNS down for the whole house; the
deny-level panic lint has been the sole defence for eleven phases, and it does not
cover arithmetic overflow, slicing, dependency `unwrap`s or allocation failure.
The boundary and the supervisor are the real mitigation, and they must be built
correctly the first time — in particular as a future wrapper whose `poll` is the
catching frame, since a boundary written around an `async` block silently fails to
catch anything after the first suspension point.

Beyond code, the phase must leave behind what nothing in the codebase prevents:
that the root trust anchor is pinned and compiled in with rollover a non-goal, so
a missed KSK roll SERVFAILs every lookup on the network; that local names belong
under an unsigned or internal suffix because a local record under a signed public
zone is unprovable and validating clients may SERVFAIL it; that infrastructure
config changes need SSH and a restart, and therefore a household DNS gap; and that
with replication a non-goal, the only rollback is pointing the household back at
Pi-hole, which must be written down, in IP addresses, before it is needed.
