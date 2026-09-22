# SPDD Analysis: Phase 3 — `Upstream` port, forwarding, pool

**Project**: `styx` — a filtering DNS resolver written from scratch in Rust, replacing
Pi-hole's role on a home network (recursive/forwarding resolution, per-client blocking
policy, Leptos admin UI).

**Codebase state**: **Greenfield, no existing implementation.** The repository at the time
of this analysis contains only the decision record, the roadmap, the per-phase specs and
an inert `arch-lint.toml`. There is no git history, no Cargo workspace and no Rust source.
Every "existing concept" below is therefore a *decided* concept — settled in design review
and binding on this phase — not code that can be read. All strategic grounding comes from
those recorded decisions, which are inlined here in full because the source documents are
being retired once this analysis exists.

---

## Original Business Requirement

> *Verbatim, from the phase specification for Phase 3.*

```markdown
# Phase 3 — `Upstream` port, forwarding, pool

> Part of ROADMAP.md · Previous: Phase 2 — Server loop · Next: Phase 4 — Answer cache

## Scope

- The `Upstream` trait; a Do53 forwarder over UDP and TCP.
- Concrete `HealthState` per member — SRTT EWMA, consecutive failures, circuit
  state, last-probe-at — fed by the outcomes of real traffic (decision 7).
- All four `SelectionStrategy` implementations (decision 4).
- Probe policy: idle-beyond-window members and currently-down members only
  (decision 8). Healthy, actively-used upstreams generate no probe traffic.

## Exit criteria

Failover, round-robin, weighted and race behaviour proven at socket level against
fake upstreams; circuit open and close under an injected `Clock`.
```

### The referenced decisions, inlined

The phase spec cites decisions by number against a record that is being deleted. Their
full text and rationale, which is the load-bearing part:

- **"Decision 4" — All four selection strategies ship in v1.** Ordered failover,
  round-robin, race, weighted — behind a `SelectionStrategy` port, chosen per pool in
  config.
- **"Decision 7" — No health-check trait.** The pool owns a concrete `HealthState` per
  member (SRTT EWMA, consecutive failures, circuit state, last-probe-at), fed by outcomes
  of real traffic that the pool already observes. Probing is `Upstream::resolve(canary)`
  with per-kind config defaults — a forwarder's canary is one query, a recursor's is a
  full descent, which is the correct test.
- **"Decision 8" — Probes run only when needed**: against any member idle beyond a window
  (the ordered-failover standby case — passive health is structurally blind to an upstream
  receiving zero traffic), and against any member currently marked down, to decide when to
  restore it. Healthy, actively-used upstreams generate no probe traffic.

### Position in the build

Phase 3 sits inside a dependency-ordered, risk-ordered build in which
**the cutover is last**: styx runs on a dev box until the whole of v1 works and the
household's resolver stays on Pi-hole until then. Nothing mid-build has to be shippable,
breaking changes stay free, and phases are ordered by dependency and risk rather than
usability. The accepted consequence of that ordering — and it bears on this phase — is
that there is no operational feedback at all until the very end.

**Phases this phase depends on:**

- **Phase 0 — Foundation and gates.** Cargo workspace in the crate-per-feature shape, a
  *working* (syn-engine) `arch-lint.toml` with `no-unwrap-expect`, `require-tracing`,
  `tracing-env-init`, `no-sync-io` and `require-thiserror` enabled, a second independent
  `cargo tree --edges normal` layering gate, the `hickory-dev-only` check, `clippy.toml`
  with the 15 denied lints, lefthook, GitHub Actions and the `just gate` target.
- **Phase 1 — Wire codec (`styx-proto`).** Header, question, RR, RDATA for every v1
  rrtype, name compression on both encode and decode, compression-pointer loop detection,
  EDNS(0) OPT. Phase 3 encodes outbound queries and decodes upstream responses entirely
  through it.
- **Phase 2 — Server loop and test harness.** UDP/TCP listeners, TC bit and inbound TCP
  fallback, the request pipeline skeleton, the injectable `Clock`, the in-process fake
  root/TLD/authoritative servers built on `hickory-proto` and driven over real sockets,
  and the declared hot-path ports. Phase 2 also fixes the pipeline order as a correctness
  property: **local records → filter → cache → upstream**. Phase 3 supplies the last stage
  of that pipeline.

**Phases that depend on this phase:**

- **Phase 4 — Answer cache.** Sits between the pipeline and the pool; caches what the pool
  returns, subject to bailiwick rules.
- **Phase 5 — Recursion (`styx-recursion`).** Implements the *same* `Upstream` port as a
  recursor, and publishes `RecursionDiagnostics` as a read model deliberately separate
  from this phase's `HealthState`.
- **Phase 6 — DNSSEC (`styx-dnssec`).** Forwarder paths *pull* DS/DNSKEY on demand through
  the pool; the design of the `ChainSource` port depends on the `Upstream` port staying
  narrow (see below).
- **Phase 11 — Web UI (`styx-web`).** Surfaces health and, specifically, must carry the
  loud `race` privacy warning.
- **Phase 12 — Cutover hardening.** The panic boundary and supervised task model that the
  outbound I/O tasks written here eventually run under.

---

## Domain Concept Identification

### Existing Concepts (decided, not yet coded)

Greenfield: none of these exist as code. Each is a design-review decision that binds this
phase.

- **`Upstream` (the unifying abstraction)**: an upstream is *either* a forwarder or a
  recursor. A pool holds upstreams of mixed kinds, each with its own health and behaviour
  config. **Recursion is an implementation of the same port, not a separate server mode.**
  This is the single most important structural commitment in the phase: it is why Phase 5
  has somewhere to plug in without reshaping the server, and why a home deployment can run
  "recursor first, public forwarder as fallback" as an ordinary pool rather than as a
  special case in the request path.
- **The `Upstream` port must stay narrow.** The DNSSEC decision records the reasoning
  explicitly: validation is its own crate behind a `ChainSource` port, where
  `styx-recursion` *pushes* chain material it already collected during descent (DS RRsets
  arrive unasked in DO=1 referrals, per RFC 4035 §3.1.4) while forwarder paths *pull*
  DS/DNSKEY on demand — one validator, two feeding strategies. That split exists **to
  avoid widening the `Upstream` port with a "chain material observed en route" field that
  would be permanently empty for forwarders.** Phase 3 owns the port's shape, so Phase 3
  owns honouring that constraint.
- **`SelectionStrategy` (port)**: the per-pool choice among ordered failover, round-robin,
  race and weighted. All four ship in v1; the strategy is a config-chosen per-pool
  behaviour, not a compile-time one.
- **`HealthState` (concrete, pool-owned)**: SRTT EWMA, consecutive failures, circuit
  state, last-probe-at. Deliberately a concrete struct owned by the pool and **not** a
  trait. Rationale, in full: the pool *already observes* the outcome of every real query
  it dispatches, so a health-check abstraction would be a second, redundant source of
  truth over data the pool holds anyway. Probing is not a separate mechanism either — it
  is `Upstream::resolve(canary)`, because a forwarder's canary is one query and a
  recursor's canary is a full descent, **which is the correct test**: a recursor whose
  root connectivity is broken must fail its probe, and only a real descent detects that.
- **Probe policy**: probes fire only against (a) any member idle beyond a window and (b)
  any member currently marked down. Rationale, in full: passive health is
  **structurally blind to an upstream receiving zero traffic** — the ordered-failover
  standby case, where the secondary sees no queries at all while the primary is up, so its
  health record can never be anything but stale. Down members are probed to decide when to
  restore them. Healthy, actively-used upstreams generate no probe traffic, because their
  real traffic already answers the question.
- **`RecursionDiagnostics` (Phase 5, named distinctly on purpose)**: per-kind diagnostics
  travel a *separate path*. `styx-recursion` publishes root/TLD reachability as its own
  read model, consumed directly by `styx-admin`/`styx-web`, **never through the pool**,
  and named distinctly from selection health **so the two are never conflated**. Phase 3
  must therefore not grow a "diagnostics" surface on the pool or on the port that Phase 5
  would be tempted to fill.
- **Answer cache (Phase 4)**: global, keyed `(qname, qtype, qclass)`, living in
  `styx-resolution`. Structurally distinct from the recursion-only infrastructure cache
  (delegations, NS sets, per-nameserver RTT and EDNS capability, keyed by zone and
  nameserver), which lives in `styx-recursion`. Phase 3 must not invent a third cache:
  per-nameserver RTT belongs to recursion's infrastructure cache, and per-*upstream* SRTT
  belongs to `HealthState`. These are different things at different layers and must not be
  merged.
- **Injectable `Clock`**: decided in Phase 2 and stated to be un-retrofittable. Every
  timestamp in this phase — SRTT sample time, circuit open/half-open transitions,
  last-probe-at, idle-window evaluation, query deadline — reads it.
- **`styx-proto`**: the shared-foundation crate. The rule that feature crates never depend
  on each other explicitly does not reach it; it is the one recorded exception, and the
  layering config must be written so as not to forbid it.
- **Config split with a hard boundary**: a TOML file owns everything needed before the DB
  exists or in order to reach it —
  **listen addresses, upstreams and pools, selection strategy**, TLS material, trust
  anchor, DB path, log mode. Turso owns everything a human edits at runtime. No overlap
  means no precedence rule. The accepted consequence, recorded as such: **changing an
  upstream requires SSH and a restart, which is the thing people most want to do from the
  UI.** Phase 3's configuration therefore does not need hot reload, and must not grow one.
- **The hot path touches no I/O** (meaning storage I/O): a DB outage degrades logging and
  admin, never resolution. Nothing in the pool may read or write the database.

### New Concepts Required

- **Do53 forwarder**: an `Upstream` implementation speaking classic DNS over UDP with TCP
  fallback on truncation. Relates to `Upstream` as its first concrete implementation and
  to `styx-proto` as its codec.
- **Upstream pool**: the aggregate that holds N members, owns each member's `HealthState`,
  delegates member ordering/choice to a `SelectionStrategy`, dispatches, records outcomes,
  and runs the probe policy. It is the only writer of `HealthState`.
- **Health outcome / observation**: the value recorded per dispatch (success with latency,
  timeout, transport error, protocol-level failure) that feeds SRTT, the
  consecutive-failure counter and the circuit.
- **Circuit state**: closed / open / half-open per member, with the transitions driven by
  consecutive failures and by elapsed time read from the injected `Clock`.
- **Probe scheduler**: the background activity that evaluates the idle-window and
  down-member conditions and issues canary resolves. Distinct from the pool's dispatch
  path, but writing into the same `HealthState`.
- **Upstream kind / canary config**: per-kind defaults for what a probe query *is*,
  because the forwarder and the recursor need structurally different canaries.
- **Selection outcome and per-query upstream attribution**: which member answered, needed
  downstream by the query-log pipeline and the UI, and needed *within* this phase by
  `race` to account for the queries it did not use.

### Key Business Rules

- **An upstream is either a forwarder or a recursor, behind one port.** No second server
  mode, no branch in the request pipeline on "forwarding vs recursive".
- **The port stays narrow.** No "chain material observed en route" field, no diagnostics
  channel, no recursion-shaped affordance that a forwarder would leave permanently empty.
- **The pool is the sole owner and sole writer of `HealthState`.** Health is derived from
  outcomes of traffic the pool already observes; nothing else publishes into it and
  nothing reads it as a general-purpose metric source.
- **Probing is resolution, not a side-channel.** A probe is `Upstream::resolve(canary)`
  through the same code path as a real query, so a probe proves what a real query would
  do.
- **Probes are issued only to idle-beyond-window members and to down members.** A healthy,
  actively-used upstream generates zero probe traffic.
- **Selection health and recursion diagnostics are never the same object and never share a
  name.**
- **Every timestamp comes from the injected `Clock`.** No `Instant::now()` on any path
  this phase owns, or the circuit tests cannot exist.
- **Truncated UDP answers retry over TCP.** A TC=1 response is not an answer.
- **The pool touches no database.** Upstream and pool configuration is file-owned and
  restart-scoped.
- **`race` is a privacy decision, not a performance knob** (see Technical Risks).

---

## Strategic Approach

### Solution Direction

Phase 3 delivers the terminal stage of the resolution pipeline fixed in Phase 2 (local
records → filter → cache → upstream) as one feature crate's worth of domain, application
and infrastructure modules, in the project's decided shape: **one crate per feature, with
`domain` / `application` / `infrastructure` as modules inside it**, Cargo enforcing
feature-to-feature isolation and arch-lint enforcing layering within the crate.
Cross-feature needs are expressed as a port in the consumer's `domain`, implemented by an
adapter in the binary.

Concretely, the direction is:

- **`domain`**: the `Upstream` port, the `SelectionStrategy` port, `HealthState` and its
  transitions as pure data and pure functions, the probe policy as a decision function
  over health and clock readings, upstream/pool identity and configuration types, and a
  `thiserror` error enum for upstream failure modes. All of it deterministic and testable
  without a socket.
- **`application`**: the pool — dispatch, outcome recording, strategy invocation, probe
  scheduling. It orchestrates; it does not itself speak the wire.
- **`infrastructure`**: the Do53 forwarder — UDP send/receive, truncation detection, TCP
  fallback, timeouts, and `styx-proto` encode/decode.

Health is a **fold over dispatch outcomes**, not a subsystem: the pool already sees every
result, so recording is a call on the way back, and the probe scheduler exists solely to
manufacture observations where real traffic cannot supply them.

Data flow: request pipeline → pool → `SelectionStrategy` chooses (or, for `race`, chooses
several) → `Upstream::resolve` → outcome recorded into that member's `HealthState` →
response returned. In parallel and off the query path, the probe scheduler reads
`HealthState` plus the `Clock` and issues canary resolves through exactly the same
`Upstream::resolve`.

Testing follows the project's decided default: **TDD cycles run at socket level**, driving
real UDP/TCP against an ephemeral-port server with in-process fakes and an injectable
`Clock`. The fakes are built on `hickory-proto`, which is the
**test oracle and a `[dev-dependencies]` entry only** — the reasoning being that if styx's
own codec encodes the fixtures, the resolver and its oracle share every bug and a green
suite proves only self-consistency. A CI check asserts `hickory-proto` appears in no
normal or build dependency path. For this phase that means the fake upstreams are
hickory-backed and controllable: able to be slow, to time out, to truncate, to return
SERVFAIL, and to go away and come back.

### Key Design Decisions

- **`Upstream` as one port for forwarders and recursors** → Trade-off: the port's method
  set is constrained to the intersection of what both kinds can offer, so recursion-only
  information (chain material seen during descent, root/TLD reachability) has to travel
  elsewhere. → **Recommended and binding**: keep it. The cost is exactly two extra seams
  (`ChainSource` for DNSSEC, `RecursionDiagnostics` for observability), both already
  decided, and the benefit is that a mixed pool works and Phase 5 plugs in without
  touching the request pipeline. Widening the port would put a permanently-empty field on
  every forwarder.
- **`HealthState` concrete, no health-check trait** → Trade-off: no pluggable health
  strategy; health semantics are fixed in the pool. → **Recommended and binding**: keep
  it. A trait here would abstract over data the pool already owns and invite a second
  source of truth. Concrete state fed by real outcomes is both simpler and strictly better
  informed than any external checker, which by definition sees different traffic than the
  resolver does.
- **Probing is `Upstream::resolve(canary)`** → Trade-off: a recursor's probe is expensive
  (a full descent) compared with a cheap ping. → **Recommended and binding**: the expense
  *is* the point. A cheap liveness check on a recursor tests nothing that matters; a
  descent tests root reachability, delegation handling and the answer path. Cost is
  contained by the probe policy, not by weakening the probe.
- **Probe only idle-beyond-window and down members** → Trade-off: a
  healthy-but-lightly-used upstream may have a slightly stale SRTT, and there is a window
  in which a newly-failed upstream is detected only by a real query. →
  **Recommended and binding**: correct trade. Passive health is structurally blind *only*
  to zero-traffic members, so that is exactly the hole probes fill. Probing healthy busy
  upstreams would add outbound traffic that tells you nothing their real traffic did not
  already say — and outbound traffic to third-party resolvers is a privacy cost, not just
  a bandwidth one.
- **Circuit breaker over plain failure counting** → Trade-off: an extra state machine and
  an extra set of constants to tune. → **Recommended**: required by the exit criteria
  ("circuit open and close under an injected `Clock`") and required by the restore
  question: a down member must be re-admitted on evidence, and half-open is the cheapest
  correct way to gather that evidence.
- **Four strategies behind one port, chosen per pool in config** → Trade-off: four code
  paths to test, and one of them (`race`) has a privacy profile the others do not. →
  **Recommended and binding**: all four ship. The mitigation for `race` is a loud warning
  in the UI, not omission and not a config comment.
- **SRTT for upstream selection is not the recursion infrastructure cache's per-nameserver
  RTT** → Trade-off: two RTT-shaped things in the system. → **Recommended and binding**:
  keep them separate. They are keyed differently (upstream identity vs. zone+nameserver),
  owned by different crates, and consumed by different decisions. Merging them would
  couple `styx-recursion`'s internals to the pool, which the crate-isolation rule forbids
  anyway.
- **Do53 only in this phase; UDP-first with TCP fallback** → Trade-off: no encrypted
  *outbound* transport, so forwarded queries are visible on the wire to the upstream's
  network path. → **Recommended**: matches the phase scope exactly. The `Upstream` port
  must not be shaped in a way that forecloses an encrypted forwarder later (see
  Ambiguities).
- **Errors as `thiserror` enums, `Result<T, E>` everywhere, `tracing` for observability**
  → Not optional: the project's lint configuration denies `unwrap`/`expect` outside tests,
  requires `thiserror`, requires `tracing`, denies sync I/O, and denies `indexing_slicing`
  and `arithmetic_side_effects`. SRTT arithmetic and any byte handling in the forwarder
  are therefore checked operations by construction.

### Alternatives Considered

- **A separate "recursive mode" alongside "forwarding mode"** → Rejected at design review.
  It would duplicate the request pipeline, make a mixed pool impossible, and make Phase 5
  a rewrite of Phase 2 and 3 rather than an addition.
- **A `HealthCheck` trait with pluggable checkers** → Rejected. It abstracts over
  information the pool already holds, creates a second source of truth, and — worse — an
  external checker's probe traffic is not the resolver's traffic, so it can report healthy
  for an upstream that fails every real query.
- **Cheap liveness probes (e.g. a fixed short query, or transport-level reachability)** →
  Rejected for recursors specifically, where they would pass while the thing that matters
  is broken. The canary must be a real resolve.
- **Continuous probing of all members on a fixed interval** → Rejected. It multiplies
  outbound traffic to third parties for information that real traffic already provides on
  every member except the idle ones.
- **Widening `Upstream` with recursion-observed DNSSEC chain material** → Rejected
  explicitly in the DNSSEC decision: the field is permanently empty for forwarders. The
  `ChainSource` port with push (recursion) and pull (forwarder) feeding is the accepted
  shape instead.
- **Routing recursion diagnostics through the pool's health surface** → Rejected
  explicitly: they are published as a separate read model with a distinct name precisely
  so they can never be conflated with selection health.
- **Per-pool or per-upstream caches** → Rejected. The answer cache is global and keyed
  `(qname, qtype, qclass)`; the only other cache in v1 is recursion's infrastructure
  cache.
- **Omitting `race` because of its privacy profile** → Rejected. All four strategies ship;
  the answer is a visible warning where a human chooses it.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **Canary content per upstream kind**: recorded as an open implementation-level choice to
  be decided at the keyboard. What exactly a forwarder's canary query is (a fixed
  well-known name? a name whose failure is unambiguous? one that will not be answered from
  a cache and therefore actually tests the path?) and what a recursor's descent target is,
  are both unfixed. Needs clarification: a probe that can be satisfied trivially proves
  nothing, and a probe that depends on a third party's uptime produces false negatives.
- **SRTT decay constants and circuit thresholds**: explicitly recorded as open,
  implementation-level, and to be decided at the keyboard. Needs clarification: the EWMA
  weight, the consecutive-failure count that opens the circuit, the open-state duration
  before half-open, and how many half-open successes close it.
- **Idle window length**: the probe policy names "idle beyond a window" without fixing the
  window. It interacts directly with the standby case it exists for.
- **What counts as a failure for health purposes**: a timeout clearly does; a transport
  error clearly does. SERVFAIL, REFUSED and a malformed response are judgement calls, and
  conflating "the upstream is broken" with "the upstream correctly told us this name is
  broken" would fail out a healthy provider on a bad domain. Not settled by the
  requirement.
- **`race` accounting**: when N members are raced, one answer is used and N−1 are
  discarded. Whether the discarded results feed `HealthState` (they are genuine
  observations) is not specified, and the answer materially changes what health means
  under `race`.
- **Encrypted outbound transport**: v1 explicitly includes DoT/DoH **inbound** and
  explicitly excludes DoQ in both directions; encrypted **outbound** forwarding is named
  nowhere. The phase scope says "a Do53 forwarder", singular. Needs clarification only to
  the extent that the port must not be shaped so as to foreclose it.
- **Pool membership vs. multiple pools**: configuration owns "upstreams and pools"
  (plural) and strategy is chosen "per pool", but nothing in this phase's scope says how a
  query selects a *pool*. Likely out of scope here; worth naming rather than silently
  assuming one pool.

### Edge Cases

- **Every member down.** Ordered failover with an exhausted list, or a pool whose members
  are all circuit-open. The pipeline must get a definite, non-panicking answer (SERVFAIL)
  rather than hanging, and the probe policy must keep trying to restore.
- **All members idle at boot.** At startup no member has any health record at all, so
  "idle beyond window" is trivially true for every member. Whether the pool cold-starts by
  probing everything, or treats unknown as healthy and learns from the first real queries,
  is a real behavioural fork.
- **Truncation and TCP fallback.** A TC=1 UDP response must be retried over TCP; the
  latency sample and the failure accounting for the combined operation need a defined
  meaning.
- **Upstream returns a response that does not match the query** (wrong ID, wrong question
  section). This is both a correctness matter and a spoofing-resistance matter; the
  forwarder must reject it, and the rejection must be classified as a failure of a known
  kind.
- **A member recovers exactly while half-open.** Concurrent probe and real traffic hitting
  the same member in half-open needs a defined rule, or the circuit can flap.
- **`race` where the fastest responder is also the wrong one** — a fast REFUSED beating a
  slow correct answer. Racing on latency alone selects for speed, not truth.
- **Weighted selection with a zero weight, a single member, or all weights equal.**
  Degenerate configurations must be well-defined rather than dividing by zero — which,
  under `arithmetic_side_effects = deny`, is a compile-visible concern rather than a
  runtime surprise.
- **Round-robin under concurrency.** The cursor is shared mutable state on the hot path;
  fairness and contention both matter.
- **Clock behaviour under the injected `Clock`.** Tests will jump time forward by large
  amounts; SRTT and circuit timing must not overflow or misbehave under a jump, and must
  not depend on wall-clock monotonicity assumptions the fake clock does not honour.
- **A probe and a real query racing to record conflicting outcomes** for the same member.
- **An upstream that is reachable but chronically slow.** SRTT captures it; whether it is
  ever removed from rotation under a non-race strategy is undefined.

### Technical Risks

- **`race` selection is a privacy hazard, not a load-balancing mode.** Recorded verbatim
  as a project risk: one query goes to N providers, so
  **outbound QPS multiplies and every provider in the pool sees every domain**. In a mixed
  pool containing the recursor,
  **the privacy posture changes per query non-deterministically** — some queries are
  resolved privately by descent, others are simultaneously handed to every configured
  third party, and which happens is not predictable from the query. This needs a
  **loud warning in the UI, not a config comment**. Impact: a user who selects `race` for
  latency silently adopts the worst privacy profile in the system. Mitigation direction:
  implement `race` faithfully, keep the per-query attribution needed to make the behaviour
  visible, and treat the UI warning (Phase 11) as a requirement this phase writes down,
  not an afterthought. It also sits badly beside the deliberate exclusion of EDNS Client
  Subnet, which was omitted precisely because it leaks client topology — `race` leaks the
  query itself to everyone.
- **Probe traffic is outbound traffic to third parties.** Every probe is a query a
  third-party resolver sees. The narrow probe policy is itself the mitigation; loosening
  it later would quietly re-open a privacy cost, not just a bandwidth one.
- **Health can be wrong in the direction that matters.** Passive health, by construction,
  learns only from traffic that already happened. A member that just broke is discovered
  by a real query failing — i.e. by a user-visible failure. The circuit limits how many,
  but does not eliminate the first.
- **Concurrency around `HealthState`.** It is read on the hot path by selection and
  written on the hot path by outcome recording, from many tasks at once. Contention here
  is a resolution-latency problem, and a torn or lock-heavy design would show up as tail
  latency under load.
- **The exit criteria require time control that cannot be retrofitted.** The injected
  `Clock` is decided upstream in Phase 2 precisely because it cannot be added later; if
  anything in this phase reads real time directly, "circuit open and close under an
  injected `Clock`" becomes untestable and the fix is a rewrite.
- **The lint regime is strict and load-bearing.** `unwrap`/`expect` denied outside tests,
  `thiserror` required, `tracing` required, sync I/O denied, `indexing_slicing` and
  `arithmetic_side_effects` denied. SRTT arithmetic, weight arithmetic and timeout
  arithmetic all become checked operations. This is the intended tax, but it makes
  otherwise-trivial code verbose and it is not optional.
- **`panic = "deny"` is load-bearing and its real mitigation arrives last.** styx is a
  **single process, single binary** — DNS listeners, Leptos SSR and background workers
  share state via `Arc` — so a panic anywhere takes DNS down for the whole house. The
  `catch_unwind` boundary and supervised task model are Phase 12; everything before relies
  on the lint. The probe scheduler in this phase is a long-lived background task and is
  therefore exactly the kind of thing that must not be able to die silently or take the
  process with it.
- **`hickory-proto` must remain dev-only.** The fake upstreams for this phase are the
  natural place for it to leak into a normal dependency path. The CI check exists because
  the exception would otherwise rot into a real dependency; this phase is where the
  pressure is highest.
- **No operational feedback.** Phases 1 through 7 produce nothing a human can look at
  except `dig` output, and because the cutover is last, nobody is waiting on it either.
  Pool behaviour under real household traffic — which upstreams actually flap, how often,
  how slow — is unknown until the very end, when acting on it is most expensive.
  Socket-level tests against controllable fakes are the only signal this phase gets.
- **Crate-isolation pressure.** Phase 5's recursor implements this port from another crate
  and must not be allowed to reach into pool internals; Phase 6's forwarder-side DNSSEC
  pull must not be allowed to widen the port. Both pressures land on the boundary defined
  here, and both are enforced by the layering gates rather than by discipline.

### Acceptance Criteria Coverage

The phase states its exit criteria as two clauses; both are decomposed here.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | Failover behaviour proven at socket level against fake upstreams | Yes | Requires fakes that can fail, time out and recover on command. Needs the standby-probe case covered explicitly, since that is the scenario the probe policy exists for. |
| 2 | Round-robin behaviour proven at socket level against fake upstreams | Yes | Needs a concurrency case, not just a sequential one; fairness under parallel dispatch is where a shared cursor goes wrong. |
| 3 | Weighted behaviour proven at socket level against fake upstreams | Yes | Distribution assertions need a defined tolerance, and degenerate weight configurations need defined behaviour (see Edge Cases). |
| 4 | Race behaviour proven at socket level against fake upstreams | Yes | Must assert the *fan-out*, not only the answer — that N queries left the box — because the fan-out is the privacy hazard and is invisible if only the returned answer is checked. Whether losing responses feed health is unspecified (see Ambiguities). |
| 5 | Circuit **open** under an injected `Clock` | Yes | Blocked on choosing the consecutive-failure threshold — explicitly an open keyboard-level choice. The test shape is independent of the value; the value needs to be picked and then asserted. |
| 6 | Circuit **close** under an injected `Clock` | Yes | Depends on the half-open/restore rule, which is the same open choice, and on the down-member probe path being what drives restoration. |
| — | *Implied by scope, not stated as an exit criterion*: Do53 forwarder over **both** UDP and TCP | Partial | Scope names UDP and TCP; the exit criteria name neither. TCP fallback on TC=1 needs its own socket-level test or it ships untested. |
| — | *Implied by scope, not stated*: `HealthState` fields (SRTT EWMA, consecutive failures, circuit state, last-probe-at) all fed by real traffic | Partial | Only circuit behaviour is named in the exit criteria. SRTT decay is unverified by the stated ACs and its constants are an open choice. |
| — | *Implied by scope, not stated*: healthy actively-used upstreams generate **no** probe traffic | Partial | This is a negative assertion and will not be covered by any of the six stated criteria. It needs an explicit test that counts probe queries against a busy healthy fake and asserts zero, or the policy's whole point is unenforced. |

---

## Summary

Phase 3 is small in surface and large in consequence: it fixes the shape of the `Upstream`
port that Phases 5 and 6 must live within, and it establishes health as a *derived*
property of traffic the pool already observes rather than as a subsystem with its own
abstraction. The three commitments that must survive into design are (1) one port for
forwarders and recursors, kept narrow; (2) concrete pool-owned `HealthState` with probing
as real resolution, scoped to the zero-traffic blind spot; and (3) `race` treated as a
privacy decision with a visible warning rather than as a latency feature. The open items —
SRTT decay constants, circuit thresholds, and the canary question per upstream kind — are
recorded as deliberate keyboard-level choices, not as unknowns.
