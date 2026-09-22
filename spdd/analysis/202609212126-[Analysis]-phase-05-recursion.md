# SPDD Analysis: Phase 5 — Recursion (`styx-recursion`)

> Project: **styx** — a filtering DNS resolver written from scratch in Rust, replacing
> Pi-hole's role on a home network (recursive/forwarding resolution, per-client blocking
> policy, Leptos admin UI). Single process, single binary.
>
> **Codebase context: greenfield, no existing implementation.** At the time of this
> analysis the repository contains only `SPEC.md`, `ROADMAP.md`, `docs/specs/` and a
> stub `arch-lint.toml`. There is no git repository, no Cargo workspace, no `.rs` file,
> no schema and no prior SPDD artefact. All grounding therefore comes from the settled
> design record rather than from code, and every decision that record carries is
> **inlined below in full** — this document must stand alone once that record is gone.

---

## Original Business Requirement

The following is the phase specification verbatim.

```markdown
# Phase 5 — Recursion (`styx-recursion`)

> Part of [ROADMAP.md](../../ROADMAP.md) · Previous: [Phase 4 — Answer cache](04-answer-cache.md) · Next: [Phase 6 — DNSSEC](06-dnssec.md)

The first of the two hand-written security-critical subsystems.

## Scope

- The infrastructure cache: delegations, NS sets, per-nameserver RTT and EDNS
  capability, keyed by zone and nameserver (decision 5).
- The descent, with **relaxed QNAME minimisation present from the first test**
  (decision 10) — it changes what is asked at every step and is not a bolt-on.
  CNAME chasing, glue handling, bailiwick enforcement, loop and depth limits.
- The `RecursionDiagnostics` read model, published separately from `HealthState`
  (decision 9).

## Exit criteria

Hermetic socket tests, **and** the differential run against `unbound` over the
domain corpus — RCODE and rrset agreement.
```

### Governing decisions referenced by the requirement (inlined verbatim)

The phase spec cites three decisions by number. Because the source record is being
retired, their full text and rationale are reproduced here.

**The infrastructure cache decision — "Two structurally different caches."**
> The _answer cache_ (RRsets + messages, keyed by question) is global and lives in
> `styx-resolution`. The _infrastructure cache_ (delegations, NS sets, per-nameserver
> RTT and EDNS capability, keyed by zone and nameserver) lives in `styx-recursion` and
> is used only by recursion.

**The diagnostics decision — "Per-kind diagnostics travel a separate path."**
> `styx-recursion` publishes root/TLD reachability as its own read model, consumed
> directly by `styx-admin`/`styx-web`, never through the pool. Named distinctly from
> selection health (`RecursionDiagnostics` vs `HealthState`) so they are never
> conflated.

**The QNAME-minimisation decision — "QNAME minimisation (RFC 9156) ships in v1, in
relaxed mode."**
> A naive recursor sends the full qname to the root and to every TLD server on the way
> down — the same leak the ECS non-goal exists to prevent, one layer up. The descent
> sends only the next label and falls back to the full qname when a server responds
> badly, because a nontrivial number of real authoritative servers mishandle minimised
> queries. This changes what the descent asks at every step, so it is designed in from
> the first recursion test; it is not a bolt-on.

### Surrounding decisions that bind this phase (inlined verbatim)

**Recursion is first-class, not a stretch goal.**
> Both forwarding and recursion are first-class in v1.

**Everything is hand-written.**
> The entire DNS stack is written from scratch — wire codec, server loop, caches,
> recursion algorithm, DNSSEC validation. No `hickory-dns`, no `domain` crate for the
> protocol.

**Recursion is an `Upstream`, not a server mode.**
> `Upstream` is the unifying abstraction. An upstream is _either_ a forwarder or a
> recursor. A pool holds upstreams of mixed kinds, each with its own health and
> behaviour config. Recursion is an implementation of the same port, not a separate
> server mode.

**Health is concrete and passive; probes are exceptional.**
> No health-check trait. The pool owns a concrete `HealthState` per member (SRTT EWMA,
> consecutive failures, circuit state, last-probe-at), fed by outcomes of real traffic
> that the pool already observes. Probing is `Upstream::resolve(canary)` with per-kind
> config defaults — a forwarder's canary is one query, a recursor's is a full descent,
> which is the correct test.
>
> Probes run only when needed: against any member idle beyond a window (the
> ordered-failover standby case — passive health is structurally blind to an upstream
> receiving zero traffic), and against any member currently marked down, to decide when
> to restore it. Healthy, actively-used upstreams generate no probe traffic.

**DNSSEC chain material is pushed out of the descent.**
> DNSSEC validation is its own crate behind a `ChainSource` port: `styx-recursion`
> _pushes_ chain material it already collected during descent (DS RRsets arrive unasked
> in DO=1 referrals, per RFC 4035 §3.1.4), while forwarder paths _pull_ DS/DNSKEY on
> demand. One validator, two feeding strategies. This avoids widening the `Upstream`
> port with a "chain material observed en route" field that would be permanently empty
> for forwarders.

**The hot path touches no I/O.**
> Matcher state is in memory, built at boot and on reload. Turso holds config, adlist
> definitions, clients/groups and history only. A DB outage degrades logging and admin,
> never resolution.

**Crate shape and isolation.**
> One crate per feature; `domain`/`application`/`infrastructure` are modules inside it.
> Cargo enforces feature-to-feature isolation; arch-lint enforces layering within a
> crate.
>
> Feature crates never depend on each other. Cross-feature needs are expressed as a port
> in the consumer's `domain`, implemented by an adapter in the binary — e.g.
> `styx-resolution` declares a `FilterPolicy` port and `styx` wires `styx-filtering`
> into it. `styx-web` may depend on a feature's `application` layer, because it is
> presentation, not a peer.
>
> `styx-proto` is shared foundation, not a feature crate. Every crate parses through the
> wire codec, so "feature crates never depend on each other" does not reach it. This is
> the one explicit exception, and `[[restrict-use]]` must be written so as not to forbid
> it.

**Testing style.**
> TDD cycles run at socket level by default. Feature tests drive real UDP/TCP against an
> ephemeral-port server, with in-process fake root and authoritative servers, and an
> injectable `Clock` — because RRSIGs carry inception and expiration timestamps, so any
> recorded signature fixture expires on a date you did not choose. Time injection cannot
> be retrofitted into a validator; it is a rewrite.
>
> `hickory-proto` is the test oracle, `[dev-dependencies]` only. The fake root/TLD/
> authoritative servers and the expected-byte fixtures have to encode DNS wire format; if
> our own codec encodes them, the resolver and its oracle share every bug and a green
> suite proves only self-consistency. The from-scratch ban is on shipping code, not the
> test rig. A CI check asserts `hickory-proto` appears in no normal or build dependency
> path, or the exception rots into a real dependency.

**Acceptance — why the differential run is the gate.**
> Acceptance runs in two tiers. Per push, hermetic and fast: socket tests, fuzzing, and
> the full lint/arch gate. Per phase, non-hermetic: a corpus of real domains resolved
> through both styx and a local `unbound`, diffing RCODE, AD bit and rrset contents.
> **In-process fakes only prove the resolver does what we _think_ delegation means; the
> differential run is the only gate that catches a shared misreading.** It depends on the
> live internet and is flaky by nature, so it gates a phase and never a push.

**Configuration boundary.**
> Config has two stores with a hard boundary: file owns infrastructure, DB owns policy. A
> TOML file owns everything needed before the DB exists or in order to reach it — listen
> addresses, upstreams and pools, selection strategy, TLS material, trust anchor, DB
> path, log mode. Turso owns everything a human edits at runtime. No overlap means no
> precedence rule, and a dead DB cannot touch resolution, because nothing resolution needs
> lives there. Accepted consequence: changing an upstream requires SSH and a restart,
> which is the thing people most want to do from the UI.

**Cutover is last.**
> styx runs on a dev box until everything works; the household's resolver stays on
> Pi-hole until v1 is complete. Nothing mid-build has to be shippable, breaking changes
> stay free, and phases are ordered by dependency and risk rather than usability. Accepted
> consequence: no operational feedback — cache behaviour, odd client queries, DHCP churn —
> until the end, when it is most expensive to act on.

### Non-goals that bear on this phase (inlined verbatim)

- **EDNS Client Subnet (RFC 7871).** Deliberately omitted; it leaks client topology.
  *This is the privacy posture that relaxed QNAME minimisation extends one layer up: ECS
  stops styx from telling an upstream who is asking; QNAME minimisation stops styx from
  telling the root and every TLD server what is being asked.*
- **DoQ (DNS-over-QUIC, RFC 9250)**, inbound or outbound. *The descent therefore speaks
  Do53 over UDP with TCP fallback only.*
- **Authoritative zone serving.** Local records and per-zone overrides are
  resolution/filtering concerns, not a zone-file server. *The recursor never serves a
  zone; it only follows delegations.*
- **Multi-node or replicated deployment.** One box, one binary, local DB file. *The
  infrastructure cache is process-local and needs no coherence protocol.*
- **RFC 5011 automated trust anchor rollover.** *Out of this phase entirely; the trust
  anchor is the next phase's concern.*
- **DHCP server / multi-user admin & audit trail.** *No bearing on the descent.*

### Phase position

| Relationship | Phase | Why it matters here |
|---|---|---|
| Depends on | **Phase 0 — Foundation and gates** | Workspace, a *working* arch-lint (the committed one is inert), CI, the `just gate` target. `styx-recursion` cannot be a crate before the workspace exists. |
| Depends on | **Phase 1 — Wire codec** (`styx-proto`) | Every query the descent sends and every referral it parses goes through this codec. `styx-proto` is the one permitted cross-crate dependency. |
| Depends on | **Phase 2 — Server loop and test harness** | Supplies the UDP/TCP machinery, the injectable `Clock` the descent's timeouts and RTT decay are measured against, and — critically — the in-process fake root, TLD and authoritative servers built on `hickory-proto` that the hermetic half of this phase's exit criteria runs against. |
| Depends on | **Phase 3 — `Upstream` port, forwarding, pool** | Defines the `Upstream` trait that the recursor implements, and the `HealthState` that `RecursionDiagnostics` must be kept distinct from. |
| Depends on | **Phase 4 — Answer cache** | Supplies the global answer cache and, more importantly, the bailiwick rules governing what is cacheable at all — which the descent must respect when it harvests referrals and glue. |
| Depended on by | **Phase 6 — DNSSEC** (`styx-dnssec`) | The `ChainSource` push strategy is fed by DS RRsets this phase's descent collects from DO=1 referrals. If the descent does not retain that material, phase 6d cannot be built without re-querying. |
| Depended on by | **Phase 11 — Web UI** (`styx-web`) | Consumes `RecursionDiagnostics` directly, not through the pool. |
| Depended on by | **Phase 12 — Cutover hardening** | The household only moves off Pi-hole once the recursor is trusted. |

---

## Domain Concept Identification

### Existing Concepts (from codebase)

**Greenfield, no existing implementation.** Nothing in this list exists as code yet;
each is a concept *established by an earlier phase's specification* that this phase
consumes rather than defines. They are "existing" in the sense that this phase must not
redefine or fork them.

- **`Upstream` (port, defined in phase 3)**: the unifying abstraction for "something that
  can answer a question". A pool holds upstreams of mixed kinds — forwarders and
  recursors — each with its own health and behaviour config. *Recursion implements this
  port; it is not a separate server mode.* Relationship: the recursor is one `Upstream`
  implementation among several.
- **`HealthState` (concrete type, owned by the pool, phase 3)**: SRTT EWMA, consecutive
  failures, circuit state, last-probe-at, per pool member, fed by the outcomes of real
  traffic the pool already observes. Relationship: the pool derives a recursor's
  `HealthState` from whole-descent outcomes; the recursor never writes to it and never
  routes diagnostics through it.
- **Answer cache (phase 4)**: global, keyed `(qname, qtype, qclass)`, holding RRsets and
  messages, with TTL handling, RFC 2308 negative caching and bailiwick rules.
  Relationship: sibling to, and structurally different from, the infrastructure cache
  this phase introduces. The descent reads and populates it for *answers*; it never
  stores delegation or nameserver-performance material there.
- **`Clock` (injectable, phase 2)**: the single source of time. Relationship: governs
  every descent timeout, every RTT sample, every infrastructure-cache TTL and every
  circuit-style backoff in this phase; it cannot be retrofitted.
- **`styx-proto` wire codec (phase 1)**: message encode/decode, hand-written, fuzzed.
  Relationship: the only cross-crate dependency `styx-recursion` is permitted.
- **Fake root/TLD/authoritative servers (phase 2 harness)**: in-process, built on
  `hickory-proto`, driven over real sockets. Relationship: the hermetic half of this
  phase's exit criteria; deliberately built with a *different* codec than the one under
  test, so that a green suite is not merely self-consistency.
- **Pipeline order (fixed in phase 2)**: local records → filter → cache → upstream.
  Relationship: the recursor sits at the far end of that pipeline; anything that reaches
  it has already missed local records, policy and the answer cache.

### New Concepts Required

- **Descent**: one recursive resolution attempt for one question, from a starting zone
  cut down to an authoritative answer. Owns the current zone cut, the nameservers being
  tried, the accumulated CNAME chain, and the budget (depth, query count, wall clock).
  Relationship: created per query the recursor `Upstream` receives; consults and
  populates the infrastructure cache; emits diagnostics and DNSSEC chain material as
  by-products.
- **Zone cut / Delegation**: the (parent zone, child zone, NS set) triple learned from a
  referral. Relationship: the unit the descent advances by, and the primary keying
  concept of the infrastructure cache.
- **NS set**: the set of nameserver names authoritative for a zone, together with
  whatever addresses are known for them — from in-bailiwick glue, or resolved separately
  when glue is absent or out of bailiwick. Relationship: owned by a delegation; each
  member accrues its own metrics.
- **Nameserver metrics**: per-nameserver, per-address RTT (smoothed), reachability,
  EDNS capability (does this server handle EDNS0 at all, at what buffer size, does it
  tolerate unknown options), and — new here and load-bearing — **whether this server
  mishandles minimised queries**. Relationship: lives in the infrastructure cache; drives
  server selection within an NS set and drives the QNAME-minimisation fallback.
- **Infrastructure cache**: the store for delegations, NS sets and nameserver metrics,
  keyed by zone and by nameserver. Private to `styx-recursion`, used only by recursion.
  Relationship: structurally different from the answer cache — different key space
  (zone/nameserver vs question), different contents (topology and performance vs
  answers), different lifetime rules (NS TTLs and observed behaviour vs record TTLs and
  RFC 2308 negative TTLs), and different consumers (the descent alone vs the whole
  resolution path). Merging them would mean either polluting the global answer cache's
  question-keyed space with topology, or making a performance store subject to answer-
  cache eviction policy.
- **QNAME-minimisation state machine**: per-descent state deciding, at each step, what
  question is actually put on the wire — the next label only (as NS, or as the original
  qtype at the final step) versus the full qname — and how a bad response is classified
  as "this server mishandles minimisation" rather than "this name does not exist".
  Relationship: wraps *every* query the descent sends; its fallback verdicts are recorded
  against the nameserver in the infrastructure cache so the lesson outlives the descent.
- **Bailiwick rule (applied, not defined here)**: the test that a record offered by a
  server is one that server is entitled to speak for. Relationship: gates what glue,
  what referral data and what answers the descent will believe and cache — a
  cache-poisoning defence, not an optimisation.
- **CNAME chain**: the sequence of aliases followed within one client question, with its
  own loop and length limits, and its own restart-at-the-root semantics when the target
  leaves the current zone.
- **`RecursionDiagnostics`**: a read model published by `styx-recursion` describing
  root/TLD reachability and descent health. Relationship: consumed **directly** by the
  admin/web layer, never routed through the pool, and named distinctly from `HealthState`
  so the two are never conflated. `HealthState` answers "should the pool send the next
  query here?"; `RecursionDiagnostics` answers "is the internet's delegation
  infrastructure reachable from this box?" — different questions, different consumers,
  different lifetimes.
- **Chain material collected en route**: DS RRsets (and the referrals carrying them) that
  arrive unasked in DO=1 referrals. Relationship: retained by the descent and pushed to
  the next phase's `ChainSource`; the reason it must be *retained* here is that
  re-querying for it later would double the descent's traffic and could reach a different
  server with a different view.
- **Root hints**: the bootstrap set of root nameserver names and addresses, and the
  priming query that replaces them with a live root NS set. Relationship: the seed of the
  infrastructure cache; it comes from the TOML file, because file owns infrastructure.

### Key Business Rules

- **Minimise by default, fall back on evidence.** Every step of the descent asks only for
  the next label below the current zone cut. The full qname is sent only after a server
  has demonstrated it mishandles a minimised query. *Why:* a naive recursor tells the
  root and every TLD server on the way down the whole name being looked up — that is the
  exact leak the EDNS Client Subnet non-goal exists to prevent, one layer up. *Why
  relaxed rather than strict:* a nontrivial number of real authoritative servers
  mishandle minimised queries, and a strict recursor simply fails on those names.
  Governs: descent, QNAME-minimisation state machine, nameserver metrics.
- **The fallback verdict must not be confused with a negative answer.** A server that
  returns NXDOMAIN, an empty NOERROR, FORMERR, NOTIMP or REFUSED to a minimised
  *intermediate* query may be broken rather than authoritative for that absence. The
  state machine must classify, retry with the full qname, and only then conclude. Governs:
  QNAME-minimisation state machine, descent.
- **Nothing outside a server's bailiwick is believed or cached.** Applies to glue,
  referral NS sets, and answers alike. Governs: descent, infrastructure cache, answer
  cache interaction.
- **The infrastructure cache never holds answers, and the answer cache never holds
  topology.** Governs: infrastructure cache, answer cache.
- **Every descent is bounded.** Depth, total outbound queries, CNAME chain length, and
  wall-clock budget, all measured against the injectable `Clock`. An unbounded recursor is
  a denial-of-service amplifier against third parties and against itself. Governs:
  descent.
- **Diagnostics never travel through the pool.** `RecursionDiagnostics` is published by
  `styx-recursion` and read by the admin/web layer directly. Governs:
  `RecursionDiagnostics`, `HealthState`.
- **A recursor's health probe is a full descent.** Not a single query — that is the
  correct test of a recursor, and it is what makes the recursor a peer of a forwarder
  behind the same port. Governs: `Upstream` implementation.
- **No EDNS Client Subnet is ever attached to an outbound query.** Governs: descent, EDNS
  handling.
- **The descent performs no I/O other than DNS.** No database, no disk. Governs: crate
  boundaries.
- **DO=1 is set on descent queries and the DS material that comes back is retained**, even
  though validation itself lands in the next phase. *Why now:* the alternative is a
  descent redesign one phase later, and DS RRsets arrive unasked in referrals, so the only
  cost is keeping them.
- **Authoritative answers are distinguished from referrals and from lame delegations.** A
  server that answers non-authoritatively for a zone it was delegated is lame; the descent
  must move on and remember.

---

## Strategic Approach

### Solution Direction

`styx-recursion` is a feature crate with `domain` / `application` / `infrastructure`
modules inside it, depending on no other feature crate — only on `styx-proto`, the one
explicit shared-foundation exception.

- **`domain`** holds the descent as a deterministic, I/O-free state machine: given the
  current descent state and a parsed response, it produces the next action (query server
  X for question Q, follow a CNAME, return an answer, fail). The QNAME-minimisation state
  machine, bailiwick rules, budgets and the delegation/NS-set types live here. This is
  where the correctness of the resolver actually lives, and it is testable without a
  socket.
- **`application`** drives that state machine: it owns the loop, consults the
  infrastructure cache, issues queries through the transport, applies timeouts against the
  injected `Clock`, records nameserver metrics, accumulates DNSSEC chain material, and
  publishes `RecursionDiagnostics`.
- **`infrastructure`** holds the concrete infrastructure cache and the Do53 transport
  adapter (UDP with TCP fallback on TC), plus the root-hints loader.

The crate's outward face is an implementation of the `Upstream` port from phase 3 —
identical in shape to the forwarder. The binary wires it into a pool. Nothing about the
server loop, the pipeline order or the pool changes to accommodate it. *Why:* making
recursion "a mode" would fork the pool, the health model and the config into two shapes
and make a mixed pool — a recursor alongside a forwarder, with a selection strategy
between them — impossible to express.

Errors are `thiserror` enums returned through `Result<T, E>`; there is no panic path, and
no exception-mapping layer. Observability is `tracing` spans — one span per descent, one
child per outbound query — which is also what makes the differential run's disagreements
diagnosable.

Data flow: `Upstream::resolve(question)` → descent state machine seeded from the
infrastructure cache (root hints if cold) → loop { choose server from NS set by metric →
compose the minimised question → send → classify response as referral / answer / CNAME /
lame / broken-minimisation → update infrastructure cache and metrics → advance zone cut }
→ authoritative answer, with collected chain material attached for the next phase's
validator to pull from, and diagnostics updated as a side effect.

### Key Design Decisions

- **QNAME minimisation is built into the first test, not added later.**
  *Trade-off:* it makes the very first descent harder — the question on the wire is never
  simply the client's question, and every response classification has an extra "was this a
  minimisation failure?" branch. Adding it afterwards would be cheaper *today*.
  *Recommendation:* build it in. It changes what is asked at every step, so retrofitting
  it means rewriting the descent's core loop and every test fixture that encodes an
  expected outbound query. The privacy rationale is the same one behind refusing EDNS
  Client Subnet: do not hand out more than the answer requires. Relaxed, not strict, mode —
  because strict mode fails outright on the nontrivial population of authoritative servers
  that mishandle minimised queries, and a resolver that cannot resolve is not private, it
  is broken.

- **The infrastructure cache is a separate store, not a namespace in the answer cache.**
  *Trade-off:* two caches to size, evict, instrument and reason about, instead of one.
  *Recommendation:* separate. The key spaces differ (zone + nameserver vs
  `(qname, qtype, qclass)`), the contents differ (delegations, NS sets, RTT, EDNS
  capability vs RRsets and messages), the consumers differ (recursion alone vs the whole
  resolution path), and the lifetime rules differ (observed behaviour and NS TTLs vs record
  TTLs and RFC 2308 negative caching). It also keeps the crate boundary honest: the
  infrastructure cache is private to `styx-recursion`, so no other crate can grow a
  dependency on recursion's internal topology model.

- **`RecursionDiagnostics` is published directly to the admin/web layer, not through the
  pool.**
  *Trade-off:* a second observability path to wire, and the temptation to "just add a
  field to `HealthState`" is real.
  *Recommendation:* separate path, distinct name. Routing per-kind diagnostics through the
  pool would force `HealthState` to carry fields that are permanently meaningless for a
  forwarder — the same shape of mistake the `ChainSource` port exists to avoid on the
  DNSSEC side (widening `Upstream` with a "chain material observed en route" field that
  would be permanently empty for forwarders). The distinct naming is deliberate: the two
  answer different questions and must never be conflated in code, in the UI, or in a
  conversation about an outage.

- **The recursor's health probe is a full descent.**
  *Trade-off:* an expensive probe.
  *Recommendation:* keep it. It is the only probe that actually tests what a recursor does,
  and probes are rare by construction — they run only against members idle beyond a window
  (the ordered-failover standby case, where passive health is structurally blind because
  the upstream receives zero traffic) and against members currently marked down, to decide
  when to restore them. Healthy, actively-used upstreams generate no probe traffic at all.

- **DO=1 during descent, with DS material retained, before there is a validator.**
  *Trade-off:* this phase carries work whose consumer does not exist yet, and the retained
  material is dead weight until the next phase.
  *Recommendation:* do it now. DS RRsets arrive unasked in DO=1 referrals (RFC 4035
  §3.1.4), so collecting them costs nothing extra on the wire; the alternative is either
  re-querying later (doubling traffic, and possibly reaching a different server with a
  different view) or redesigning the descent one phase later.

- **Root hints come from the TOML file.**
  *Trade-off:* changing them requires SSH and a restart, which is exactly the accepted
  consequence already recorded for upstream configuration.
  *Recommendation:* file, not DB. The recursor must work before the database exists and
  without it ever existing — a dead DB cannot touch resolution, because nothing resolution
  needs lives there.

- **The differential run against a local `unbound` is the phase gate, not a nicety.**
  *Trade-off:* it needs the live internet, and real DNS changes underneath the corpus, so
  it will sometimes fail for reasons that are not a bug here.
  *Recommendation:* keep it as the gate, and keep it out of the per-push gate. In-process
  fakes only prove the resolver does what *we think* delegation means; a fake built from
  the same misreading as the resolver will agree with it enthusiastically. The differential
  run is the only check that catches a shared misreading, because `unbound` was written by
  other people reading the same RFCs independently.

### Alternatives Considered

- **Strict QNAME minimisation (no fallback).** Rejected: a nontrivial number of real
  authoritative servers mishandle minimised queries, so strict mode turns a privacy win
  into resolution failures on real names. Relaxed mode keeps the privacy default and
  degrades per-server, on evidence.
- **QNAME minimisation as a later increment.** Rejected: it changes what is asked at every
  step. Every descent test encodes an expected outbound question, so bolting it on means
  rewriting the loop and the fixtures together.
- **One cache for everything.** Rejected: see above — different keys, contents, consumers
  and lifetimes; and it would leak recursion's topology model across a crate boundary.
- **Recursion as a distinct server mode rather than an `Upstream`.** Rejected: it would
  fork the pool, the selection strategies and the health model, and make a mixed pool
  inexpressible.
- **Diagnostics folded into `HealthState`.** Rejected: permanently-empty fields on the
  forwarder side, and two different questions answered by one conflated type.
- **Using an existing DNS library for the descent.** Rejected by the project's founding
  constraint: the entire stack is written from scratch. `hickory-proto` appears only as the
  test oracle in `[dev-dependencies]`, precisely so that the resolver and its fakes do not
  share every bug — and a CI check asserts it never appears in a normal or build dependency
  path.
- **Deferring DO=1 to the DNSSEC phase.** Rejected: re-querying for DS material later is
  strictly worse than keeping what arrives unasked.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **"Loop and depth limits" is unquantified.** The phase spec names the concern but not the
  numbers — maximum delegation depth, maximum outbound queries per client question, maximum
  CNAME chain length, per-query and whole-descent timeouts. These are implementation-level
  choices to settle at the keyboard, consistent with how the design record treats SRTT decay
  constants, circuit thresholds and the canary question per upstream kind; but they must be
  named constants with a written rationale, not scattered literals, because they are the
  denial-of-service boundary.
- **The minimisation fallback trigger set is not enumerated.** Which response conditions
  count as "responds badly"? At minimum: FORMERR, NOTIMP, REFUSED, SERVFAIL, an NXDOMAIN at
  an intermediate label, an empty NOERROR that is neither referral nor answer, and timeout.
  Each needs an explicit verdict, and the boundary between "broken server" and "genuine
  absence" is the whole difficulty.
- **Fallback scope and memory are unstated.** Does a fallback apply to that one query, the
  rest of that descent, or that nameserver for a cached period? The infrastructure cache
  holding per-nameserver EDNS capability strongly implies per-nameserver memory with a TTL,
  but the requirement does not say so outright.
- **`RecursionDiagnostics` contents are named only as "root/TLD reachability".** The exact
  read model — which roots, which TLDs, last-success timestamps, priming state, descent
  failure counts — is undetermined. Its *routing* (direct to admin/web, never through the
  pool) and its *naming* (distinct from `HealthState`) are settled; its shape is not.
- **Infrastructure cache sizing and eviction policy are unspecified.** It has no stated
  memory budget, unlike the matcher's documented figure.
- **The corpus for the differential run is undefined** — size, selection, how it is
  curated, and how often it is refreshed.
- **IPv6 behaviour during descent is unaddressed.** Whether the descent prefers A or AAAA
  glue, and what happens on a box with no IPv6 path to some roots, is not stated.

### Edge Cases

- **Glue-less delegation.** The NS set names servers under a zone that is not a descendant
  of the delegated zone, so no glue can be provided; their addresses must be resolved by a
  sub-descent — which can recurse into the same situation. This needs its own budget, or it
  is an unbounded loop.
- **Circular glue dependency.** `a.example.` is served by `ns.b.example.` and vice versa,
  with no usable glue on either side. Must terminate.
- **Out-of-bailiwick glue offered anyway.** A classic cache-poisoning vector: the record must
  be discarded, not merely deprioritised.
- **Lame delegation.** The parent delegates to a server that answers non-authoritatively, or
  refuses. The descent must try the rest of the NS set and record the lameness rather than
  concluding SERVFAIL for the name.
- **Empty non-terminal.** A name with no records but with descendants must yield NOERROR/
  NODATA, not NXDOMAIN — and a minimised query at exactly that label is the textbook case
  where a naive implementation manufactures a false NXDOMAIN.
- **Minimisation against a server that is broken only for some names.** The per-nameserver
  fallback flag is a coarse instrument; a partially-broken server means either unnecessary
  full-qname leakage or a per-name distinction the cache is not keyed for.
- **CNAME to a name in a different zone, and CNAME loops.**
- **DNAME.** Not mentioned in the requirement at all; it changes how a qname is rewritten
  mid-descent and interacts directly with minimisation.
- **Referral loop / delegation to the same zone.** A server that refers to the zone it was
  already asked about.
- **Truncation (TC) on a referral.** TCP fallback machinery comes from phase 2, but the
  descent must retry the same *minimised* question over TCP, not the full one.
- **EDNS-intolerant server.** Must be discovered, cached as a capability, and re-tried
  without EDNS — while the DO=1 requirement pulls in the other direction.
- **Priming failure / all roots unreachable.** What the recursor returns, and what
  `RecursionDiagnostics` shows, when the box has no network at all.
- **Root or TLD NS set changing mid-descent** (the cache holds a delegation that has just
  been superseded).
- **Answer arriving before the descent reaches the target zone** — a server answering
  authoritatively for a name below its own zone cut.

### Technical Risks

- **This is one of the two hand-written security-critical subsystems.** A bug in the descent
  is a cache-poisoning or downgrade vector, not a cosmetic defect. Mitigation direction:
  keep the descent's decision logic in an I/O-free `domain` state machine that can be tested
  exhaustively, and gate the phase on the differential run.
- **The differential gate depends on the live internet and is flaky by nature.** Real DNS
  changes underneath the corpus, so the job will sometimes fail for reasons that are not a
  bug in styx — and that is exactly why it gates a phase and never a push. **The recorded
  consequence is that a genuine regression can hide behind a shrug.** Mitigation direction:
  every differential failure must be triaged to a named cause before the phase is called
  done; a disagreement is never dismissed on the strength of "DNS moved". Curate the corpus
  toward names with stable delegation structure so that movement is rare enough for a
  failure to be notable.
- **Hermetic fakes can only confirm a shared misreading.** The in-process root/TLD/auth
  servers are built by the same people reading the same RFCs as the resolver. Mitigation
  direction: the fakes encode wire format with `hickory-proto` rather than with our own
  codec, so at least the *encoding* is independently derived; and the differential run is
  the gate for the *semantics*.
- **Hand-written wire parsing under `indexing_slicing = deny` and
  `arithmetic_side_effects = deny`.** Every label offset and TTL decrement becomes a checked
  operation. That is the intended tax, but it makes the codec verbose and
  compression-pointer loop detection fiddly — and the descent handles attacker-influenced
  referrals all day. Fuzzing is not optional.
- **`panic = "deny"` is load-bearing.** In a single process, a panic anywhere takes DNS down
  for the whole house; the `catch_unwind` boundary and supervised task model are the real
  mitigation and they do not arrive until the final phase. Until then the lint is the only
  guard, so the descent must contain no unchecked indexing, no unwrap on parsed data, and no
  arithmetic that can overflow on hostile TTLs or counts.
- **Resolution-first plus a last cutover removes every feedback loop.** Phases 1 through 7
  produce nothing a human can look at except `dig` output, and no one is waiting on it
  either. This phase sits in the middle of that stretch: no operational feedback on cache
  behaviour, no real client traffic, no external pressure. The accepted cost of not doing a
  live migration under two hand-written security-critical subsystems.
- **The committed `arch-lint.toml` enforces nothing** until the foundation phase replaces
  it. The file contains `[[layers]]`, which routes arch-lint to its tree-sitter engine; that
  engine ships only a Kotlin grammar and discovers zero `.rs` files, so the run exits green
  having checked nothing. If that fix has not landed, the `domain`/`application`/
  `infrastructure` separation inside `styx-recursion` is unenforced and will drift. Verify
  with a deliberate violation — an inert config looks identical to a passing one.
- **Infrastructure-cache memory on a Raspberry Pi.** The delegation and nameserver-metric
  store grows with the breadth of names resolved and has no stated budget.
- **Descent amplification.** Glue-less delegations and CNAME chains can multiply one client
  query into many outbound queries; without hard budgets styx becomes a reflector.
- **The privacy property is testable only by observing outbound traffic.** Nothing in an
  answer reveals whether the full qname leaked to the root. Tests must assert on what the
  fakes *received*, not only on what came back — otherwise minimisation can silently
  regress to full-qname behaviour while every functional test stays green.
- **`hickory-proto` leaking out of `[dev-dependencies]`.** The CI check asserting it appears
  in no normal or build dependency path must be in place before this phase writes its test
  rig, or the exception rots into a real dependency.

### Acceptance Criteria Coverage

The phase states two exit criteria. Both are preserved verbatim in the canvas Safeguards
section.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | **Hermetic socket tests** — the descent proven over real UDP/TCP against the in-process fake root, TLD and authoritative servers, under an injected `Clock`. | Yes | Depends on the phase-2 harness existing and on `hickory-proto` being available as the fakes' encoder. Tests must additionally assert on the *questions the fakes received*, or the minimisation property is untested. Fixtures for glue-less delegation, lame delegation, empty non-terminal, CNAME chains and minimisation-hostile servers must be authored as part of this phase — the harness supplies the machinery, not the scenarios. |
| 2 | **The differential run against `unbound` over the domain corpus — RCODE and rrset agreement.** | Partial | Addressable, but three things are undefined and must be settled inside this phase: the corpus itself (size, selection, curation, refresh cadence), the local `unbound` configuration it is diffed against (it must be configured to recurse, with a comparable DNSSEC posture, or the diff is meaningless), and the triage discipline for a disagreement. Note the deliberate narrowing: this phase diffs **RCODE and rrset contents**; the **AD bit** is explicitly the next phase's criterion, since there is no validator yet. The recorded risk — that it needs the live internet, is flaky by nature, gates a phase and never a push, and that a genuine regression can therefore hide behind a shrug — applies in full. |
