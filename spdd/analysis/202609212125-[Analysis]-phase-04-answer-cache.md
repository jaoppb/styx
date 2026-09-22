# SPDD Analysis: styx Phase 4 — Answer cache

> **Project**: `styx` — a filtering DNS resolver written from scratch in Rust, replacing
> Pi-hole's role on a home network (recursive/forwarding resolution, per-client blocking
> policy, Leptos admin UI). Single process, single binary, one box.
>
> **Codebase state**: **Greenfield, no existing implementation.** At the time of this
> analysis the repository contains only `SPEC.md`, `ROADMAP.md`, `docs/specs/` and an
> inert `arch-lint.toml`. There is no git repository, no Cargo workspace, no `.rs` file
> and no migration. Concept-driven codebase exploration therefore returned zero matches
> for every domain noun (`cache`, `rrset`, `ttl`, `bailiwick`, `negative`, `message`);
> `spdd/analysis/` and `spdd/prompt/` exist but are empty, so there is no prior SPDD
> context to inherit. Every "existing concept" named below exists as a *committed design
> decision for an earlier phase*, not as code. All grounding comes from the project's
> decision record and phase specs, which are reproduced inline here because those source
> documents are being retired once this analysis is written.

---

## Original Business Requirement

The phase specification, verbatim:

```markdown
# Phase 4 — Answer cache

> Part of [ROADMAP.md](../../ROADMAP.md) · Previous: [Phase 3 — Upstream pool](03-upstream-pool.md) · Next: [Phase 5 — Recursion](05-recursion.md)

## Scope

- RRset and message cache keyed `(qname, qtype, qclass)`, global (decision 15).
- TTL handling, RFC 2308 negative caching, and bailiwick rules governing what is
  cacheable at all.

## Exit criteria

TTL expiry, eviction and negative-cache behaviour under injected time; no
out-of-bailiwick data is ever cached.
```

### The decisions this phase inherits, inlined

The phase spec above refers to numbered decisions in a project-wide decision record that
is being deleted. Their full text and rationale, which this phase must preserve:

**Two structurally different caches.** The *answer cache* (RRsets + messages, keyed by
question) is global and lives in `styx-resolution`. The *infrastructure cache*
(delegations, NS sets, per-nameserver RTT and EDNS capability, keyed by zone and
nameserver) lives in `styx-recursion` and is used only by recursion. *Phase 4 builds only
the first.* They differ structurally because they are keyed on different things and
answer different questions: the answer cache is keyed by what a **client asked** and is
consumed by every resolution path; the infrastructure cache is keyed by **where to ask
next** and is meaningless outside a recursive descent. Collapsing them into one store
would key delegation state by question, which is the wrong index and would leak recursion
internals into every forwarding query.

**The answer cache stays global, keyed `(qname, qtype, qclass)`.** Group policy is applied
as a filter over the resolution result, on the way out. **No per-group cache namespaces: N
groups would multiply memory and shred the hit rate the cache exists to provide.** Full
per-client groups are a v1 feature — clients, groups and list-to-group assignment are
first-class in the domain model, the DB and the UI — so the temptation to namespace the
cache per group is real and is explicitly rejected here. The verdict is computed per
query from a bitmask walk (`!(allow & g) && (block & g)`), which is cheap; duplicating
cached DNS data per group is not.

**Local records are answered before the cache and are always Insecure.** A/AAAA/CNAME/PTR
rows held in the database, editable in the UI, matched ahead of the answer cache and ahead
of any upstream. **They never enter the answer cache** and never reach the validator: AD
cleared, no forged signature, the same honesty rule as a blocked reply.

**Blocked replies: five modes, NXDOMAIN by default** (`NXDOMAIN`, `NULL` = `0.0.0.0`/`::`,
`NODATA`, `IP`, `IP-NODATA-AAAA`). Regardless of mode: qtypes other than A/AAAA get NODATA,
blocked replies carry a short TTL so unblocking takes effect quickly, **AD is always
cleared and no RRSIG is ever forged**, and filtering is applied *before* validation — a
block is not a validation verdict.

**Consequence for this phase: neither local records nor blocked replies ever enter the
answer cache, because both are forged answers.** Caching a forged answer would let one
group's block leak into another group's resolution (the cache is global by design), and
would make an unblock take effect only after the forged TTL expired rather than
immediately.

**The pipeline order is fixed and is a correctness property, not a detail**:
`local records → filter → cache → upstream`.

**The hot path touches no I/O.** Matcher state is in memory, built at boot and on reload.
The database holds config, adlist definitions, clients/groups and history only. A database
outage degrades logging and admin, never resolution. *The answer cache is therefore a
process-local, memory-only structure with no persistence and no warm start.*

**TDD cycles run at socket level by default**, with an **injectable `Clock`** — because
RRSIGs carry inception and expiration timestamps, so any recorded signature fixture
expires on a date you did not choose. **Time injection cannot be retrofitted into a
validator; it is a rewrite.** The `Clock` was therefore built in Phase 2, before anything
needed it, and it is what makes this phase's TTL and expiry behaviour testable at all.

**The entire DNS stack is written from scratch** — wire codec, server loop, caches,
recursion algorithm, DNSSEC validation. No `hickory-dns`, no `domain` crate for the
protocol. `hickory-proto` is a `[dev-dependencies]`-only test oracle, because the fakes and
expected-byte fixtures must not share bugs with our own codec; a CI check asserts it
appears in no normal or build dependency path.

**One crate per feature; `domain`/`application`/`infrastructure` are modules inside it.**
Cargo enforces feature-to-feature isolation, arch-lint enforces layering within a crate.
**Feature crates never depend on each other** — cross-feature needs are expressed as a
port in the consumer's `domain`, implemented by an adapter in the `styx` binary.
`styx-proto` is the single explicit exception: it is shared foundation, not a feature,
because every crate parses through the wire codec.

**Lint policy**: 15 denied clippy lints workspace-wide, including `indexing_slicing = deny`
and `arithmetic_side_effects = deny` — **every label offset and TTL decrement becomes a
checked operation**; plus `no-unwrap-expect`, `require-thiserror`, `require-tracing` and
`no-sync-io` enforced by arch-lint.

**`panic = "deny"` is load-bearing.** In a single process, a panic anywhere takes DNS down
for the whole house.

**The cutover is last.** styx runs on a dev box until everything works; the household's
resolver stays on Pi-hole until v1 is complete. **Accepted consequence: no operational
feedback — cache behaviour, odd client queries, DHCP churn — until the end, when it is
most expensive to act on.** Cache behaviour is named explicitly in that list.

### Non-goals that bear directly on this phase

- **EDNS Client Subnet (RFC 7871) is deliberately omitted; it leaks client topology.**
  Consequence for the cache: the key needs no client-subnet dimension and no
  scope-prefix-length bookkeeping. A cached answer is valid for every client.
- **Multi-node or replicated deployment.** One box, one binary, local DB file. The cache
  is process-local; there is no distributed invalidation, no cache coherence problem and
  no shared store.
- **Authoritative zone serving.** Local records and per-zone overrides are resolution and
  filtering concerns, not a zone-file server — which is also why local records bypass the
  cache rather than being loaded into it as a pseudo-zone.
- **DoQ (DNS-over-QUIC)** and **RFC 5011 automated trust anchor rollover** are out of v1;
  neither touches the cache.

### Position in the phase order

| | Phase | Relationship to Phase 4 |
|---|---|---|
| 0 | Foundation and gates | Provides the workspace shape, the working arch-lint config, `clippy.toml` and the `just gate` target this phase is checked by. |
| 1 | Wire codec (`styx-proto`) | **Hard dependency.** Provides the decoded `Message`/`Question`/resource-record/RDATA types the cache stores, and name handling with compression on encode *and* decode. |
| 2 | Server loop and test harness | **Hard dependency.** Provides the injectable `Clock`, the socket-level test harness with in-process fake root/TLD/authoritative servers, the `FilterPolicy` and `LocalRecords` ports, and the fixed pipeline order that places the cache after local records and filtering. |
| 3 | `Upstream` port, forwarding, pool | **Hard dependency.** Provides the responses the cache is populated from and the `Upstream` boundary the cache sits in front of. |
| **4** | **Answer cache** | **This phase.** |
| 5 | Recursion (`styx-recursion`) | **Depends on this phase.** Builds the *other* cache (infrastructure), consumes this one for answers, and exercises bailiwick enforcement during descent. |
| 6 | DNSSEC (`styx-dnssec`) | **Depends on this phase.** Validated data flows through the answer cache; whether signatures and validation state are cached alongside answers is decided against this phase's structure. |
| 8 | Filtering (`styx-filtering`) | **Depends on this phase.** Implements the group-policy filter that is applied over the cache result on the way out, and the blocked replies that must never enter the cache. |

---

## Domain Concept Identification

### Existing Concepts

*(Greenfield: none of these exist as code. Each is a committed design artefact delivered
by an earlier phase, and is the context this phase builds on.)*

- **`Message` / `Header` / `Question` / resource record / RDATA / EDNS(0) OPT** *(Phase 1,
  `styx-proto`)*: the decoded representation of a DNS message. The answer cache stores and
  returns these types; it never holds raw wire bytes, because the wire form is
  compression-dependent and therefore not a stable value.
- **Domain name** *(Phase 1)*: label sequence with case-insensitive comparison and
  compression handling. The cache key's first component; the bailiwick rule is expressed
  entirely as a suffix relation over names.
- **`Clock`** *(Phase 2)*: the injectable time source. Every TTL decision in this phase
  reads time through it and never through the system clock directly. It is what makes this
  phase's exit criteria expressible as fast, deterministic tests instead of tests that
  sleep.
- **Resolution pipeline** *(Phase 2)*: the fixed order `local records → filter → cache →
  upstream`. The cache is the fourth stage, and its position is a correctness property.
- **`LocalRecords` port** *(Phase 2)*: consulted ahead of the cache. Its results are a
  cache *bypass*, both on read and on write.
- **`FilterPolicy` port** *(Phase 2)*: consulted ahead of the cache. Its blocked verdicts
  are a cache bypass on write, and its group-scoped filtering is applied to the cache's
  result on the way out.
- **Query-log observer** *(Phase 2)*: the hot-path hook that receives resolution outcomes
  for synchronous rollup counters. The cache produces an outcome — hit or miss — that this
  observer will want to record.
- **`Upstream` port, pool, `HealthState`, `SelectionStrategy`** *(Phase 3)*: the source of
  the responses the cache is populated from, and the work a cache hit avoids.
- **Infrastructure cache** *(Phase 5, `styx-recursion`)*: the *other* cache — delegations,
  NS sets, per-nameserver RTT and EDNS capability, keyed by zone and nameserver. Named
  here so it is never conflated with this phase's work. It does not exist yet, this phase
  does not build it, and nothing in this phase's key space or entry shapes should be
  designed to accommodate it.

### New Concepts Required

- **Answer cache**: a single, global, process-local, memory-only store of DNS answers,
  living in `styx-resolution`. Global in two senses that both matter: one instance per
  process, and one key space shared by every client and every group.
- **Cache key**: the question tuple `(qname, qtype, qclass)` and nothing else. No client
  identity, no group identity, no client subnet, no upstream identity. Name comparison is
  case-insensitive, so the key must canonicalise the name.
- **RRset entry**: a set of records sharing owner name, type and class, held together with
  the TTL that governs them and the time they were admitted. The RRset is the unit of TTL
  and the unit at which DNSSEC signs, so it is the natural unit of storage.
- **Message entry**: a whole cached response — its RCODE, its flags, and the content of its
  answer, authority and additional sections — for the cases where an answer is not
  reducible to one RRset of the queried type (a CNAME chain, a referral-shaped response, a
  negative answer carrying a SOA).
- **Negative-cache entry (RFC 2308)**: a cached *absence*. Two distinct kinds — a name that
  does not exist (NXDOMAIN) and a name that exists with no data of the requested type
  (NODATA) — whose lifetime is derived from the SOA record accompanying the denial rather
  than from any answer TTL, because there is no answer record to carry one.
- **TTL machinery**: the conversion from a record's relative TTL, at admission time, into
  an absolute expiry instant read from the `Clock`; the computation of the remaining TTL to
  serve on a hit; and the rule that an entry whose remaining TTL has reached zero is not a
  hit. Under `arithmetic_side_effects = deny` every one of these is a checked operation.
- **Eviction policy**: the bounded-capacity discipline that keeps the cache inside a memory
  budget on a Raspberry Pi-class machine, distinct from expiry (which removes entries
  because they are stale) — eviction removes entries that are still fresh because there is
  no room.
- **Bailiwick rule**: the predicate deciding whether a record in a response may be admitted
  at all, based on whether the responding server has authority over the record's owner
  name. It is the cache's security boundary.
- **Cacheability policy**: the broader admission decision of which the bailiwick rule is
  one clause — also excluding forged answers (local records, blocked replies) and any
  response whose shape makes it unsafe or meaningless to store.
- **Cache lookup outcome**: what the pipeline receives — a fresh positive hit, a fresh
  negative hit (itself carrying which kind of denial it is), or a miss.

### Conceptual Relationships

- The **answer cache** is owned by `styx-resolution` and shared across every listener task
  in the single process. It is keyed by **cache key**, which is derived purely from the
  client's **question**.
- A **cache key** resolves to either an **RRset entry**, a **message entry**, or a
  **negative-cache entry**. All three carry **TTL machinery** state; all three were subject
  to the **cacheability policy**, of which the **bailiwick rule** is the security-critical
  clause, before being admitted.
- **Local records** and **blocked replies** relate to the cache only by exclusion: they
  short-circuit ahead of it and are never written into it.
- **Group policy** relates to the cache as a transformation applied *after* lookup, never
  as a dimension of the key.
- The **`Clock`** is a collaborator of the TTL machinery and the eviction policy, not a
  property of any entry.
- The cache sits **between** the filter stage and the **`Upstream` pool**: a hit means the
  pool is never consulted.
- `styx-recursion` (Phase 5) is a separate feature crate and therefore **cannot depend on
  `styx-resolution` directly**. Its need for the answer cache must be expressed as a port
  declared in its own `domain`, wired to this phase's cache by an adapter in the `styx`
  binary.

### Key Business Rules

- **The key is the question and only the question.** `(qname, qtype, qclass)` — no group,
  no client, no subnet. Governs: cache key. Rationale that must not be lost: per-group
  namespaces would multiply memory by the number of groups and destroy the hit rate the
  cache exists to provide.
- **Group policy filters the result, it does not partition the store.** Governs: the
  relationship between the cache and filtering.
- **Forged answers are never cached.** Local records and blocked replies both bypass the
  cache on write. Governs: cacheability policy. Rationale: the cache is global, so a cached
  forgery would leak across groups; and a short-TTL block exists precisely so that
  unblocking takes effect quickly, which caching would defeat.
- **Out-of-bailiwick data is never admitted.** A server may only teach the cache about
  names it has authority over. Governs: bailiwick rule. This is the cache-poisoning
  defence, and the exit criterion states it absolutely — *ever*, not *usually*.
- **TTL is counted down against injected time.** An entry's life is measured from admission
  using the `Clock`; an expired entry is a miss, not a stale hit. Governs: TTL machinery.
- **Negative answers are cached with a lifetime derived from the SOA**, per RFC 2308, and
  NXDOMAIN and NODATA are distinguishable on retrieval because they produce different
  responses. Governs: negative-cache entry.
- **Name comparison is case-insensitive.** Two questions differing only in the case of the
  qname are the same key. Governs: cache key. *(An invariant of DNS itself, not a project
  choice.)*
- **The cache performs no I/O and has no persistence.** Governs: the whole component. A
  database outage must not be observable from the resolution path, and there is no warm
  start after a restart.
- **The cache is consulted only after local records and after filtering**, and only before
  the upstream pool. Governs: pipeline placement.
- **Every TTL arithmetic operation is checked.** No implicit wrap, no saturation by
  accident. Governs: TTL machinery, under `arithmetic_side_effects = deny`.
- **No panics on the hot path.** No unwrap, no expect, no indexing that can be out of
  bounds; errors are `thiserror` enums returned through `Result`. Governs: the whole
  component, under `panic = "deny"` and `no-unwrap-expect`.

---

## Strategic Approach

### Solution Direction

Build the answer cache as a new set of modules **inside the `styx-resolution` crate**,
following the project's rule that a crate is a feature and `domain`/`application`/
`infrastructure` are modules within it:

- **`domain`** holds the *policy*: the cache key and its canonicalisation, the entry shapes,
  the TTL arithmetic, the negative-caching rules, and — most importantly — the
  **cacheability predicate including the bailiwick rule**. This is pure, deterministic
  logic parameterised by the `Clock`, with no storage concerns and no I/O. It is where the
  security-critical decision lives, and it is testable in isolation, which matters because
  "no out-of-bailiwick data is ever cached" is an absolute claim that deserves exhaustive
  unit coverage in addition to socket-level tests.
- **`infrastructure`** holds the *store*: the concurrent map, the bounded capacity, the
  eviction mechanism, and the memory accounting. It is a mechanism, and it is replaceable
  without touching policy.
- **`application`** holds the *wiring*: the lookup-then-miss-then-admit flow at the cache
  stage of the resolution pipeline, and the emission of hit/miss outcomes toward the
  query-log observer.

The store is expressed as a **trait (port)** so that the pipeline depends on the capability
rather than the concrete structure, and so that Phase 5's `styx-recursion` — a separate
feature crate that may not name `styx-resolution` — can declare its own port for the same
capability and have the `styx` binary wire the single shared instance into both. There is
one cache instance per process, shared by `Arc`, exactly as the single-process,
single-binary architecture intends.

The general data flow: *question arrives at the cache stage → canonicalise to a key → look
up → on a fresh hit, compute remaining TTL from the `Clock` and return → on a miss or an
expired entry, resolve through the upstream pool → run the response through the
cacheability predicate → admit the parts that pass, discarding the parts that do not →
return the response.* The result then continues out through group-policy filtering.

### Key Design Decisions

- **RRset-granular storage as the primary unit, with message entries for the shapes that do
  not reduce to one RRset.** *Trade-offs*: whole-message caching is simpler and preserves
  the exact response, but it stores the same RRset repeatedly under different questions,
  cannot share data between a query for `A` and a chased CNAME, and gives Phase 5's descent
  and Phase 6's per-RRset signature verification nothing they can address. RRset granularity
  costs response assembly on every hit. → **Recommend RRset-primary.** The phase spec names
  both ("RRset and message cache"), the RRset is the unit at which DNS assigns TTLs and at
  which DNSSEC signs, and the two consuming phases both work per-RRset. Message entries are
  the narrower case, used where the response is not one RRset of the queried type.
- **Absolute expiry instants computed at admission, rather than stored relative TTLs
  decremented over time.** *Trade-offs*: storing a deadline means one `Clock` read and one
  checked subtraction per lookup, and no background work; storing a countdown means either
  a sweeper mutating every entry or the same subtraction anyway. → **Recommend absolute
  deadlines**, which also makes the injected-`Clock` tests read naturally: advance time, assert
  the entry is gone.
- **Lazy expiry on lookup, with eviction driven by the capacity bound.** *Trade-offs*: a
  background sweeper task reclaims memory from entries nobody asks for again, but it is a
  second concurrent writer on the hot-path structure and another thing that can panic in a
  process where `panic = "deny"` is load-bearing. Lazy expiry alone lets dead entries
  occupy memory until evicted. → **Recommend lazy expiry plus capacity-bounded eviction**
  for this phase; expired entries are reclaimable by the eviction pass, so no separate
  sweeper is required to hold the memory bound. Revisit only if measurement shows
  otherwise.
- **The bailiwick check runs at admission, not at retrieval.** *Trade-offs*: checking on the
  way out would let poisoned data sit in the store and rely on every read path
  re-validating it. Checking on the way in means one place to get right and one place to
  test. → **Recommend admission-time**, which is also what the exit criterion literally
  requires: *no out-of-bailiwick data is ever cached*, not *never served*.
- **Concurrency via a sharded concurrent map, not the `ArcSwap` whole-replacement pattern
  used for the filtering matcher.** *Trade-offs*: `ArcSwap` is ideal for the matcher because
  it is immutable between explicit reloads; the cache is mutated on the hot path by every
  miss, so wholesale replacement is wrong for it. A single lock over one map would serialise
  every query in a process that serves a whole house. → **Recommend sharding**, with the
  invariant that no lock is ever held across an `await`.
- **A bounded, configurable capacity rather than an unbounded cache.** *Trade-offs*: an
  unbounded cache has a better hit rate right up to the point where it takes the box down;
  the deployment target is a Raspberry Pi that must also hold a filtering matcher sized at
  roughly 45–75MB per million domains. → **Recommend a hard bound** with the specific
  value left to configuration and measurement, consistent with the project's habit of
  deferring tuning constants to the keyboard.
- **The cache stage emits an explicit hit/miss outcome into the existing query-log observer
  hook rather than logging on its own.** *Trade-offs*: none material; the hook already
  exists from Phase 2 precisely so the product half does not rewrite the hot path later. →
  **Recommend reusing it.**

### Alternatives Considered

- **Per-group cache namespaces.** Rejected by explicit project decision: with N groups,
  memory multiplies and the hit rate — the entire reason the cache exists — is shredded.
  Group policy is cheap to evaluate per query (a bitmask test); duplicated DNS data is not.
- **Caching local records and blocked replies.** Rejected: both are forged answers. Because
  the cache is global, a cached forgery would be served to clients in groups where the
  block does not apply; and blocked replies deliberately carry a short TTL so that
  unblocking takes effect quickly, which caching would defeat. Both also clear AD and forge
  no signature, so they must never be mistaken later for validated data.
- **Persisting the cache to the database for a warm start after restart.** Rejected: the hot
  path touches no I/O, and a database outage must degrade only logging and admin. A warm
  cache is not worth coupling resolution to storage.
- **Keying on client identity or client subnet to support per-client answers.** Rejected:
  EDNS Client Subnet is a deliberate non-goal because it leaks client topology, so there is
  no per-client variation in upstream answers to preserve, and per-client keying would have
  the same memory and hit-rate problem as per-group namespaces.
- **A single unified cache also holding delegations, NS sets, RTT and EDNS capability.**
  Rejected by explicit project decision: the answer cache and the infrastructure cache are
  *structurally* different — different keys, different consumers, different lifetimes. The
  infrastructure cache is keyed by zone and nameserver and is used only by recursion, and
  it belongs to a later phase in a different crate.
- **Reaching for an existing DNS cache implementation.** Rejected: the entire DNS stack —
  wire codec, server loop, **caches**, recursion, validation — is written from scratch by
  decision, and `hickory-proto` is admissible only as a `[dev-dependencies]` test oracle,
  enforced by a CI check.
- **Reading the system clock directly for TTL decisions.** Rejected: the injectable `Clock`
  exists precisely so time-dependent behaviour is testable, it was built in an earlier phase
  because it could not have been retrofitted, and this phase's exit criteria are stated
  "under injected time". Bypassing it would make the exit criteria untestable and would
  poison the DNSSEC phase, whose signature fixtures carry fixed inception and expiration
  timestamps.
- **A background expiry sweeper task from day one.** Deferred rather than rejected outright:
  it adds a second concurrent mutator and another task that can fail in a process where a
  panic takes DNS down for the whole house, for a benefit that capacity-bounded eviction
  already delivers.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **Which specific bailiwick rule.** The phase spec says "bailiwick rules governing what is
  cacheable at all" without stating them. The relevant standard concept — a server may only
  supply data at or below the zone it is authoritative for, and records outside that are
  discarded — needs pinning down precisely for the answer, authority and additional
  sections separately, since the additional section is the classic poisoning vector.
  **Needs a written rule per section before implementation.**
- **TTL clamping.** Nothing states whether a minimum or maximum TTL is imposed, or how a
  TTL of zero is handled (served once and not stored, or stored and immediately expired).
  Real-world resolvers cap absurd TTLs in both directions. **Needs a decision.**
- **Whether signatures and validation state are cached.** DNSSEC arrives in Phase 6 and
  hard-fails on bogus answers; it needs RRSIG material and a notion of Secure / Insecure /
  Bogus. The phase spec is silent on whether this phase's entries carry that. **Needs a
  decision now**, because the alternative is either re-validating on every cache hit or
  rewriting the entry shapes one phase later.
- **Serve-stale behaviour.** Nothing states whether an expired entry may be served while a
  refresh is in flight. The exit criterion "TTL expiry ... under injected time" reads as
  *expired means gone*. **Assume no serve-stale unless decided otherwise, and record it.**
- **Request coalescing for concurrent identical misses.** Nothing says whether N simultaneous
  misses for the same key produce N upstream queries or one. This materially affects
  outbound query volume and interacts with the `race` selection strategy, which is already
  flagged as a privacy hazard because it fans one query out to every provider in a pool.
  **Needs a decision, or an explicit deferral.**
- **Cache flush / purge.** The admin UI arrives in Phase 11 and will plausibly want a
  "flush cache" button. Nothing specifies it. **Note the seam now, build it later.**
- **How a CNAME chain is cached and served.** Phase 5 lists CNAME chasing as its own work,
  but a forwarded response can contain a chain too, and it is exactly the case that does not
  reduce to one RRset of the queried type. **Needs the message-entry shape to account for
  it.**
- **Eviction policy specifics.** "Eviction" is an exit criterion but no policy is named
  (LRU, LFU, random, TTL-ordered). **Needs a choice, and the exit criterion needs an
  observable definition to test against.**

### Edge Cases

- **A response whose additional section carries records for an unrelated zone** — the
  poisoning case the bailiwick rule exists for. Must be discarded without discarding the
  legitimate parts of the same response.
- **A referral-shaped response arriving on a forwarding path**, where a forwarder returns
  delegation data rather than an answer. What, if anything, is cacheable.
- **Mixed-validity responses**: one RRset in bailiwick, one out. Partial admission must be
  the behaviour; whole-response rejection would be over-strict and whole-response
  acceptance would be a poisoning hole.
- **TTL zero and TTL at the protocol maximum**, including the near-expiry boundary where a
  checked subtraction can underflow under `arithmetic_side_effects = deny`.
- **Clock jumps.** The `Clock` is injected and tests will move it in large steps; the code
  must behave sanely when the elapsed interval exceeds any stored TTL.
- **NODATA versus NXDOMAIN for the same name**: a name that exists with an `A` but no
  `AAAA` must produce a NODATA negative entry that does not suppress the positive `A`
  answer, and must not be confusable with NXDOMAIN.
- **A negative response with no SOA**, from which no RFC 2308 lifetime can be derived.
- **Case-differing qnames** hitting the same key, and **trailing-dot / root-label**
  normalisation at the key boundary.
- **A question whose qtype is `ANY` or a meta-type**, which is not a normal cacheable
  question.
- **Cache full of fresh entries** — eviction must make progress without unbounded scanning
  on the hot path.
- **Concurrent admission of the same key by two tasks**, which must not corrupt the store
  and must leave exactly one entry.
- **A block applied to a name that is already in the cache from before the rule existed** —
  correct by construction, since filtering runs *before* the cache stage, but worth an
  explicit test because getting the pipeline order wrong here would be silent.
- **Unblocking a name**: because blocked replies were never cached, the next query resolves
  normally with no flush required. Also worth an explicit test, as it is the observable
  payoff of the never-cache-forgeries rule.

### Technical Risks

- **The bailiwick rule is a security boundary, and "ever" is a strong word.** A gap here is a
  cache-poisoning vulnerability in a resolver serving a household. *Mitigation*: put the
  predicate in `domain` as pure logic, test it exhaustively in isolation *and* at socket
  level against the in-process fake root/TLD/authoritative servers, and make the
  admission path the only way into the store.
- **TTL arithmetic under `arithmetic_side_effects = deny`.** Every decrement and elapsed
  computation is a checked operation, and the near-expiry boundary is where an
  underflow-shaped bug would otherwise hide. *Mitigation*: centralise all TTL arithmetic in
  one small `domain` module with property-style tests around the boundaries; the lint is
  the intended tax, not an obstacle to route around.
- **Memory budget on a Raspberry Pi.** The filtering matcher alone is projected at roughly
  45–75MB per million domains, and the cache must coexist with it, the query-log ring and a
  Leptos SSR web layer in one process. An unbounded cache is a denial of service against the
  box it runs on. *Mitigation*: hard capacity bound from the start, with accounting that can
  actually be measured.
- **Hot-path contention.** The cache is read on every query and written on every miss, shared
  across all listener tasks. A coarse lock makes the cache the bottleneck it was meant to
  remove. *Mitigation*: shard, and never hold a lock across an `await`.
- **`panic = "deny"` in a single process.** A panic in the cache takes DNS down for the whole
  house, and the `catch_unwind` boundary is not built until the final hardening phase.
  *Mitigation*: no unwrap, no expect, no unchecked indexing; `thiserror` enums through
  `Result`; the lint gate runs on every push.
- **Conflating the two caches.** The strongest structural risk to the project's design, since
  the infrastructure cache arrives one phase later and is superficially "also a cache".
  *Mitigation*: distinct names, distinct crates, distinct keys, and an explicit statement in
  the code's own documentation that this cache is keyed by question and knows nothing about
  zones or nameservers.
- **Cross-crate access from `styx-recursion`.** Feature crates may not depend on each other,
  so Phase 5 cannot simply reach into `styx-resolution`. If the cache is not exposed behind a
  port now, Phase 5 either violates the layering rule or forces a refactor. *Mitigation*:
  define the capability as a trait in this phase and let the binary wire it.
- **DNSSEC coupling deferred by one phase.** If entries cannot carry signature material and a
  validation verdict, Phase 6 must either re-validate every hit or reshape this phase's
  entries. *Mitigation*: resolve the ambiguity above before the entry shapes are frozen.
- **No operational feedback until cutover.** Cache behaviour is named explicitly among the
  things that will not be observed until the household is migrated, which is the last phase.
  Hit rate, memory growth and eviction pressure under a real query mix are all invisible
  until then. *Mitigation*: instrument counters and expose them from day one, so that when
  the cutover happens the data is already being collected; and lean on the socket-level
  harness with synthetic query mixes in the meantime.
- **The differential acceptance run touches the live internet.** Phase-gating runs compare
  styx against a local `unbound` over a corpus of real domains. Cached answers with
  differing TTL remainders are a plausible source of spurious diffs. *Mitigation*: the
  differential run gates a phase, never a push, and the comparison is on RCODE, AD bit and
  rrset contents — the remaining-TTL dimension needs an explicit tolerance rule.

### Acceptance Criteria Coverage

The phase's exit criteria, decomposed. **These are preserved verbatim in full as:**
*"TTL expiry, eviction and negative-cache behaviour under injected time; no
out-of-bailiwick data is ever cached."*

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | **TTL expiry under injected time** — an admitted entry stops being a hit once its TTL has elapsed on the injected `Clock`, and the TTL served on a hit reflects time already elapsed | Yes | Directly served by absolute-deadline storage plus the Phase 2 `Clock`. Gap: TTL clamping and TTL-zero handling are unspecified and must be decided before the assertions can be written. |
| 2 | **Eviction under injected time** — entries are removed under capacity pressure, observably and without unbounded hot-path work | Partial | The mechanism is clear but no eviction *policy* is named in the requirement, and "under injected time" implies the test drives it deterministically. Needs a named policy and an observable definition (e.g. a capacity bound plus an eviction counter) before it is testable. |
| 3 | **Negative-cache behaviour under injected time** — NXDOMAIN and NODATA are cached per RFC 2308, distinguishable on retrieval, with lifetimes derived from the accompanying SOA, and they expire | Yes | Gap: the no-SOA denial case has no specified behaviour, and whether a negative NODATA entry for one qtype may coexist with a positive entry for another qtype at the same name must be asserted explicitly. |
| 4 | **No out-of-bailiwick data is ever cached** — records the responding server has no authority over are discarded at admission | Yes | Gap: the precise rule per message section (answer / authority / additional) is not written down. Also needs the partial-admission behaviour for mixed-validity responses decided, and the assertion must inspect the store's contents directly rather than only observing responses, since "cached" is a stronger claim than "served". |
| 5 | **Scope: RRset and message cache keyed `(qname, qtype, qclass)`, global** | Yes | Gap: the CNAME-chain and referral-shaped cases that motivate the message entry need their shape pinned down. |
| 6 | **Implicit: forged answers never enter the cache** — local records and blocked replies | Yes | Not stated in this phase's exit criteria but load-bearing for the project. Fully assertable now for local records (Phase 2 port exists); the blocked-reply half can only be fully exercised once Phase 8 lands, so this phase should assert the *cache's* refusal via its admission path rather than via a real block. |
| 7 | **Implicit: the cache performs no I/O and holds no persistence** | Yes | Enforced by the `no-sync-io` arch-lint rule and by the absence of any storage dependency in `styx-resolution`. |
