# styx Phase 4 — Answer cache (`styx-resolution`)

> **Project**: `styx` — a filtering DNS resolver written from scratch in Rust, replacing
> Pi-hole's role on a home network: recursive/forwarding resolution, per-client blocking
> policy, and a Leptos admin UI. Single process, single binary, one box, local DB file.
>
> **Codebase state at the start of this phase**: greenfield with respect to this component
> — there is no existing answer-cache implementation anywhere in the workspace. Phases 0–3
> have delivered the workspace, the wire codec, the server loop with its injectable
> `Clock` and socket-level harness, and the `Upstream` pool.
>
> **This document is self-contained.** The project's decision record and per-phase specs
> are retired; every decision, rationale, accepted consequence, non-goal and risk that
> bears on this phase is reproduced here in full.

---

## Requirements

Implement the **answer cache**: a single, global, process-local, memory-only store of DNS
answers keyed by the client's question, sitting between the filtering stage and the
`Upstream` pool, so that a repeated question is answered without a network round trip.

Design and enforce the rules that decide **what may enter it at all** — TTL lifetime,
RFC 2308 negative caching of NXDOMAIN and NODATA, and the bailiwick rule that discards any
record the responding server has no authority over — and make all of it observable and
deterministic under the injected `Clock`.

**Boundaries — what this phase is and is not.**

- It builds **one** of the project's two caches. This is the *answer cache*: RRsets and
  messages, keyed by question, global, living in `styx-resolution`, consumed by every
  resolution path. It is **not** the *infrastructure cache* — delegations, NS sets,
  per-nameserver RTT and EDNS capability, keyed by zone and nameserver — which lives in
  `styx-recursion`, is used only by recursion, and is built in **Phase 5 — Recursion**.
  **They are structurally different and must never be conflated.** They are keyed on
  different things and answer different questions: the answer cache is keyed by what a
  *client asked*; the infrastructure cache is keyed by *where to ask next* and is
  meaningless outside a recursive descent. Collapsing them into one store would index
  delegation state by question — the wrong index — and would leak recursion internals into
  every forwarding query.
- It is a **cache**, not a zone server. Authoritative zone serving is a project non-goal;
  local records and per-zone overrides are resolution and filtering concerns.
- It performs **no I/O** and has **no persistence**. There is no warm start after a
  restart.
- It introduces **no** DNSSEC validation logic. Validation arrives in
  **Phase 6 — DNSSEC**; this phase only ensures the entry shapes can carry what that phase
  will need.

**Value.** Every cache hit is one fewer query leaving the house. On a resolver that is
also a privacy device — EDNS Client Subnet is deliberately omitted because it leaks client
topology, and the `race` selection strategy is flagged as a privacy hazard precisely
because it shows every domain to every provider in a pool — reducing outbound query volume
is a privacy outcome, not only a latency one. And the bailiwick rule is the component's
cache-poisoning defence: this resolver answers for an entire household.

### The decisions this phase inherits, with their rationale

**Two structurally different caches.** *(Stated above; this is the single most important
structural distinction in the resolution half of the project.)*

**The answer cache stays global, keyed `(qname, qtype, qclass)`.** Group policy is applied
as a **filter over the resolution result, on the way out**. **No per-group cache
namespaces: N groups would multiply memory and shred the hit rate the cache exists to
provide.** Full per-client groups are a v1 feature — clients, groups and list-to-group
assignment are first-class in the domain model, the DB and the UI — so the pull toward
namespacing the cache per group is real, and it is explicitly rejected. The per-group
verdict is computed from a bitmask walk (`!(allow & g) && (block & g)`) and is cheap;
duplicating cached DNS data N ways is not.

**Local records are answered before the cache and are always Insecure.** A/AAAA/CNAME/PTR
rows held in the database and editable in the UI are matched ahead of the answer cache and
ahead of any upstream. **They never enter the answer cache** and never reach the
validator: AD cleared, no forged signature — the same honesty rule as a blocked reply.
*Accepted consequence recorded for that decision*: a local name under a signed public zone
(`nas.example.com` where `example.com` is signed) is unprovable and validating clients may
SERVFAIL it; the documented guidance is to keep local names under an unsigned or internal
suffix.

**Blocked replies: five modes, NXDOMAIN by default** — `NXDOMAIN` (the default here),
`NULL` (`0.0.0.0`/`::`), `NODATA`, `IP`, `IP-NODATA-AAAA`. Regardless of mode: qtypes
other than A/AAAA get NODATA,
**blocked replies carry a short TTL so unblocking takes effect quickly**,
**AD is always cleared and no RRSIG is ever forged**, and filtering is applied *before*
validation — a block is not a validation verdict.

**Therefore: local records and blocked replies never enter this cache, because both are
forged answers.** Two reasons, both load-bearing. First, the cache is global by design, so
a cached forgery would be served to clients in groups where the block does not apply — the
very cross-group leak that keying on the question alone is otherwise safe from. Second,
blocked replies carry a deliberately short TTL so that unblocking takes effect quickly;
caching them would defeat the reason that TTL is short.

**The pipeline order is fixed and is a correctness property, not a detail**:
`local records → filter → cache → upstream`.

**The hot path touches no I/O.** Matcher state is in memory, built at boot and on reload;
the database holds config, adlist definitions, clients/groups and history only.
**A database outage degrades logging and admin, never resolution.** The answer cache is
consequently memory-only, process-local, with no persistence and no warm start.

**The injectable `Clock` (delivered in Phase 2 — Server loop and test harness) is what
makes this phase's TTL and expiry behaviour testable, and it could not have been
retrofitted.** It exists because RRSIGs carry inception and expiration timestamps, so any
recorded signature fixture expires on a date you did not choose —
*time injection cannot be retrofitted into a validator; it is a rewrite*. It was therefore
built one phase before anything needed it. This phase's exit criteria are stated "under
injected time", and they are only expressible as fast, deterministic tests because that
`Clock` already exists.

**The entire DNS stack is written from scratch** — wire codec, server loop, **caches**,
recursion algorithm, DNSSEC validation. No `hickory-dns`, no `domain` crate for the
protocol. `hickory-proto` is a `[dev-dependencies]`-only test oracle, because the
in-process fakes and expected-byte fixtures must encode DNS wire format, and if our own
codec encoded them the resolver and its oracle would share every bug and a green suite
would prove only self-consistency. A CI check asserts `hickory-proto` appears in no normal
or build dependency path.

**One crate per feature; `domain` / `application` / `infrastructure` are modules inside
it.** Cargo enforces feature-to-feature isolation; arch-lint enforces layering within a
crate. **Feature crates never depend on each other** — cross-feature needs are expressed
as a trait (port) in the consumer's `domain`, implemented by an adapter in the `styx`
binary. `styx-proto` is the single explicit exception: it is shared foundation, not a
feature, because every crate parses through the wire codec.

**Lint policy**: 15 denied clippy lints workspace-wide, including
`indexing_slicing = deny` and `arithmetic_side_effects = deny` — **every label offset and
TTL decrement becomes a checked operation; that is the intended tax**. arch-lint
additionally enforces `no-unwrap-expect` (`allow_in_tests = true`), `require-thiserror`,
`require-tracing` and `no-sync-io`.

**`panic = "deny"` is load-bearing.** In a single process, a panic takes DNS down for the
whole house. The lint helps; a `catch_unwind` boundary and a supervised task model are the
real mitigation, and they arrive only in **Phase 12 — Cutover hardening**.

**The cutover is last.** styx runs on a dev box until everything works; the household
stays on Pi-hole until v1 is complete. **Accepted consequence: no operational feedback —
cache behaviour, odd client queries, DHCP churn — until the end, when it is most expensive
to act on.** *Cache behaviour is named explicitly in that list, which makes
instrumentation in this phase a mitigation rather than a nicety.*

**Acceptance runs in two tiers.** Per push, hermetic and fast: socket tests, fuzzing, and
the full lint/arch gate. Per phase, non-hermetic: a corpus of real domains resolved
through both styx and a local `unbound`, diffing RCODE, AD bit and rrset contents.
In-process fakes only prove the resolver does what we *think* delegation means; the
differential run is the only gate that catches a shared misreading. It depends on the live
internet and is flaky by nature, so it gates a phase and never a push.

### Non-goals that bear on this phase

- **EDNS Client Subnet (RFC 7871) — deliberately omitted; it leaks client topology.** The
  cache key therefore needs no client-subnet dimension and no scope-prefix-length
  bookkeeping. A cached answer is valid for every client.
- **Multi-node or replicated deployment.** One box, one binary, local DB file. The cache
  is process-local: no distributed invalidation, no coherence problem, no shared store.
- **Authoritative zone serving.** Local records are a resolution concern, which is also
  why they bypass the cache rather than being loaded into it as a pseudo-zone.
- **DHCP server**, **DoQ**, **multi-user admin / audit trail**, **RFC 5011 automated trust
  anchor rollover** — none touch the cache.

### Phase dependencies

**This phase depends on:**

- **Phase 0 — Foundation and gates**: the Cargo workspace shape, a *working* arch-lint
  config (the committed one routes to a Kotlin-only tree-sitter engine and checks zero
  `.rs` files), the `cargo tree` layering gate, `clippy.toml` with the 15 denied lints,
  and the `just gate` target this phase is checked by.
- **Phase 1 — Wire codec (`styx-proto`)**: the decoded `Message`, `Header`, `Question`,
  resource-record and RDATA types the cache stores, name handling with compression on both
  encode and decode, and EDNS(0) OPT.
- **Phase 2 — Server loop and test harness**: the **injectable `Clock`**; the socket-level
  harness with in-process fake root, TLD and authoritative servers built on
  `hickory-proto` and driven over real sockets; the `LocalRecords` and `FilterPolicy`
  ports; the query-log observer hook; and the fixed pipeline order
  `local records → filter → cache → upstream`.
- **Phase 3 — `Upstream` port, forwarding, pool**: the `Upstream` trait and Do53 forwarder
  whose responses populate the cache, and the pool a cache hit avoids consulting.

**Phases that depend on this phase:**

- **Phase 5 — Recursion (`styx-recursion`)**: consumes this cache for answers, builds the
  separate infrastructure cache, and exercises bailiwick enforcement throughout its
  descent with relaxed QNAME minimisation. Because feature crates never depend on each
  other, it reaches this cache only through a port declared in its own `domain` and wired
  by the `styx` binary.
- **Phase 6 — DNSSEC (`styx-dnssec`)**: validated data flows through this cache; the entry
  shapes must be able to carry signature material and a validation verdict, or Phase 6
  either re-validates on every hit or reshapes this phase's types.
- **Phase 8 — Filtering (`styx-filtering`)**: implements the group-policy filter applied
  over this cache's result on the way out, and the five blocked-reply modes that must
  never enter this cache.
- **Phase 10 — Query log pipeline**: consumes the hit/miss outcomes this phase emits into
  the Phase 2 observer hook.

---

## Entities

```mermaid
classDiagram
direction TB

class CacheKey {
    -CanonicalName qname
    -RecordType qtype
    -RecordClass qclass
    +from_question(Question) Result~CacheKey, CacheError~
    +qname() CanonicalName
    +qtype() RecordType
    +qclass() RecordClass
}

class CanonicalName {
    -Name inner
    +canonicalize(Name) CanonicalName
    +is_subdomain_of(CanonicalName) bool
    +label_count() usize
    +inner() Name
}

class CacheEntry {
    <<enumeration>>
    Positive(PositiveEntry)
    Negative(NegativeEntry)
    +deadline() Deadline
    +is_fresh(Instant) bool
    +heap_size() HeapBytes
}

class PositiveEntry {
    <<enumeration>>
    RRset(CachedRRset)
    Message(CachedMessage)
}

class CachedRRset {
    +CanonicalName owner
    +RecordType rtype
    +RecordClass rclass
    +Vec~Rdata~ rdata
    +Ttl original_ttl
    +Deadline deadline
    +SecurityStatus security
    +Option~Vec~Rrsig~~ signatures
    +remaining_ttl(Instant) Result~Ttl, CacheError~
}

class CachedMessage {
    +ResponseCode rcode
    +MessageFlags flags
    +Vec~CachedRRset~ answer
    +Vec~CachedRRset~ authority
    +Vec~CachedRRset~ additional
    +Deadline deadline
    +to_response(CacheKey, Instant) Result~Message, CacheError~
}

class NegativeEntry {
    +DenialKind kind
    +CachedRRset soa
    +Deadline deadline
    +SecurityStatus security
    +to_response(CacheKey, Instant) Result~Message, CacheError~
}

class DenialKind {
    <<enumeration>>
    NxDomain
    NoData
}

class SecurityStatus {
    <<enumeration>>
    Indeterminate
    Insecure
    Secure
    Bogus
}

class Deadline {
    -Instant at
    +from_ttl(Instant, Ttl) Result~Deadline, CacheError~
    +remaining(Instant) Result~Ttl, CacheError~
    +has_expired(Instant) bool
}

class TtlPolicy {
    +Ttl floor
    +Ttl ceiling
    +Ttl negative_ceiling
    +clamp(Ttl) Ttl
    +effective_negative_ttl(CachedRRset) Result~Ttl, CacheError~
}

class HeapBytes {
    -usize octets
    +new(usize) HeapBytes
    +get() usize
    +checked_add(HeapBytes) Result~HeapBytes, CacheError~
    +saturating_sub(HeapBytes) HeapBytes
}

class Bailiwick {
    -CanonicalName zone
    +of_response(Question, Message) Bailiwick
    +permits(CanonicalName) bool
}

class Admission {
    +TtlPolicy ttl
    +evaluate(Bailiwick, Message, AnswerSource, Instant) AdmissionOutcome
    -is_forged_source(AnswerSource) bool
}

class AdmissionOutcome {
    +Vec~CacheEntry~ admitted
    +Vec~RejectedRecord~ rejected
}

class RejectedRecord {
    +CanonicalName owner
    +RecordType rtype
    +RejectReason reason
}

class RejectReason {
    <<enumeration>>
    OutOfBailiwick
    ForgedAnswer
    UncacheableQtype
    ZeroTtl
    MalformedDenial
    NoSoaInDenial
    InadmissibleSource
}

class AnswerSource {
    <<enumeration, Phase 2 domain::answer>>
    LocalRecord
    Blocked
    CacheHit
    Upstream
    Recursion
    Error
}

class AnswerCache {
    <<interface>>
    +lookup(CacheKey) Lookup
    +admit(CacheKey, AdmissionOutcome) Result~usize, CacheError~
    +purge_all() usize
    +stats() CacheStats
}

class Lookup {
    <<enumeration>>
    Hit(CacheEntry)
    Miss
    Expired
}

class ShardedAnswerCache~C~ {
    -Vec~Shard~ shards
    -Arc~C~ clock
    -CacheCapacity capacity
    -TtlPolicy ttl_policy
    +shard_for(CacheKey) usize
}

class Shard {
    +RwLock~ShardInner~ inner
}

class ShardInner {
    +HashMap~CacheKey, CacheEntry~ map
    +VecDeque~CacheKey~ recency
    +HeapBytes bytes
}

class CacheCapacity {
    +usize max_entries
    +HeapBytes max_bytes
    +needs_eviction(usize, HeapBytes) bool
}

class Eviction {
    +evict(ShardInner, Instant, CacheCapacity) EvictionReport
}

class EvictionReport {
    +usize expired_reclaimed
    +usize evicted_fresh
}

class CacheStats {
    +u64 hits
    +u64 misses
    +u64 negative_hits
    +u64 admitted
    +u64 rejected_out_of_bailiwick
    +u64 expired
    +u64 evicted
    +usize entries
    +HeapBytes bytes
}

class CacheError {
    <<enumeration>>
    TtlOverflow
    DeadlineInThePast
    UncacheableQuestion
    MissingSoa
    ResponseAssembly
    ByteAccountingOverflow
}

class Clock {
    <<interface>>
    +now() Instant
}

CacheKey "1" --> "1" CanonicalName : qname
CacheKey "1" --> "0..1" CacheEntry : indexes
CacheEntry "1" --> "1" Deadline : expires at
CacheEntry "1" --> "1" HeapBytes : heap_size
CacheEntry --> PositiveEntry : Positive
CacheEntry --> NegativeEntry : Negative
PositiveEntry --> CachedRRset : RRset
PositiveEntry --> CachedMessage : Message
CachedMessage "1" o-- "0..*" CachedRRset : sections
NegativeEntry "1" --> "1" DenialKind : kind
NegativeEntry "1" --> "1" CachedRRset : SOA
CachedRRset "1" --> "1" SecurityStatus : verdict
Admission "1" --> "1" TtlPolicy : clamps with
Admission "1" ..> "1" Bailiwick : consults
Admission "1" --> "1" AdmissionOutcome : produces
Admission "1" ..> "1" AnswerSource : rejects forged
AdmissionOutcome "1" o-- "0..*" RejectedRecord : rejected
RejectedRecord "1" --> "1" RejectReason : why
AnswerCache <|.. ShardedAnswerCache : implements
AnswerCache "1" --> "1" Lookup : returns
ShardedAnswerCache "1" o-- "1..*" Shard : shards
ShardedAnswerCache "1" --> "1" Clock : reads time from
ShardedAnswerCache "1" --> "1" CacheCapacity : bounded by
ShardedAnswerCache "1" --> "1" CacheStats : publishes
Shard "1" --> "1" ShardInner : guards
ShardInner "1" o-- "0..*" CacheEntry : holds
ShardInner "1" --> "1" HeapBytes : bytes
CacheCapacity "1" --> "1" HeapBytes : max_bytes
CacheStats "1" --> "1" HeapBytes : bytes
Eviction "1" ..> "1" ShardInner : compacts
Eviction "1" --> "1" EvictionReport : reports
```

**Entity notes — deliberate exclusions from the model.**

- `CacheKey` has **no** client field, **no** group field and **no** client-subnet field.
  This is the global-key decision made structural: group policy is a filter over the
  result on the way out, never a dimension of the key, because N groups would multiply
  memory and shred the hit rate.
- There is **no** `DelegationEntry`, `NsSetEntry`, `NameserverRtt` or `EdnsCapability`
  type here. Those belong to the *infrastructure cache* in `styx-recursion`, keyed by zone
  and nameserver, built in Phase 5.
- `AnswerSource` is **not declared here**. It is Phase 2's
  `styx-resolution::domain::answer::AnswerSource`, the crate's single provenance type,
  and this phase only consumes it. `Admission` takes it as an argument so it can refuse
  `LocalRecord` and `Blocked` explicitly and name the refusal in
  `RejectReason::ForgedAnswer`, rather than relying on callers to remember not to offer
  them. Only `Upstream` and `Recursion` are admissible. `CacheHit` (the cache's own
  output) and `Error` are rejected wholesale with `RejectReason::InadmissibleSource`, so
  the match over the enum is exhaustive and has no silent default.
- `SecurityStatus` and `CachedRRset::signatures` are present but only ever
  `Indeterminate`/`None` in this phase. They exist now because Phase 6 hard-fails on bogus
  answers and would otherwise force either re-validation on every hit or a reshape of
  these types one phase later.
- `HeapBytes` wraps the byte-count arithmetic used for capacity accounting
  (`ShardInner::bytes`, `CacheCapacity::max_bytes`, `CacheStats::bytes`) behind a checked
  add and a saturating subtract, the same checked-and-saturating discipline `styx-proto`'s
  `Ttl` uses for its own decrement — a manually accumulated counter is exactly where
  `arithmetic_side_effects = deny` bites. `CacheStats`'s plain `u64` hit/miss counters and
  `CacheCapacity::max_entries` carry no arithmetic rule of their own — they are compared,
  never accumulated by hand — and stay bare integers for that reason.

---

## Approach

### 1. Placement and layering

- The cache is a set of modules **inside the `styx-resolution` crate**. The project's rule
  is one crate per feature, with `domain`, `application` and `infrastructure` as modules
  inside it; arch-lint enforces the layering by path glob and `cargo tree` independently
  enforces the link graph.
- **`domain`** holds *policy* and nothing else: `CacheKey`, `CanonicalName`, the entry
  types, `Deadline` and `TtlPolicy`, `DenialKind`, `Bailiwick`, `Admission`,
  `AdmissionOutcome`, `RejectReason`, `CacheError`, and the `AnswerCache` trait. Pure,
  deterministic, `Clock`- parameterised, no I/O, no collections library concerns.
  **The security-critical decision — the bailiwick rule — lives here**, because "no
  out-of-bailiwick data is ever cached" is an absolute claim and deserves exhaustive unit
  coverage on pure logic in addition to socket-level tests.
- **`infrastructure`** holds *mechanism*: `ShardedAnswerCache`, `Shard`, `ShardInner`,
  `Eviction`, capacity accounting, and the `tracing` instrumentation. Replaceable without
  touching policy.
- **`application`** holds *wiring*: the cache stage of the resolution pipeline — lookup,
  miss, resolve through the pool, admit, respond — and the emission of the hit/miss
  outcome into the Phase 2 query-log observer hook.

### 2. The cache as a port

- `AnswerCache` is a **trait in `styx-resolution::domain`**, implemented by
  `ShardedAnswerCache` in `infrastructure`. The pipeline depends on the trait.
- **Phase 5 — Recursion is a separate feature crate and may not name `styx-resolution`.**
  It will declare its own port for this capability in `styx-recursion::domain`, and the
  `styx` binary will implement that port with an adapter holding the concrete cache or
  parameterized over `<A: AnswerCache>`. Defining the capability as a trait now is what
  makes that possible without violating the layering rule or refactoring this phase.
- One instance per process, shared by `Arc` across every listener task — the
  single-process, single-binary architecture.

### 3. Time and TTL

- **All time comes from the injected `Clock`.** No `Instant::now()`, no
  `SystemTime::now()`, anywhere in this component. This is not a testing convenience — it
  is the reason the exit criteria are expressible at all, and the same `Clock` is what
  keeps Phase 6's RRSIG fixtures from expiring on a date nobody chose.
- **Store absolute deadlines, computed once at admission**, rather than relative TTLs
  decremented over time. One `Clock` read and one checked subtraction per lookup; no
  background mutation. Tests read naturally: advance the clock, assert the entry is gone.
- **Every TTL computation is checked arithmetic.** Under `arithmetic_side_effects = deny`
  there is no implicit wrap and no accidental saturation; `Deadline::from_ttl` and
  `Deadline::remaining` return `Result` and are the only places this arithmetic appears.
- **TTL clamping**: a configurable floor and ceiling for positive entries and a separate
  ceiling for negative entries, because real-world TTLs range from absurdly short to
  absurdly long and an unclamped ceiling turns one bad zone into a long-lived error.
- **A record with TTL zero is served but never stored** (`RejectReason::ZeroTtl`) —
  storing it would mean admitting an entry that is already expired.

### 4. Cacheability and the bailiwick rule

- **The bailiwick check runs at admission, not at retrieval.** The exit criterion is
  literally *no out-of-bailiwick data is **ever cached*** — not "never served". Checking
  on the way in gives one place to get right and one place to test; checking on the way
  out would let poisoned data sit in the store and rely on every read path re-validating
  it.
- **The bailiwick of a response is the zone the responding server has authority over**,
  and a record may be admitted only if its owner name is at or below that zone. The rule
  is applied **per section, with different strictness**:
  - **Answer section**: admissible if the owner name is the qname, or is reached from the
    qname by a CNAME/DNAME chain whose every link is itself in bailiwick.
  - **Authority section**: admissible only for the SOA or NS of a zone at or above the
    qname's bailiwick.
  - **Additional section**: **the strictest**, because it is the classic cache-poisoning
    vector. Admissible only as glue — address records for names at or below the zone whose
    NS records appeared in the authority section of the same response.
- **Partial admission is the required behaviour.** A response mixing in-bailiwick and
  out-of-bailiwick records admits the former and records the latter in
  `AdmissionOutcome::rejected` with `RejectReason::OutOfBailiwick`. Whole-response
  rejection would be over-strict; whole-response acceptance would be the hole.
- **Forged answers are refused by the cache itself.** `Admission` rejects
  `AnswerSource::LocalRecord` and `AnswerSource::Blocked` with
  `RejectReason::ForgedAnswer`. The pipeline already short-circuits both ahead of the
  cache, but the cache refusing them independently means the invariant holds even if a
  future caller forgets.
- **Meta-qtypes are not cacheable questions.** `ANY`, `AXFR`, `IXFR` and `OPT` produce
  `RejectReason::UncacheableQtype` and never form a key.

### 5. Negative caching (RFC 2308)

- Two kinds, kept distinguishable on retrieval because they produce different responses:
  **NXDOMAIN** (the name does not exist) and **NODATA** (the name exists with no data of
  the requested type).
- **Lifetime is derived from the SOA accompanying the denial** — the minimum of the SOA's
  own TTL and the SOA `MINIMUM` field — then clamped by the negative ceiling. There is no
  answer record to carry a TTL, which is why the SOA is required.
- **A denial with no SOA is not cached** (`RejectReason::NoSoaInDenial`). It is answered
  and forgotten.
- **A NODATA entry for one qtype must not suppress a positive entry for another qtype at
  the same name.** This falls out of keying on `(qname, qtype, qclass)`, but it is the
  kind of thing that is correct by construction right up until it is not, so it is
  asserted explicitly.

### 6. Storage, concurrency and eviction

- **Sharded concurrent map**, not the `ArcSwap` whole-replacement pattern used for the
  filtering matcher. `ArcSwap` is right for the matcher because the matcher is immutable
  between explicit reloads; the cache is mutated on the hot path by every miss, so
  wholesale replacement is wrong for it. A single lock over one map would serialise every
  query in a process serving a whole house.
- **No lock is ever held across an `await`.** The store is synchronous; network work
  happens outside the guard.
- **Lazy expiry on lookup, plus capacity-bounded eviction.** An expired entry is reported
  as `Lookup::Expired` and removed, never served. A background sweeper task is
  *deferred, not rejected*: it would be a second concurrent mutator and one more task that
  can fail in a process where a panic takes DNS down for the whole house, for a benefit
  that capacity-bounded eviction already delivers.
- **Eviction is distinct from expiry.** Expiry removes stale entries; eviction removes
  *fresh* entries because there is no room. The eviction pass reclaims expired entries
  first and only then evicts by recency, and it does bounded work per call — no unbounded
  scan on the hot path.
- **A hard capacity bound from the start**, on both entry count and estimated bytes. The
  deployment target is a Raspberry Pi that must simultaneously hold the filtering matcher
  (projected at roughly **45–75MB per million domains**, after the allowlist decision put
  two bitmasks on every terminal instead of one), the query-log ring and a Leptos SSR web
  layer, all in one process. An unbounded cache is a denial of service against the box it
  runs on.
- **Byte accounting is `HeapBytes`, not a bare `usize`.** `ShardInner::bytes` is a manually
  accumulated counter — incremented in `admit`, decremented on eviction — which is exactly
  where `arithmetic_side_effects = deny` is meant to bite. `HeapBytes` wraps the checked
  add (returns `CacheError::ByteAccountingOverflow` rather than wrapping to a huge value)
  and a saturating subtract (never underflows), the same checked/saturating pairing
  `styx-proto`'s `Ttl` already uses for its decrement. `CacheCapacity::max_bytes` and
  `CacheStats::bytes` share the same type, so a byte count is never silently compared
  against or reported as a plain integer.

### 7. Observability

- `tracing` throughout (arch-lint's `require-tracing`), with the cache stage emitting its
  hit/miss outcome into the **query-log observer hook that Phase 2 already declared** —
  that hook exists precisely so the product half does not rewrite the hot path later.
- `CacheStats` counts hits, misses, negative hits, admissions,
  **out-of-bailiwick rejections**, expiries, evictions, entries and bytes, from day one.
  This is a direct mitigation for the accepted consequence that **cache behaviour gets no
  operational feedback until the cutover, which is the last phase** — when the household
  finally moves over, the data must already be being collected.

### 8. Error handling

- `CacheError` is a `thiserror` enum (arch-lint's `require-thiserror`), returned through
  `Result`. **No `unwrap`, no `expect`, no unchecked indexing** anywhere in this component
  — `panic = "deny"` is load-bearing and its real mitigation, the `catch_unwind` boundary,
  does not arrive until Phase 12.
- A cache error is **never** allowed to fail a query. Every error path degrades to "treat
  it as a miss" or "do not admit this record", and is logged. The cache is an
  optimisation; it must not be able to break resolution.

### 9. Testing strategy

- **Pure unit tests in `domain`** for the bailiwick predicate, TTL arithmetic at its
  boundaries, key canonicalisation and negative-TTL derivation. The bailiwick predicate
  gets exhaustive coverage because it is the security boundary.
- **Socket-level tests** against the Phase 2 in-process fake root, TLD and authoritative
  servers over real sockets, driving the whole pipeline. These are the default TDD cycle
  for this project.
- **Injected-clock tests** for every expiry, eviction and negative-cache assertion.
- **Store-introspection tests** for the bailiwick criterion. Asserting on the *response*
  is insufficient: "cached" is a stronger claim than "served", so the test must inspect
  the store's contents directly and find the poisoned record absent.
- `hickory-proto` is available as the **test oracle only**, and a CI check asserts it
  never becomes a real dependency.

---

## Structure

### Crate and module layout

```text
styx-resolution/
  src/
    domain/
      cache/
        key.rs             CacheKey, CanonicalName
        entry.rs           CacheEntry, SecurityStatus
        positive_entry.rs  PositiveEntry, CachedRRset, CachedMessage
        negative_entry.rs  NegativeEntry, DenialKind
        ttl.rs             Deadline, TtlPolicy
        bytes.rs           HeapBytes
        bailiwick.rs       Bailiwick
        admission.rs       Admission, AdmissionOutcome, RejectedRecord,
                           RejectReason (AnswerSource imported from domain::answer)
        port.rs            trait AnswerCache, Lookup
        capacity.rs        CacheCapacity
        stats.rs           CacheStats
        error.rs           CacheError (thiserror)
    application/
      cache_stage.rs       the lookup → miss → resolve → admit flow
    infrastructure/
      cache/
        sharded.rs         ShardedAnswerCache, Shard, ShardInner
        eviction.rs        Eviction, EvictionReport
```

### Trait (port) relationships

1. `AnswerCache` (in `domain::cache::port`) defines the cache capability: `lookup`,
   `admit`, `purge_all`, `stats`. Consumers prefer static dispatch via generics
   (`<A: AnswerCache>`, `impl AnswerCache`).
2. `ShardedAnswerCache` (in `infrastructure::cache::sharded`) implements `AnswerCache`.
3. `Clock` (from Phase 2) is consumed generically as `Arc<C>` where `C: Clock`; nothing in
   this component reads the system clock.
4. `CacheError` implements `std::error::Error` via `thiserror::Error`.
5. `CanonicalName` wraps `styx_proto`'s name type; it does not replace it.
6. `HeapBytes` (in `domain::cache::bytes`) is the one place byte-count arithmetic happens;
   `CacheEntry::heap_size`, `ShardInner::bytes`, `CacheCapacity::max_bytes` and
   `CacheStats::bytes` all carry it rather than a bare `usize`.

### Dependency direction

1. `domain::cache` depends on `styx-proto` and on `domain::clock` only. It depends on
   **no** `infrastructure` module and on **no** other feature crate.
2. `infrastructure::cache` depends on `domain::cache` (to implement the trait) and on
   `styx-proto`. Never the reverse.
3. `application::cache_stage` depends on `domain::cache` (the trait, not the
   implementation), on the Phase 3 `Upstream` pool, and on the Phase 2 query-log observer
   hook.
4. The `styx` binary constructs the single `ShardedAnswerCache`, wraps it in `Arc`, and
   injects it into the pipeline.
5. **`styx-recursion` (Phase 5) will not depend on `styx-resolution`.** It declares its
   own port in `styx-recursion::domain`; the `styx` binary implements that port with an
   adapter over the concrete cache or generic `<A: AnswerCache>`. This is the
   cross-feature rule: feature crates never name each other, cross-feature needs are
   ports in the consumer's `domain`, implemented by an adapter in the binary.
6. `styx-proto` may be depended on by any crate — it is the one explicit exception to the
   cross-feature rule, because every crate parses through the wire codec, and
   `[[restrict-use]]` must be written so as not to forbid it.

### Layer responsibilities

1. **`domain` layer** — policy: what a key is, what an entry is, when it expires, what may
   be admitted, and the bailiwick rule. Pure, `Clock`-parameterised, no I/O, no allocation
   strategy. Exhaustively unit-testable.
2. **`application` layer** — orchestration: the cache stage of the fixed pipeline
   `local records → filter → cache → upstream`, and outcome emission to the query-log
   observer.
3. **`infrastructure` layer** — mechanism: sharded storage, capacity accounting, eviction,
   `tracing` spans and counters.
4. **Error layer** — `CacheError` as a `thiserror` enum returned through `Result`; every
   error degrades to a miss or a non-admission and never fails a query.

### Position in the resolution pipeline

```text
client query
  → LocalRecords lookup      (Phase 2 port; hit ⇒ Insecure answer, AD cleared,
                              no forged signature, BYPASSES the cache entirely)
  → FilterPolicy verdict     (Phase 2 port, Phase 8 implementation; blocked ⇒ one of five
                              modes, short TTL, AD cleared, no forged RRSIG,
                              BYPASSES the cache entirely)
  → AnswerCache::lookup      ◀── THIS PHASE
       Hit(fresh)            ⇒ assemble response with remaining TTL, return
       Expired | Miss        ⇒ continue
  → Upstream pool            (Phase 3: strategy, HealthState, Do53 forwarder)
  → Admission::evaluate      ◀── THIS PHASE (bailiwick, TTL clamp, forgery refusal)
  → AnswerCache::admit       ◀── THIS PHASE
  → group-policy filter over the result on the way out  (Phase 8)
  → response to client
```

---

## Operations

### 1. Create `domain::cache::key` — `CanonicalName`, `CacheKey`

1. **Responsibility**: turn a `Question` into the global cache key, and provide the
   suffix relation the bailiwick rule is expressed in.
2. **`CanonicalName`**
   - Field (private): the underlying `styx-proto` name, stored with every label
     lowercased. Set only by `canonicalize`.
   - `canonicalize(name) -> CanonicalName`: lowercase ASCII labels only (DNS name
     comparison is case-insensitive; non-ASCII bytes are left untouched), normalise the
     root label so `example.com` and `example.com.` canonicalise identically.
   - `is_subdomain_of(&self, other) -> bool`: true when `other` is the root, or when
     `self`'s labels end with `other`'s labels, compared right-to-left. Returns true for
     equality. Used by the bailiwick rule and nowhere else that matters.
   - `label_count(&self) -> usize`.
   - `inner(&self) -> Name`: read accessor unwrapping the underlying `styx-proto` name,
     used wherever an owner name is written back into an outgoing wire `Message`.
3. **`CacheKey`**
   - Fields (private, set only by `from_question`): `qname: CanonicalName`,
     `qtype: RecordType`, `qclass: RecordClass`.
   - `from_question(&Question) -> Result<CacheKey, CacheError>`: canonicalises the name;
     returns `CacheError::UncacheableQuestion` for the meta-qtypes `ANY`, `AXFR`, `IXFR`,
     `OPT`.
   - `qname(&self) -> CanonicalName`, `qtype(&self) -> RecordType`,
     `qclass(&self) -> RecordClass`: read accessors, used by `CachedMessage::to_response`
     and `NegativeEntry::to_response` to rebuild the outgoing `Question` section.
   - Derives `Eq`, `Hash`, `Clone`, `Debug`.
4. **Constraints**: no client, group or subnet field may ever be added — the key is the
   question and only the question. No indexing that can be out of bounds; label comparison
   uses iterators, not offsets.

### 2. Create `domain::cache::ttl` — `Deadline`, `TtlPolicy`

1. **Responsibility**: the single place in the component where TTL arithmetic happens.
2. **`Deadline`**
   - Field (private): the absolute `Instant` at which the entry stops being fresh.
   - `from_ttl(now, ttl) -> Result<Deadline, CacheError>`: checked addition; on overflow
     returns `CacheError::TtlOverflow`.
   - `remaining(&self, now) -> Result<Ttl, CacheError>`: checked subtraction; saturates at
     zero rather than underflowing, and never panics near the expiry boundary.
   - `has_expired(&self, now) -> bool`.
3. **`TtlPolicy`**
   - Fields: `floor`, `ceiling`, `negative_ceiling`, all configurable.
   - `clamp(ttl) -> Ttl`.
   - `effective_negative_ttl(soa) -> Result<Ttl, CacheError>`: the minimum of the SOA
     record's own TTL and its `MINIMUM` field, per RFC 2308, then clamped by
     `negative_ceiling`.
4. **Constraints**: **every** arithmetic operation here is checked —
   `arithmetic_side_effects = deny` applies workspace-wide and this module is where it
   bites. No operation in this module may panic for any input.

### 3. Create `domain::cache::bytes` — `HeapBytes`

1. **Responsibility**: the single place manual byte-count arithmetic happens for capacity
   accounting — the same role `ttl.rs` plays for TTL arithmetic, for the one other counter
   in this component that is accumulated by hand rather than read off a collection's own
   length.
2. **`HeapBytes`**
   - Field (private): a `usize` count of estimated heap bytes.
   - `new(usize) -> HeapBytes`.
   - `get(&self) -> usize`: read accessor.
   - `checked_add(&self, other: HeapBytes) -> Result<HeapBytes, CacheError>`: on overflow
     returns `CacheError::ByteAccountingOverflow` rather than wrapping to a huge value.
   - `saturating_sub(&self, other: HeapBytes) -> HeapBytes`: never underflows, the same
     checked-and-saturating pairing `styx-proto`'s `Ttl` uses for its own decrement.
3. **Constraints**: no setter — every change goes through `checked_add` or `saturating_sub`
   and produces a new value. `CacheEntry::heap_size`, `ShardInner::bytes`,
   `CacheCapacity::max_bytes` and `CacheStats::bytes` all use this type; none of them holds
   a bare `usize` for a byte count.

### 4. Create `domain::cache::entry`, `positive_entry`, `negative_entry` — the entry types

1. **Responsibility**: the three shapes a cached answer can take, plus their freshness,
   split by concept — the shared shape in `entry.rs`, the positive shapes in
   `positive_entry.rs`, the negative shape in `negative_entry.rs` — the way `styx-proto`
   splits `domain/rdata/basic.rs` from `domain/rdata/dnssec.rs` rather than letting one
   file accumulate every entry-shaped type.
2. **`entry.rs`**
   - **`CacheEntry`**: the `Positive`/`Negative` enum, with `deadline()`, `is_fresh(now)`
     and `heap_size() -> HeapBytes` for capacity accounting.
   - **`SecurityStatus`**: `Indeterminate` / `Insecure` / `Secure` / `Bogus`.
     **In this phase every admitted entry is `Indeterminate` and `signatures` is `None`.**
     The type exists now because Phase 6 — DNSSEC hard-fails on bogus answers, and bolting
     a verdict onto these types one phase later would mean either re-validating on every
     cache hit or reshaping the store.
3. **`positive_entry.rs`**
   - **`CachedRRset`**: owner, type, class, the RDATA set, the original TTL as received,
     the computed `Deadline`, a `SecurityStatus`, and an optional signature list.
     `remaining_ttl(now)` delegates to `Deadline::remaining`.
   - **`CachedMessage`**: RCODE, flags, and the answer/authority/additional sections as
     `CachedRRset` vectors, with the entry `Deadline` being the earliest deadline among
     them. `to_response(key, now)` rebuilds a `Message` with every TTL recomputed from
     `now`. *This is the shape used where an answer does not reduce to one RRset of the
     queried type — a CNAME chain, or a referral-shaped response arriving on a forwarding
     path.*
   - **`PositiveEntry`**: the `RRset`/`Message` enum wrapping the two shapes above.
4. **`negative_entry.rs`**
   - **`NegativeEntry`**: `DenialKind` (`NxDomain` or `NoData`), the SOA that justified and
     timed it, the `Deadline`, a `SecurityStatus`. `to_response(key, now)` produces the
     correct RCODE for the kind — NXDOMAIN for `NxDomain`, NOERROR with an empty answer
     section for `NoData` — with the SOA in the authority section and its TTL recomputed.
   - **`DenialKind`**: `NxDomain` / `NoData`.
5. **Constraints**: entries are immutable once admitted; a change means a fresh admission.

### 5. Create `domain::cache::bailiwick` — `Bailiwick`

1. **Responsibility**: the security boundary. Decide which zone a responder is entitled to
   teach the cache about, and whether a given owner name falls inside it.
2. **`of_response(question, message) -> Bailiwick`**: derive the zone of authority from
   the question and the response's authority section — the SOA owner when present,
   otherwise the deepest NS owner at or above the qname, otherwise the qname itself.
3. **`permits(&self, owner) -> bool`**: `owner.is_subdomain_of(&self.zone)`.
4. **Section rules**, applied by `Admission` and documented on this type:
   - **Answer**: the owner is the qname, or is reached from the qname by a CNAME/DNAME
     chain whose every link is itself permitted.
   - **Authority**: SOA or NS only, for a zone at or above the bailiwick.
   - **Additional**: **strictest** — address records only, and only for names at or below
     the zone whose NS records appeared in this same response's authority section.
     *This is the classic poisoning vector and gets the tightest rule.*
5. **Constraints**: pure function of its inputs, no `Clock`, no I/O, no allocation beyond
   the chain walk. Exhaustively unit-tested; this is the one predicate in the phase whose
   failure is a vulnerability rather than a bug.

### 6. Create `domain::cache::admission` — `Admission`, `AdmissionOutcome`

1. **Responsibility**: the complete answer to "may this be cached at all?", of which the
   bailiwick rule is one clause.
2. **`evaluate(&self, bailiwick: &Bailiwick, message: &Message, source: AnswerSource, now: Instant) -> AdmissionOutcome`**
   - Refuse outright when `source` is `AnswerSource::LocalRecord` or
     `AnswerSource::Blocked` → every record rejected with
     `RejectReason::ForgedAnswer`. The test is the private helper
     `is_forged_source(source: AnswerSource) -> bool`. It is private so that no caller
     can run it *instead of* `evaluate`: the check lives on the only path into the
     store.
   - Refuse outright when `source` is `AnswerSource::CacheHit` or `AnswerSource::Error`
     → every record rejected with `RejectReason::InadmissibleSource`. Only `Upstream` and
     `Recursion` proceed. The match is exhaustive, with no wildcard arm, so a variant
     added later has to be classified here.
     **Local records and blocked replies are forged answers and never enter this cache**:
     the cache is global, so a cached forgery would be served to clients in groups where
     the block does not apply; and blocked replies carry a deliberately short TTL so
     unblocking takes effect quickly, which caching would defeat.
   - Group records into RRsets by `(owner, type, class)`.
   - Apply the per-section bailiwick rule; out-of-bailiwick RRsets go to `rejected` with
     `RejectReason::OutOfBailiwick`. **Partial admission**: the in-bailiwick parts of a
     mixed-validity response are still admitted.
   - Reject TTL-zero RRsets with `RejectReason::ZeroTtl` — served once, never stored.
   - Clamp surviving TTLs via `TtlPolicy` and compute each `Deadline` from `now`.
   - For a denial (NXDOMAIN, or NOERROR with an empty answer section), build a
     `NegativeEntry` with the kind and the SOA-derived lifetime; with no SOA present,
     reject with `RejectReason::NoSoaInDenial` and cache nothing.
   - Decide RRset-vs-message shape: an answer that reduces to one RRset of the queried
     type becomes a `CachedRRset`; anything else — a CNAME chain, a referral-shaped
     response — becomes a `CachedMessage`.
3. **`AdmissionOutcome`**: the admitted entries and the rejected records with reasons. The
   rejection list is not decoration: it drives the `rejected_out_of_bailiwick` counter and
   is what the store-introspection tests assert against.
4. **Constraints**: `Admission` is the **only** path into the store. The `AnswerCache`
   trait accepts an `AdmissionOutcome`, never a raw `Message`, so there is no way to
   insert unvetted data.
5. **Shape constraint** *(amendment, 2026-09-24)*: `evaluate` is a thin composition of
   named, guard-claused helpers — one each for forged-source refusal, per-section
   bailiwick admission (answer, authority, additional), TTL-zero rejection, TTL clamping
   plus deadline computation, negative-entry construction, and RRset-vs-message shape
   selection — rather than one function holding every step inline. Each helper returns
   early on its own reject reason instead of nesting the next step inside its success
   branch. This is what keeps the security-critical path clear of both `excessive_nesting`
   (threshold 4) and `too_many_lines` (threshold 60), per Phase 0 Approach §10.

### 7. Create `domain::cache::port`, `capacity`, `stats` — the `AnswerCache` trait

1. **Responsibility**: the capability, stated independently of the storage mechanism, so
   the pipeline and Phase 5's adapter both depend on a trait — split by concept into
   `port.rs` (the trait and its lookup result), `capacity.rs` (the bound it is checked
   against) and `stats.rs` (what it reports), rather than one file collecting all four.
2. **`port.rs`** — trait `AnswerCache` and `Lookup`
   - `lookup(&self, key: &CacheKey) -> Lookup` — `Hit(entry)` only when fresh against the
     `Clock`; `Expired` when an entry was found but is stale (it is removed as a side
     effect); `Miss` otherwise.
   - `admit(&self, key: &CacheKey, outcome: AdmissionOutcome) -> Result<usize, CacheError>`
     — returns how many entries were stored.
   - `purge_all(&self) -> usize` — the seam the Phase 11 — Web UI "flush cache" action
     will use. Present now so it is not retrofitted through a lock-free hot-path structure
     later.
   - `stats(&self) -> CacheStats`.
3. **`capacity.rs`** — **`CacheCapacity`**: `max_entries: usize`, `max_bytes: HeapBytes`,
   and `needs_eviction(entries: usize, bytes: HeapBytes) -> bool`. `max_entries` stays a
   bare `usize` — it is only ever compared, never accumulated by hand, so no arithmetic
   rule attaches to it; `max_bytes` shares `HeapBytes` with the counter it bounds.
4. **`stats.rs`** — **`CacheStats`**: `hits`, `misses`, `negative_hits`, `admitted`,
   `rejected_out_of_bailiwick`, `expired`, `evicted` as plain `u64` counters — accumulated
   by an atomic `fetch_add` over the life of the process, with no validated range or
   meaningful overflow risk to guard — plus `entries: usize` and `bytes: HeapBytes`, the
   latter sharing the same type as `ShardInner::bytes` so a byte count is never reported as
   a bare integer at the one point it becomes externally visible.
5. **Constraints**: `AnswerCache` is `Send + Sync`, no `async` — the store is synchronous
   and no lock is held across an `await`. Consumers use static dispatch (`<A: AnswerCache>`,
   `impl AnswerCache`).

### 8. Create `infrastructure::cache::sharded` — `ShardedAnswerCache`

1. **Responsibility**: the concurrent, bounded, memory-only store.
2. **Construction**: `new(clock: Arc<C>, capacity: CacheCapacity, ttl: TtlPolicy,
   shard_count: usize)` where `C: Clock`. One instance per process, shared by `Arc`.
3. **`shard_for(key)`**: hash the key, index into the shard vector. Uses checked indexing
   — `indexing_slicing = deny`.
4. **`lookup`**: read-lock the shard, look up, read `Clock::now()` once, check freshness;
   on a stale entry upgrade to a write lock, remove it, count an expiry, return `Expired`.
   Bump recency on a hit. Increment hit/miss/negative-hit counters.
5. **`admit`**: write-lock the shard, insert the admitted entries, fold each entry's
   `heap_size()` into `ShardInner::bytes` via `HeapBytes::checked_add` — the resulting
   `CacheError::ByteAccountingOverflow`, like every `CacheError`, degrades to "not
   admitted" rather than failing the query — then call `Eviction::evict` if the capacity
   bound is exceeded.
6. **`purge_all`**: clear every shard, return the count removed.
7. **`stats`**: snapshot the atomic counters plus current entries and bytes.
8. **Instrumentation**: `tracing` spans on `lookup` and `admit`; a `warn`-level event
   whenever a record is rejected as out of bailiwick, because that is either a broken
   upstream or an attack and either way somebody should be able to see it.
9. **Constraints**: no lock held across an `await`; no `unwrap`/`expect` on lock results
   (poisoning is handled explicitly and degrades to a miss); no I/O of any kind —
   arch-lint's `no-sync-io` applies.

### 9. Create `infrastructure::cache::eviction` — `Eviction`

1. **Responsibility**: keep the store inside its bound, doing bounded work per call.
2. **`evict(inner, now, capacity) -> EvictionReport`**
   - **First pass**: reclaim entries already expired against `now`. Free memory, no useful
     data lost.
   - **Second pass**, only if still over the bound: evict least-recently-used *fresh*
     entries until the store is back under both the entry-count and byte bounds.
   - Each removal, in either pass, shrinks `ShardInner::bytes` via
     `HeapBytes::saturating_sub` — eviction only ever removes what was accounted for, so a
     saturating subtract is the right primitive and it never panics.
   - Return counts of each, so the two are separately observable — **expiry and eviction
     are different events and the exit criteria name them separately.**
3. **Constraints**: bounded work per invocation; no unbounded scan on the hot path.

### 10. Create `domain::cache::error` — `CacheError`

1. **Definition**: a `thiserror` enum. Variants: `TtlOverflow`, `DeadlineInThePast`,
   `UncacheableQuestion`, `MissingSoa`, `ResponseAssembly`, `ByteAccountingOverflow` (from
   `HeapBytes::checked_add`, the one other manually accumulated counter in this
   component).
2. **Usage**: returned through `Result` from every fallible operation.
3. **Constraints**: **no `CacheError` may ever fail a client query.** Every call site
   degrades to "treat it as a miss" or "do not admit this record", logs at `warn`, and
   continues. The cache is an optimisation; it must not be able to break resolution. Error
   text must not leak internal state into anything client-visible.

### 11. Create `application::cache_stage` — the pipeline stage

1. **Responsibility**: wire the cache into the fixed order
   `local records → filter → cache → upstream`.
2. **Flow**
   - Build the `CacheKey` from the question; on `UncacheableQuestion`, skip the cache
     entirely in both directions and go straight to the pool.
   - `lookup`. On `Hit`, assemble the response with recomputed TTLs and return, reporting
     `AnswerSource::CacheHit` in the `ResolutionOutcome`.
   - On `Miss` or `Expired`, resolve through the Phase 3 `Upstream` pool.
   - Map the response's `kind` to its provenance — `UpstreamKind::Forwarder` →
     `AnswerSource::Upstream`, `UpstreamKind::Recursor` → `AnswerSource::Recursion` —
     with an exhaustive match. Derive the `Bailiwick` from the question and the response,
     run `Admission::evaluate` with that source, `admit`, and report the same source in
     the `ResolutionOutcome`.
   - Return the response; group-policy filtering (Phase 8) is applied over it on the way
     out.
3. **Outcome emission**: report hit / miss / negative-hit into the query-log observer hook
   declared in Phase 2, so Phase 10's pipeline gets the data with no hot-path rewrite.
4. **Constraints**: this stage never calls `LocalRecords` or `FilterPolicy` itself — they
   run before it, by the fixed pipeline order, and that order is a correctness property.

### 12. Create the test suites

1. **`domain` unit tests**
   - `bailiwick`: exhaustive — in-zone, out-of-zone, sibling zone, parent zone, root, the
     qname itself, a CNAME chain with a poisoned link, and glue for a name outside the
     delegated zone. Answer, authority and additional sections tested separately.
   - `ttl`: TTL zero, TTL at the protocol maximum, the instant of expiry, one unit past
     it, a clock jump larger than any stored TTL, and the floor/ceiling clamps.
   - `bytes`: `HeapBytes::checked_add` overflowing at `usize::MAX`, `saturating_sub` below
     zero, and ordinary accumulation round-tripping through `admit` and `evict`.
   - `key`: case-differing qnames collide; trailing-dot and root-label forms collide;
     `ANY`/`AXFR`/`IXFR`/`OPT` are refused.
   - `admission`: mixed-validity partial admission; forged-source refusal for both
     `LocalRecord` and `Blocked`; `InadmissibleSource` refusal for `CacheHit` and
     `Error`; admission for both `Upstream` and `Recursion`; denial with and without an
     SOA; NODATA versus NXDOMAIN.
2. **Socket-level tests** against the Phase 2 in-process fakes over real sockets: a second
   identical query is served from cache with a reduced TTL and no outbound traffic; after
   the clock advances past the TTL, the query goes upstream again; a NODATA denial is
   cached and re-served; a positive `A` and a NODATA `AAAA` for the same name coexist.
3. **Store-introspection tests** for the bailiwick criterion: a fake authoritative server
   returns a response whose additional section contains an address record for an unrelated
   zone; assert that record is **absent from the store**, not merely absent from the
   response.
   *"Cached" is a stronger claim than "served" and the assertion must match the claim.*
4. **Eviction tests** under an injected clock: fill past the entry bound and past the byte
   bound; assert expired entries are reclaimed before fresh ones are evicted; assert the
   `EvictionReport` distinguishes the two.
5. **Unblock test**: a name that was blocked resolves normally on the next query with no
   cache flush, because the blocked reply was never cached. This is the observable payoff
   of the never-cache-forgeries rule and is worth asserting explicitly.
6. **Concurrency test**: many tasks admitting the same key simultaneously leave exactly
   one entry and no corruption.

---

## Norms

1. **Layering** — `domain` never names `infrastructure`; `infrastructure` implements
   `domain` traits; `application` depends on traits, not implementations. Enforced by
   arch-lint's `[[scopes]]` / `[[deny-scope-dep]]` on a syn-engine config, and
   independently by a `cargo tree --edges normal` gate, because arch-lint reads source
   text while `cargo tree` reads the real link graph and they catch different mistakes.
2. **Cross-crate** — `styx-resolution` names no other feature crate. `styx-proto` is the
   one permitted shared foundation. A future consumer in another feature crate declares
   its own port and the `styx` binary adapts.
3. **Error handling** — `thiserror` enums, `Result<T, CacheError>`, never a bare `String`
   error. No `unwrap`, no `expect`, no `panic!`, no unchecked indexing in non-test code
   (`no-unwrap-expect` with `allow_in_tests = true`, `indexing_slicing = deny`). A cache
   error degrades the cache, never the query.
4. **Arithmetic** — all TTL and deadline arithmetic is checked and confined to
   `domain::cache::ttl`. `arithmetic_side_effects = deny` is workspace-wide and this is
   where it is most likely to bite.
5. **Time** — `Clock` only. `Instant::now()` and `SystemTime::now()` do not appear in this
   component, in production code or in tests.
6. **I/O** — none. No file, no socket, no database, from any module of this component
   (`no-sync-io`).
7. **Concurrency** — sharded locking; no lock held across an `await`; lock poisoning
   handled explicitly and degraded to a miss rather than unwrapped.
8. **Logging** — `tracing` throughout (`require-tracing`), spans on the hot-path entry
   points, `warn` on every out-of-bailiwick rejection, `debug` on eviction pressure. No
   qname is logged at a level that would contradict the project's privacy modes — the
   `Private` mode never writes a qname to disk, and this component must not be the thing
   that does.
9. **Testing** — socket-level by default against the Phase 2 fakes; pure unit tests for
   `domain` policy; `hickory-proto` as the test oracle, `[dev-dependencies]` only, with
   the CI `hickory-dev-only` check asserting it never appears in a normal or build
   dependency path.
10. **Naming** — this component is consistently called the **answer cache**, never "the
    cache". The word "cache" unqualified is ambiguous in this project from Phase 5 onward,
    and the two caches must never be conflated. Module docs state explicitly that this
    cache is keyed by question and knows nothing about zones or nameservers.
11. **Documentation** — every public item carries a doc comment; the bailiwick and
    admission modules carry module-level docs stating the rule and **why** it exists,
    because that rationale is the part most likely to be lost.
12. **Object Calisthenics** — this phase's code follows `AGENTS.md`, including its
    primitive-obsession/newtype test: a primitive is wrapped only when it carries a
    validated range, a checked arithmetic operation, a non-trivial wire encoding or named
    constants — **domain rules attached to the value, not the primitive-ness of its
    type**. `HeapBytes` (checked-add byte accounting that reports
    `CacheError::ByteAccountingOverflow` rather than wrapping, paired with a saturating
    subtract that never underflows) is this phase's own worked example, alongside
    `Deadline` (checked construction from a `Ttl`, saturating remaining-time arithmetic),
    which already followed the same discipline before `AGENTS.md` wrote it down.
    `CacheStats`'s plain `u64` hit/miss/eviction counters and `CacheCapacity::max_entries`
    stay bare integers deliberately: neither carries a domain rule beyond straightforward
    counting and comparison, and wrapping them would be ceremony with no behaviour behind
    it.

---

## Safeguards

### 1. Exit criteria (preserved verbatim)

> **TTL expiry, eviction and negative-cache behaviour under injected time; no
> out-of-bailiwick data is ever cached.**

And the phase scope, verbatim:

> - RRset and message cache keyed `(qname, qtype, qclass)`, global.
> - TTL handling, RFC 2308 negative caching, and bailiwick rules governing what is
>   cacheable at all.

### 2. Functional constraints

- The cache key is `(qname, qtype, qclass)` and **nothing else** — no client, no group, no
  client subnet, no upstream identity.
- Group policy is a filter over the result on the way out; it is **never** a dimension of
  the key, and there are **no per-group cache namespaces**.
- **Local records and blocked replies never enter this cache.** Both are forged answers.
- An expired entry is never served. No serve-stale in this phase.
- NXDOMAIN and NODATA are cached separately and remain distinguishable on retrieval.
- A denial with no SOA is not cached.
- A TTL-zero record is served but not stored.
- Meta-qtypes (`ANY`, `AXFR`, `IXFR`, `OPT`) never form a key.
- `purge_all` exists and empties the store completely.

### 3. Security constraints

- **No out-of-bailiwick data is ever cached.** Checked at admission, not at retrieval, so
  the poisoned record never enters the store at all.
- The additional section gets the strictest rule — glue only, only for names at or below a
  zone delegated in the same response's authority section.
- Mixed-validity responses admit the valid parts and reject the rest; neither
  whole-response acceptance nor whole-response rejection is acceptable.
- `Admission` is the only path into the store; `admit` accepts an `AdmissionOutcome`,
  never a raw `Message`.
- Every out-of-bailiwick rejection is counted and logged at `warn`.
- No cache error message reaches a client; errors degrade to a miss.

### 4. Performance and resource constraints

- Hard bounds on both entry count and estimated bytes, configurable. **The cache must
  coexist on a Raspberry Pi with the filtering matcher, projected at roughly 45–75MB per
  million domains after the allowlist decision put two bitmasks on every terminal instead
  of one**, plus the query-log ring and a Leptos SSR web layer, all in one process.
- Sharded locking; no single global lock on the hot path.
- Eviction does bounded work per invocation; no unbounded scan while a lock is held.
- A cache hit performs zero network I/O and zero disk I/O.

### 5. Technical constraints

- Memory-only, process-local, no persistence, no warm start. **A database outage must be
  entirely unobservable from the resolution path.**
- All time via the injected `Clock`; no system clock reads.
- All TTL arithmetic checked; no operation in the TTL module may panic for any input.
- No `unwrap`/`expect`/`panic!`/unchecked indexing in non-test code.
- `thiserror` enums through `Result`; `tracing` for all logging.
- `hickory-proto` in `[dev-dependencies]` only, asserted by the CI `hickory-dev-only`
  check.
- The cache is exposed as a trait so Phase 5 can consume it through its own port without
  `styx-recursion` depending on `styx-resolution`.
- **Object Calisthenics is partly gated now**, per Phase 0 Norm 17: nesting depth
  (`excessive_nesting`, threshold 4), function length (`too_many_lines`, threshold 60),
  module length (`xtask module-size`, 400 counted lines per file) and mixed field
  visibility (`partial_pub_fields`) are mechanically enforced. Primitive wrapping —
  `HeapBytes`'s checked-add/saturating-sub pairing is this phase's own worked example —
  first-class collections and full words remain a review discipline: no lint decides
  whether a `u16` carries a domain rule.
- **This phase's code must pass the extended gate** *(amendment, 2026-09-24, per Phase 0
  Approach §10)*: `[[restrict-use]]` rules ban synchronous I/O in `domain`/`application`
  and `anyhow` in this library crate, backing Norms 3 and 6 mechanically rather than by
  convention alone — `CacheError` stays a `thiserror` enum end to end. `evaluate`
  (Operation 6) is decomposed into guard-claused helpers so the bailiwick logic — the
  component's security boundary — clears `excessive_nesting` and `too_many_lines` rather
  than accreting into one function. `HeapBytes`, `Deadline`, `CanonicalName`, `CacheKey`,
  `Bailiwick` and `ShardedAnswerCache` keep every field private behind their
  constructors, so `partial_pub_fields` has nothing to catch.

### 6. Verification constraints

- The bailiwick criterion is verified by **inspecting the store**, not by inspecting
  responses. "Never cached" is a stronger claim than "never served".
- Every expiry, eviction and negative-cache assertion drives the injected `Clock`; no test
  sleeps.
- Expiry and eviction are separately observable and separately asserted.
- `CacheStats` counters are asserted alongside behaviour, so the instrumentation that is
  the only mitigation for having no operational feedback until cutover is itself known to
  work.
- Pure `domain` unit tests plus socket-level tests against the Phase 2 in-process fakes;
  the fakes prove only that the resolver does what *we* think delegation means, which is
  why the per-phase differential run against a local `unbound` exists at all.

### 7. Boundary constraints — what this phase must not do

- Must not build any part of the **infrastructure cache** — delegations, NS sets,
  per-nameserver RTT, EDNS capability. That is keyed by zone and nameserver, lives in
  `styx-recursion`, is used only by recursion, and belongs to **Phase 5 — Recursion**.
- Must not implement DNSSEC validation. `SecurityStatus` stays `Indeterminate` and
  `signatures` stays `None` until **Phase 6 — DNSSEC**; the fields exist only so that
  phase does not force a reshape.
- Must not implement filtering, blocked-reply construction or the matcher — **Phase 8 —
  Filtering**.
- Must not implement the query-log pipeline — it only emits into the hook Phase 2
  declared; **Phase 10 — Query log pipeline** consumes it.
- Must not add persistence, a background sweeper task, serve-stale, or request coalescing
  in this phase. Each is a deliberate deferral recorded here, not an oversight.

### 8. Accepted consequences and residual risks

- **No operational feedback on cache behaviour until the cutover, which is the last
  phase.** The household stays on Pi-hole until v1 is complete, so hit rate, memory growth
  and eviction pressure under a real query mix are invisible until the most expensive
  moment to act on them. This is the accepted cost of not doing a live migration under two
  hand-written security-critical subsystems. Mitigation: `CacheStats` from day one, and
  synthetic query mixes through the socket harness in the meantime.
- **The bailiwick rule is a security boundary, and "ever" is a strong word.** A gap is a
  cache-poisoning vulnerability in a resolver serving a household. Mitigation: pure
  `domain` logic, exhaustive unit tests, store-introspection socket tests, and a single
  admission path.
- **`panic = "deny"` is load-bearing and its real mitigation arrives last.** The
  `catch_unwind` boundary and supervised task model are Phase 12 — Cutover hardening.
  Until then the lint and the no-panic discipline in this component are the whole defence.
- **DNSSEC coupling is deferred by one phase.** If the entry shapes turn out not to carry
  what Phase 6 needs, that phase either re-validates on every hit or reshapes the store.
  Mitigation: `SecurityStatus` and `signatures` are present from the start.
- **The differential gate depends on the live internet**, so real DNS changes underneath
  the corpus and the job will sometimes fail for reasons that are not a bug here. That is
  why it gates a phase and never a push — and it also means a genuine regression can hide
  behind a shrug. Remaining-TTL differences between styx and `unbound` need an explicit
  tolerance rule in the comparison, since the diff is on RCODE, AD bit and rrset contents.
- **Deferred with intent, to be revisited with measurement**: request coalescing for
  concurrent identical misses (which interacts with the `race` selection strategy, itself
  already flagged as a privacy hazard because one query goes to N providers and every
  provider sees every domain); a background expiry sweeper; serve-stale; and the concrete
  values of the TTL floor, TTL ceiling, negative ceiling, shard count and capacity bounds,
  which follow the project's habit of deferring tuning constants to the keyboard.
