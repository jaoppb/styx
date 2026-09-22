# SPDD Analysis: Phase 8 — Filtering (`styx-filtering`)

> Project: **styx** — a filtering DNS resolver written from scratch in Rust, replacing
> Pi-hole's role on a home network (recursive/forwarding resolution, per-client blocking
> policy, Leptos admin UI). Single process, single binary, one box, local DB file.
>
> **Codebase context: greenfield, no existing implementation.** At the time of this
> analysis the repository contains only `SPEC.md`, `ROADMAP.md`, the per-phase specs under
> `docs/specs/`, and an inert `arch-lint.toml` inherited from an upstream Kotlin template.
> There is no git repository, no Cargo workspace, no Rust source, no migrations and no
> prior SPDD artifacts. Every statement below is therefore grounded in the project's
> settled design record rather than in read source code, and all "existing concepts" are
> concepts **committed by prior phases' specifications**, not concepts observed in code.
>
> This document is deliberately self-contained. The specification documents it was derived
> from are being retired; the decisions, their rationale, their accepted consequences and
> the recorded risks are reproduced here in full so nothing downstream needs them.

---

## Original Business Requirement

The following is the phase specification verbatim.

```markdown
# Phase 8 — Filtering (`styx-filtering`)

> Part of [ROADMAP.md](../../ROADMAP.md) · Previous: [Phase 7 — Encrypted inbound](07-encrypted-inbound.md) · Next: [Phase 9 — Storage](09-storage.md)

The largest phase in the product half, and the one most likely to want splitting
once started — see the risk in ROADMAP.md.

## Scope

- The reversed-label radix trie, walked right-to-left, wildcard nodes matching all
  descendants; one `RegexSet` for every regex rule (decision 16).
- **Two** per-group bitmasks on every terminal — `allow` and `block` — returned by
  one walk, verdict `!(allow & g) && (block & g)`, allow winning unconditionally
  over exact, wildcard and regex blocks (decisions 17 and 19).
- Immutable matcher, replaced wholesale via `ArcSwap` on explicit reload
  (decision 18).
- **Blocked-reply construction**: five modes with NXDOMAIN as default, NODATA for
  qtypes other than A/AAAA, short TTL, AD always cleared, no forged RRSIG, applied
  before validation (decision 20).
- **Adlist ingestion**: per-list staging, sanity checks (not HTML, minimum valid
  domain count, no collapse against the last ingest), last-known-good retention,
  and a stale marker carrying the reason (decision 21).
- The adapter in the `styx` binary wiring this into
  [phase 2](02-server-loop.md)'s `FilterPolicy` port.

## Exit criteria

Memory measured at one million domains against the revised ~45–75MB target (two
masks, not one); a reload under load causes no hot-path stall; each of the five
blocking modes is asserted to clear AD and forge no signature; an adlist fixture
serving HTTP 200 with an HTML body is rejected and the previous copy survives.
```

### Governing decisions this phase implements (inlined, with rationale)

The phase spec's numbered references are resolved here so this analysis stands alone.

1. **Full per-client groups in v1.** Clients, groups and list-to-group assignment are
   first-class in the domain model, the database and the UI. Not a v2 retrofit.

2. **The answer cache stays global, keyed `(qname, qtype, qclass)`.** Group policy is
   applied as a filter over the resolution result, on the way out. *Why:* per-group cache
   namespaces would multiply memory by N groups and shred the hit rate the cache exists to
   provide. This is what forces filtering to be a verdict function over a shared result
   rather than a cache-partitioning scheme.

3. **The matcher is a reversed-label radix trie plus a single `RegexSet`.** The trie is
   walked label-by-label right-to-left; a node flagged *wildcard* matches all descendants,
   so exact and wildcard lookups are the same operation rather than two code paths. All
   regex rules compile into one `RegexSet` automaton, so regex rule count is near-free at
   query time — it is explicitly **not** a linear scan over compiled regexes. Sizing
   target ~30–50MB per million domains (single-mask baseline), chosen so the resolver fits
   a Raspberry Pi.

4. **Per-group is a bitmask on each terminal, not a matcher per group.** One lookup, then
   `mask & client_groups`. *Why:* a matcher per group multiplies both build time and
   resident memory by the group count and makes reload N times more expensive, for a
   structure whose contents are overwhelmingly shared between groups.

5. **Reload is an explicit operation with an atomic swap.** The matcher is immutable and
   replaced wholesale via `ArcSwap`. There is
   **no mutation under a lock on the hot path**. *Why:* the hot path is a DNS response
   path with a latency budget; a writer lock held during a rebuild of a million-entry
   structure would stall every concurrent query.

6. **Allowlists are a second bitmask, and allow beats block unconditionally.** Each
   terminal carries an `allow` mask and a `block` mask; one walk returns both, and the
   verdict is `!(allow & g) && (block & g)`. Exact, wildcard and regex rules all feed the
   same pair, so an allow on `cdn.example.com` beats a wildcard block on `*.example.com`
   and beats a regex block. *Why:* every blocklist over-blocks eventually; without this,
   one bad list entry breaks a banking app and there is no escape hatch.
   **Accepted consequence:** per-terminal mask memory doubles — the ~30–50MB per million
   figure becomes **~45–75MB**, and that revised figure is what the exit criteria measure
   against.

7. **Blocked replies: five modes, NXDOMAIN by default.** The Pi-hole set — `NXDOMAIN`
   (styx's default), `NULL` (`0.0.0.0`/`::`, Pi-hole's default), `NODATA`, `IP`,
   `IP-NODATA-AAAA` — selectable in configuration. **Regardless of mode:** qtypes other
   than A/AAAA get NODATA; blocked replies carry a short TTL so unblocking takes effect
   quickly; **AD is always cleared and no RRSIG is ever forged**; and filtering is applied
   *before* validation, because a block is not a validation verdict.
   *Why this matters here:* Pi-hole never resolved this interaction and ships the breakage
   as bug reports, and because styx's validator **hard-fails** bogus answers with
   SERVFAIL, vagueness about the block/validate interaction is unaffordable.
   **Accepted consequence:** five response paths must each be tested against the
   validator, and a client validating with CD=0 receives an unsigned answer for a signed
   name — a deliberate lie, documented as one.

8. **Adlist ingestion is staged, validated, and keeps the last known good.** Each list is
   fetched into a staging buffer and must pass sanity checks before it replaces anything:
   the content-type is not HTML, it parses to at least a minimum count of syntactically
   valid domains, and the count has not collapsed against the previous ingest. *Why:* the
   dangerous failure is not a 404 — it is a captive portal or an error page served as HTTP
   200, which parses as thousands of junk domains and blackholes real traffic. Any failure
   leaves the previous good copy in place, marks the list stale in the UI
   **with the reason**, and the matcher rebuild proceeds from the remaining lists. The
   staleness badge and a manual "accept the shrink" override are therefore **required**
   UI, not optional.

9. **The hot path touches no I/O.** Matcher state is in memory, built at boot and on
   reload. The database holds configuration, adlist definitions, clients/groups and
   history only. A database outage degrades logging and admin, never resolution.

10. **Configuration has two stores with a hard boundary: the TOML file owns
    infrastructure, the database owns policy.** Clients, groups, adlists, allow/block
    rules, local records, privacy level and **blocking mode** are database-owned and
    runtime-editable. Listen addresses, upstreams, pools, TLS material, trust anchor and
    DB path are file-owned and need a restart. *Why:* no overlap means no precedence rule,
    and it structurally guarantees that a dead database cannot touch resolution.

11. **One crate per feature; `domain` / `application` / `infrastructure` are modules
    inside it.** Cargo enforces feature-to-feature isolation; an architecture lint
    enforces layering within a crate.

12. **Feature crates never depend on each other.** Cross-feature needs are expressed as a
    port in the consumer's `domain`, implemented by an adapter in the binary — concretely,
    the resolution crate declares a `FilterPolicy` port and the `styx` binary wires
    `styx-filtering` into it. The shared wire-codec crate (`styx-proto`) is the single
    explicit exception, because every crate parses through it.

13. **The pipeline order is fixed and is a correctness property, not a detail:** local
    records → **filter** → cache → upstream. Local records and blocks are both forged
    answers, so both clear AD, forge no signature, and **never enter the answer cache**.

14. **Local records are answered before the cache and are always Insecure** — AD cleared,
    no forged signature. Blocked replies follow the same honesty rule. This is the shared
    principle the blocked-reply builder must not violate.

### Non-goals that bear on this phase

- **EDNS Client Subnet (RFC 7871).** Deliberately omitted; it leaks client topology. The
  matcher therefore never sees or reasons about a subnet option.
- **DHCP server.** Clients are identified by IP plus optional manual naming; styx never
  owns the lease table. Client identity is best-effort and breaks on DHCP churn — the
  filtering verdict is only as trustworthy as the IP→group resolution feeding it.
- **Authoritative zone serving.** Local records and per-zone overrides are
  resolution/filtering concerns, not a zone-file server.
- **Multi-user admin, roles, audit trail.** There is no record of who changed a rule or
  disabled blocking.
- **Multi-node or replicated deployment.** One process; matcher state is process-local and
  needs no distribution story.

### Risks recorded against this phase

- **"Keep last known good" means a dead adlist blocks forever.** The staging decision
  trades one failure mode for another: a list whose URL rots keeps enforcing a frozen copy
  indefinitely, and the only signal is a staleness badge nobody is looking at. **Staleness
  must be visible on the dashboard, not buried on an adlist settings page.**
- **Five blocking modes multiply the validator interaction surface.** Configurability was
  chosen with eyes open, but each mode is a **distinct response path** that has to be
  proven not to set AD and not to forge a signature. This is exactly the kind of plural
  that hides an untested combination.
- **Phase 8 grew.** It holds the matcher, allowlist precedence, five blocked-reply modes
  and the adlist ingestion contract. It is the largest phase in the product half and the
  one most likely to want splitting once started.
- **Client identity is unreliable by construction.** Per-client groups keyed on IP will
  silently misattribute after a DHCP lease change. Manual naming and a visible "last seen"
  are mitigations, not fixes.

### Open choices deliberately left to the keyboard

- **Group mask width — `u64` versus a roaring bitmap.** Putting two masks on every
  terminal instead of one doubles the memory cost of this choice: a `u64` pair is 16 bytes
  per terminal, and the ~30–50MB/million estimate becomes ~45–75MB. Sixty-four groups is
  almost certainly enough for a house.
  **This is the number to measure at the end of this phase rather than guess now.**
- **The blocked-reply TTL value.**
- **The adlist sanity thresholds** — the minimum valid-domain count and the collapse
  ratio.

---

## Domain Concept Identification

### Existing Concepts (committed by prior phases — no code exists yet)

- **`FilterPolicy` port** — the hot-path seam this phase implements. Declared in the
  resolution crate's `domain` during the server-loop phase with a no-op implementation, so
  that the product half does not rewrite the hot path when it arrives. Owned by
  resolution, satisfied by filtering, wired by the binary.
- **Query / question** — `(qname, qtype, qclass)`. Produced by the wire codec phase. The
  matcher consumes the qname; the blocked-reply builder consumes the whole question plus
  the request header.
- **Client** — identified by source IP, optionally manually named. Resolves to a set of
  groups. Its lifecycle (auto-discovered on first query versus added by hand, what group
  an unknown client lands in, what happens to history rows on deletion) is deliberately
  **undecided here** and belongs to the storage phase's schema design. This phase must
  therefore consume a *group mask*, not a client record.
- **Group** — the unit of policy. Blocklists, allowlists and clients all attach to groups.
  Represented on the hot path purely as a bit position.
- **Answer cache** — global, keyed `(qname, qtype, qclass)`, sits *after* the filter in
  the pipeline. Blocked replies never enter it.
- **Local records** — matched ahead of the filter, always Insecure, never cached. The
  precedent for the blocked reply's honesty rule.
- **Validator** — hard-fails bogus answers with SERVFAIL. Filtering runs *before* it; a
  block is not a validation verdict. The five blocked-reply paths interact with this
  component's AD-bit contract.
- **Query-log observer** — the hot-path port that receives the decision (blocked/allowed
  and, where relevant, by which rule) for synchronous rollup counters. Its implementation
  lands in a later phase; this phase must emit a verdict rich enough to feed it.
- **Clock** — injectable, declared in the server-loop phase, used everywhere time appears.
  Relevant here for blocked-reply TTLs and for ingest timestamps/staleness ages.

### New Concepts Required

- **Domain rule** — a single filtering statement in one of three syntactic forms: *exact*
  name, *wildcard* subtree, or *regular expression*. All three forms feed the same
  allow/block mask pair, which is what makes "allow wins" uniform across forms.
- **Reversed-label trie** — the compiled index of exact and wildcard rules, walked
  right-to-left one label at a time. A wildcard node matches every descendant, which is
  what collapses exact and wildcard lookup into one walk rather than two.
- **Terminal** — a trie node carrying policy: an `allow` mask and a `block` mask, both
  per-group. The unit whose memory footprint the exit criteria measure.
- **Regex rule set** — every regex rule compiled into a single multi-pattern automaton, so
  that adding regex rules costs build time but essentially no query time. Each pattern
  index maps back to its own allow/block mask pair.
- **Matcher snapshot** — the immutable, fully-built artifact combining trie and regex set.
  It is never mutated; it is replaced.
- **Matcher handle** — the atomically-swappable holder of the current snapshot. Readers
  take a cheap snapshot of the pointer; a reload publishes a whole new one.
- **Verdict** — the outcome of one lookup: allowed or blocked, plus enough provenance to
  log *why* (which rule form, which group). Derived as `!(allow & g) && (block & g)`.
- **Blocking mode** — the five-valued, database-owned configuration selecting the shape of
  a blocked reply: `NXDOMAIN` (default), `NULL`, `NODATA`, `IP`, `IP-NODATA-AAAA`.
- **Blocked-reply builder** — the component turning (question, request header, mode) into
  a response message that honours the mode-independent invariants.
- **Adlist definition** — a configured source: URL, enablement, the groups it feeds, its
  last successful ingest and its staleness state. Database-owned.
- **Staging buffer** — the place a fetch lands *before* it is allowed to replace anything.
  The entire point of the ingestion design.
- **Sanity check / ingest outcome** — the accept-or-reject determination over a staging
  buffer, and its result: accepted (with a count) or rejected (with a reason).
- **Stale marker / stale reason** — the durable, human-readable record of why a list is
  running on a frozen copy. Required UI surface, not a log line.
- **Accept-the-shrink override** — the manual escape hatch for a list that legitimately
  got smaller, without which the collapse check becomes a permanent block on a valid
  update.

### Conceptual Relationships

- A **group** is the join point: clients belong to groups; adlists and hand-written rules
  target groups; the hot path reduces all of it to one integer mask per client.
- An **adlist** is ingested into a **staging buffer**, judged by **sanity checks** into an
  **ingest outcome**, and only on acceptance does it contribute **domain rules** to the
  next **matcher snapshot**. On rejection the previous good copy contributes instead and a
  **stale marker** is written.
- **Domain rules** compile into either the **trie** (exact, wildcard) or the **regex set**
  (regex); both produce **terminals** carrying the same allow/block mask pair.
- A **matcher snapshot** is built offline from all accepted lists plus hand-written rules,
  then published through the **matcher handle**. The hot path only ever reads.
- The **verdict** flows two ways: to the **blocked-reply builder** if blocked, and to the
  **query-log observer** either way.
- **Ownership/lifecycle boundary:** adlist definitions, rules, groups and blocking mode
  live in the database and change at human speed. The matcher snapshot lives in memory and
  changes only at an explicit reload. The hot path reads only in-memory state — no
  database access, ever, on a query.

### Key Business Rules

- **Allow beats block, unconditionally and across all rule forms.**
  `!(allow & g) && (block & g)`. An allow on an exact name defeats a wildcard block on its
  parent and defeats a regex block. This exists because every blocklist over-blocks
  eventually and users need an escape hatch that does not require editing a list.
- **A wildcard node matches all descendants**, so exact and wildcard are one lookup, not
  two.
- **Policy is evaluated against the client's group mask**, not against a per-group
  matcher. One walk, then a bitwise test.
- **The matcher is immutable; reload replaces it wholesale.** No mutation under a lock on
  the hot path, ever.
- **A block is not a validation verdict.** Filtering is applied before validation.
- **AD is always cleared on a blocked reply and no RRSIG is ever forged** — in every one
  of the five modes, with no exception.
- **Non-A/AAAA qtypes get NODATA** regardless of the configured mode.
- **Blocked replies carry a short TTL**, so that unblocking takes effect quickly.
- **Blocked replies never enter the answer cache** (they are forged, exactly like local
  records).
- **A staged list replaces nothing until it passes every sanity check**: content-type is
  not HTML, it parses to at least a minimum count of syntactically valid domains, and the
  count has not collapsed against the previous ingest.
- **Any ingest failure preserves the previous good copy**, records a stale marker carrying
  the reason, and the rebuild proceeds from the remaining lists. One bad list does not
  fail a reload.
- **Staleness must be visible on the dashboard**, because "keep last known good" otherwise
  silently enforces a frozen list forever.
- **The hot path performs no I/O.** No database read, no file read, no network call, on a
  query.

---

## Strategic Approach

### Solution Direction

Build `styx-filtering` as a self-contained feature crate with `domain`, `application` and
`infrastructure` modules, depending on no other feature crate. Its public surface is a
matcher it owns and a policy implementation the `styx` binary adapts onto the resolution
crate's `FilterPolicy` port.

Split the crate along a hard **build-time / query-time** seam, because the two halves have
opposite constraints:

- The **query-time** half is pure, allocation-shy, I/O-free and immutable: take a snapshot
  of the current matcher, walk the name right-to-left, run the regex automaton, combine
  the two mask pairs, return a verdict. Everything it touches was computed before the
  query arrived.
- The **build-time** half is allowed to be slow, allocating and fallible: fetch adlists
  into staging buffers, run sanity checks, parse accepted buffers into rules, merge with
  hand-written rules and group assignments, compile the trie and the regex set, and
  publish the result with one atomic pointer store.

Data flow on a query: request → local records →
**`FilterPolicy` adapter → matcher snapshot lookup → verdict** → (blocked: blocked-reply
builder → response, never cached, never validated as a resolution result) or (allowed:
cache → upstream). Either way the verdict is handed to the query-log observer.

Data flow on a reload: explicit trigger → per-list fetch into staging → per-list sanity
verdict → accepted buffers plus last-known-good copies of rejected ones plus hand-written
rules → compile snapshot → atomic publish → old snapshot dropped when the last in-flight
query releases it.

Treat the phase as **five separable work streams**, because the phase is already flagged
as the most likely in the product half to want splitting, and a clean seam now is much
cheaper than a split later:

1. **Matcher** — trie, regex set, snapshot, lookup.
2. **Allow/block precedence** — the dual mask pair and the verdict function.
3. **Blocked-reply construction** — the five modes and their shared invariants.
4. **Adlist ingestion** — staging, sanity checks, last-known-good, stale markers.
5. **Hot-path wiring** — the `ArcSwap` handle, the reload operation, and the binary-side
   adapter onto `FilterPolicy`.

Streams 1–2 are one cohesive unit and should not be separated (the dual mask is part of
the terminal's shape, not an addition to it). Stream 3 depends on the wire codec and the
validator's AD contract but not on the matcher. Stream 4 depends on nothing on the hot
path and is the most naturally severable. Stream 5 is the integration point and must come
last.

### Key Design Decisions

- **Two masks per terminal, not a separate allowlist structure.** *Trade-off:*
  per-terminal memory doubles (~30–50MB/million → ~45–75MB per million) against a second
  full walk and a second structure to keep coherent. → **Recommended: two masks.** One
  walk returning both masks makes "allow wins" a property of the data rather than of the
  ordering of two lookups, which is exactly the class of bug that would otherwise surface
  as "the allow worked for exact rules but not for regex". The doubled memory is an
  accepted, budgeted consequence and the exit criteria measure against the revised figure.

- **One `RegexSet` automaton rather than a vector of compiled regexes.** *Trade-off:* a
  slower, all-or-nothing compile at build time and a pattern-index→mask side table,
  against query cost that grows with rule count. → **Recommended: the single automaton.**
  Regex rules are a user-facing feature; if their cost is linear per query, the feature
  becomes a performance footgun and the honest answer would be to cap it. Near-free query
  cost is what makes it safe to expose at all.

- **`ArcSwap` wholesale replacement rather than any in-place mutation.** *Trade-off:*
  transient double memory during a rebuild (two snapshots resident) against a guaranteed
  stall-free hot path. → **Recommended: wholesale replacement.** On a Raspberry Pi the
  peak is the binding constraint and must be sized for, but a lock held across a
  million-entry rebuild is a latency outage for the whole house. The exit criterion — a
  reload under load causes no hot-path stall — is the acceptance test for this choice.

- **Mask width: fix `u64` now, measure at the end of the phase.** *Trade-off:* a hard cap
  of 64 groups against a roaring bitmap's unbounded groups at higher per-terminal cost and
  pointer-chasing on the hot path. → **Recommended: build against a narrow, swappable mask
  abstraction, ship `u64`, and take the measurement the exit criteria require before
  declaring the phase done.** Sixty-four groups is almost certainly enough for a house;
  the point of the measurement is to know rather than to assume, and the abstraction is
  what keeps the answer cheap if the measurement surprises.

- **Blocking mode is database-owned, runtime-editable configuration; the blocked-reply
  builder is a pure function of (question, request header, mode).** *Trade-off:* five
  response paths to test against the validator, versus one mode and a migration story for
  users arriving from Pi-hole. → **Recommended: all five, with the invariants factored so
  they cannot be forgotten per mode.** The mode should choose only the *content* of the
  answer; clearing AD, forging nothing, short TTL and the non-A/AAAA NODATA rule must be
  structurally shared, not repeated five times. This directly addresses the recorded risk
  that "five modes hides an untested combination".

- **Sanity checks are a gate on the staging buffer, not a post-hoc validation of a live
  list.** *Trade-off:* a fetch that is discarded wholesale on a marginal failure, versus a
  partial update. → **Recommended: all-or-nothing per list.** A partially-applied captive
  portal page is the exact failure the design exists to prevent; and per-list granularity
  means one rotten list never blocks the others from updating.

- **Ingest failure is a per-list condition, never a reload failure.** *Trade-off:* the
  system keeps running with known-stale data, versus loudly refusing to reload. →
  **Recommended: degrade per list, and make the staleness loud instead.** Refusing the
  whole reload because one URL 404'd would mean an unrelated list's legitimate update is
  blocked by someone else's dead host. The cost is the recorded "dead adlist blocks
  forever" risk, whose mitigation is a dashboard-level staleness surface and the manual
  accept-the-shrink override — both of which must be *produced* by this phase as data even
  though they are *rendered* two phases later.

- **The verdict carries provenance, not just a boolean.** *Trade-off:* a slightly wider
  return type on the hot path against a query log that can say which rule blocked a
  domain. → **Recommended: carry it.** Without provenance the allowlist escape hatch is
  unusable in practice — a user who cannot see *which* rule blocked a name cannot write
  the allow.

### Alternatives Considered

- **Per-group matcher instances.** Rejected: multiplies memory and rebuild time by the
  group count for structures that overwhelmingly share content, and makes reload N times
  more expensive on the device least able to afford it.
- **Per-group answer-cache namespaces (filtering by cache partition).** Rejected: N groups
  would multiply cache memory and shred the hit rate the cache exists to provide.
  Filtering as an outbound filter over a globally-keyed cache is the deliberate
  alternative.
- **Allowlist as a separate structure consulted first.** Rejected: two lookups and two
  structures to keep coherent, and "allow wins" becomes a property of call ordering rather
  than of the data — which is precisely how it ends up holding for exact rules and
  silently failing for regex ones.
- **A single blocking mode (NXDOMAIN only).** Rejected: the project explicitly targets
  replacing Pi-hole on a real household, and Pi-hole's mode set is part of what users have
  tuned around. The cost — five validator-interaction paths — is accepted and is called
  out as a recorded risk rather than wished away.
- **A hickory-dns or `domain`-crate DNS stack.** Rejected project-wide: the entire DNS
  stack is written from scratch. The wire-format oracle used in tests is a dev-dependency
  only, with a CI check asserting it appears in no normal or build dependency path.
- **Mutating the matcher in place under a lock on rule edits.** Rejected: a writer lock
  across a rebuild stalls every concurrent query; the hot path must never block on policy
  maintenance.
- **RFC 7871 EDNS Client Subnet to sharpen per-client policy.** Rejected as a project
  non-goal: it leaks client topology.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **The blocked-reply TTL value is unspecified.** "Short" is the requirement; the number
  is explicitly left to implementation. Needs a concrete default and a decision on whether
  it is configurable at all.
- **The adlist sanity thresholds are unspecified.** The minimum valid-domain count and the
  collapse ratio are both explicitly open. A too-low minimum defeats the captive-portal
  check; a too-tight collapse ratio turns every legitimate list shrink into a manual
  override.
- **Reload trigger surface is undefined.** "Explicit reload" is settled; *what* triggers
  it — a UI action, a scheduled ingest, a signal, a CLI subcommand — is not stated by this
  phase, and the UI phase that would own the button is three phases later.
- **Group-mask provenance is undefined here.** How a source IP becomes a group mask
  (lookup table, default group for unknown clients) is deliberately a storage-phase schema
  question. This phase must accept the mask as an input and must not invent the lookup.
- **The `IP` and `IP-NODATA-AAAA` modes need an address source.** The mode implies a
  configured address to return; where it lives (file-owned infrastructure config versus
  database-owned policy) is not stated. The file/database boundary rule says policy is
  database-owned, which points at the database, but this is an inference, not a recorded
  decision.
- **Rule-form precedence *within* the same verdict side is unstated.** Allow-beats-block
  is settled across all three forms; whether a more-specific block beats a less-specific
  block is moot under a bitmask union (they OR together), but this should be stated
  explicitly so nobody later "fixes" it into a specificity ordering.
- **Whether hand-written allow/block rules are ingested through the same staging path** as
  adlists is not stated. They come from the database rather than the network, so the
  sanity checks are meaningless for them, but the rebuild has to combine both sources.

### Edge Cases

- **The root and single-label names.** A right-to-left walk needs defined behaviour for
  the root label and for a query with one label; a wildcard at the root would block
  everything.
- **Trailing dots, case, and IDN/punycode.** Two spellings of the same name must not
  produce two terminals, or an allow written in one spelling will fail to defeat a block
  written in the other.
- **A wildcard block and an exact allow on the same node.** The canonical escape-hatch
  case; must be a test, not an assumption.
- **A regex that matches nothing, or everything.** A catastrophically broad user regex is
  functionally a global block; the single automaton makes it cheap to evaluate, which
  means nothing stops it at query time. Validation belongs at rule-entry time.
- **An invalid regex from user input.** Must fail the rule, not the rebuild.
- **A reload that produces an empty matcher** (every list rejected on first ever ingest,
  with no last-known-good to fall back to). Blocking silently becomes a no-op; this needs
  a distinct, visible state rather than looking like "nothing is blocked".
- **First ingest of a new list.** The collapse check has no previous count to compare
  against; the rule must be defined rather than inferred.
- **A list that legitimately shrinks** (upstream cleaned it up). Rejected by the collapse
  check forever without the manual accept-the-shrink override — which makes that override
  a functional requirement, not UI polish.
- **A non-A/AAAA qtype for a blocked name** — NODATA in every mode, including the modes
  whose whole purpose is returning an address.
- **A blocked name under a DNSSEC-signed zone, queried with CD=0 by a validating client.**
  The client gets an unsigned answer for a signed name and may fail it. This is the
  accepted deliberate lie and must be documented as such, not silently emitted.
- **A blocked name with DO=1 set.** The reply must carry no RRSIG and must not set AD.
- **Reload while queries are in flight.** In-flight lookups must keep their old snapshot
  alive and complete against it; nothing may observe a half-built matcher.
- **Two reloads overlapping.** Needs a defined outcome (serialize, or last-writer-wins)
  rather than two builders racing to publish.
- **Memory peak during rebuild on a Raspberry Pi** — old snapshot plus new snapshot plus
  staging buffers resident simultaneously.
- **Duplicate domains across lists feeding different groups.** One terminal, masks OR'd —
  which is the intended behaviour and should be asserted so a later dedup "optimisation"
  does not break it.
- **An adlist served as HTTP 200 with an HTML body** — the named, must-reject case.
- **A very large adlist, or one that never terminates.** Staging needs bounds; an
  unbounded fetch on a Pi is a memory failure, and a rebuild is exactly when memory is
  tightest.

### Technical Risks

- **Reload memory peak versus the Raspberry Pi target.** Two snapshots plus staging
  buffers at ~45–75MB per million domains per snapshot. *Mitigation direction:* stage and
  parse per-list rather than all at once, drop staging buffers before compiling, and make
  the measurement required by the exit criteria cover the *peak*, not just the steady
  state.
- **The five-mode validator interaction surface hides an untested combination** — the
  explicitly recorded risk. *Mitigation direction:* factor the invariants (AD cleared, no
  RRSIG, short TTL, non-A/AAAA → NODATA) so they are applied once and structurally cannot
  be skipped per mode, and drive the assertion as a matrix over {five modes} × {A, AAAA,
  other qtype} × {DO=0, DO=1} × {signed zone, unsigned zone} rather than as five
  hand-written tests.
- **A dead adlist enforces a frozen copy indefinitely**, with a staleness badge as the
  only signal — the explicitly recorded risk. *Mitigation direction:* this phase must
  produce staleness as first-class, queryable state carrying a reason and an age, so that
  the UI phase can put it on the dashboard rather than on a settings page. If staleness is
  only a log line, the mitigation is impossible downstream.
- **The hot path must perform no I/O, and that is easy to violate by accident** — one
  database read for a group lookup or one lazy load of a rule would do it.
  *Mitigation direction:* the crate's layering and the architecture lint should make the
  hot-path types structurally incapable of reaching infrastructure.
- **Project-wide lint policy makes this code verbose**: index/slice operations and
  arithmetic are denied lints, and the trie walk is nothing but label offsets and index
  arithmetic. *Mitigation direction:* expect checked operations throughout and budget for
  it rather than fighting it; fuzzing the rule parser and the label walk is the
  complement.
- **Panics are denied and the process is shared** — a panic in the matcher takes DNS down
  for the whole house, and the `catch_unwind` boundary does not arrive until the final
  phase. *Mitigation direction:* fallible parsing everywhere, no unwrap/expect outside
  tests, and fuzz the adlist parser specifically since it consumes untrusted network
  bytes.
- **Client identity is unreliable by construction** (no DHCP ownership). A lease change
  silently misattributes a group mask and therefore a filtering verdict. *Mitigation
  direction:* nothing in this phase can fix it; the verdict's provenance and the query log
  are what make it diagnosable.
- **Regex rules are user input compiled into a shared automaton.** A pathological pattern
  costs build time, and a broad one silently blocks widely. *Mitigation direction:*
  validate and size-bound patterns at rule-entry time, and surface the matched pattern in
  the verdict's provenance.
- **Phase size.** The phase carries five substantial concerns and is flagged as the one
  most likely to want splitting. *Mitigation direction:* keep the five work streams
  separable with explicit seams so a split is a clean cut rather than a refactor.
- **No operational feedback until the very end.** The household stays on the existing
  resolver until the whole build is complete, so this phase's behaviour under real traffic
  and real client churn is unknown until the cutover, when it is most expensive to act on.
  *Mitigation direction:* the exit criteria's load-based reload test and the memory
  measurement are the only substitutes available.

### Acceptance Criteria Coverage

The phase's exit criteria, assessed one by one.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | Memory measured at one million domains against the revised ~45–75MB target (two masks, not one) | Yes | Needs a defined measurement method (resident set versus allocator-reported), a defined corpus, and a decision on whether the *rebuild peak* is measured or only the steady state. The peak is the binding constraint on a Raspberry Pi. This measurement is also the input to the deferred `u64`-versus-roaring-bitmap call, which is due at the end of this phase. |
| 2 | A reload under load causes no hot-path stall | Yes | "No stall" needs a quantified threshold (e.g. a latency percentile bound) and a defined load profile, or the assertion is unfalsifiable. The test must hold a query in flight across the swap to prove the old snapshot stays alive. |
| 3 | Each of the five blocking modes is asserted to clear AD and forge no signature | Yes | Addressable, and the recorded risk says to go wider than the literal wording: the combination space is {five modes} × {A, AAAA, other qtype} × {DO=0, DO=1} × {signed, unsigned zone}. Asserting five cases satisfies the letter and leaves exactly the untested combination the risk warns about. Should also assert the short TTL and that no blocked reply enters the answer cache. |
| 4 | An adlist fixture serving HTTP 200 with an HTML body is rejected and the previous copy survives | Yes | Covers the content-type/HTML check and last-known-good retention. Leaves two of the three sanity checks unasserted by the criteria as written — the minimum-valid-domain-count floor and the collapse check — plus the stale marker's *reason* being recorded and the accept-the-shrink override. These should be added rather than inferred. |
| — | Allow-beats-block precedence across exact, wildcard **and regex** | **Gap** | The single most important user-facing behaviour of the phase has no exit criterion. The escape-hatch rationale ("one bad list entry and a banking app is broken") demands an explicit assertion that an allow defeats each of the three block forms. |
| — | The hot path performs no I/O | **Gap** | Structurally required and architecturally enforced elsewhere, but unasserted by this phase's criteria. Worth a test that resolution continues correctly with the database absent. |
| — | Filtering is applied before validation, and blocked replies never enter the answer cache | **Gap** | Both are settled correctness properties of the fixed pipeline order (local records → filter → cache → upstream) but neither appears in the criteria. The cache-pollution case in particular is silent when it goes wrong. |
| — | Staleness is exposed as queryable state carrying a reason and an age | **Gap** | The rendering belongs to the UI phase, but the *data* must exist here, or the recorded "dead adlist blocks forever" mitigation cannot be built downstream. |

---

## Handoff

Dependencies satisfied before this phase can start, by number and title:

- **Phase 0 — Foundation and gates** (workspace, working architecture lint, CI, the `gate`
  target)
- **Phase 1 — Wire codec** (`styx-proto`; the blocked-reply builder constructs messages
  through it)
- **Phase 2 — Server loop and test harness** (the `FilterPolicy` port this phase
  implements, the fixed pipeline order, the injectable `Clock`, the socket-level test
  harness)
- **Phase 4 — Answer cache** (the cache this phase must never pollute, sitting after the
  filter)
- **Phase 6 — DNSSEC** (the validator whose AD contract the five blocked-reply modes must
  not violate, and whose hard-fail behaviour is why the block/validate interaction must be
  exact)

Phases that depend on this one:

- **Phase 9 — Storage** (persists adlist definitions, allow/block rules, groups,
  list-to-group assignment and the blocking mode this phase consumes)
- **Phase 10 — Query log pipeline** (consumes the verdict and its provenance for exact
  rollup counters)
- **Phase 11 — Web UI** (renders the staleness badge with its reason on the dashboard, the
  accept-the-shrink override, and per-group allow/block rule editing that makes
  "allow always wins" visible)
- **Phase 12 — Cutover hardening** (the household's real traffic first meets this phase
  here)
