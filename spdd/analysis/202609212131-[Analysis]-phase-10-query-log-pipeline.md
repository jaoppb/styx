# SPDD Analysis: Phase 10 — Query Log Pipeline (styx)

**Project**: `styx` — a filtering DNS resolver written from scratch in Rust, replacing Pi-hole's
role on a home network (recursive/forwarding resolution, per-client blocking policy, Leptos admin
UI). Single process, single binary, one box, local database file.

**Codebase context**: **greenfield, no existing implementation.** There is no git repository, no
Cargo workspace, and no source code at the time of this analysis — only the decision record and
the phase specs. Every statement below about "existing" concepts refers to concepts that *earlier
phases are contracted to deliver*, not to code that can be read today. All grounding therefore
comes from the project's recorded decisions, their rationale, and the accepted consequences,
which are inlined in full throughout this document so it stands alone.

---

## Original Business Requirement

The phase specification, verbatim:

> # Phase 10 — Query log pipeline
>
> ## Scope
>
> - Rollup counters incremented **synchronously via atomics** on the response path —
>   never queued, never dropped, so every dashboard number is exact.
> - Raw rows and the live ring through a bounded channel that drops when full and
>   exposes `dropped_detail`.
> - `Detailed` and `Private` modes; the four privacy levels; and the **explicit
>   purge action** that is required, or `Private` is a lie.
> - History views degrade to aggregates-only when raw rows are absent. They must not
>   error.
>
> ## Exit criteria
>
> A load test asserting the atomic counters and the raw rows diverge by exactly
> `dropped_detail` and by nothing else.

*(The spec's original cross-references to numbered decisions are replaced above by the decision
text itself, which is reproduced in full in the next section.)*

### Governing decisions inherited by this phase, with their rationale

These were settled in a design review before any code was written. They are not this phase's to
revisit; they are this phase's to implement.

1. **The hot path touches no I/O.** Matcher state is in memory, built at boot and on reload. The
   database holds config, adlist definitions, clients/groups and history only. **Why**: a database
   outage must degrade logging and admin but never resolution. Because the resolver needs nothing
   from the database, this is a structural guarantee rather than a discipline.

2. **One query-log ingest pipeline, two configurable modes.** The in-memory ring is **always
   present and serves the live view in both modes**; rollups are **always permanent**. The mode
   decides *only* whether raw rows are persisted — `Detailed` keeps them for a configurable window
   (default 7 days), `Private` never writes a qname to disk. **Why**: two pipelines would mean two
   code paths that drift; one pipeline with a persistence switch means the live view, the
   counters and the degradation behaviour are identical in both modes and get tested once.

3. **Rollups are permanent and exact.** Hourly buckets per `(client, decision, qtype)` plus top-N
   domains per bucket, a few KB/day, retained indefinitely. **Why**: aggregates are cheap enough
   that there is no reason to ever expire them, and a dashboard whose history vanishes is not a
   dashboard.

4. **Split write paths.** Rollup counters increment **synchronously via atomics on the response
   path — never queued, never dropped**, so every dashboard number is always exact. Only raw rows
   and the live ring go through a **bounded channel**, which **drops when full** and exposes a
   visible **`dropped_detail`** counter. **Why**: dashboards cannot be allowed to lie. A queued
   counter that drops under load produces numbers that are quietly wrong and that nobody can
   detect. Detail, by contrast, is allowed to degrade gracefully — a missing raw row is an
   inconvenience, a missing count is a falsehood.

5. **History views degrade to aggregates-only when raw rows are absent — they must not error.**
   **Why**: raw rows are absent in three entirely normal situations (`Private` mode, a retention
   window that has rolled past, a purge), so their absence is a expected state and not a fault.

6. **Switching to `Private` is not retroactive.** Existing raw rows survive until an explicit
   purge action, **which the UI must offer or the mode is a lie**. **Why**: a user who flips to
   `Private` believes their history is gone. If the rows are still on disk and nothing offers to
   remove them, the setting has misled them about their own privacy.

7. **All four privacy levels ship in v1** — log everything / hide domains / hide clients /
   anonymous. **Why**: retrofitting anonymisation into a schema that assumed full qnames means a
   migration. The schema is designed once, complete, in the previous phase; the levels have to be
   representable from the first revision.

8. **Config has two stores with a hard boundary: the TOML file owns infrastructure, the database
   owns policy.** The file owns everything needed before the database exists or in order to reach
   it — listen addresses, upstreams, TLS material, trust anchor, database path, **log mode**. The
   database owns everything a human edits at runtime — clients, groups, adlists, rules, local
   records, **privacy level**, blocking mode. **Why**: no overlap means no precedence rule, and it
   strengthens the no-I/O-on-the-hot-path guarantee, because nothing resolution needs lives in the
   database. **Accepted consequence**: the log mode cannot be changed from the UI; it needs a file
   edit and a restart. The privacy level *can* be changed from the UI.

9. **One crate per feature; `domain` / `application` / `infrastructure` are modules inside it.**
   Cargo enforces feature-to-feature isolation; an architecture lint enforces layering within a
   crate. **Feature crates never depend on each other** — cross-feature needs are expressed as a
   **port (trait) in the consumer's `domain`**, implemented by an adapter in the binary. The web
   crate may depend on a feature crate's `application` layer, because it is presentation, not a
   peer. The shared wire-codec crate is the one explicit exception to the no-cross-dependency rule.

10. **The query-log observer port was declared on the hot path in phase 2, with a no-op
    implementation**, precisely so that the product half would not have to rewrite the hot path
    later. The pipeline order was fixed there too, as a correctness property: **local records →
    filter → cache → upstream**. This phase supplies the real implementation behind that
    already-existing port.

11. **The cutover is last.** styx runs on a dev box until everything works; the household's
    resolver stays on Pi-hole until v1 is complete. **Why**: nothing mid-build has to be
    shippable, breaking changes stay free, and phases are ordered by dependency and risk rather
    than usability. **Accepted consequence for this phase**: no operational feedback — real query
    volumes, real client churn, real cardinality of domains — until the end. Rollup sizing and
    channel sizing are therefore reasoned about, not measured.

12. **Behaviour tests run at socket level by default**, driving real UDP/TCP against an
    ephemeral-port server with in-process fakes and an **injectable `Clock`**. **Why**: time
    injection cannot be retrofitted. For this phase the `Clock` is what makes hourly bucket
    boundaries, the 7-day retention window and TTL-shaped expiry testable without sleeping.

13. **Lint policy is aggressive and workspace-wide**, including denied `indexing_slicing`,
    `arithmetic_side_effects` and `panic`. **Why for this phase**: `panic = "deny"` is
    load-bearing because in a single process a panic in a background task or a request handler
    takes DNS down for the whole house. Ring indexing and counter arithmetic in this phase are
    both squarely in the path of those lints.

### Non-goals that bear on this phase

- **No DHCP server.** Clients are identified by IP plus optional manual naming. styx never owns
  the lease table, so **client identity is best-effort and breaks on DHCP churn**. This phase
  keys rollups and raw rows on a client identity that is known to be unreliable.
- **No multi-user admin, no roles, no audit trail.** There is a single admin password. **You can
  never tell who purged the query log, or who changed the privacy level** — there is no audit
  trail to record it in, by design.
- **No multi-node or replicated deployment.** One box, one binary, local database file. There is
  no shipping of logs elsewhere, no remote aggregation, no second writer to reconcile against.
- **No EDNS Client Subnet.** Deliberately omitted because it leaks client topology. The same
  privacy instinct is what the four privacy levels serve at the storage layer.

### Recorded risk carried into this phase

> **Two write paths for the query log must stay consistent.** Atomic counters and raw rows can
> disagree if a bug lands in either; behaviour tests need to assert they agree under load and
> diverge only by the `dropped_detail` count.

This is the risk that the phase's exit criterion exists to discharge. It is recorded as a
*standing* risk, not a one-time check: any future change to either write path can reintroduce it,
so the load test is a permanent gate and not a milestone.

### Open implementation-level choices explicitly left to the keyboard

The decision record classes these as non-blocking and to be decided during implementation:

- **Rollup bucket granularity** (hourly is the stated default; the final granularity is a
  keyboard call).
- **Top-N width** — how many domains are retained per bucket.

Neither is a design question this analysis should settle; both are recorded here so they are not
mistaken for omissions.

---

## Domain Concept Identification

### Existing Concepts (contracted by earlier phases — greenfield, none implemented yet)

- **Query-log observer port**: declared in **Phase 2 — Server loop and test harness** as a
  hot-path trait with a no-op implementation, alongside the filter-policy and local-records ports.
  Its shape already exists so that this phase can supply a real implementation without touching
  the resolution pipeline. — *This phase implements it; it does not redesign it.*
- **Resolution response path**: the request pipeline from **Phase 2**, with the fixed order local
  records → filter → cache → upstream. This is where the observer is called and where the
  synchronous counter increment must happen. — *Owns the moment a query event comes into being.*
- **Decision (filter verdict)**: produced by **Phase 8 — Filtering**. A query is allowed, blocked
  (by exact, wildcard or regex rule, with allow winning unconditionally), or answered from local
  records — and blocked replies come in five modes. — *The `decision` dimension of every rollup
  bucket key comes from here.*
- **Client and Group**: first-class in the domain model, the database and the UI, from **Phase 8**
  and **Phase 9 — Storage**. A client is identified by IP with optional manual naming. — *The
  `client` dimension of the bucket key, and the subject of the "hide clients" privacy level.*
- **Qtype / qname / qclass**: from the wire codec of **Phase 1**. — *The `qtype` dimension of the
  bucket key; qname is the subject of the "hide domains" privacy level.*
- **Turso schema (policy + history)**: designed **once, complete**, in **Phase 9 — Storage**,
  explicitly including raw rows, hourly rollups and all four privacy levels, so that this phase
  needs no migration. — *This phase writes into a schema it did not design and must not need to
  extend.*
- **Injectable `Clock`**: from **Phase 2**. — *Assigns every event to a bucket and drives both
  retention and test determinism.*
- **Log mode (file-owned config)** and **privacy level (database-owned config)**: the hard
  config boundary means these two settings live in different stores and change through different
  mechanisms. — *A structural fact this phase must encode, not a detail.*

### New Concepts Required

- **Query event**: the record of one resolved query — timestamp, client identity, qname, qtype,
  decision, response code, whether it was a cache hit, and elapsed time. Created on the response
  path; consumed by three sinks with different durability guarantees. — *Relates to Client,
  Decision and Qtype; it is the single input from which all three sinks derive.*
- **Rollup bucket key**: the tuple `(bucket start instant, client, decision, qtype)` that names
  one aggregate. — *Derived from the query event; the aggregation dimension of the whole phase.*
- **Rollup counters**: the exact, never-dropped totals held against a bucket key, incremented
  atomically on the response path. — *The authoritative numbers; everything on the dashboard that
  claims to be a count comes from here.*
- **Top-N domains per bucket**: the most-queried domains within a bucket, retained alongside the
  counters. — *The one aggregate that carries qname material, so it is the one aggregate the
  privacy levels must reach into.*
- **In-memory ring**: a bounded, always-present buffer of the most recent query events, serving
  the live view in **both** modes. — *Never persisted; its presence is what makes `Private` mode
  still useful rather than blind.*
- **Bounded detail channel**: the single queue carrying events to the raw-row writer and the ring.
  It **drops when full** rather than blocking or growing. — *The seam that keeps the hot path free
  of both I/O and backpressure.*
- **`dropped_detail` counter**: the visible count of events the channel refused. — *The exact
  quantity by which raw rows are permitted to lag the rollup counters, and nothing else.*
- **Log mode** (`Detailed` | `Private`): file-owned; decides only whether raw rows are persisted.
  `Detailed` retains them for a configurable window defaulting to 7 days; `Private` never writes a
  qname to disk. — *Orthogonal to privacy level; both apply.*
- **Privacy level** (log everything | hide domains | hide clients | anonymous): database-owned,
  editable at runtime. — *Determines what a stored or displayed event is allowed to contain.*
- **Purge action**: an explicit, user-invoked removal of existing raw rows, offered by the UI. —
  *The only thing that makes a switch to `Private` honest about history already on disk.*
- **Retention sweep**: the background expiry of raw rows older than the configured window in
  `Detailed` mode. — *Distinct from purge: time-driven and automatic, versus user-driven and
  immediate.*
- **History read models**: the query shapes the UI consumes — a detailed history view backed by
  raw rows and an aggregate-only view backed by rollups, with the former **degrading to the
  latter** when raw rows are absent. — *The consumer-facing expression of "must not error".*

### Key Business Rules

- **Counters are exact, always.** The rollup counter increment happens synchronously on the
  response path via atomics. It is never queued, never dropped, never conditional on the log mode
  or the privacy level. — *Governs: rollup counters, query event, log mode, privacy level.*
- **The ring is always present, in both modes.** `Private` mode does not disable the live view; it
  disables persistence. — *Governs: in-memory ring, log mode.*
- **Rollups are permanent.** No expiry, no retention window, no purge. — *Governs: rollup
  counters, purge action, retention sweep.*
- **`Private` never writes a qname to disk.** Not in raw rows, and — because top-N carries domain
  material — the privacy level must be honoured in the aggregate path too, not only the raw path.
  — *Governs: log mode, privacy level, top-N, raw rows.*
- **The detail channel drops rather than blocks.** A full channel must never apply backpressure to
  the response path, because that would put queueing latency on resolution. — *Governs: bounded
  detail channel, query event.*
- **Every drop is counted and visible.** `dropped_detail` is not an internal metric; it is exposed
  so that a user reading a partially-complete history knows it is partial. — *Governs:
  `dropped_detail`, history read models.*
- **Raw rows and counters may diverge by exactly `dropped_detail`, and by nothing else.** This is
  the phase's invariant and its exit criterion. — *Governs: rollup counters, raw rows,
  `dropped_detail`.* Note the invariant is stated over a window in which no retention sweep or
  purge has run — those legitimately remove raw rows and are not divergence.
- **Absence of raw rows is a normal state, not an error.** Three legitimate causes: `Private`
  mode, retention expiry, purge. History views degrade to aggregates and return a result. —
  *Governs: history read models, log mode, retention sweep, purge action.*
- **A mode switch is not retroactive.** Flipping to `Private` stops new writes; it does not erase
  old ones. Only the purge action does that, and the UI must offer it. — *Governs: log mode, purge
  action, raw rows.*
- **No I/O on the hot path.** The response path touches atomics and a channel `try_send`, nothing
  else. A database outage degrades logging and admin, never resolution. — *Governs: the whole
  pipeline.*
- **All four privacy levels must be representable without a migration**, because the schema was
  designed once and complete in the previous phase. — *Governs: privacy level, raw rows, top-N.*

---

## Strategic Approach

### Solution Direction

A **single ingest pipeline with a forked write path**, living in its own feature crate with
`domain` / `application` / `infrastructure` as modules inside it, wired into the resolution hot
path through the observer port that Phase 2 already declared.

The data flow in one line: **response path → (a) synchronous atomic counter increment, always;
and (b) non-blocking `try_send` into a bounded channel, which a background async task drains into
the in-memory ring and, in `Detailed` mode only, into raw rows in the database.**

Everything strategic about this phase follows from the fork being *asymmetric on purpose*:

- **Path (a) is lossless and cheap.** Counters are in-memory atomics keyed by bucket. They are
  flushed to the database periodically by a background task, but the *authoritative* value is the
  in-memory one, so a database outage delays persistence of the counts without ever losing an
  increment or blocking a response.
- **Path (b) is lossy by design.** A `try_send` that fails increments `dropped_detail` and returns
  immediately. Nothing about the response waits on it.

The privacy level and the log mode are applied **in the consumer of the channel and in the
counter-flush**, not at the call site on the hot path. This keeps the hot path's work constant
regardless of configuration, and it means the runtime-editable privacy level takes effect without
touching anything on the resolution side. The one place this needs care is top-N, which lives in
path (a) and carries qname material — so the privacy level has to be readable from the aggregate
path as well, via a cheaply-readable shared snapshot rather than a database round-trip.

Three consumer-facing surfaces round it out: the **live view** off the ring (both modes), the
**history read models** with their aggregate-only degradation, and the **purge action** as an
explicit application-layer operation the UI invokes.

### Key Design Decisions

- **Where the bucket-key aggregation map lives (in-memory sharded map vs. direct database
  upsert)**: a direct upsert per query is I/O on the hot path and is disqualified outright.
  Trade-off is therefore between a lock-free concurrent map of bucket key → atomic counters and a
  simpler mutex-guarded map. → **Recommend a concurrent map holding atomics**, because the counter
  increment is the only thing in this phase that is genuinely on the hot path and must not
  contend. The keyspace is small and bounded by `clients × decisions × qtypes` per bucket, which
  on a home network is tens to low hundreds of entries per hour.

- **Whether the counter flush to the database is on a timer or on bucket rollover**: a
  rollover-only flush means up to an hour of counts exist only in memory and are lost on an
  unclean restart. → **Recommend both** — periodic flush of the open bucket plus a final flush on
  rollover and on shutdown. The counters are the numbers that must be exact; "exact until the
  process dies" is not exact.

- **Whether `dropped_detail` is per-process or per-bucket**: per-process is simpler; per-bucket
  makes the divergence invariant checkable *per bucket*, which is what a history view actually
  needs in order to say "this hour is incomplete". → **Recommend a monotonic per-process counter
  for the visible metric, with the per-bucket attribution available to the read model**, so a
  history view can mark a specific hour as degraded rather than the whole dashboard.

- **Whether the privacy level anonymises at write time or at read time**: read-time anonymisation
  keeps the data and filters the view, which means the disk still holds what the level promised to
  hide — directly contrary to the `Private`-is-not-a-lie principle. → **Recommend write-time**:
  "hide domains" means the qname is not written, "hide clients" means the client identity is not
  written, "anonymous" means neither is. Nothing that a level hides ever reaches disk. This is
  also what makes the levels truly non-retrofittable and why they had to be in the schema from the
  start.

- **Whether the ring is bounded by count or by memory**: → **Recommend count**, sized in config.
  It is the live view's backing store, a human looks at a few hundred recent queries at most, and
  a count bound is trivially reasoned about under the denied-arithmetic lint.

- **Whether the channel consumer writes raw rows one at a time or in batches**: single-row writes
  make the consumer the bottleneck and make the channel fill sooner, which converts database
  latency into `dropped_detail`. → **Recommend batching with a size-and-time trigger**, so that
  the drain rate is decoupled from per-row database latency. This is the single largest lever on
  how often detail is actually dropped.

- **Whether the purge is a hard delete or a tombstone**: a tombstone leaves qnames on disk, which
  defeats the purpose entirely. → **Recommend a hard delete of raw rows, leaving rollups
  untouched**, and returning a count of what was removed so the UI can confirm it happened. Note
  the consequence: with no audit trail in v1, a purge is unattributable and irreversible.

- **Whether history degradation is signalled or silent**: silent degradation looks identical to
  "there were no queries". → **Recommend the read model carrying an explicit marker** stating
  which of the three causes applies (private mode, outside retention, purged) so the UI can say so
  rather than showing an empty table.

### Alternatives Considered

- **Single write path — queue everything, including counters.** Rejected: a bounded queue that
  drops would make counts wrong under exactly the load where counts matter most, and an unbounded
  queue would trade that for unbounded memory on a Raspberry Pi. Dashboards that lie are worse
  than dashboards that are incomplete.
- **Blocking send on the detail channel.** Rejected: backpressure on the detail path becomes
  latency on the resolution path, violating the no-I/O-on-the-hot-path guarantee in spirit if not
  in letter. Dropping is the deliberate choice, and `dropped_detail` is the price paid for it
  being visible.
- **Two separate pipelines, one per mode.** Rejected by the recorded decision: two code paths
  drift, and the live view, counters and degradation behaviour would then need testing twice.
- **Deriving aggregates from raw rows by query at read time.** Rejected: it makes the counts
  depend on rows that may have been dropped, expired or purged, which directly contradicts
  permanent-and-exact rollups. It also makes every dashboard render a table scan.
- **Read-time anonymisation / a `Private` mode that hides rather than declines to write.**
  Rejected: see above — it would leave on disk exactly what the mode promised not to write.
- **Retroactive purge on switching to `Private`.** Rejected by the recorded decision: an automatic
  destructive action on a config change is a footgun; the explicit purge action is the honest
  form, provided the UI actually offers it.
- **A separate metrics/telemetry backend for the counters.** Rejected: multi-node and external
  dependencies are non-goals; one box, one binary, local database file.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **The interaction of log mode and privacy level is not spelled out.** `Private` never writes a
  qname; "hide clients" never writes a client. Whether `Private` + "log everything" means "write a
  raw row with the qname elided" or "write no raw row at all" needs settling. The plain reading of
  "never writes a qname to disk" is that `Private` suppresses raw-row persistence entirely; that
  reading should be the one implemented and stated explicitly.
- **Whether the privacy level reaches the top-N aggregate.** Top-N is domain data inside a rollup,
  and rollups are permanent and never purged. If the level does not reach it, "hide domains" is
  partially false and a purge does not remove all domain material. This must be resolved as: the
  level applies to top-N collection too, and when domains are hidden, top-N is simply not
  collected.
- **"Visible" `dropped_detail` is not defined.** Exposed where — a UI badge, a log line, a metrics
  endpoint, all three? The dashboard is the place it matters, since the point is that a user
  reading incomplete history knows it is incomplete.
- **Purge scope is unspecified.** All raw rows, or a date range, or per-client? The honest minimum
  for "`Private` is not a lie" is all raw rows; anything narrower is an addition.
- **Rollup bucket granularity and top-N width** are explicitly open and left to implementation.
  They are noted, not resolved here.
- **What happens to history rows when a client or a group is deleted** was flagged as a schema
  question for the previous phase. Whichever way it was answered there binds this phase's writes;
  if it was not answered, it surfaces here.

### Edge Cases

- **Bucket rollover under load.** Events arriving exactly at the hour boundary must land in
  exactly one bucket, and the flush of the closing bucket must not race increments still landing
  in it. The injectable `Clock` makes this testable; without care it is a lost-count bug in the
  one path that is not allowed to lose counts.
- **Database unavailable while the channel drains.** Raw-row writes fail; the consumer must not
  panic (`panic = "deny"` is load-bearing — a panicking background task in a single process is a
  household outage), must not block forever, and must not silently swallow the failure. Failed
  batches are a distinct condition from `dropped_detail` and conflating them would corrupt the
  invariant.
- **Mode or privacy-level change while the channel holds in-flight events.** Events queued under
  the old setting drain under the new one. Whether the setting is captured at enqueue or applied
  at drain changes what lands on disk during the switch. Applying at drain is safer for privacy
  (the stricter setting wins for anything not yet written) and should be the rule.
- **Retention sweep versus the divergence invariant.** A sweep legitimately deletes raw rows, so
  any assertion comparing counters to rows must be scoped to a window in which no sweep or purge
  ran, or it will fail for a correct system.
- **Purge racing an in-flight drain.** A purge that runs while the consumer is mid-batch can be
  followed immediately by rows the purge was meant to precede. The purge must therefore drain or
  fence the channel, not merely issue a delete.
- **Process restart with an open bucket.** In-memory counters not yet flushed are lost unless the
  flush is periodic and shutdown-triggered. Exactness is a durability claim, not just an
  arithmetic one.
- **Client identity churn mid-bucket.** Because DHCP is a non-goal and clients are keyed by IP, a
  lease change can attribute one household device's queries across two client keys within a single
  hour, or two devices to one key. The counts remain arithmetically exact; their *meaning* is
  best-effort, and that distinction should be documented rather than papered over.
- **Ring reads concurrent with writes.** The live view reads while the consumer writes; under
  denied `indexing_slicing`, every ring index is a checked operation and a torn read must be
  impossible, not merely unlikely.
- **A query that is answered from local records or from the cache.** These still produce query
  events and must be counted; the decision dimension needs a representation for them, not just
  allowed/blocked.
- **Extremely high cardinality of distinct domains within one bucket**, e.g. a device doing random
  subdomain lookups. Top-N collection must be bounded in memory regardless of how many distinct
  domains appear, not just bounded in what it finally stores.

### Technical Risks

- **The recorded standing risk: the two write paths can disagree.** Atomic counters and raw rows
  can diverge if a bug lands in either. *Impact*: the dashboard and the detailed history tell
  different stories, and there is no third source to arbitrate. *Mitigation*: the phase's exit
  criterion — a load test asserting they agree under load and diverge only by `dropped_detail` —
  run as a permanent gate rather than a one-time check, because any future change to either path
  can reintroduce it.
- **Counter contention on the hot path.** The increment is the one piece of this phase that runs
  per query. A poorly-sharded or lock-guarded map turns logging into a resolution bottleneck.
  *Mitigation*: lock-free per-bucket atomics, and a resolution-latency assertion under logging
  load.
- **Denied `arithmetic_side_effects` and `indexing_slicing` on counters and the ring.** Every
  increment and every ring index becomes a checked operation. *Impact*: verbosity and the
  temptation to reach for a wrapping shortcut that hides an overflow. *Mitigation*: saturating or
  explicitly-checked arithmetic with the choice documented, and ring arithmetic expressed so the
  bound is structural.
- **`panic = "deny"` in a background task.** In a single process, a panic anywhere takes DNS down
  for the whole house, and the `catch_unwind` boundary is not implemented until the final phase.
  Everything before it relies on the lint. *Mitigation*: no unwrapping in the consumer, the sweep
  or the flush; every fallible step returns a `Result` and logs.
- **Channel sizing is unmeasurable before the cutover.** Because the cutover is last, there is no
  real traffic to size the channel or the ring against, so `dropped_detail` behaviour in
  production is a guess until the final phase. *Mitigation*: make both sizes configurable, and
  make `dropped_detail` prominent enough that the first week of real traffic answers the question.
- **Privacy is a write-time guarantee that is easy to leak at a boundary.** A qname can escape via
  a log line, an error message, a trace span or a top-N entry even when the raw row is suppressed.
  *Mitigation*: treat every outbound surface as in scope for the privacy level, and assert
  absence at the disk and log boundaries, not just in the row writer.
- **A purge is irreversible and unattributable.** With no audit trail in v1 and no multi-user
  admin, there is no record of who purged or when. *Mitigation*: confirmation in the UI and a
  returned count; the absence of attribution is an accepted consequence of the no-audit-trail
  non-goal, not a defect to fix here.
- **Retention deletes on a local database file can be large and slow.** A 7-day window on a busy
  network is a lot of rows to delete at once. *Mitigation*: bounded, chunked deletion on a
  background task, never on a request or the hot path.

### Acceptance Criteria Coverage

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | Rollup counters incremented synchronously via atomics on the response path — never queued, never dropped, so every dashboard number is exact | Yes | Exactness is also a durability claim: needs periodic + rollover + shutdown flush, or an unclean restart loses the open bucket |
| 2 | Raw rows and the live ring go through a bounded channel that drops when full and exposes `dropped_detail` | Yes | "Exposes" is undefined — the dashboard is the surface that matters; failed database writes must be a distinct condition from channel drops |
| 3 | `Detailed` and `Private` modes | Yes | `Detailed` retention window is configurable, default 7 days; mode is file-owned and needs a restart, unlike the privacy level |
| 4 | The four privacy levels (log everything / hide domains / hide clients / anonymous) | Yes | Must apply write-time, and must reach top-N as well as raw rows, or "hide domains" is partly false and permanent rollups retain domain material |
| 5 | The explicit purge action, or `Private` is a lie | Yes | Scope should be all raw rows; must fence in-flight drains; UI offering it is the next phase's obligation but the application-layer operation is this phase's |
| 6 | History views degrade to aggregates-only when raw rows are absent, and must not error | Yes | Should carry an explicit cause marker (private / expired / purged) so degradation is distinguishable from "no queries" |
| 7 | **Exit criterion**: a load test asserting the atomic counters and the raw rows diverge by exactly `dropped_detail` and by nothing else | Yes | Must be scoped to a window with no retention sweep and no purge, since both legitimately remove rows; should be a permanent gate, not a one-time check |

---

## Phase Position

- **Depends on**: **Phase 2 — Server loop and test harness** (the query-log observer port on the
  hot path, the request pipeline, the injectable `Clock`); **Phase 8 — Filtering** (the decision
  verdict that forms a rollup dimension, and clients/groups); **Phase 9 — Storage** (the Turso
  schema, designed once and complete, already containing raw rows, hourly rollups and all four
  privacy levels, so this phase needs no migration).
- **Depended on by**: **Phase 11 — Web UI** (`styx-web` — the dashboard, the live view, the
  history views, the privacy-level control and the purge button all consume what this phase
  produces); **Phase 12 — Cutover hardening** (the panic boundary and the musl artifacts, then the
  household — at which point `dropped_detail` finally meets real traffic).
