# SPDD Analysis: styx Phase 9 — Storage (Turso policy schema, designed once)

> **Self-containment note.** The source design record (`SPEC.md`) and the phase
> spec folder (`docs/specs/`) are being deleted once this analysis and its
> companion canvas are written. Every decision, rationale, accepted consequence,
> non-goal and risk this phase depends on is therefore reproduced inline here in
> full. Nothing in this document refers to an external file by number or name.

---

## Original Business Requirement

The requirement is the Phase 9 spec, reproduced verbatim, followed verbatim by
the project-level decisions, non-goals, open questions and risks that bear on it.

### Phase 9 — Storage (Turso) — verbatim

> # Phase 9 — Storage (Turso)
>
> The schema is designed **once, complete**. Privacy levels and rollups have to be
> in it from the start or decision 28 becomes a migration.
>
> ## Scope
>
> - **Policy only** (decision 42): clients, groups, list-to-group assignments,
>   adlist definitions, allow/block rules, local records, privacy level, blocking
>   mode, raw rows, hourly rollups. Infrastructure config — listeners, upstreams,
>   pools, strategy, TLS, trust anchor, DB path — stays in TOML and is never
>   mirrored here.
> - **Client lifecycle must be settled here, not in phase 11**: how
>   a client comes into existence (auto-discovered on first query vs. added by
>   hand), what group an unknown client lands in, and what happens to history rows
>   when a client or group is deleted. It is schema, so it cannot be deferred to the
>   UI phase.
> - Migrations; adlist definitions and parsing.
> - A DB outage degrades logging and admin, never resolution (decision 22) — now
>   structurally guaranteed, since nothing resolution needs lives in the DB.
>
> ## Exit criteria
>
> Migrations apply cleanly on an empty DB and forward from each prior revision; all
> four privacy levels and the `Detailed`/`Private` modes are representable without a
> further migration; and resolution is proven unaffected with the DB file removed
> mid-run, deleting only logging and admin.

### Project decisions this phase inherits — verbatim text, with the numbers resolved

The phase spec above cites "decision 42", "decision 28" and "decision 22". Those
citations are meaningless once the source record is deleted, so the decisions
themselves are reproduced here. The numbered references above should be read as
pointing at the following text.

**The hard config boundary — two stores, no overlap** (the spec's "decision 42"):

> **Config has two stores with a hard boundary: file owns infrastructure, DB owns
> policy.** A TOML file owns everything needed before the DB exists or in order to
> reach it — listen addresses, upstreams and pools, selection strategy, TLS
> material, trust anchor, DB path, log mode. Turso owns everything a human edits at
> runtime — clients, groups, adlists, allow/block rules, local records, privacy
> level, blocking mode. The UI can change only DB-backed things; file changes need
> a restart. No overlap means no precedence rule, and it strengthens [the hot-path
> decision]: a dead DB cannot touch resolution, because nothing resolution needs
> lives there. Accepted consequence: changing an upstream requires SSH and a
> restart, which is the thing people most want to do from the UI.

**The hot path touches no I/O** (the spec's "decision 22"):

> **The hot path touches no I/O.** Matcher state is in memory, built at boot and on
> reload. Turso holds config, adlist definitions, clients/groups and history only.
> A DB outage degrades logging and admin, never resolution.

**Privacy levels ship in v1** (the spec's "decision 28"):

> **Privacy levels ship in v1** (log everything / hide domains / hide clients /
> anonymous). Retrofitting anonymisation into a schema that assumed full qnames
> means a migration.

**One query-log ingest pipeline, two configurable modes:**

> The in-memory ring is always present and serves the live view in both modes;
> rollups are always permanent. The mode decides only whether raw rows are
> persisted — `Detailed` keeps them for a configurable window (default 7 days),
> `Private` never writes a qname to disk.

**Rollups are permanent and exact:**

> Hourly buckets per (client, decision, qtype) plus top-N domains per bucket, a few
> KB/day, retained indefinitely.

**Split write paths:**

> Rollup counters increment synchronously via atomics on the response path — never
> queued, never dropped, so every dashboard number is always exact. Only raw rows
> and the live ring go through a bounded channel, which drops when full and exposes
> a visible `dropped_detail` counter. Dashboards cannot lie; detail degrades
> gracefully.

**History views degrade to aggregates-only when raw rows are absent** — they must
not error.

**Switching to `Private` is not retroactive:**

> Existing raw rows survive until an explicit purge action, which the UI must offer
> or the mode is a lie.

**Full per-client groups in v1:**

> clients, groups and list-to-group assignment are first-class in the domain model,
> the DB and the UI.

**Per-group is a bitmask on each terminal**, not a matcher per group: one lookup,
then `mask & client_groups`.

**Allowlists are a second bitmask, and allow beats block unconditionally:**

> Each terminal carries an `allow` mask and a `block` mask; one walk returns both,
> and the verdict is `!(allow & g) && (block & g)`. Exact, wildcard and regex rules
> all feed the same pair, so an allow on `cdn.example.com` beats a wildcard block on
> `*.example.com` and beats a regex block. Every blocklist over-blocks eventually;
> without this, one bad list entry and a banking app is broken with no escape hatch.
> Accepted consequence: per-terminal mask memory doubles — the ~30–50MB per million
> figure becomes ~45–75MB.

**Reload is an explicit operation with an atomic swap.** The matcher is immutable
and replaced wholesale via `ArcSwap`; no mutation under a lock on the hot path.

**Adlist ingestion is staged, validated, and keeps the last known good:**

> Each list is fetched to a staging buffer and must pass sanity checks before it
> replaces anything: content-type is not HTML, it parses to at least a minimum count
> of syntactically valid domains, and the count has not collapsed against the
> previous ingest. The dangerous failure is not a 404 — it is a captive portal or
> error page served as HTTP 200, which parses as thousands of junk domains and
> blackholes real traffic. Any failure leaves the previous good copy in place, marks
> the list stale in the UI **with the reason**, and the matcher rebuild proceeds from
> the remaining lists. The staleness badge and a manual "accept the shrink" override
> are therefore required UI, not optional.

**Blocked replies: five modes, NXDOMAIN by default** — `NXDOMAIN` (default here),
`NULL` (`0.0.0.0`/`::`, Pi-hole's default), `NODATA`, `IP`, `IP-NODATA-AAAA`,
selectable in config. Regardless of mode: qtypes other than A/AAAA get NODATA,
blocked replies carry a short TTL, AD is always cleared and no RRSIG is ever
forged, and filtering is applied before validation.

**Local records are answered before the cache and are always Insecure:**

> A/AAAA/CNAME/PTR rows in Turso, editable in the UI, matched ahead of the answer
> cache and ahead of any upstream. They never enter the answer cache and never reach
> the validator: AD cleared, no forged signature, same honesty rule as a blocked
> reply. Accepted consequence: a local name under a signed public zone
> (`nas.example.com` where `example.com` is signed) is unprovable and validating
> clients may SERVFAIL it — the documented guidance is to keep local names under an
> unsigned or internal suffix.

**Admin auth is a single password:**

> Argon2id-hashed in Turso, seeded from `STYX_ADMIN_PASSWORD` or a generated
> first-boot secret printed once to the log. Signed, HttpOnly, `SameSite=Strict`
> session cookie plus an origin check. The UI refuses to serve until a credential
> exists — no default password, no unauthenticated setup wizard on the LAN. Accepted
> consequence: no audit trail; you can never tell who disabled blocking.

**One crate per feature; `domain`/`application`/`infrastructure` are modules inside
it.** Cargo enforces feature-to-feature isolation; arch-lint enforces layering
within a crate.

**Feature crates never depend on each other.** Cross-feature needs are expressed as
a port in the consumer's `domain`, implemented by an adapter in the binary. The
web crate may depend on a feature's `application` layer, because it is
presentation, not a peer.

**Single process, single binary.** DNS listeners, Leptos SSR and background workers
share state via `Arc`. The web UI is a compile-time Cargo feature (`web`, default
on) so a headless resolver can be built, and CI builds and tests
`--no-default-features` on every commit.

**The cutover is last.** styx runs on a dev box until everything works; the
household's resolver stays on Pi-hole until v1 is complete. Accepted consequence:
no operational feedback — cache behaviour, odd client queries, DHCP churn — until
the end, when it is most expensive to act on.

### Non-goals that bear on this phase — verbatim

- **DHCP server.** Clients are identified by IP plus optional manual naming. styx
  never owns the lease table, so client identity is best-effort and breaks on DHCP
  churn.
- **Multi-node or replicated deployment.** One box, one binary, local DB file.
- **Authoritative zone serving.** Local records and per-zone overrides are
  resolution/filtering concerns, not a zone-file server.
- **Multi-user admin, roles, audit trail.** Follows from the single-password
  decision.
- **EDNS Client Subnet (RFC 7871).** Deliberately omitted; it leaks client
  topology.

### The open question this phase is required to close — verbatim

> **Client lifecycle is undefined.** Clients are identified by IP (DHCP is a
> non-goal), but nothing says how one comes into existence — auto-discovered on
> first query, or added by hand — what group an unknown client lands in, or what
> happens to history rows when a client or a group is deleted. Decidable during
> phase 9's schema design, but it _is_ schema, so it cannot be left to phase 11.

### Open implementation-level choices left to the keyboard — verbatim

> Remaining choices are implementation-level and get decided at the keyboard: [...]
> rollup bucket granularity and top-N width [...]

Also recorded, and relevant because group identity is a schema concern:

> **Group mask width — `u64` or roaring bitmap — is now a sharper call.** Two masks
> on every terminal instead of one, so the memory cost of the choice doubles: a
> `u64` pair is 16 bytes per terminal, and the ~30–50MB/million estimate becomes
> ~45–75MB. 64 groups is almost certainly enough for a house; this is the number to
> measure at the end of phase 8 rather than guess now.

### Risks recorded against this phase — verbatim

> **Phase 9 now carries schema decisions that phase 11 would rather make.** Client
> lifecycle and default-group semantics are UI-shaped questions with schema
> consequences; answering them two phases early, without the UI to think against,
> is the cost of designing the schema once.

> **Client identity is unreliable by construction** (DHCP non-goal). Per-client
> groups keyed on IP will silently misattribute after a lease change. Manual naming
> and a visible "last seen" are mitigations, not fixes.

> **Two write paths for the query log must stay consistent.** Atomic counters and
> raw rows can disagree if a bug lands in either; behaviour tests need to assert
> they agree under load and diverge only by the `dropped_detail` count.

> **"Keep last known good" means a dead adlist blocks forever.** A list whose URL
> rots keeps enforcing a frozen copy indefinitely, and the only signal is a
> staleness badge nobody is looking at. Staleness needs to be visible on the
> dashboard, not buried on an adlist settings page.

> **Local records under a signed public zone will break validating clients.** The
> mitigation is documentation — "put local names under an unsigned suffix" — which
> is a mitigation only for people who read it.

### Phase position

- **Depends on:** Phase 0 — Foundation and gates (workspace, arch-lint, `just
  gate`); Phase 2 — Server loop and test harness (the hot-path ports and the
  injectable `Clock`, which the retention and bucket arithmetic must use); Phase 8
  — Filtering (the matcher this schema feeds, the allow/block mask semantics, the
  five blocked-reply modes, and the adlist ingestion contract whose state these
  tables persist).
- **Depended on by:** Phase 10 — Query log pipeline (writes raw rows and rollups
  into these tables, implements the four privacy levels and the explicit purge);
  Phase 11 — Web UI (reads and mutates every policy table here, holds the Argon2id
  credential row, surfaces adlist staleness and the "accept the shrink" override);
  Phase 12 — Cutover hardening (the DB-removal resilience proof is part of what
  makes the cutover safe).

---

## Domain Concept Identification

### Codebase and schema context

**Greenfield, no existing implementation.** The repository contains only `SPEC.md`,
`ROADMAP.md`, `docs/specs/`, and an `arch-lint.toml` that is the upstream Kotlin
template and enforces nothing. There is no git repository, no Cargo workspace, no
crate, no source file, no migration directory and no database. Every concept below
is therefore grounded in the decision record reproduced verbatim above, not in
code. Conventions that the analysis treats as "existing" are the conventions the
decision record mandates for code that phases 0–8 will have written by the time
this phase starts: one crate per feature with `domain`/`application`/
`infrastructure` as modules inside it, traits as ports declared in the consumer's
`domain`, `thiserror` error enums and `Result<T, E>` at every boundary, `tracing`
for observability, and hand-written SQL migrations against a local Turso
(SQLite-compatible) file.

### Existing Concepts (from the decision record — no code exists yet)

- **Client**: a device on the home network, identified by IP address, optionally
  given a human name by hand. It is the subject of per-client blocking policy and
  the key dimension of history. It relates to Group by membership, and to the query
  log as the attribution key. Identity is best-effort by construction because DHCP
  is a non-goal and styx never sees the lease table.
- **Group**: a named policy bucket. Clients belong to groups; adlists are assigned
  to groups; allow and block rules are scoped to groups. Its runtime form is a bit
  position in the per-terminal `allow`/`block` masks the matcher carries, and the
  verdict is `!(allow & g) && (block & g)` where `g` is the querying client's
  group mask.
- **Adlist**: a remote blocklist URL with ingestion state. It owns the domains it
  contributed at its last successful ingest, its enabled flag, its last-known-good
  domain count (needed to detect a collapse on the next ingest), and a staleness
  marker carrying the failure reason. It is assigned to groups.
- **List-to-group assignment**: the many-to-many relation that makes an adlist
  apply to some groups and not others. First-class in the domain model, the DB and
  the UI.
- **Allow/block rule**: a per-group filtering rule in one of three shapes — exact
  domain, wildcard (a node flagged wildcard matches all descendants), regex (all
  regex rules compile into one `RegexSet`). All three shapes feed the same
  `allow`/`block` mask pair, so an allow rule beats a wildcard block and beats a
  regex block.
- **Local record**: an A, AAAA, CNAME or PTR answer served from the DB, matched
  ahead of the answer cache and ahead of any upstream, always marked Insecure with
  AD cleared and no forged signature.
- **Privacy level**: one of four — log everything, hide domains, hide clients,
  anonymous. It governs what may be written to disk in raw rows and in the rollup
  top-N.
- **Blocking mode**: one of five blocked-reply shapes — `NXDOMAIN` (the default
  here), `NULL`, `NODATA`, `IP`, `IP-NODATA-AAAA`.
- **Raw query row**: one persisted record of one query — timestamp, client, qname,
  qtype, decision, subject to the privacy level and to the log mode. Written only
  in `Detailed` mode, through a bounded channel that drops when full.
- **Hourly rollup**: a permanent, exact aggregate — buckets per (client, decision,
  qtype) plus top-N domains per bucket, a few KB/day, retained indefinitely,
  incremented synchronously via atomics so dashboards cannot lie.
- **Admin credential**: a single Argon2id password hash living in Turso, seeded
  from `STYX_ADMIN_PASSWORD` or a generated first-boot secret printed once.

### New Concepts Required

- **Migration revision ledger**: the applied-migration table that makes "apply
  cleanly on an empty DB and forward from each prior revision" checkable. Required
  by the exit criteria; nothing in the decision record names it, but it is the only
  way the criterion can be met.
- **Adlist entry (persisted last-known-good domain set)**: the decision record says
  ingestion keeps the last known good copy and that the matcher is built at boot.
  Those two together force the parsed domain set to live in the DB — a boot with no
  network must still produce the same matcher. This is the concept the phrase "last
  known good" implies but does not name.
- **Policy snapshot**: the in-memory, immutable read model that the resolver
  actually consults — matcher masks, the client-IP-to-group-mask map, the local
  record set, the blocking mode and the privacy level — built by a full read of the
  DB at boot and on explicit reload, swapped wholesale via `ArcSwap`. This is the
  concept that makes "a dead DB cannot touch resolution" structural rather than
  aspirational: after the snapshot is built, the resolver never reads the DB again.
- **Client lifecycle state**: `first_seen` and `last_seen` timestamps and the
  origin of a client row (auto-discovered vs. added by hand). Required to close the
  open question and to make the "visible last seen" mitigation for IP
  misattribution possible.
- **Purge action**: the explicit operation that deletes surviving raw rows after a
  switch to `Private`, and the same machinery applied to one client's history.
  Named as a required behaviour by the decision record; it is new as a schema-level
  concern because it defines what may be deleted without breaking rollups.

### Conceptual relationships

- A **Client** belongs to zero or more **Groups**; a Group holds zero or more
  Clients. Zero groups is not a valid runtime state — see the default-group rule
  below — but it must be representable transiently while editing.
- A **Group** owns zero or more **allow/block rules**. Rules have no meaning
  outside their group.
- An **Adlist** is assigned to zero or more **Groups**; a Group has zero or more
  Adlists. An Adlist owns its parsed **entries** exclusively; entries have no
  meaning outside their list.
- **Local records**, **privacy level**, **blocking mode** and the **admin
  credential** are global: they belong to the installation, not to a group or a
  client. (Local records being global follows from the decision that they are
  matched ahead of the cache and ahead of any upstream, with no per-group
  qualifier anywhere in the record.)
- **Raw query rows** and **hourly rollups** reference a client by its IP, and
  reference no group at all — the rollup dimensions are explicitly (client,
  decision, qtype). This is the fact that makes the "what happens to history when a
  group is deleted" half of the open question answerable with "nothing".
- The **Policy snapshot** is derived from every policy table at once and owned by
  no table. It is a build output, not persisted state.

### Key Business Rules

- **No overlap between the two config stores.** Everything needed before the DB
  exists or in order to reach it lives in TOML — listen addresses, upstreams and
  pools, selection strategy, TLS material, trust anchor, DB path, log mode.
  Everything a human edits at runtime lives in Turso — clients, groups, adlists,
  allow/block rules, local records, privacy level, blocking mode. Nothing appears
  in both. Governs: every table in this phase, and every field the schema might be
  tempted to mirror. Rationale, stated because it is the load-bearing part: no
  overlap means there is no precedence rule to get wrong, and it makes "a dead DB
  cannot touch resolution" structural — nothing resolution needs lives there. The
  accepted consequence is real and must not be quietly designed around: changing
  an upstream requires SSH and a restart, and that is the thing people most want to
  do from the UI.
- **The hot path touches no I/O.** No query-time read may reach the database.
  Governs: the policy snapshot, and by extension every table that feeds it.
- **The schema is designed once, complete.** Privacy levels and rollups are in it
  from the start, because adding them later is a migration. Governs: the raw row
  and rollup tables, and the nullability of every field an anonymisation level must
  be able to omit.
- **All four privacy levels ship in v1** — log everything, hide domains, hide
  clients, anonymous — because retrofitting anonymisation into a schema that
  assumed full qnames means a migration. Governs: raw rows and the rollup top-N.
- **Rollups are permanent and exact.** Hourly buckets per (client, decision,
  qtype), top-N domains per bucket, a few KB/day, retained indefinitely. Counters
  increment synchronously via atomics on the response path — never queued, never
  dropped. Governs: the rollup table, its retention (none), and its independence
  from the raw-row retention window.
- **Raw rows are best-effort; rollups are not.** Raw rows travel a bounded channel
  that drops when full and exposes `dropped_detail`. Governs: the write path's
  error semantics — a failed raw-row insert is a logged degradation, never an
  error propagated toward resolution.
- **History views degrade to aggregates-only when raw rows are absent, and must
  not error.** Governs: every read query shape over history.
- **Switching to `Private` is not retroactive.** Existing raw rows survive until an
  explicit purge action, which the UI must offer or the mode is a lie. Governs: the
  purge operation and the fact that a mode change is not itself a delete.
- **Allow beats block unconditionally**, across exact, wildcard and regex rules
  alike, because every blocklist over-blocks eventually and without an escape hatch
  one bad list entry breaks a banking app. Governs: the rule table's shape — a rule
  carries its action, and the two masks are built from the same rows.
- **Adlist ingestion never replaces a good copy with a bad one.** Not HTML, at
  least a minimum count of valid domains, no collapse against the previous count;
  any failure keeps the previous copy, marks the list stale with the reason, and
  the rebuild proceeds from the remaining lists. Governs: the adlist state columns
  and the entry table's replace-atomically semantics.
- **Blocked and local answers never lie about security.** AD cleared, no forged
  RRSIG. Governs nothing in the schema directly, but constrains local records to
  carry no signature material and no DNSSEC status column — there is nothing to
  store, and a column would invite forging one.
- **Client identity is IP, best-effort.** No lease table, no DHCP. Governs the
  client table's key and the presence of `last_seen`.

---

## Strategic Approach

### Solution Direction

A single feature crate — `styx-storage` — with `domain`, `application` and
`infrastructure` as modules inside it, matching the project's one-crate-per-feature
rule. `domain` holds the row and policy types and the ports as traits; `application`
holds the snapshot build, the ingestion state transitions and the purge and
retention operations; `infrastructure` holds the Turso connection, the hand-written
SQL migrations and the trait implementations. Consumers never depend on this crate
directly: feature crates never depend on each other, so the resolver and filtering
crates declare their own ports in their own `domain`, and the `styx` binary wires
the storage adapters into them. The web crate may depend on this crate's
`application` layer, because it is presentation rather than a peer.

Data flow has exactly two directions, and they never cross on the hot path:

- **Boot and reload (DB → memory, once per generation):** read every policy table,
  build the matcher masks, the client-IP-to-group-mask map, the local record set,
  and the resolved blocking mode and privacy level, then swap the whole immutable
  snapshot in via `ArcSwap`. After this, resolution is DB-free.
- **Response path (memory → DB, asynchronously and best-effort for detail, exactly
  for counts):** rollup counters increment in memory synchronously via atomics and
  are flushed to the rollup table by a background writer; raw rows and the live ring
  go through the bounded channel that drops when full. Nothing on this path can
  fail a query.

Admin mutations (UI writes) go DB-first and then request an explicit reload; they
never mutate the live snapshot in place.

### Key Design Decisions

- **Client lifecycle: auto-discovery on first query, by the logging path, never by
  the resolver.** Trade-off: hand-only creation means a fresh install shows an empty
  client list and per-client policy is unusable until someone types in every IP;
  auto-discovery on the resolver's own path would put a write on the hot path and
  break the no-I/O rule. → **Recommendation: a client row is created lazily by the
  query-log consumer the first time an unseen IP appears, carrying `first_seen`,
  `last_seen`, a null name and an origin marker of "discovered". A human may also
  create a row by hand ahead of time, with origin "manual". The two converge on the
  same row keyed by IP.** Rationale: discovery is a logging concern, so it inherits
  the logging path's properties — off the hot path, best-effort, droppable. A
  dropped discovery costs nothing, because the next query rediscovers.
- **Unknown clients resolve against a seeded, undeletable Default group.** Trade-off:
  "unknown means no policy" is a fail-open that silently disables blocking for any
  device that appears between reloads; "unknown means blocked" is a fail-closed that
  breaks the network on a lease change. → **Recommendation: every client that is not
  explicitly assigned to a group resolves with the Default group's mask, and the
  Default group exists from the first migration and cannot be deleted.** Rationale:
  it makes the common case — a household where nobody wants per-device policy — work
  with zero configuration, it gives the "what group does an unknown client land in"
  question a single unambiguous answer at both the schema and the runtime level, and
  it means a lease change degrades to the household default rather than to no
  filtering at all.
- **History is keyed by client IP as a plain column with no foreign key to the
  client table.** Trade-off: a foreign key gives referential integrity and lets the
  UI join a name onto history rows cheaply, but it couples the log write path to the
  existence of a client row, and it forces a choice between cascading history away on
  client delete and blocking the delete. → **Recommendation: raw rows and rollups
  carry the client IP denormalised, with no FK; deleting a client deletes its name
  and its group assignments and nothing else.** Rationale: the log write path must
  never fail because a policy row is missing, history is a fact ledger and deleting a
  device's label should not erase what happened on the network, and under the "hide
  clients" privacy level the stored client key is redacted — which would be a
  dangling foreign key by construction. The name join becomes a lookup by IP, which
  is what the UI wants anyway.
- **Group deletion cascades to rules and assignments and touches no history.**
  Trade-off: preserving rules for a deleted group would leave orphans that silently
  reappear if an ID is reused. → **Recommendation: deleting a group cascades to its
  allow/block rules, its client memberships and its adlist assignments; history is
  untouched because rollup dimensions are (client, decision, qtype) and carry no
  group at all.** Rationale: this falls directly out of the rollup dimensions
  already fixed by the decision record, so it needs no new invariant.
- **Group bit positions are assigned at snapshot-build time, not stored.**
  Trade-off: storing a bit index makes the mapping stable and auditable, but it has
  to be allocated, freed and defended against reuse races. → **Recommendation: the
  DB stores a stable group ID; the bit position is derived during each matcher
  build, since the matcher is rebuilt wholesale on every reload and no mask is ever
  persisted.** Rationale: a derived index cannot go stale, and it keeps the still-open
  `u64`-versus-roaring-bitmap width question out of the schema entirely — that choice
  is measured at the end of the filtering phase and must not be frozen into a column
  here.
- **The parsed last-known-good domain set is persisted per adlist.** Trade-off: not
  persisting it keeps the DB small, but then a boot without network produces an empty
  matcher — which is a silent, total loss of filtering. → **Recommendation: persist
  entries per list and replace them atomically only after the staging buffer passes
  every sanity check.** Rationale: "the matcher is built at boot" and "keep the last
  known good" are only compatible if the good copy is on disk.
- **Adlist ingestion state is a column set, not a log.** Trade-off: an ingestion
  history table would make "why is this list stale" answerable over time. →
  **Recommendation: store last-success timestamp, last-attempt timestamp, the
  last-good domain count (needed to compute the collapse ratio on the next attempt),
  a stale flag, a machine-readable failure reason and the human text, plus an
  "accepted shrink" acknowledgement.** Rationale: the required UI is a badge with a
  reason and a manual override, not a forensic timeline; and the audit-trail non-goal
  says the project does not keep who-did-what records.
- **Settings are a small typed key/value table with a single-row guard, not one
  column per setting.** Trade-off: a wide singleton row is more type-safe in SQL. →
  **Recommendation: key/value with values validated on read into typed enums in
  `domain`, guarded so only one logical settings set exists.** Rationale: the
  DB-owned settings are few and heterogeneous (privacy level, blocking mode, admin
  credential, retention acknowledgements), and every one of them is validated in Rust
  anyway. The important property is not the shape but the boundary: only DB-owned
  settings may appear here, and the TOML-owned list must never acquire a mirror
  column.
- **Log mode (`Detailed`/`Private`) stays in TOML; privacy level stays in the DB.**
  Trade-off: they look like the same knob and a user will expect both in the UI. →
  **Recommendation: honour the boundary exactly as written — log mode is named in the
  TOML-owned list, privacy level in the DB-owned list — and read the exit criterion's
  "the `Detailed`/`Private` modes are representable without a further migration" as a
  requirement on the schema's ability to represent the absence of raw rows, not as a
  requirement to store the mode.** Rationale: the no-overlap rule is the whole point;
  storing the mode in both places creates exactly the precedence question the rule
  exists to eliminate.
- **Migrations are hand-written, forward-only SQL with an applied-revision ledger,
  applied at startup before the snapshot is built.** Trade-off: no down-migrations
  means a bad migration needs a new forward migration rather than a rollback. →
  **Recommendation: accept it.** Rationale: the deployment is one box with one local
  DB file, replication is a non-goal, and the exit criterion asks only that
  migrations apply cleanly on an empty DB and forward from each prior revision.

### Alternatives Considered

- **Storing the resolver's operational config (upstreams, pools, listeners) in the
  DB so the UI could edit it.** Rejected: it is precisely the overlap the hard
  boundary forbids. Admitting it would create a precedence rule between TOML and DB
  and would make the DB load-bearing for resolution, destroying the property that a
  dead DB cannot touch resolution. The accepted consequence — SSH and a restart to
  change an upstream — is known and is the price.
- **Foreign-keying history to clients.** Rejected above: it couples the log write
  path to policy rows and is incompatible with the "hide clients" privacy level.
- **Per-group query-log dimensions.** Rejected: the rollup dimensions are fixed at
  (client, decision, qtype) plus top-N domains, and adding a group dimension
  multiplies bucket count for a number nobody asked for.
- **Querying the DB at match time for per-client group membership.** Rejected: it is
  I/O on the hot path, which is the one rule the whole architecture is arranged
  around.
- **Deferring the client lifecycle question to the Web UI phase.** Rejected because
  it is schema: the columns that record how a client came into existence, when it was
  last seen, and whether its history survives its deletion cannot be added later
  without the migration this phase exists to avoid. The cost — answering a UI-shaped
  question two phases early, with no UI to think against — is accepted deliberately.
- **An ingestion history table per adlist.** Rejected: more than the required badge
  needs, and adjacent to the audit-trail non-goal.
- **Storing group bitmask positions.** Rejected above: derived at build time, and it
  keeps the undecided mask-width question out of the schema.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **Client lifecycle — the phase's own headline gap.** The requirement states three
  sub-questions and mandates that they be answered here, not in the UI phase: how a
  client comes into existence, what group an unknown client lands in, and what
  happens to history rows when a client or group is deleted. Nothing in the record
  answers any of them. **This is the most important thing this phase must settle, it
  is schema and therefore cannot be deferred, and the recorded risk is explicit that
  answering it two phases early — without the UI to think against — is the accepted
  cost of designing the schema once.** The Strategic Approach above resolves all
  three concretely; the canvas must carry those resolutions as binding constraints
  with their rationale, not as suggestions.
- **"Representable without a further migration" for `Detailed`/`Private`.** The
  modes are named in the TOML-owned config list, yet the exit criterion asks the
  schema to represent them. Resolved above as a requirement on the schema's ability
  to represent raw-row absence, with the mode itself staying in TOML — because the
  alternative reintroduces the precedence rule the no-overlap boundary eliminates.
  Worth stating loudly in the canvas, because it is the single place where a
  well-meaning implementer is most likely to breach the boundary.
- **The raw-row retention window's home.** "Detailed keeps them for a configurable
  window (default 7 days)" does not say which store owns the number. It is a property
  of the log mode, which is TOML-owned, so it goes to TOML — but the deletion job
  that enforces it is a DB operation, so the seam has to be drawn explicitly.
- **What "anonymous" means precisely, as distinct from hiding both.** Four levels
  are named — log everything, hide domains, hide clients, anonymous — but only the
  middle two describe themselves. The schema must make all four representable;
  whether "anonymous" additionally coarsens timestamps or suppresses the rollup
  top-N entirely is a behaviour question for the query-log phase, and the schema must
  not foreclose either reading. Concretely: every field an anonymisation level might
  need to omit must be nullable from the first migration.
- **Whether local records are global or group-scoped.** The record calls them
  "A/AAAA/CNAME/PTR rows in Turso, editable in the UI" with no group qualifier
  anywhere, and lists them among global DB-owned settings alongside privacy level
  and blocking mode. Read as global. If a future version wants per-group local
  records, that is a migration, and it should be named as such rather than
  pre-built.
- **Whether the blocking mode is global or per-group.** Same shape of ambiguity:
  the five modes are described as "selectable in config", and the DB-owned list names
  "blocking mode" without a group qualifier. Read as global.

### Edge Cases

- **A client's IP is reassigned by DHCP to a different device.** History before and
  after the lease change is attributed to the same row; per-group policy silently
  follows the address, not the device. This is unreliable by construction — styx
  never owns the lease table — and manual naming plus a visible "last seen" are
  mitigations, not fixes. The schema's obligation is to make `last_seen` present and
  cheap to show.
- **A device appears for the first time between two reloads.** It is discovered by
  the logging path, so it exists in the client list, but the in-memory snapshot was
  built without it — it resolves with the Default group's mask until the next
  reload. This is the correct behaviour under the no-I/O rule and must be documented
  rather than worked around with a hot-path read.
- **A client is deleted while its device is still on the network.** It is
  rediscovered on the next query with a fresh `first_seen`, a null name and Default
  group membership. Deletion is therefore "forget the labelling", not "ban the
  device". The UI must say so.
- **Switching to `Private` with weeks of raw rows on disk.** Nothing is deleted
  until the explicit purge is run. If the UI does not offer that purge, the mode is
  a lie — this is stated as a requirement, not a preference.
- **Purging raw rows must not disturb rollups.** They live in separate tables with
  separate retention (raw rows: a window; rollups: forever) and the purge touches
  only the former. A purge that took rollups with it would silently destroy the one
  thing that is supposed to be permanent and exact.
- **Reading history when raw rows are absent** — either because the mode is
  `Private`, because the window expired, or because a purge ran. The view must
  degrade to aggregates only and must not error.
- **An adlist's first-ever ingest.** There is no previous count to compare against,
  so the collapse check has nothing to compare and only the minimum-count and
  not-HTML checks apply. The schema must allow a null last-good count.
- **A list that legitimately shrank.** The collapse check rejects it forever until a
  human accepts the shrink; the acknowledgement has to be persisted or the next
  ingest rejects it again.
- **A dead adlist blocks forever.** Keeping the last known good means a list whose
  URL rotted keeps enforcing a frozen copy indefinitely, with a staleness badge as
  the only signal. The schema's part is a last-success timestamp that makes "frozen
  for 60 days" computable and surfaceable on the dashboard, not buried in a settings
  page.
- **Deleting a group that clients belong to.** Those clients may end up in no group
  at all, at which point the Default-group fallback is what keeps them filtered
  rather than silently unfiltered.
- **Deleting the Default group.** Must be impossible — enforced at the schema level,
  not only in the UI, because the UI is not the only caller.
- **First boot with no credential.** The UI refuses to serve until one exists; the
  schema must represent "no credential yet" as a first-class state rather than as a
  seeded default password.
- **The DB file is removed or corrupted mid-run.** Resolution must continue
  unaffected from the in-memory snapshot; only logging writes and admin fail. This is
  an exit criterion, so it needs a test that actually deletes the file.
- **Two write paths disagreeing.** Atomic counters and raw rows can diverge if a bug
  lands in either; they must agree under load except by exactly the `dropped_detail`
  count. The schema's contribution is making both independently queryable so the
  assertion can be written.
- **Clock skew and bucket boundaries.** Hourly buckets and a retention window both
  do date arithmetic; the project mandates an injectable clock, and these operations
  must use it or the tests are not deterministic.

### Technical Risks

- **Boundary erosion.** The single largest risk to this phase is a future need
  ("just let me change the upstream from the UI") pulling an infrastructure field
  into the DB. The moment one field exists in both stores, a precedence rule is
  required, and the "a dead DB cannot touch resolution" property stops being
  structural. Mitigation direction: state the forbidden list explicitly in the
  schema documentation and assert it — the table set is small enough that a test can
  enumerate it.
- **Write amplification on a Raspberry Pi's SD card.** Raw rows at household query
  volume plus hourly rollup flushes on flash storage. Mitigation direction: batch
  the rollup flush (counters are authoritative in memory between flushes) and keep
  raw-row writes on the already-bounded channel.
- **The rollup flush is the one place where "exact" could become "approximately".**
  Counters are exact in memory; if a flush is lost on a crash the persisted number
  is not. Mitigation direction: flush frequency and crash behaviour are explicit
  design points for the query-log phase, and the schema must let a flush be
  idempotent (upsert into a bucket rather than insert-and-hope).
- **Schema-once is a one-shot.** Anything missed here becomes the migration this
  phase exists to avoid. Mitigation direction: make every privacy-sensitive column
  nullable from the first migration, and include the rollup top-N structure even
  though the query-log phase is what fills it.
- **Client identity is unreliable by construction.** Carried forward deliberately:
  per-client groups keyed on IP will silently misattribute after a lease change.
  Manual naming and a visible "last seen" are mitigations, not fixes, and the DHCP
  non-goal means there is no fix available in v1.
- **No audit trail.** A consequence of the single-password decision that lands here
  as a schema consequence: no table records who changed what, so a policy change
  that breaks the network has no attribution. Accepted.
- **No operational feedback until the cutover.** The cutover is last, so this schema
  will be exercised against real household traffic — real client churn, real query
  volume, real odd devices — only at the very end, when changing it is most
  expensive. This sharpens every "designed once" risk above.
- **Turso/SQLite concurrency.** A single writer with concurrent readers, on one box,
  with a background log writer and a UI issuing mutations. Mitigation direction: one
  owned writer path, WAL-style concurrency settings decided at the keyboard, and no
  write ever on the hot path — which is already true.

### Acceptance Criteria Coverage

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | Migrations apply cleanly on an empty DB | Yes | Needs the applied-revision ledger, which the requirement does not name but the criterion implies. |
| 2 | Migrations apply forward from each prior revision | Yes | Trivially true at one revision; the test has to be written so it stays true as revisions accumulate. Forward-only — no down-migrations, accepted because the deployment is one box with one local file. |
| 3 | All four privacy levels representable without a further migration | Yes | Requires every privacy-sensitive column nullable from migration 1, including the rollup top-N domain. The exact meaning of "anonymous" beyond hiding both dimensions is left to the query-log phase; the schema must not foreclose either reading. |
| 4 | `Detailed`/`Private` modes representable without a further migration | Partial | Resolved as the schema representing raw-row absence, with the mode itself staying TOML-owned per the no-overlap boundary. Flagged above as the most likely place for a boundary breach. |
| 5 | Resolution unaffected with the DB file removed mid-run, deleting only logging and admin | Yes | Requires the in-memory snapshot to be complete — matcher masks, client-to-group map, local records, blocking mode — and the test to delete the file for real, not mock a failure. |
| 6 | Policy-only scope: no infrastructure config mirrored into the DB | Yes | Best enforced as an enumerated table/settings-key list asserted by a test, since this is the property most likely to erode over time. |
| 7 | Client lifecycle settled here rather than in the UI phase | Yes | Resolved in Strategic Approach: lazy discovery by the logging path, seeded undeletable Default group for unknown and ungrouped clients, history keyed by IP with no FK and surviving client deletion, group deletion cascading to rules and assignments and touching no history. |
| 8 | Adlist definitions and parsing | Yes | Requires the persisted last-known-good entry set, plus the state columns the sanity checks and the required UI badge need: last-good count, stale flag, failure reason, accepted-shrink acknowledgement, last-success timestamp. |

### Open implementation-level choices deliberately left to the keyboard

- **Rollup bucket granularity** — hourly is the stated intent; the exact bucket key
  and whether sub-buckets exist is decided at the keyboard.
- **Top-N width** — how many domains each bucket retains.
- **Group mask width** (`u64` vs. roaring bitmap) — measured at the end of the
  filtering phase, and kept out of this schema entirely by deriving bit positions at
  build time rather than storing them.
