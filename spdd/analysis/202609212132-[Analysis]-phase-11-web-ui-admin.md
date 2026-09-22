# SPDD Analysis: Phase 11 — Web UI (`styx-web`, Leptos SSR)

> **Self-contained document.** The project's SPEC.md and per-phase spec files are
> being deleted after this analysis is written. Every decision, rationale,
> accepted consequence, non-goal and risk that bears on this phase is reproduced
> here in full. Nothing in this document defers to an external file.

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
tree-sitter engine that ships only a Kotlin grammar and therefore discovers zero
`.rs` files and exits green having checked nothing). Replacing that file is the
job of Phase 0. Consequently, every statement below about "existing concepts",
architecture conventions and layering is grounded in the project's recorded
design decisions rather than in read source code, and is flagged as such.

### Phase position and dependencies

Phase 11 is the second-to-last phase of twelve. The full ordering is:

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
| **11** | **Web UI** | **`styx-web` — auth, dashboard, groups, adlists** |
| 12 | Cutover hardening | Panic boundary, musl artifacts, then the household |

**Phase 11 depends directly on:**

- **Phase 0 — Foundation and gates.** Supplies the Cargo workspace shape, the
  working syn-engine `arch-lint.toml` with `[[scopes]]` per feature crate ×
  domain/application/infrastructure, `[[deny-scope-dep]]` layering rules and
  `[[restrict-use]]` isolation rules; the independent `cargo tree --edges normal`
  layering gate; the 15 denied clippy lints; lefthook pre-commit/pre-push; the
  GitHub Actions gate; and — critically for this phase — the
  `--no-default-features` headless build that CI runs on every commit.
- **Phase 8 — Filtering.** Supplies the matcher (reversed-label radix trie plus a
  single `RegexSet`), the two per-terminal bitmasks (`allow` and `block`) whose
  precedence the UI must make visible, the five blocked-reply modes, the
  `ArcSwap` reload operation the UI triggers, and the adlist ingestion contract
  including per-list staging, sanity checks, last-known-good retention and the
  stale marker carrying its reason.
- **Phase 9 — Storage.** Supplies the Turso schema the UI edits: clients, groups,
  list-to-group assignments, adlist definitions, allow/block rules, local
  records, privacy level, blocking mode, raw query rows and hourly rollups. It
  also settles client lifecycle (how a client comes into existence, what group an
  unknown client lands in, what happens to history rows when a client or group is
  deleted) — decisions Phase 11 would rather make with the UI to think against,
  but which are schema and therefore cannot be deferred.
- **Phase 10 — Query log pipeline.** Supplies the exact rollup counters that back
  every dashboard number, the in-memory ring that serves the live view, the
  bounded detail channel and its `dropped_detail` counter, the `Detailed` /
  `Private` modes, the four privacy levels, the explicit purge action, and the
  rule that history views degrade to aggregates-only when raw rows are absent
  rather than erroring.
- **Phases 3, 5 and 6** indirectly, for read models the UI surfaces: pool
  `HealthState` per upstream member (SRTT EWMA, consecutive failures, circuit
  state, last-probe-at), the selection strategy in force per pool (the `race`
  warning depends on this), and `RecursionDiagnostics` — root/TLD reachability
  published by `styx-recursion` as its own read model, consumed directly by
  `styx-admin`/`styx-web` and never routed through the pool, deliberately named
  distinctly from selection health so the two are never conflated.

**Phase 12 — Cutover hardening depends on Phase 11.** It adds the `catch_unwind`
boundary around the web layer and a supervised task model, builds the musl
release artifacts for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`
on `v*` tags, and soaks on one machine before the household's resolver is pointed
at styx. Phase 11 ships with a known, accepted hole that Phase 12 closes.

---

## Original Business Requirement

The following is the Phase 11 specification, reproduced verbatim.

```markdown
# Phase 11 — Web UI (`styx-web`, Leptos SSR)

> Part of [ROADMAP.md](../../ROADMAP.md) · Previous: [Phase 10 — Query log](10-query-log.md) · Next: [Phase 12 — Cutover hardening](12-cutover.md)

## Scope

- Argon2id password in Turso, seeded from `STYX_ADMIN_PASSWORD` or a generated
  first-boot secret printed once; a signed, HttpOnly, `SameSite=Strict` session
  cookie **plus an origin check** on every server function (decision 32).
- The UI refuses to serve until a credential exists. No default password, no
  unauthenticated setup wizard on the LAN.
- Dashboard, clients and groups, adlists, live view, history, local records.
- **Required, not optional** (decision 21): a per-adlist stale marker showing the
  failure reason, surfaced on the dashboard rather than buried in adlist settings,
  and a manual "accept the shrink" override for a list that legitimately shrank.
- Allow/block rule editing per group, reflecting decision 19's precedence — the UI
  has to make "allow always wins" visible, or users will not trust the escape
  hatch.
- **A loud warning on `race` selection.** It multiplies outbound QPS and shows
  every domain to every provider in the pool. This belongs in the UI, not a config
  comment.

## Exit criteria

Every mutation is rejected without a valid session cookie *and* without a matching
origin; a fresh install refuses to serve until a credential exists; the headless
`--no-default-features` build still passes with this crate absent.
```

### Governing decisions referenced above, inlined in full

The requirement above cites three decisions by number. Because the decision
record is being deleted, each is reproduced here with its rationale and its
accepted consequences.

**Admin auth is a single password.** Argon2id-hashed in Turso, seeded from
`STYX_ADMIN_PASSWORD` or a generated first-boot secret printed once to the log.
Signed, HttpOnly, `SameSite=Strict` session cookie **plus an origin check**,
because Leptos server functions are POST endpoints and every mutation is
otherwise CSRF-able. The UI refuses to serve until a credential exists — no
default password, no unauthenticated setup wizard on the LAN. *Accepted
consequence: no audit trail; you can never tell who disabled blocking.*

**Allowlists are a second bitmask, and allow beats block unconditionally.** Each
matcher terminal carries an `allow` mask and a `block` mask; one walk returns
both, and the verdict is `!(allow & g) && (block & g)`. Exact, wildcard and regex
rules all feed the same pair, so an allow on `cdn.example.com` beats a wildcard
block on `*.example.com` and beats a regex block. *Rationale: every blocklist
over-blocks eventually; without this, one bad list entry and a banking app is
broken with no escape hatch.* Accepted consequence: per-terminal mask memory
doubles — the ~30–50MB per million domains figure becomes ~45–75MB.

**Adlist ingestion is staged, validated, and keeps the last known good.** Each
list is fetched to a staging buffer and must pass sanity checks before it
replaces anything: content-type is not HTML, it parses to at least a minimum
count of syntactically valid domains, and the count has not collapsed against the
previous ingest. *Rationale: the dangerous failure is not a 404 — it is a captive
portal or error page served as HTTP 200, which parses as thousands of junk
domains and blackholes real traffic.* Any failure leaves the previous good copy
in place, marks the list stale in the UI **with the reason**, and the matcher
rebuild proceeds from the remaining lists. The staleness badge and a manual
"accept the shrink" override are therefore required UI, not optional.

---

## Domain Concept Identification

### Existing Concepts

From prior phases. The project is greenfield, so "existing" here means
"specified and built by phases 0–10, not yet written".

- **Admin credential**: the single Argon2id password hash persisted in Turso.
  Business purpose: gate every mutation and every view of the admin surface.
  Relationship: it is the sole subject in the system; there is no user table, no
  role, no principal identity beyond "the admin". Owned by Phase 9's schema,
  seeded and verified by this phase.
- **Client**: a network device identified by IP address plus optional manual
  naming, with a "last seen" timestamp. Business purpose: the unit that group
  policy attaches to. Relationship: many clients to one group (or to a default
  group); history rows and rollups reference it. Lifecycle (auto-discovery vs.
  manual creation, default group for an unknown client, cascade behaviour on
  delete) is settled by Phase 9's schema, not here.
- **Group**: a named policy bucket carrying a bit position in the matcher's
  64-wide (or roaring) mask. Business purpose: per-client blocking policy.
  Relationship: owns adlist assignments and allow/block rules; clients belong to
  it.
- **Adlist**: a URL-addressed blocklist definition with an enabled flag, a group
  assignment, a last-ingest timestamp, a domain count from the last good ingest,
  and — crucially for this phase — a **stale marker with a reason**. Relationship:
  assigned to groups; feeds the matcher's `block` mask.
- **Allow rule / Block rule**: an exact, wildcard or regex pattern scoped to a
  group, feeding the `allow` or `block` bitmask on a matcher terminal.
  Relationship: allow unconditionally beats block within the same group mask.
- **Local record**: an A/AAAA/CNAME/PTR row in Turso, matched ahead of the answer
  cache and ahead of any upstream. Business purpose: name local devices.
  Relationship: a resolution concern, not a zone-file server.
- **Privacy level**: one of four — log everything / hide domains / hide clients /
  anonymous. Relationship: governs what the query-log pipeline records and what
  history and live views may display.
- **Blocking mode**: one of five blocked-reply modes — `NXDOMAIN` (the default
  here), `NULL` (`0.0.0.0`/`::`, which is Pi-hole's default), `NODATA`, `IP`,
  `IP-NODATA-AAAA`. Relationship: a DB-backed policy setting, therefore editable
  from the UI.
- **Rollup bucket**: an hourly count per (client, decision, qtype) plus top-N
  domains per bucket. Business purpose: exact, permanently retained dashboard
  numbers. Relationship: incremented synchronously via atomics on the response
  path — never queued, never dropped — so every dashboard number is always exact.
- **Raw query row**: a persisted per-query record, kept only in `Detailed` mode
  for a configurable window (default 7 days). Relationship: goes through a bounded
  channel that drops when full and exposes a visible `dropped_detail` counter;
  history degrades to aggregates-only when these are absent.
- **Live ring**: the in-memory query ring, always present in both modes, serving
  the live view. Relationship: never touches disk, so it is available even under
  `Private`.
- **`HealthState`**: per-pool-member SRTT EWMA, consecutive failures, circuit
  state, last-probe-at. Relationship: a read model the UI displays; distinct from
  recursion diagnostics.
- **`RecursionDiagnostics`**: root/TLD reachability published by `styx-recursion`
  as its own read model, consumed directly by the admin/web layer and never
  through the pool. Deliberately named distinctly from `HealthState` so the two
  are never conflated.
- **Selection strategy**: one of ordered failover, round-robin, race, weighted —
  chosen per pool in the TOML file. Relationship: read-only in the UI, but `race`
  demands a loud warning.

### New Concepts Required (introduced by this phase)

- **Session**: a server-side-validated, signed, HttpOnly, `SameSite=Strict`
  cookie-borne token representing "the admin is logged in". Business purpose: it
  is the only thing standing between the LAN and full control of the household's
  DNS policy. Relationship: created by a successful password verification against
  the Argon2id hash; consumed by every server function.
- **Origin check**: a second, independent gate asserting the request's `Origin`
  (or `Referer` when `Origin` is absent) matches the server's own. Business
  purpose: Leptos server functions are POST endpoints; a `SameSite=Strict` cookie
  is necessary but is not on its own a complete CSRF defence across every browser
  and every navigation path, and every mutation is otherwise CSRF-able. This is
  **not optional** and is asserted in the phase's exit criteria as a separate
  condition from the session cookie.
- **Server-function guard**: the single composition point that both gates pass
  through before any mutation or any data read executes. Business purpose: make
  "authenticated and same-origin" structurally impossible to forget on a new
  server function.
- **Credential bootstrap**: the first-boot path that reads `STYX_ADMIN_PASSWORD`
  or generates a secret, prints it **once** to the log, hashes it with Argon2id,
  and stores it. Business purpose: there is no default password and no
  unauthenticated setup wizard reachable from the LAN. Until a credential exists
  the UI **refuses to serve**.
- **Page/view models**: read-shaped projections assembled in `styx-web` for the
  dashboard, clients and groups, adlists, live view, history and local records.
  Business purpose: keep the presentation layer from reaching into feature-crate
  internals; it consumes feature crates' `application` layers only.
- **Stale-adlist surface**: a per-adlist marker carrying the *failure reason*,
  hoisted onto the dashboard rather than living on an adlist settings page.
- **Shrink-acceptance override**: an explicit, manual admin action that tells
  ingestion "this list legitimately shrank; accept the new smaller copy".
- **Raw-row purge action**: an explicit destructive action that deletes persisted
  raw query rows.
- **`race` hazard warning**: a prominent, non-dismissable-by-default warning
  surfaced wherever the active selection strategy is displayed.

### Key Business Rules

- **No mutation without both gates.** Every server function requires a valid
  session cookie *and* a matching origin. Either alone is insufficient; the exit
  criterion names them separately and conjunctively.
- **No credential, no service.** A fresh install refuses to serve the UI until a
  credential exists. There is no default password. There is no unauthenticated
  setup wizard on the LAN.
- **The secret is printed exactly once.** A generated first-boot secret goes to
  the log on generation and is never retrievable afterwards; only the Argon2id
  hash is persisted.
- **Allow always wins, visibly.** The verdict is `!(allow & g) && (block & g)`.
  The UI must *show* that an allow rule overrides exact, wildcard and regex
  blocks in the same group, because the escape hatch is worthless if users do not
  trust it.
- **A stale adlist is a dashboard-level fact.** "Keep last known good" means a
  list whose URL rots keeps enforcing a frozen copy indefinitely. The only signal
  is a staleness badge, so the badge cannot be buried.
- **The shrink override is manual and per-list.** Automatic acceptance would
  defeat the collapse check that exists to catch captive portals and error pages
  served as HTTP 200.
- **Switching to `Private` is not retroactive.** Existing raw rows survive the
  mode change until an explicit purge action is taken. Without the purge action in
  the UI, the mode is a lie.
- **The UI may change only DB-backed things.** Clients, groups, adlists,
  allow/block rules, local records, privacy level, blocking mode — yes.
  Listen addresses, upstreams and pools, selection strategy, TLS material, trust
  anchor, DB path, log mode — no; those live in TOML and need a restart.
- **Dashboard numbers are exact; detail may be lossy.** Rollups are incremented
  synchronously via atomics and never dropped. Raw rows and the live ring go
  through a bounded channel that drops when full, and the drop count is exposed as
  `dropped_detail`. The UI must not present a dropped-detail deficit as if the
  aggregates were wrong.
- **History degrades, never errors.** When raw rows are absent — `Private` mode,
  post-purge, or past the retention window — history views fall back to
  aggregates-only.
- **The web UI must be removable.** It is a compile-time Cargo feature (`web`,
  default on), and the `--no-default-features` build must still pass with the
  crate absent.
- **Presentation may depend downward; peers may not depend sideways.** Feature
  crates never depend on each other; cross-feature needs are expressed as a port
  in the consumer's `domain` implemented by an adapter in the binary.
  `styx-web` is the single explicit exception: it may depend on a feature crate's
  `application` layer, because it is presentation, not a peer.
- **A DB outage degrades logging and admin, never resolution.** The hot path
  touches no I/O; nothing resolution needs lives in the DB. The UI failing is
  never allowed to be the reason DNS stops.
- **Client identity is best-effort.** Clients are identified by IP plus optional
  manual naming; styx never owns a lease table. Per-client groups keyed on IP will
  silently misattribute after a DHCP lease change. Manual naming and a visible
  "last seen" are mitigations, not fixes — and both are UI obligations.

---

## Strategic Approach

### Solution Direction

`styx-web` is a Leptos server-side-rendered crate behind the default-on `web`
Cargo feature, compiled into the single `styx` binary alongside the DNS
listeners and background workers, sharing state via `Arc`. It is the project's
**presentation layer**: it consumes the `application` layers of the feature
crates (filtering, storage, query log) and the read models those phases publish,
and it owns no domain logic of its own.

The general flow for a read is: browser request → Leptos SSR route → the
server-function guard (session + origin) → a feature crate's `application`-layer
query → a page/view model assembled in `styx-web` → rendered HTML. For a
mutation: browser POST to a Leptos server function → the same guard → a feature
crate's `application`-layer command → persisted in Turso → where relevant, an
explicit matcher reload with an atomic `ArcSwap` swap → a fresh render.

Three structural commitments shape everything else:

1. **Two independent gates, composed once.** Session validation and origin
   validation are separate checks combined in one guard that every server
   function passes through. The guard is the unit that gets tested; individual
   server functions are not trusted to remember.
2. **Refuse-to-serve is a startup-time state, not a redirect.** "No credential
   exists" does not mean "show a setup page"; it means the web layer does not
   bind or does not answer. The operator's recovery path is `STYX_ADMIN_PASSWORD`
   or reading the first-boot log line — both out-of-band relative to the LAN.
3. **Feature-gating is load-bearing and CI-enforced.** The `web` feature is
   default-on, and CI builds and tests `--no-default-features` on every commit —
   because otherwise the headless build rots within a month. The crate boundary,
   the `Cargo.toml` feature wiring and every `#[cfg(feature = "web")]` seam in the
   binary are therefore part of this phase's deliverable, not an afterthought.

### Key Design Decisions

- **Argon2id single password vs. a user table.**
  Trade-off: a single password gives a trivially auditable auth surface, no user
  lifecycle, no password-reset flows and no role model — at the cost of no audit
  trail whatsoever. → **Recommendation: single password**, as decided. The
  accepted consequence is explicit and must be carried into the UI's own
  documentation: *you can never tell who disabled blocking.* Multi-user admin,
  roles and audit trail are explicit v1 non-goals that follow directly from this
  choice. Designing for a future user table is out of scope; the seam, if one is
  ever wanted, is the credential-verification step.

- **Session cookie alone vs. cookie plus origin check.**
  Trade-off: `SameSite=Strict` blocks the common cross-site POST, and adding an
  origin check costs a header comparison plus a configuration question (what *is*
  our origin, on a LAN box reachable by IP, by hostname, and possibly by mDNS
  name?). → **Recommendation: both, unconditionally.** Leptos server functions
  are POST endpoints; every mutation in the application is one. A missing or
  mismatched origin must be a rejection, and the exit criteria test it as a
  condition distinct from the cookie. The configuration question is real and is
  recorded as an ambiguity below.

- **Refuse-to-serve vs. a first-boot setup wizard.**
  Trade-off: a setup wizard is the friendlier onboarding, and every consumer
  appliance ships one. → **Recommendation: refuse to serve.** An unauthenticated
  setup wizard on a LAN is an unauthenticated takeover of the household's DNS for
  anyone who reaches the box first — including anything already compromised on
  the network. The generated-secret-printed-once path gives the same onboarding
  without the window.

- **Where the stale-adlist marker lives.**
  Trade-off: an adlist settings page is the tidy information-architecture home for
  per-adlist state; the dashboard is already the densest screen. →
  **Recommendation: the dashboard, with the failure reason on the badge.** The
  reasoning is the accepted risk of last-known-good retention: a list whose URL
  rots keeps enforcing a frozen copy indefinitely, and the only signal is a
  staleness badge nobody is looking at. A badge on a page nobody opens is
  equivalent to no badge. The reason string must travel with the marker, because
  "stale" without "HTTP 200 with `text/html` body" or "domain count collapsed from
  180k to 12" does not tell the operator whether to fix the URL or accept the
  shrink.

- **Automatic vs. manual shrink acceptance.**
  Trade-off: automatic acceptance after N consecutive shrinks would reduce
  babysitting. → **Recommendation: manual, explicit, per-list.** The collapse
  check exists precisely because a captive portal or error page served as HTTP 200
  parses as thousands of junk domains. Any automatic path reopens the hole the
  check was built to close.

- **Making allow-beats-block visible.**
  Trade-off: showing precedence costs screen space and a second concept in the
  rule editor. → **Recommendation: show it, per group.** The allow mask exists
  because every blocklist over-blocks eventually and one bad list entry otherwise
  breaks a banking app with no escape hatch. An escape hatch users do not believe
  in does not get used, and the support outcome is the same as not having one.
  The rule editor should let an admin see, for a given domain and group, that an
  allow rule wins over an exact block, a wildcard block and a regex block alike.

- **Raw-row purge as an explicit action.**
  Trade-off: purging automatically on the switch to `Private` would be the
  least-surprising behaviour for a privacy setting. → **Recommendation: explicit
  action, prominently offered near the privacy setting.** The recorded decision is
  that switching to `Private` is not retroactive — existing raw rows survive until
  an explicit purge. The UI obligation is therefore to make the purge impossible
  to miss at the moment the mode is changed, or the mode is a lie. This is a
  presentation-layer responsibility for a storage-layer fact.

- **`race` warning placement and tone.**
  Trade-off: the strategy is set in TOML and is read-only in the UI, so a warning
  here cannot prevent anything. → **Recommendation: warn loudly anyway, wherever
  the active strategy is shown.** One query goes to N providers, so outbound QPS
  multiplies and every provider in the pool sees every domain; in a mixed pool
  containing the recursor, the privacy posture changes per query
  non-deterministically. This is a privacy hazard, not a load-balancing mode, and
  the recorded judgement is that it belongs in the UI, not in a config comment —
  precisely because a config comment is read once, at the moment of a choice made
  for latency reasons, and never again.

- **Read-only display of TOML-owned configuration.**
  Trade-off: showing infrastructure config the admin cannot edit invites the
  question "why can't I change this?"; hiding it makes the box opaque. →
  **Recommendation: display it, clearly marked as file-owned and
  restart-required.** The config boundary is hard: a TOML file owns everything
  needed before the DB exists or in order to reach it — listen addresses,
  upstreams and pools, selection strategy, TLS material, trust anchor, DB path,
  log mode — and Turso owns everything a human edits at runtime. No overlap means
  no precedence rule, and it structurally guarantees that a dead DB cannot touch
  resolution, because nothing resolution needs lives there. *Accepted consequence:
  changing an upstream requires SSH and a restart, which is the thing people most
  want to do from the UI.* The UI's job is to make that boundary legible rather
  than to pretend it is not there.

- **`styx-web` depending on feature crates' `application` layers.**
  Trade-off: this is a deliberate hole in an otherwise strict rule that feature
  crates never depend on each other, expressing cross-feature needs as a port in
  the consumer's `domain` implemented by an adapter in the binary. →
  **Recommendation: take the exception, and keep it narrow.** `styx-web` is
  presentation, not a peer; the port-and-adapter dance exists to keep *peer
  features* from coupling, and presentation depending downward on several
  features is the normal, intended shape. The narrowness matters: `styx-web` may
  reach `application`, never another crate's `domain` internals or
  `infrastructure`, and the `[[restrict-use]]` and `cargo tree` gates from Phase 0
  must encode that as an allowance, not as a blanket exemption.

### Alternatives Considered

- **A separate `styx-admin` HTTP API consumed by a client-rendered SPA.**
  Rejected: it doubles the auth surface (API tokens plus session), makes the CSRF
  story harder rather than easier, and adds a build toolchain the project does not
  otherwise need. Leptos SSR keeps mutations as server functions behind one guard.
- **Running the web UI in a separate process or on a separate binary.**
  Rejected: the recorded shape is single process, single binary, with DNS
  listeners, Leptos SSR and background workers sharing state via `Arc`. A separate
  process would need IPC to the matcher and the in-memory ring, which is the
  hot-path state the whole design keeps in memory precisely to avoid I/O.
  (Note the cost this imposes: see the panic risk below.)
- **Making the web UI a non-optional part of the binary.** Rejected: a headless
  resolver build is an explicit goal, which is why `web` is a Cargo feature at
  all, and why CI builds `--no-default-features` on every commit.
- **Mirroring infrastructure config into the DB so the UI could edit it.**
  Rejected: two stores for the same setting means a precedence rule, and a
  precedence rule is the thing the hard boundary was drawn to avoid. It would also
  break the structural guarantee that a dead DB cannot affect resolution.
- **Deferring the origin check to Phase 12 alongside the panic boundary.**
  Rejected: the phase's own exit criteria require it, and unlike the panic
  boundary it is not a cross-cutting runtime concern — it is a line in the guard.
- **Auto-purging raw rows on the switch to `Private`.** Rejected above; the
  recorded decision is explicitly non-retroactive.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **What counts as "our origin" on a LAN box.** The box is plausibly reachable by
  IPv4 literal, IPv6 literal, a `.local` mDNS name, a router-assigned hostname and
  a manually configured DNS name — possibly on both HTTP and HTTPS and on a
  non-default port. The origin check must accept the legitimate set without
  becoming a wildcard that accepts everything. Whether this is derived from the
  listen address, configured explicitly in TOML, or both, is unspecified and must
  be decided before the guard is written.
- **Session lifetime, renewal and revocation.** Nothing specifies how long a
  session lasts, whether it slides on activity, whether sessions are stored
  server-side (and therefore revocable) or are purely signed stateless tokens, or
  what happens to live sessions when the password is changed. With no audit trail
  and a single shared credential, "log everyone out" is the only revocation
  primitive there is, and it is unspecified.
- **Whether the password can be changed from the UI at all.** The credential is
  seeded from `STYX_ADMIN_PASSWORD` or a first-boot secret; the spec does not say
  whether a rotate-password server function exists, nor how it interacts with the
  environment variable on the next restart (does the env var win, and therefore
  silently undo a UI rotation?).
- **Rate limiting and lockout on the login endpoint.** A single password on a LAN
  with no audit trail and no second factor is exactly the target for offline-free
  online guessing. Argon2id makes each attempt costly, which is a partial
  mitigation, but nothing specifies a lockout, a backoff, or whether failed
  attempts are logged (they cannot be attributed, but they can be counted).
- **Whether "refuses to serve" means "does not bind" or "answers with an error".**
  Materially different: not binding makes the failure obvious to anyone probing
  the port; answering with a 503 makes the failure obvious to the operator's
  browser. The exit criterion tests the behaviour without naming it.
- **How the live view is delivered.** Leptos SSR supports server-sent events,
  WebSockets and polling. Nothing specifies which, and the choice interacts with
  both the origin check (WebSocket upgrades carry `Origin` but are not subject to
  `SameSite` in the same way) and the panic risk (a long-lived streaming handler
  is a long-lived opportunity to panic).
- **What triggers a matcher reload from the UI.** Editing an allow rule changes a
  bitmask in the DB; the in-memory matcher is immutable and replaced wholesale via
  `ArcSwap` on an explicit reload. Whether the UI reloads implicitly on every rule
  edit, batches, or exposes an explicit "apply" button is unspecified — and it is
  user-visible, because until the swap happens the rule the admin just saved is
  not in force.
- **Whether the shrink override is a one-shot acceptance or a persistent setting.**
  "Accept the shrink" for this ingest, or "stop checking collapse for this list"?
  The former is safer; the latter is what a user with a genuinely shrinking list
  will ask for on the third prompt.
- **Client lifecycle as it surfaces in the UI.** Phase 9 settles the schema
  question (auto-discovery vs. manual, default group, cascade on delete), but the
  UI consequences — can an admin delete a client, what warning precedes losing its
  history, what does an auto-discovered client look like before it is named —
  follow from an answer made two phases earlier without the UI to think against.
  This is a recorded ordering cost, not a defect.

### Edge Cases

- **`STYX_ADMIN_PASSWORD` set *and* a credential already in the DB.** Does the env
  var re-seed, overwrite, or is it ignored? A silent overwrite on every restart
  makes UI-side rotation meaningless; a silent ignore makes the env var useless as
  a recovery path.
- **Empty or trivially weak `STYX_ADMIN_PASSWORD`.** An empty string is
  technically "a credential exists" and would satisfy refuse-to-serve while
  providing no protection.
- **Browser sends no `Origin` header.** Same-origin `GET` navigations and some
  older clients omit it. The guard must decide between falling back to `Referer`
  and rejecting outright, and the fallback must not become the bypass.
- **History view under `Private`, immediately after a purge, and past the
  retention window.** Three distinct routes to "raw rows absent", all of which
  must degrade to aggregates-only rather than error.
- **`dropped_detail` non-zero while rollups are exact.** The live view and history
  are visibly missing queries that the dashboard counts. Without an explicit
  presentation of `dropped_detail`, this reads as a bug in the dashboard.
- **An adlist that is stale *and* disabled**, or stale and assigned to no group.
  The badge is still true but the enforcement consequence is different.
- **Every adlist stale at once** (the box lost WAN access). The dashboard surface
  must not become a wall of identical badges that buries the one list that failed
  for a different reason.
- **A group deleted while clients are assigned to it**, and the interaction with
  the matcher's bit positions — a freed bit reused by a new group would silently
  inherit the old group's policy on any terminal not rebuilt.
- **An allow rule and a block rule for the same exact domain in the same group.**
  Allow wins; the UI must show that it wins rather than presenting two rules of
  equal standing.
- **A regex rule that does not compile.** All regex rules compile into one
  `RegexSet`; a single bad pattern must be rejected at the point of entry in the
  UI, not at the next matcher rebuild where it would fail the whole reload.
- **A local record under a signed public zone.** Local records are answered before
  the cache and are always Insecure — AD cleared, no forged signature — so a name
  like `nas.example.com` where `example.com` is signed is unprovable and
  validating clients may SERVFAIL it. The documented guidance is to keep local
  names under an unsigned or internal suffix. The local-records editor is the one
  place this guidance can actually reach the person about to make the mistake.
- **Session cookie present but the credential row is gone** (DB restored from an
  older backup, or the file was deleted). The system is simultaneously "has a
  logged-in admin" and "has no credential, must refuse to serve".
- **The DB is unreachable while the UI is being used.** Admin and logging degrade;
  resolution must be provably unaffected. The UI must fail in a way that says so
  rather than implying DNS is down.

### Technical Risks

- **A panic in a Leptos request handler takes DNS down for the whole house.**
  This is the single largest risk this phase introduces. Single process means the
  web layer and the DNS listeners share a fate. `panic = "deny"` as a lint policy
  helps and is load-bearing, but the *real* mitigation — a `catch_unwind` boundary
  around the web layer and a supervised task model — is **Phase 12**, not this
  phase. Phase 11 therefore ships with this hole open, deliberately, and
  everything before Phase 12 relies on the lint. Mitigation direction within this
  phase: no `unwrap`/`expect` anywhere in `styx-web` (the Phase 0 arch-lint
  `no-unwrap-expect` rule with `allow_in_tests = true` enforces it), fallible
  rendering paths returning `Result<T, E>` with `thiserror` enums rather than
  panicking, and no indexing or arithmetic that the denied
  `indexing_slicing` / `arithmetic_side_effects` lints would reject.
- **The headless build rots silently.** A `web`-gated crate that nobody builds
  without the feature accumulates unconditional imports and unconditional wiring
  in the binary within weeks. Mitigation: CI builds *and tests*
  `--no-default-features` on every commit — which is exactly why that gate was
  specified at Phase 0 rather than added here, and why it appears in this phase's
  exit criteria.
- **The presentation-layer exception widening into a general exemption.**
  `styx-web` may depend on feature crates' `application` layers. If the Phase 0
  `[[restrict-use]]` and `cargo tree` gates are written as a blanket exemption for
  `styx-web`, the crate can reach into another crate's `domain` or
  `infrastructure` unnoticed. Mitigation: encode the allowance at
  `application`-module granularity, and verify it with a deliberate violation —
  an inert config looks identical to a passing one, which is the failure mode that
  already bit the committed `arch-lint.toml`.
- **The origin check is easy to write in a way that always passes.** A guard that
  compares against a value derived from the request itself (e.g. the `Host`
  header) is a no-op. Mitigation: the exit criterion must be tested with a request
  carrying a *valid session cookie* and a *foreign origin*, and assert rejection —
  not merely tested with no cookie at all.
- **Client identity is unreliable by construction.** DHCP is a v1 non-goal;
  clients are identified by IP plus optional manual naming, so styx never owns the
  lease table and per-client groups keyed on IP silently misattribute after a
  lease change. Manual naming and a visible "last seen" are mitigations, not
  fixes, and both land in this phase's UI.
- **Two write paths for the query log must stay consistent.** Atomic rollup
  counters and raw rows can disagree if a bug lands in either; the specified
  behaviour is that they diverge by exactly `dropped_detail` and by nothing else.
  The UI is where a divergence becomes visible to a human, so it must present both
  numbers rather than silently reconciling them.
- **Argon2id parameter choice on a Raspberry Pi.** The memory and time cost that
  makes online guessing expensive is the same cost paid on every login on
  constrained hardware, and a too-aggressive memory parameter on a Pi is a
  self-inflicted denial of service against the box that is also serving DNS.
- **Secret printed once is genuinely once.** If the operator misses the log line
  (log rotation, a container that discarded stdout, a first boot under a service
  manager), the only recovery is `STYX_ADMIN_PASSWORD` or deleting the credential
  row. That recovery path must exist and be documented, or a missed log line
  bricks the admin surface.
- **No operational feedback until the very end.** The cutover is last: styx runs
  on a dev box until everything works, and the household's resolver stays on
  Pi-hole until v1 is complete. Nothing mid-build has to be shippable, breaking
  changes stay free, and phases are ordered by dependency and risk rather than
  usability. *Accepted consequence: no operational feedback — cache behaviour, odd
  client queries, DHCP churn — until the end, when it is most expensive to act
  on.* Phase 11 is the first phase that produces something a human can look at,
  which means it is also the first phase where UI assumptions made across phases
  8–10 get tested — and any that are wrong are wrong in schema that was designed
  once, deliberately, two phases earlier.

### Acceptance Criteria Coverage

The phase states three exit criteria. Each is decomposed against the approach
above.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | Every mutation is rejected without a valid session cookie | Yes | Requires the single composed guard; the test must enumerate every server function, or a new one added later escapes the assertion. Consider a test that fails when a server function is registered without the guard. |
| 2 | Every mutation is rejected without a matching origin | Yes | Must be tested *with* a valid session cookie and a foreign origin, or it proves nothing beyond AC1. Blocked on resolving what the legitimate origin set is (see ambiguities). |
| 3 | A fresh install refuses to serve until a credential exists | Yes | Behaviour is unambiguous; the *mechanism* (does not bind vs. answers 503) is unspecified and must be pinned before the test is written. Also needs the empty-`STYX_ADMIN_PASSWORD` case decided. |
| 4 | The headless `--no-default-features` build still passes with this crate absent | Yes | Inherited gate from Phase 0; this phase's obligation is that every `#[cfg(feature = "web")]` seam in the `styx` binary is correct and that no unconditional dependency on `styx-web` leaks in. Should also *test*, not only build, without default features. |

**Scope items without an explicit exit criterion.** The following are named as
required, not optional, in the phase scope but are not covered by the three
stated exit criteria. They need acceptance of their own or they will be built
loosely:

| Scope item | Addressable? | Gaps/Notes |
|-----|-------------|--------------|
| Per-adlist stale marker showing the failure reason, on the dashboard | Yes | Needs an assertion that the reason string reaches the dashboard, not merely that a boolean stale flag exists. Fixture: an adlist serving HTTP 200 with an HTML body (the Phase 8 fixture) should surface a reason distinguishable from a collapse. |
| Manual "accept the shrink" override | Partial | Blocked on whether it is one-shot or persistent (see ambiguities). Testable either way once decided. |
| Allow/block rule editing per group making "allow always wins" visible | Partial | "Visible" is not directly assertable. Suggest an assertion on the view model: for a domain with both an allow and a block in the same group, the model reports allow as the effective verdict *and* carries the overridden block rules. |
| Explicit purge action for raw query rows | Yes | Assert the purge is offered at the point the privacy mode is switched to `Private`, and that history degrades to aggregates-only afterwards rather than erroring. |
| Loud warning on `race` selection | Yes | Assert the warning is present in the rendered view whenever the active strategy is `race`, and absent otherwise. |
| Dashboard, clients and groups, adlists, live view, history, local records | Partial | Six surfaces with no per-surface criterion. At minimum, each should have a test that it renders under both `Detailed` and `Private`, and with the DB unreachable. |

---

## Non-goals that bear on this phase

Reproduced with the reasoning that produced them, because they are the boundary
this phase must not quietly cross.

- **Multi-user admin, roles, audit trail.** Follows directly from the single
  Argon2id password decision. There is no principal to attribute an action to, so
  there is nothing to audit. Do not build a half-audit log that records actions
  without actors; it would imply an accountability the system does not have.
- **DHCP server.** Clients are identified by IP plus optional manual naming; styx
  never owns the lease table, so client identity is best-effort and breaks on DHCP
  churn. The UI must present client identity as best-effort (manual naming, a
  visible "last seen") rather than as authoritative.
- **Authoritative zone serving.** Local records and per-zone overrides are
  resolution/filtering concerns, not a zone-file server. The local-records editor
  edits resolution behaviour; it is not a zone editor and should not grow toward
  one.
- **Multi-node or replicated deployment.** One box, one binary, local DB file. The
  UI has no cluster view, no node picker and no notion of a remote instance.
- **EDNS Client Subnet.** Deliberately omitted; it leaks client topology. There is
  no UI toggle for it, and the same privacy reasoning is what makes the `race`
  warning necessary.
- **DoQ (DNS-over-QUIC), inbound or outbound.** Not a listener the UI reports on.
- **RFC 5011 automated trust anchor rollover.** The trust anchor is pinned and
  overridable by a file path in config, behind a `TrustAnchorSource` port; RFC
  5011 needs state that survives restarts, which would drag storage into the
  validator phase for a rollover pre-announced months ahead. *Accepted
  consequence: a KSK roll needs a release or a file edit, and missing one
  SERVFAILs every lookup — this is a monitoring obligation, not code.* The UI
  should make the active trust anchor visible for exactly that reason, but it is
  read-only, file-owned config.

---

## Summary

- **Project type**: Rust, fullstack single binary — Leptos server-side rendering
  compiled into the same process as the DNS listeners.
- **Codebase state**: greenfield, no existing implementation.
- **Existing concepts identified**: 14 (from phases 3, 5, 6, 8, 9, 10).
- **New concepts required**: 9.
- **Key design decisions**: 10.
- **Acceptance Criteria coverage**: 4/4 stated criteria addressable; 6 additional
  required-not-optional scope items lack stated criteria, 3 of them fully
  addressable and 3 blocked on an ambiguity.
- **Open questions / risks**: 9 ambiguities, 13 edge cases, 9 technical risks.
- **Largest open risk**: a panic in a Leptos handler takes DNS down for the whole
  house, and the real mitigation — a `catch_unwind` boundary around the web layer
  plus a supervised task model — does not arrive until Phase 12.
