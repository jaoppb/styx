# styx — ROADMAP

A filtering DNS resolver written from scratch in Rust. Replaces Pi-hole's role on a
home network: recursive/forwarding resolution, per-client blocking policy, and a
Leptos admin UI.

This is a build-it-properly project, not a ship-it-this-quarter project. v1 contains
two hand-written security-critical subsystems — a recursive resolver and a DNSSEC
validator — so the repo optimises for a long correctness grind: spec-first,
socket-level behaviour tests, aggressive lints, CI from the first commit.

This file says in what order v1 gets written. **What** each phase is, and **why**
every decision in it was taken, lives in that phase's REASONS Canvas under
[`spdd/prompt/`](spdd/prompt/). Each canvas is self-contained: decisions, rationale,
accepted consequences, non-goals and risks are reproduced in full, so no canvas
defers to another file. The strategic analysis each canvas was derived from is kept
alongside it in [`spdd/analysis/`](spdd/analysis/).

---

## What sets the shape

Two decisions govern the ordering.

**The cutover is last.** styx runs on a dev box until everything works; the
household's resolver stays on Pi-hole until v1 is complete. Nothing mid-build has to
be shippable, breaking changes stay free, and phases are ordered by dependency and
risk rather than by usability. Accepted consequence: no operational feedback — cache
behaviour, odd client queries, DHCP churn — until the end, when it is most expensive
to act on.

**Resolution comes before product.** Depth-first on the two security-critical
subsystems while they have full attention, then the matcher, storage and UI on top.
That order is only safe because the hot path touches no I/O: matcher state is in
memory, built at boot and on reload, and the resolver never needs the database to
exist.

Taking the phases out of order is how this stalls.

---

## Phases

| # | Phase | Delivers | Canvas |
|---|-------|----------|--------|
| 0 | Foundation and gates | Workspace, working arch-lint, CI, the `just gate` target | [canvas](spdd/prompt/202609212135-%5BFeat%5D-repo-phase-00-foundation-gates.md) |
| 1 | Wire codec | `styx-proto` — encode/decode, fuzzed | [canvas](spdd/prompt/202609212136-%5BFeat%5D-proto-phase-01-wire-codec.md) |
| 2 | Server loop and test harness | UDP/TCP listeners, fake root/TLD/auth servers, injectable `Clock`, hot-path ports | [canvas](spdd/prompt/202609212137-%5BFeat%5D-server-phase-02-server-loop-harness.md) |
| 3 | `Upstream` port, forwarding, pool | Do53 forwarder, `HealthState`, all four selection strategies | [canvas](spdd/prompt/202609212138-%5BFeat%5D-resolution-phase-03-upstream-pool.md) |
| 4 | Answer cache | Global RRset/message cache, negative caching, bailiwick rules | [canvas](spdd/prompt/202609212139-%5BFeat%5D-cache-phase-04-answer-cache.md) |
| 5 | Recursion | `styx-recursion` — descent with relaxed QNAME minimisation | [canvas](spdd/prompt/202609212140-%5BFeat%5D-recursion-phase-05-recursion.md) |
| 6 | DNSSEC | `styx-dnssec` — positive chains, NSEC/NSEC3 denial, hard-fail | [canvas](spdd/prompt/202609212141-%5BFeat%5D-dnssec-phase-06-dnssec-validation.md) |
| 7 | Encrypted inbound | DoT and DoH listeners, operator-supplied certs | [canvas](spdd/prompt/202609221343-%5BFeat%5D-listeners-phase-07-encrypted-inbound.md) |
| 8 | Filtering | Matcher, allow/block precedence, blocked replies, adlist ingestion | [canvas](spdd/prompt/202609221344-%5BFeat%5D-filtering-phase-08-filtering-matcher.md) |
| 9 | Storage | Turso schema — policy only, designed once | [canvas](spdd/prompt/202609221345-%5BFeat%5D-db-phase-09-storage-schema.md) |
| 10 | Query log pipeline | Exact rollups, bounded detail channel, privacy modes | [canvas](spdd/prompt/202609221346-%5BFeat%5D-telemetry-phase-10-query-log-pipeline.md) |
| 11 | Web UI | `styx-web` — auth, dashboard, groups, adlists | [canvas](spdd/prompt/202609221347-%5BFeat%5D-web-phase-11-web-ui-admin.md) |
| 12 | Cutover hardening | Panic boundary, musl artifacts, then the household | [canvas](spdd/prompt/202609221348-%5BFeat%5D-release-phase-12-cutover-hardening.md) |

---

## Acceptance

Two tiers.

**Per push** — hermetic, fast, no network: `just gate`. Formatting, clippy's 21
denied lints, `arch-lint check`, the `cargo tree` layering gate, the
`hickory-dev-only` check, socket-level tests, and the `--no-default-features`
headless build.

**Per phase** — the exit criteria in that phase's canvas, under `## Safeguards`. For
recursion and DNSSEC that means the differential run: resolve a corpus of real
domains through both styx and a local `unbound`, diff RCODE, AD bit and rrset
contents. In-process fakes only prove the resolver does what we *think* delegation
means; the differential run is the only gate that catches a shared misreading. It
needs the live internet and is flaky by nature, so it gates a phase, never a push.

**Continuously from phase 1** — `cargo fuzz` on the codec, later on the validator.

---

## Risks specific to this ordering

- **`arch-lint.toml` is inert until phase 0 replaces it.** arch-lint has two mutually
  exclusive engines, selected by whether the config contains `[[layers]]`. With it,
  the tree-sitter engine runs — and that engine ships exactly one grammar,
  `tree-sitter-kotlin-ng`, filtering discovery to `.kt`/`.kts`. On a Rust repo it
  analyses **zero files and exits 0**, silently disabling AL001–AL013 as well. The
  committed file contains `[[layers]]`. Without it, the **syn** engine runs
  AL001–AL013 *plus* `[[scopes]]`, `[[deny-scope-dep]]` and `[[restrict-use]]`, which
  enforce layering on Rust by path glob. The fix is replacing the file in phase 0 and
  pairing it with an independent `cargo tree` gate, since arch-lint reads source text
  while `cargo tree` reads the link graph. Verify with a deliberate violation — an
  inert config looks identical to a passing one.
- **Resolution-first means no visible product for a long time.** Phases 1 through 7
  produce nothing a human can look at except `dig` output, and because the cutover is
  last, no one is waiting on it either. v1 scope is already large — two from-scratch
  security-critical subsystems, plus groups, adlists, encrypted inbound and a UI —
  and this ordering concentrates that risk into one long stretch with neither visible
  progress nor external pressure.
- **The differential gate depends on the live internet.** Real DNS changes underneath
  the corpus, so the job will sometimes fail for reasons that are not a bug here.
  That is why it gates a phase and not a push — but it also means a genuine
  regression can hide behind a shrug.
- **`panic = "deny"` is load-bearing and its real mitigation arrives last.** In a
  single process a panic in a Leptos request handler takes DNS down for the whole
  house. The `catch_unwind` boundary and supervised task model are phase 12;
  everything before it relies on the lint alone.
- **Phase 9 carries schema decisions phase 11 would rather make.** Client lifecycle
  and default-group semantics are UI-shaped questions with schema consequences.
  Answering them two phases early, without the UI to think against, is the accepted
  cost of designing the schema once — privacy levels and rollups have to be in it
  from the start or shipping them becomes a migration.
- **Phase 8 is the largest phase in the product half.** It holds the matcher,
  allowlist precedence, five blocked-reply modes and the adlist ingestion contract,
  and is the one most likely to want splitting once started. Its canvas groups
  Operations into separable work streams for that reason.
