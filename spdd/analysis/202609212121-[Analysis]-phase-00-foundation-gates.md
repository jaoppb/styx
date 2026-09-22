# SPDD Analysis: styx Phase 0 — Foundation and Gates

> **Project**: `styx` — a filtering DNS resolver written from scratch in Rust, replacing
> Pi-hole's role on a home network (recursive/forwarding resolution, per-client blocking
> policy, Leptos admin UI).
>
> **Repository state at time of analysis**: greenfield, no existing implementation. There
> is no git repository, no Cargo workspace, no Rust source file. The only files present
> are `arch-lint.toml` (an upstream Kotlin template — the thing this phase replaces),
> `SPEC.md`, `ROADMAP.md` and `docs/specs/*.md`. All codebase-grounded analysis below is
> therefore grounded in the project's settled design decisions rather than in existing
> code, and those decisions are quoted in full so this document stands alone.
>
> **Revised 2026-09-22** with a documentation-linting amendment, raised after the phase 0
> implementation had landed. The repository is no longer greenfield: the workspace, the
> gate, the self-test fixtures and the three ADRs all exist, and the amendment's analysis
> is grounded in the real repository — the linter was run against it before any of this
> was written. Everything above this line describes the state the original analysis was
> written in, and is left unchanged. Amendment content is marked where it appears.

---

## Original Business Requirement

The following is the Phase 0 specification, verbatim.

```markdown
# Phase 0 — Foundation and gates

> Part of [ROADMAP.md](../../ROADMAP.md) · Next: [Phase 1 — Wire codec](01-wire-codec.md)

Nothing DNS-related. The repo has no git and no workspace yet.

## Scope

- `git init`; Cargo workspace skeleton in the shape decision 30 requires.
- **Replace `arch-lint.toml`.** The committed file is the upstream Kotlin template
  and enforces nothing — see the risk in ROADMAP.md. The replacement is a
  syn-engine config modelled on `alloy/arch-lint.toml`: `[[scopes]]` per feature
  crate × domain/application/infrastructure, `[[deny-scope-dep]]` for the layering
  rules, `[[restrict-use]]` to keep feature crates from naming each other
  (decision 31). Enable `no-unwrap-expect` (`allow_in_tests = true`),
  `require-tracing`, `tracing-env-init`, `no-sync-io`, `require-thiserror`. Bump
  0.5.0 → 0.6.0.
- **A second, independent layering gate** built on `cargo tree --edges normal`.
  arch-lint reads source text, `cargo tree` reads the real link graph; they catch
  different mistakes.
- **`hickory-dev-only` check**: assert `hickory-proto` appears in no normal or
  build dependency path, or decision 38's asterisk rots.
- `clippy.toml` — 15 denied lints, 4 `allow-*-in-tests`. `lefthook.yml` on
  pre-commit and pre-push. GitHub Actions running the full gate plus the
  `--no-default-features` build (decision 29).
- `justfile` with a `gate` target aggregating all of it.
- ADRs: layering and the arch-lint mechanism; the `hickory-proto` exception to
  decision 2; the pinned trust anchor.

## Exit criteria

An empty workspace where `just gate` is green, **and** a deliberate `.unwrap()` in
a `domain` module plus a deliberate cross-layer `use` both fail the gate. Without
that check the config may be silently inert again.
```

### Amendment — 2026-09-22: documentation linting

The specification above is reproduced verbatim and is silent on documentation. This
amendment adds a **markdown linter to the gate**, raised after the phase 0 implementation
landed. It is recorded here rather than rewritten into the quoted spec, so the original
scope stays legible.

**Requirement**: markdown files are linted by the same gate, under the same three callers,
with the tool version pinned the same way.

**Why it belongs in phase 0 rather than later**: this repository's prose *is* one of its
primary artefacts. The SPDD contracts under `spdd/` are the specification the code is
generated from, and the ADRs are the only record of reasoning that outlives the decisions.
There are already **36 markdown files against 11 Rust files** — documentation outweighs
code better than three to one, and will keep doing so until phase 2 or 3. A gate that
governs the minority of the repository and ignores the majority is mis-aimed.

The same argument the phase already makes about the headless build applies verbatim: the
cost of wiring it is lowest now and rises with every phase, and an unexercised
configuration rots within about a month.

### Referenced decisions, inlined

The requirement above names decisions by number. Those numbers refer to a decision record
that is being retired, so each one is reproduced here in full, with its rationale.

**Decision 30 — one crate per feature; `domain`/`application`/`infrastructure` are modules
inside it.** Cargo enforces feature-to-feature isolation; arch-lint enforces layering
within a crate. (This is the shape the workspace skeleton must have.)

**Decision 31 — feature crates never depend on each other.** Cross-feature needs are
expressed as a port in the consumer's `domain`, implemented by an adapter in the binary —
e.g. `styx-resolution` declares a `FilterPolicy` port and the `styx` binary wires
`styx-filtering` into it. `styx-web` may depend on a feature's `application` layer,
because it is presentation, not a peer.

**Decision 40 — `styx-proto` is shared foundation, not a feature crate.** Every crate
parses through the wire codec, so decision 31's "feature crates never depend on each
other" does not reach it. This is the one explicit exception, and `[[restrict-use]]` must
be written so as not to forbid it.

**Decision 29 — single process, single binary.** DNS listeners, Leptos SSR and background
workers share state via `Arc`. The web UI is a compile-time Cargo feature (`web`, default
on) so a headless resolver can be built. CI builds and tests `--no-default-features` on
every commit, **or the headless build rots within a month**.

**Decision 34 — lint policy as specified.** 15 denied clippy lints workspace-wide, 4
`allow-*-in-tests` entries in `clippy.toml`. All 15 names verified against rustc 1.96.0.

**Decision 35 — arch-lint is enforced by lefthook (pre-commit/pre-push) *and* GitHub
Actions.** A lint that only runs locally is not enforcement.

**Decision 36 — CI on GitHub Actions.** Quality gates on every push/PR; release artifacts
for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` published on `v*` tags.

**Decision 2 — the entire DNS stack is written from scratch** — wire codec, server loop,
caches, recursion algorithm, DNSSEC validation. No `hickory-dns`, no `domain` crate for
the protocol.

**Decision 38 — `hickory-proto` is the test oracle, `[dev-dependencies]` only.** The fake
root/TLD/authoritative servers and the expected-byte fixtures have to encode DNS wire
format; if our own codec encodes them, the resolver and its oracle share every bug and a
green suite proves only self-consistency. Decision 2's from-scratch ban is on shipping
code, not the test rig. A CI check asserts `hickory-proto` appears in no normal or build
dependency path, **or the exception rots into a real dependency**.

**Decision 39 — acceptance runs in two tiers.** Per push, hermetic and fast: socket tests,
fuzzing, and the full lint/arch gate. Per phase, non-hermetic: a corpus of real domains
resolved through both styx and a local `unbound`, diffing RCODE, AD bit and rrset
contents. In-process fakes only prove the resolver does what we *think* delegation means;
the differential run is the only gate that catches a shared misreading. It depends on the
live internet and is flaky by nature, so it gates a phase and never a push.

**Decision 12 — the root trust anchor is pinned, overridable by a file path in config.** A
compiled-in IANA anchor with a `trust-anchor` config override, behind a
`TrustAnchorSource` port. RFC 5011 automated rollover needs state that survives restarts,
which would drag the storage layer into the validator phase for a rollover that is
pre-announced months ahead. Accepted consequence: a KSK roll needs a release or a file
edit, and missing one SERVFAILs every lookup — this is a monitoring obligation, not code.
(Phase 0 owns the ADR that records this; the code lands in phase 6.)

**Decision 41 — the cutover is last.** styx runs on a dev box until everything works; the
household's resolver stays on Pi-hole until v1 is complete. Nothing mid-build has to be
shippable, breaking changes stay free, and phases are ordered by dependency and risk
rather than usability. Accepted consequence: no operational feedback until the end.

**Decision 22 — the hot path touches no I/O.** Matcher state is in memory, built at boot
and on reload. The database holds config, adlist definitions, clients/groups and history
only. A DB outage degrades logging and admin, never resolution. (Relevant to phase 0
because it is what makes the `no-sync-io` arch-lint rule a real architectural invariant
rather than a style preference.)

**Decision 37 — TDD cycles run at socket level by default**, with an injectable `Clock`.
(Phase 0 does not implement it, but the `gate` target must be the thing that runs those
tests from phase 2 onward.)

### Position in the phase sequence

Phase 0 is the first phase and has **no upstream dependency** — it is the phase that
creates the repository. The full ordering, for context on who depends on this work:

| # | Phase | Delivers |
|---|-------|----------|
| 0 | **Foundation and gates** (this phase) | Workspace, working arch-lint, CI, the `just gate` target |
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
| 12 | Cutover hardening | Panic boundary, musl artifacts, then the household |

**Every phase 1–12 depends on phase 0**, because every one of them is gated by
`just gate`. The two with the tightest coupling are **Phase 1 — Wire codec**, which is the
first consumer of the workspace skeleton and the first crate to be written entirely under
`indexing_slicing = deny` and `arithmetic_side_effects = deny`, and
**Phase 12 — Cutover hardening**, which reuses this phase's GitHub Actions release path to
publish the `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` artifacts on `v*`
tags.

---

## Domain Concept Identification

The "domain" of this phase is the repository itself: its build topology and its
enforcement machinery. There is no business entity here, and no DNS concept appears at all
— the phase spec opens with "Nothing DNS-related."

### Existing Concepts (from codebase)

- **`arch-lint.toml` (committed, inert)**: the only artefact of this phase that already
  exists on disk. It is the upstream Kotlin template — it declares `[[layers]]` named
  `domain`/`application`/`infrastructure`/`presentation` whose `packages` are
  `com.example.*` Java package prefixes, plus a `[dependencies]` table and commented-out
  `[[constraints]]`. It relates to every other concept in this phase as the thing being
  destroyed and rebuilt. It is not a starting point; nothing in it is reusable, because
  the file's very structure selects the wrong engine (see the mechanism under Technical
  Risks).

- **The decision record and phase specs** (`SPEC.md`, `ROADMAP.md`, `docs/specs/*.md`):
  the authority for what the workspace shape and lint policy must be. These are being
  retired once this analysis and its canvas are written, which is why every decision they
  carry is reproduced inline above.

There is no Cargo manifest, no `src/`, no CI workflow, no git history. Every concept below
is new.

### New Concepts Required

- **Workspace root**: the Cargo virtual workspace that owns the shared lint configuration,
  the shared dependency versions and the member list. Its existence is what makes
  "workspace-wide" a meaningful scope for the 15 denied clippy lints, and what makes a
  single `just gate` invocation able to speak for every crate.

- **Feature crate**: a crate that owns one product capability end to end, with `domain`,
  `application` and `infrastructure` as *modules inside it* rather than as separate
  crates. Cargo enforces isolation *between* features; arch-lint enforces layering
  *within* one. The eventual roster is known from the roadmap — resolution, recursion,
  DNSSEC, filtering, storage, query log, web, admin — but phase 0 creates only the
  skeleton, not the contents.

- **Shared foundation crate (`styx-proto`)**: the single, explicit exception to
  feature-crate isolation. Every crate parses through the wire codec, so `styx-proto` is
  depended upon by everyone and depends on no one. It is a distinct concept from "feature
  crate" precisely because the `[[restrict-use]]` rules must be written so as not to
  forbid it.

- **Composition root (the `styx` binary)**: the only place where feature crates meet. A
  cross-feature need is a port declared in the consumer's `domain` and an adapter wired in
  the binary; the binary is therefore the one crate allowed to name every feature crate at
  once. Without this concept, decision 31's isolation rule would make the system
  unassemblable.

- **Layer**: `domain`, `application`, `infrastructure` — here a
  *module path within a crate*, not a crate and not a package prefix. `domain` names no
  outward dependency; `application` may name `domain`; `infrastructure` may name `domain`
  and `application`. `styx-web` sits outside this triple as presentation and may reach a
  feature's `application` layer.

- **Scope (arch-lint)**: a named region of the repository defined by path glob, which is
  how the syn engine learns what a layer is on a Rust codebase. One scope per feature
  crate × layer. Scopes are the unit that dependency rules are written against.

- **Gate**: the aggregate, hermetic, per-push verification. Not a single tool — a named
  composition of formatting, clippy's denied lints, arch-lint, the link-graph layering
  check, the `hickory-proto` containment check, socket-level tests and the headless build.
  Its defining property is that it is one command, invoked identically by a developer, by
  the pre-commit/pre-push hooks and by CI, so that the three can never disagree.

- **Independent layering check (link-graph)**: a second gate over the same invariant,
  built on the resolved dependency graph rather than on source text. It is a separate
  concept from arch-lint deliberately: arch-lint reads what the source *says*, the link
  graph reads what the build *does*, and they fail on different mistakes.

- **Dev-only dependency containment (`hickory-dev-only`)**: the check that keeps the test
  oracle out of the shipping binary. Conceptually it is the executable form of decision
  2's from-scratch rule: from-scratch is a property of shipping code, and this check is
  what makes that property observable rather than aspirational.

- **Gate self-test (the deliberate violation)**: the exit criterion elevated to a
  first-class concept, because it is the only thing that distinguishes a passing gate from
  an inert one. An enforcement tool that checks nothing and an enforcement tool that finds
  nothing wrong emit the same output. A committed, deliberately-broken sample that the
  gate must reject is the only way to tell them apart.

- **ADR (architecture decision record)**: the durable rationale for three choices whose
  reasoning would otherwise be lost — the layering model and the arch-lint engine
  mechanism, the `hickory-proto` exception to the from-scratch rule, and the pinned root
  trust anchor.

- **Markdown linter (`rumdl`)**: the documentation counterpart to clippy — a rule-based
  checker over every `.md` file, run as a gate step and pinned exactly. It is a Rust
  binary installed through `cargo install --locked`, which matters: it reaches the
  repository by the same route as arch-lint, needs no second language runtime, and is
  pinned by the same mechanism. Relates to the gate as an eighth step, and to the hooks
  and CI through the single `gate` target they already share.

- **Documentation tier**: the recognition that the repository's markdown is not one
  homogeneous thing, and that a single policy over all of it is either too loose for the
  prose or unlivable for the contracts. Two tiers:

  - **Hand-written, reader-facing** — `docs/adr/**`, `ROADMAP.md`,
    `gate-selftest/README.md`. Authored deliberately, read by humans looking for
    reasoning. Full rule set applies.
  - **Generated contracts** — `spdd/**`. Emitted by the SPDD commands, read as
    specifications. Structural rules apply; the *wrapping* rule does not, because the
    generator is what decides line width and it does not know the linter exists.

  Relates to the linter as its configuration axis, and to the SPDD workflow as the
  boundary between what a human controls and what a command emits.

### Key Business Rules

- **A crate is a feature; a layer is a module.** Governs: workspace root, feature crate,
  layer. Cargo's dependency graph is the enforcement mechanism for the first half;
  arch-lint is the enforcement mechanism for the second.

- **Feature crates never name each other.** Governs: feature crate, composition root,
  `[[restrict-use]]`. The consequence is that every cross-feature need becomes a trait (a
  port) in the consumer's `domain` and an adapter in the binary. This is an invariant the
  gate must enforce from the first commit, because retrofitting it after three features
  have reached into each other is a rewrite.

- **`styx-proto` is exempt from the rule above, and only `styx-proto`.** Governs: shared
  foundation crate. The exemption must be written into the restriction rules explicitly,
  because a rule written as "no crate may name another feature crate" would otherwise make
  the codec unusable.

- **`domain` depends outward on nothing.** Governs: layer, scope. Includes no synchronous
  I/O, no `unwrap`/`expect` in non-test code, and errors modelled as enums rather than
  stringly-typed or panicking.

- **The hot path touches no I/O**, which makes `no-sync-io` an architectural invariant
  rather than a style rule. Governs: layer, scope. A database outage must degrade logging
  and admin and never resolution; a synchronous read that sneaks into `domain` or
  `application` is a latent violation of that guarantee.

- **A lint that only runs locally is not enforcement.** Governs: gate, hooks, CI. The same
  gate runs in all three places.

- **The headless build is a first-class build.** Governs: gate, CI. The web UI is a
  compile-time Cargo feature (`web`, default on); `--no-default-features` must be built
  and tested on every commit or it rots within a month.

- **`hickory-proto` never appears in a normal or build dependency path.** Governs:
  dev-only containment, the from-scratch rule. It may appear only under
  `[dev-dependencies]`.

- **Documentation is a deliverable of this repository, and is gated like one.** Governs:
  markdown linter, gate, documentation tier. The ADRs are the only surviving record of why
  the gate has the shape it has, and the SPDD contracts are what the code is generated
  from. Neither is a by-product.

- **A rule the generator cannot satisfy is a rule that will be suppressed.** Governs:
  documentation tier, markdown linter. `spdd/**` is emitted by the SPDD commands. Imposing
  a wrapping rule those commands do not know about produces a gate that goes red on the
  next `/spdd-generate` run through no author's fault — and a gate that fails for reasons
  nobody caused is a gate that gets bypassed. The tier split exists to keep every enforced
  rule one that an author can actually act on.

- **Every gate must be proven to fail.** Governs: gate self-test. This is the exit
  criterion and, given the history of the committed config, the single most important rule
  in the phase. **It extends to the markdown gate**: a linter pointed at an over-broad
  exclusion list passes vacuously and looks identical to one finding nothing wrong. That
  is this phase's founding failure in a new medium, and it needs a fixture like every
  other rule family.

---

## Strategic Approach

### Solution Direction

Build the repository as an **empty but fully-governed workspace**: no product code, but
every structural rule that the following twelve phases must obey already expressed as an
executable check, and every check already proven to fail on a real violation.

The direction has three movements.

**First, establish the topology.** Initialise git, then lay down a Cargo virtual workspace
whose member shape encodes the crate-per-feature model: shared foundation crate, feature
crates with `domain`/`application`/`infrastructure` modules, and a composition-root binary
that owns the wiring and the `web` Cargo feature. The workspace root owns lint
configuration and dependency versions so that "workspace-wide" is enforceable from one
place.

**Second, replace the enforcement layer wholesale.** The existing `arch-lint.toml` is
discarded rather than edited, because its defect is structural: the presence of
`[[layers]]` in the file is itself what selects the wrong engine. The replacement is a
syn-engine configuration — path-glob scopes per feature crate × layer, dependency denials
between those scopes, and use-restrictions that keep feature crates from naming each other
while explicitly exempting the shared codec — plus the rule set the phase names:
no-unwrap-expect with tests allowed, require-tracing, tracing-env-init, no-sync-io,
require-thiserror. The tool is moved from 0.5.0 to 0.6.0 as part of this replacement.

**Third, surround the primary check with independent corroboration.** Three checks cover
overlapping ground on purpose: arch-lint reads source text, the link-graph check reads the
resolved dependency edges, and the dev-only containment check reads the same graph for a
different property. A single tool silently failing open is exactly the failure this
project has already experienced once; the mitigation is redundancy across tools that read
different inputs. All of it, plus formatting, clippy, tests and the headless build,
aggregates behind one `gate` target, which is then invoked identically by pre-commit,
pre-push and CI.

The phase closes by attacking its own work: a deliberate `.unwrap()` in a `domain` module
and a deliberate cross-layer `use`, both of which must turn the gate red.

**The documentation amendment adds a fourth movement**, parallel to the third rather than
after it: the same gate acquires a markdown step, pinned the same way, invoked by the same
three callers, and proven by the same kind of fixture. Nothing about the gate's shape
changes — it grows one more step, placed with the other cheap text-level checks and before
anything that compiles.

### Key Design Decisions

- **Replace `arch-lint.toml` entirely rather than amend it.** Trade-off: a rewrite
  discards a file that at least parses and runs green today, and green is comfortable. But
  the green is the defect — the file's `[[layers]]` block routes the tool into an engine
  that ships only a Kotlin grammar, discovers zero `.rs` files, and exits 0 having checked
  nothing. Any amendment that leaves `[[layers]]` in place preserves the exact failure. →
  **Replace the file, and specifically remove `[[layers]]`, because its absence is the
  engine selector.**

- **Express layers as path-glob scopes rather than as language packages.** Trade-off:
  globs are more verbose than a package-prefix list and must be maintained as crates are
  added. But Rust has no package-prefix concept for the tool to key on, and the glob-based
  scope model is the one the syn engine actually implements, with a working proof on a
  real Rust workspace. →
  **Scopes per feature crate × layer, with dependency denials written between them.**

- **Run two layering gates instead of one.** Trade-off: duplicated intent, two things to
  keep in sync, and a class of violation that fails twice with two different error
  messages. But the two read different inputs — source text versus the resolved link graph
  — so a misconfiguration in one is not a misconfiguration in the other, and a tool that
  fails open is caught by its neighbour. Given that this project's enforcement has already
  been silently inert once, redundancy is bought deliberately. →
  **Keep both, and document in the ADR that the overlap is the point.**

- **Make the deliberate-violation check an exit criterion, not a one-off manual sanity
  check.** Trade-off: the repository must carry code that is intentionally wrong, which is
  awkward to house in a workspace that otherwise must stay green. But "the config is
  inert" and "the config passes" are observationally identical, and the phase's entire
  value evaporates if the second mistake goes unnoticed the way the first did. → **Prove
  each gate fails on a real violation; this check is the deliverable, not the workspace.**

- **Build the gate as a single named target invoked by all three callers.** Trade-off: the
  target grows large and a developer cannot easily run one piece of it. But any drift
  between what CI runs and what the hooks run means the hooks are theatre and CI becomes
  the only real gate, which defeats the purpose of having hooks. →
  **One `gate` target; hooks and CI call it rather than re-listing its steps.**

- **Carry the `--no-default-features` headless build in CI from the very first commit.**
  Trade-off: a second full build on every push, on a workspace that is currently empty and
  gains nothing from it today. But the headless build is a supported product configuration
  that nobody exercises by hand, and an untested configuration rots within about a month.
  Its cost is lowest now and rises with every phase. →
  **Wire it in phase 0, when the build is trivially fast.**

- **Write three ADRs now rather than when the corresponding code lands.** Trade-off: two
  of the three (the `hickory-proto` exception, the pinned trust anchor) document choices
  whose implementation is phases away — phase 1/2 and phase 6 respectively. But both are
  choices that look like mistakes to a reader who does not know the reasoning: a
  from-scratch DNS project that lists a DNS library, and a validator that does not
  implement automated trust anchor rollover. The layering ADR likewise must record *why*
  the arch-lint configuration has its exact shape, or the next person "simplifies" it back
  into inertness. → **Write all three in phase 0, where the reasoning is freshest and the
  gate configuration they explain is being created.**

- **A Rust markdown linter, installed by `cargo install`, rather than the Node
  ecosystem's.** Trade-off: `markdownlint-cli2` is the de facto standard, has the larger
  rule set and the wider deployment; `rumdl` is at 0.2.x, pre-1.0, and will churn. Against
  that, adopting it means a Node toolchain becomes a build requirement of a Rust project —
  a second runtime to install in CI, a second version to pin, and a second lockfile to
  keep honest, all to check prose. `rumdl` arrives through `cargo install --locked`
  exactly as arch-lint does, is covered by the same pinning discipline, and needs nothing
  that is not already present. →
  **`rumdl`, pinned to an exact version, with the pre-1.0 churn accepted and stated.**

- **Two documentation tiers, expressed in one configuration file.** Trade-off: a single
  uniform policy is simpler to explain and has no boundary to get wrong, but it cannot be
  set anywhere useful — strict enough for the ADRs makes the generated contracts
  unlintable, loose enough for the contracts stops the ADRs from being checked at all. The
  linter's per-file rule-ignore mechanism expresses both tiers in one file, so there is
  still one configuration and one invocation. → **One config, two tiers: full rules on
  hand-written prose, structural rules only on `spdd/**`.**

- **Exempt the generated contracts from the wrapping rule, not from linting.**
  *(Superseded 2026-09-22 — the exemption was retired once the `/spdd-*` commands were
  taught the norms and the existing contracts were reflowed. The reasoning is kept because
  it is what the removal had to satisfy.)* Trade-off: exempting anything weakens the gate,
  and an exemption is how enforcement rots. But the alternative was worse in a specific
  way: `spdd/**` is emitted by the SPDD commands, and a wrapping rule they do not
  implement makes the gate fail on the next generated document through nobody's fault. The
  structural rules — unlabelled code fences, heading punctuation, emphasis-as-heading,
  stray blank lines — remain enforced there, and those are the ones that catch real
  defects in a generated document. → **Wrapping is a hand-written-prose rule; structure is
  a universal one.**

- **Line width set to match the prose that already exists.** Trade-off: the tool's default
  is 80, which is the conventional choice and needs no justification; but the ADRs written
  in this phase wrap at just under 90, so the default would report ~12 violations that are
  stylistic disagreements rather than defects. Setting the width to the convention already
  in use makes the hand-written tier clean on day one, which matters because a gate that
  starts red teaches people to ignore it. → **Match the existing wrap, and treat any later
  widening as a decision rather than a drift.**

### Alternatives Considered

- **Keep the committed `arch-lint.toml` and add `[[constraints]]` to it.** Rejected: the
  commented-out constraint block belongs to the tree-sitter engine, which is the engine
  that cannot see Rust at all. Adding constraints to it adds rules to a run that analyses
  zero files.

- **Drop arch-lint and rely on the Cargo dependency graph alone.** Rejected: Cargo can
  express crate-to-crate isolation but has no concept of a module layer inside a crate,
  and decision 30 puts `domain`/`application`/`infrastructure` inside crates. The
  link-graph check is therefore necessary but not sufficient, which is exactly why both
  gates exist.

- **One crate per layer (`styx-resolution-domain`, `styx-resolution-application`, …) so
  that Cargo enforces layering too.** Rejected by decision 30: it multiplies the crate
  count by three, slows the build, and pushes every intra-feature refactor through
  manifest edits. The chosen split is feature-per-crate with arch-lint covering the
  intra-crate axis.

- **Defer the gates until there is code to gate (phase 1 or later).** Rejected by decision
  35 and by the project's stated posture — CI from the first commit, because the lints in
  question (`indexing_slicing`, `arithmetic_side_effects`, `no-unwrap-expect`) change how
  the wire codec is *written*, not merely whether it passes review. Retrofitting them
  after phase 1 means rewriting the codec.

- **Run arch-lint only in CI, not in local hooks.** Rejected by decision 35 directly: a
  lint that only runs locally is not enforcement, and the converse — a lint that only runs
  remotely — makes every violation a round-trip through a failed pipeline.

- **Trust `arch-lint check` exiting 0 as evidence the gate works.** Rejected: this is
  precisely the failure already recorded against the committed file. An inert
  configuration and a satisfied one are indistinguishable from the exit code alone.

---

- **`markdownlint-cli2` (Node) for the markdown gate.** Rejected: it is the better-known
  tool with the larger rule set, but it makes a Node runtime a build dependency of a Rust
  project purely to lint prose — a second toolchain to install in CI, pin, and keep
  current. The cost is paid on every machine and in every pipeline, forever, for a check
  that a Rust binary already available through `cargo install` performs adequately.

- **A formatter (`prettier`, `dprint`, `rumdl fmt`) run in `--check` mode instead of a
  linter.** Rejected as the *primary* mechanism: a formatter enforces one canonical shape
  and would reflow the SPDD contracts wholesale, including tables and mermaid blocks,
  producing an enormous diff that reviews as noise. The structural defects worth catching
  — an unlabelled code fence, a heading that is really emphasis — are not formatting
  questions and a formatter does not report them. Auto-fix remains available as a
  developer convenience, deliberately not wired into the gate.

- **A prose linter (`vale`) for style, tone and terminology.** Rejected for this phase as
  scope: it governs writing quality rather than document structure, needs a curated
  vocabulary to be useful, and would turn a mechanical check into an editorial one. The
  structural gate is the part that can be enforced without a style argument.

- **Lint `spdd/**` under the full rule set, and reflow the 26 generated documents to
  match.** Initially rejected — it wins compliance once and loses it on the next
  `/spdd-generate` run, because the generator has no knowledge of the wrap width — and
  **subsequently adopted, once that objection was removed.** The five SPDD command
  templates were given a Markdown Output Norms block, so the generator now does know the
  wrap width; the 26 contracts were then reflowed in one pass and the exemption deleted.
  **The order was the whole argument**: reflowing first would have been exactly the
  rejected option, and would have decayed on the next generated document.

- **Defer markdown linting to a later phase.** Rejected on the phase's own logic: the cost
  is lowest now and rises with every document added, and the documentation set is already
  three times the size of the code. Deferring also means the ADRs — written in this phase,
  and the artefact most in need of being kept readable — are the ones that never get
  checked.

## Risk & Gap Analysis

### Requirement Ambiguities

- **The final crate roster is not fixed by this phase.** The requirement says
  "`[[scopes]]` per feature crate", but the feature crates are introduced across phases
  1–11 (`styx-proto` in phase 1, `styx-recursion` in phase 5, `styx-dnssec` in phase 6,
  `styx-web` in phase 11, and so on). What needs clarification: whether phase 0 creates
  placeholder crates for the whole roster, or creates a minimal skeleton plus a documented
  convention that later phases extend. The exit criterion — "an empty workspace where
  `just gate` is green" — suggests minimal, but scope configuration written for crates
  that do not yet exist is configuration nobody has proven.

- **"Bump 0.5.0 → 0.6.0" is stated without a verification step.** The entire arch-lint
  analysis in the decision record — the engine selector, the Kotlin-only grammar, the
  AL001–AL013 rule set — was spiked against 0.5.0 on 2026-09-21. Whether 0.6.0 preserves
  that behaviour, that rule numbering and that configuration schema is unverified. The
  named rules (`no-unwrap-expect`, `require-tracing`, `tracing-env-init`, `no-sync-io`,
  `require-thiserror`) must be confirmed to exist under those names in 0.6.0.

- **The 15 denied clippy lints and 4 `allow-*-in-tests` entries are given as counts, not
  as a list, in this phase spec.** Three are named elsewhere in the decision record —
  `indexing_slicing`, `arithmetic_side_effects` and `panic`, all `deny` — and all 15 were
  verified against rustc 1.96.0. The remaining twelve names and the four test-allowances
  need to be recovered and pinned to a specific toolchain version in the canvas, or the
  count is unimplementable as written.

- **"Modelled on `alloy/arch-lint.toml`" points at a reference outside this repository.**
  It is cited as a working proof on a real Rust workspace, but it is not present here and
  its content cannot be assumed. The canvas must specify the configuration shape directly
  rather than by reference.

- **Where the deliberate violations live is unspecified.** They must fail the gate on
  demand but must not fail it permanently. Whether they are a scratch edit performed and
  reverted, a fixture directory excluded from the normal gate run, or a dedicated
  negative-test target is an open question with real consequences for whether the check
  survives past phase 0.

- **The documentation amendment does not say which files are in scope.** "Markdown files"
  could mean the hand-written prose only, everything tracked in git, or everything on
  disk. The repository contains at least three populations with different authorship:
  hand-written prose, SPDD contracts generated by command, and `.claude/commands/*.md`,
  which are tool definitions vendored into the repo and not authored here at all. What
  needs clarification is whether a document nobody in this project wrote should be gated
  by it — the canvas assumes not, and excludes them.

- **The amendment does not state whether the markdown gate needs its own self-test
  fixture.** Every other rule family in this phase has one, on the explicit reasoning that
  an inert check and a passing check are indistinguishable from an exit code. A markdown
  linter whose exclusion list has quietly grown to cover everything is exactly that
  failure. The canvas should treat a fixture as required rather than optional, but the
  amendment as written does not say so.

### Edge Cases

- **A new feature crate added in a later phase with no matching scope entry.** The
  layering rules would simply not apply to it, and the gate would pass. This is the
  inert-config failure in a new dress: silence, not an error. The configuration needs a
  posture where unscoped Rust source is a failure rather than an omission.

- **`styx-web` against the layering rules.** It is presentation, not a peer, and is
  permitted to depend on a feature's `application` layer. Written carelessly, the
  feature-isolation restriction forbids exactly this and the rules become unusable at
  phase 11 — the point at which they are most inconvenient to change.

- **`styx-proto` against the same rules.** Every crate names it. A restriction written as
  "no crate may name another crate in the workspace" breaks the whole build; the exemption
  must be explicit and must be *tested*, not merely intended.

- **The composition-root binary against the same rules.** It legitimately names every
  feature crate simultaneously, which is the exact pattern the restriction exists to
  forbid everywhere else.

- **`--no-default-features` on an empty workspace.** It will pass trivially today, which
  means the check is unproven until phase 11 introduces the `web` feature and something
  that is actually conditional on it. The check is correct to add now and must not be
  mistaken for verified.

- **Hooks bypassed with `--no-verify`.** The local half of enforcement is advisory by
  construction; CI is the only non-bypassable gate. This is tolerable but should be a
  conscious position, not an accident.

- **A dependency that pulls `hickory-proto` in transitively through a normal dependency.**
  The containment check must inspect the full normal and build dependency paths, not only
  the direct manifest entries, or a transitive edge defeats it silently.

- **Lint rules interacting with the phases they govern.** `indexing_slicing` and
  `arithmetic_side_effects` set to `deny` make every label offset and TTL decrement in the
  phase 1 wire codec a checked operation. That is the intended tax, and it is paid
  starting the moment this configuration lands.

### Technical Risks

- **THE PRIMARY RISK — the committed `arch-lint.toml` enforces nothing, and the
  replacement could repeat the failure.** This was spiked on 2026-09-21 against arch-lint
  0.5.0; what was originally feared to be a missing-capability risk turned out to be a
  configuration defect. The mechanism, in full:

  - arch-lint 0.5.0 has **two mutually exclusive engines**, selected by whether the
    configuration file contains a `[[layers]]` block
    (`arch-lint-cli-0.5.0/src/main.rs:144`).
  - **With `[[layers]]` present, the tree-sitter engine runs.** That engine ships exactly
    one grammar, `tree-sitter-kotlin-ng`, and filters file discovery to `.kt`/`.kts`
    (`check_ts.rs:122`). On a Rust repository it analyses **zero files and exits 0** — a
    green run that checked nothing. It also, by virtue of being selected,
    **silently disables AL001–AL013**.
  - The file committed to this repository **does contain `[[layers]]`**, so that is
    precisely what happens today.
  - **Without `[[layers]]`, the syn engine runs.** It executes **AL001–AL013** *plus*
    `[[scopes]]`, `[[deny-scope-dep]]` and `[[restrict-use]]`
    (`arch-lint-core-0.5.0/src/declarative/config_dto.rs:27`), which enforce layering on
    Rust by path glob. `alloy/arch-lint.toml` is a working proof of this on a real Rust
    workspace.

  The conclusion carried forward: **the crate-per-feature layering decision stands; the
  fix is replacing the file in phase 0, and pairing it with an independent `cargo tree`
  gate, since arch-lint reads source text while `cargo tree` reads the link graph. Verify
  with a deliberate violation — an inert config looks identical to a passing one.**

  Mitigation direction: remove `[[layers]]` entirely (its absence is the engine selector),
  write scopes/deny-scope-dep/restrict-use for the syn engine, add the independent
  link-graph gate, and make the deliberate-violation check a standing exit criterion
  rather than a one-time confidence-builder.

- **Version drift on the 0.5.0 → 0.6.0 bump.** The engine-selection behaviour above is
  evidence from 0.5.0 source. A minor bump could change the selector, the rule
  identifiers, the configuration keys or the rule names. Mitigation: re-run the
  deliberate-violation check against 0.6.0 specifically, and pin the exact version rather
  than a range.

- **Hand-written wire parsing under `indexing_slicing = deny` and
  `arithmetic_side_effects = deny`.** Every label offset and TTL decrement becomes a
  checked operation. That is the intended tax, but it makes the codec verbose and
  compression-pointer loop detection fiddly. Fuzzing is not optional. Phase 0 sets this
  policy; phase 1 pays for it.

- **`panic = "deny"` is load-bearing.** In a single process, a panic in a Leptos request
  handler takes DNS down for the whole house. The lint helps; a `catch_unwind` boundary
  around the web layer and a supervised task model are the real mitigation — and those
  arrive in phase 12, last. Everything before phase 12 relies on the lint alone. Phase 0
  must therefore not weaken it.

- **Toolchain pinning is unstated but implied.** The 15 lint names were verified against
  rustc 1.96.0. Without a pinned toolchain, a rustc upgrade can rename or remove a lint
  and turn the whole gate red — or, worse, turn a denied lint into an unknown-lint warning
  that is ignored.

- **Gate runtime growth.** The gate is small today and is invoked on every commit and
  every push. By phase 8 it carries socket-level tests, fuzz targets and two full builds.
  A gate slow enough to be resented is a gate that gets bypassed.

- **No operational feedback loop for a long stretch.** The cutover is last, and phases 1
  through 7 produce nothing a human can look at except `dig` output. Nobody is waiting on
  the result either, so the large-scope risk is concentrated into one long stretch with
  neither visible progress nor external pressure. This raises the stakes on phase 0: the
  gate is the only continuous feedback signal that exists for most of the project, so it
  must be trustworthy and it must be fast.

- **Greenfield configuration has nothing to validate against.** Every rule written in this
  phase is written against crates that do not exist yet. Rules that are correct in the
  abstract and wrong in practice will not surface until phase 1 or later. The deliberate
  violation check is the only mitigation available — and it only proves the rules it
  exercises.

- **The markdown gate governs documents the project does not author, and this is where it
  will go wrong.** The linter was run against the repository before this amendment was
  written, and the shape of the problem is entirely in one rule. At the tool's default
  width, the hand-written prose reports around a dozen violations and the generated
  contracts report **over seven thousand** — more than 99% of everything found. Widen the
  limit to the width the ADRs already use and the hand-written tier goes to **zero** while
  the contracts still report over a thousand. No threshold fixes both: the two populations
  are wrapped by different authors to different rules, and one of those authors is a
  command.

  With the wrapping rule scoped to hand-written prose, what remains repo-wide is
  **47 structural findings**, concentrated in unlabelled code fences, headings ending in
  punctuation, and emphasis used where a heading was meant. About four-fifths are
  mechanically fixable; the rest are genuine authoring choices in generated documents that
  have to be settled by hand. **That residue is the real cost of this amendment** and it
  is paid once, in this phase, before the gate can go green.

- **The linter is pre-1.0 and its rule set will move.** A minor bump can rename a rule,
  change a default, or add one that reports on documents that were clean yesterday. This
  is the same hazard the phase already names for arch-lint and for rustc, and it takes the
  same mitigation: pin the exact version, and treat an upgrade as a change that must be
  verified rather than absorbed. The blast radius is smaller than arch-lint's — a markdown
  rule change makes the gate noisy rather than silently inert — which is the one respect
  in which this risk is milder than the ones already accepted.

- **Auto-fix is the sharp edge.** The tool can rewrite documents in place, and it offers
  to reflow prose. Run without thought across `spdd/**`, that reflows tables and mermaid
  blocks and produces a diff nobody can review. The mitigation is a posture, not a
  setting: the gate *checks* and never writes, auto-fix stays a deliberate developer
  action, and reflow stays off.

### Acceptance Criteria Coverage

The phase spec states two exit criteria; each scope bullet also functions as an implicit
deliverable criterion. Both are assessed below.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | An empty workspace where `just gate` is green | Yes | Straightforward on an empty workspace. Note the trap: green on an empty workspace is weak evidence, which is exactly why AC2 exists. |
| 2 | A deliberate `.unwrap()` in a `domain` module fails the gate | Yes | Requires the arch-lint `no-unwrap-expect` rule to be active under the syn engine with `allow_in_tests = true`, and requires a `domain` module to exist to place it in. Where the violation lives is unspecified — see Ambiguities. |
| 3 | A deliberate cross-layer `use` fails the gate | Yes | Requires `[[scopes]]` and `[[deny-scope-dep]]` to cover the layers involved. Must be exercised for a layer violation *and* ideally for a feature-crate-naming violation, since `[[restrict-use]]` is a distinct rule family that AC3 as written does not necessarily reach. |
| S1 | `git init`; Cargo workspace skeleton in the crate-per-feature shape | Yes | The member roster is the open question — minimal skeleton vs. full roster. See Ambiguities. |
| S2 | Replace `arch-lint.toml` with a syn-engine config (`[[scopes]]`, `[[deny-scope-dep]]`, `[[restrict-use]]`) + the five named rules; bump 0.5.0 → 0.6.0 | Partial | The configuration shape is fully specified by the risk analysis. The gap is 0.6.0 behaviour verification and the unavailable `alloy/arch-lint.toml` reference. |
| S3 | An independent layering gate on `cargo tree --edges normal` | Yes | Needs an explicit statement of which edges constitute a violation, so the check is not merely informational output nobody reads. |
| S4 | `hickory-dev-only` check — `hickory-proto` in no normal or build dependency path | Yes | Must cover transitive paths, not just direct manifest entries. Cannot be meaningfully exercised until phase 1 or 2 actually adds the dev-dependency; until then it passes vacuously. |
| S5 | `clippy.toml` — 15 denied lints, 4 `allow-*-in-tests` | Partial | Only three lint names are recoverable from the decision record (`indexing_slicing`, `arithmetic_side_effects`, `panic`, all `deny`). The remaining twelve and the four test-allowances must be enumerated in the canvas and pinned to rustc 1.96.0. |
| S6 | `lefthook.yml` on pre-commit and pre-push | Yes | Both hooks should invoke the single `gate` target rather than re-listing its steps, or the two drift. |
| S7 | GitHub Actions running the full gate plus `--no-default-features` | Yes | The headless build passes vacuously on an empty workspace; it becomes a real check at phase 11. Release artifacts for the two musl targets on `v*` tags belong to the same workflow family and are consumed by phase 12. |
| S8 | `justfile` with a `gate` target aggregating all of it | Yes | The aggregation is the deliverable: one command, three callers (developer, hooks, CI), no divergence. |
| S9 | ADR — layering and the arch-lint mechanism | Yes | Must record the two-engine selector and why `[[layers]]` is absent, or the config is "fixed" back into inertness by a future reader. |
| S10 | ADR — the `hickory-proto` exception to the from-scratch rule | Yes | Must record the oracle argument: a self-encoded fixture shares every bug with the code it tests, so a green suite would prove only self-consistency. |
| S11 | ADR — the pinned trust anchor | Yes | Documents a choice whose code lands in phase 6. Must carry the accepted consequence: a KSK roll needs a release or a file edit, and missing one SERVFAILs every lookup — a monitoring obligation, not code. |
| S12 | *(amendment)* Markdown linting wired into the same gate, pinned, with the hand-written and generated tiers distinguished | Yes | Verified against the repository before being written down: the hand-written tier is already clean at the chosen width, and the tier split is expressible in a single configuration file. Carries a one-off cost of ~47 structural fixes, ~80% of them mechanical. Needs a self-test fixture to avoid becoming the vacuous check this phase exists to prevent — see Ambiguities. |

**Coverage**: 3 of 3 stated exit criteria addressable; 12 scope deliverables, of which 10
are fully addressable and 2 (S2, S5) are partial pending the version verification and the
lint enumeration noted above. S12 is an amendment to the original spec rather than one of
its bullets, and is addressable in full.
