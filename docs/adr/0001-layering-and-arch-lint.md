# ADR 0001 — Layering, and how arch-lint is made to enforce it

- **Status**: accepted
- **Date**: 2026-09-22
- **Phase**: 0 — Foundation and gates

## Context

### The layering model

styx is a **crate per feature**, with `domain`, `application` and
`infrastructure` as **modules inside** each crate rather than crates of their
own. Cargo enforces feature-to-feature isolation; a linter enforces the layer
axis within a crate.

*Why layers are not separate crates*: three crates per feature triples the
crate count, slows the build, and pushes every intra-feature refactor through
manifest edits. This split puts the crate boundary where isolation actually
matters and leaves the layer axis to a tool.

**Feature crates never depend on each other.** A cross-feature need is a trait
— a **port** — declared in the *consumer's* `domain` module and implemented by
an **adapter in the binary**. `styx-resolution` will declare a `FilterPolicy`
port; the `styx` binary wires `styx-filtering` into it. The composition root is
consequently the only crate permitted to name every feature crate at once.

Without this rule, three features reach into each other and the isolation
becomes a rewrite to recover rather than a rule to follow. That is why it is
enforced from the first commit and not discovered in phase 8.

Two exemptions, both deliberate:

- **`styx-proto` and `styx-core` are shared foundations, not feature crates.** Every crate
  may depend on them, so the feature isolation rule does not reach them as targets.
  They remain bound as *sources*: neither names a feature crate, and `styx-proto` names
  no workspace-internal crate. A restriction phrased as "no crate may
  name another workspace crate" would forbid this and break the entire build.
- **`styx-web` is presentation, not a peer**, and may reach a feature's
  `application` layer. Written carelessly, the isolation rule forbids exactly
  this and the rules become unusable at phase 11 — the point at which they are
  most inconvenient to change.

### The mechanism: arch-lint has two engines

arch-lint selects between **two mutually exclusive engines**, and the selector
is whether the configuration contains a `[[layers]]` block
(`arch-lint-cli-0.5.0/src/main.rs:144`; still true at 0.6.0, `main.rs:153`).

- **With `[[layers]]`, the tree-sitter engine runs.** It ships exactly one
  grammar, `tree-sitter-kotlin-ng`, and filters discovery to `.kt`/`.kts`
  (`check_ts.rs:122`). On a Rust repository it analyses **zero files and exits
  0**. Because it is selected, it also **silently disables AL001–AL013**.
- **Without `[[layers]]`, the syn engine runs.** It executes AL001–AL013 plus
  `[[scopes]]`, `[[deny-scope-dep]]` and `[[restrict-use]]`
  (`arch-lint-core-0.5.0/src/declarative/config_dto.rs:27`), enforcing layering
  on Rust by path glob.

**The configuration this repository shipped with contained `[[layers]]`.** It
had been green since the day it was committed, having checked nothing at all.
This is not a hypothetical failure mode; it is the state phase 0 inherited.

## Decision

1. **`arch-lint.toml` contains no `[[layers]]` block, ever.** Its absence is
   the engine selector. The file was replaced wholesale rather than amended:
   the `[analyzer]`, `[[layers]]`, `[dependencies]` and commented
   `[[constraints]]` sections all belong to the engine that cannot see Rust,
   so amending it would have added rules to a run over zero files.
2. Layers are expressed as path-glob `[[scopes]]`, one per feature crate ×
   layer, with `[[deny-scope-dep]]` carrying the layering denials and
   `[[restrict-use]]` carrying feature isolation and its exemptions.
3. The rule set is `preset = "strict"` plus `no-unwrap-expect`
   (`allow_in_tests = true`), `require-tracing`, `tracing-env-init`,
   `no-sync-io` and `require-thiserror`. arch-lint is pinned to **exactly**
   0.6.0.
4. **A second, overlapping layering gate exists on purpose.** `xtask deps`
   reads the resolved link graph from `cargo metadata`; arch-lint reads source
   text. A misconfiguration in one is not a misconfiguration in the other, and
   a tool that fails open must be caught by a neighbour.
5. `no-sync-io` is treated as an **architectural invariant, not a style
   preference**: the hot path touches no I/O — matcher state is in memory,
   built at boot and on reload — and a database outage must degrade logging and
   admin while never touching resolution. A synchronous read in `domain` or
   `application` is a latent violation of that guarantee.

### Three things found by verification, each load-bearing

The engine analysis above was spiked against 0.5.0. Re-verifying against 0.6.0
turned up three mechanisms that silently defeat enforcement. Each is guarded by
a fixture, because each produces a green run that proves nothing.

1. **`[[deny-scope-dep]]` resolves `crate::` paths against the analysis root,
   not the crate root.** `crate::a::b` becomes the candidate paths `src/a/b.rs`
   and `src/a/b/mod.rs` (`arch-lint-core-0.6.0/.../scope_dep.rs:118`) — a
   single-crate assumption. In a workspace the real file is
   `crates/<crate>/src/a/b/mod.rs`, which those candidates never match, so the
   layering rules match **nothing**. Every layer scope therefore carries a
   second, root-relative glob `src/<layer>/**` alongside its real one. That
   glob matches no real file in a workspace layout, so it cannot mis-attribute
   one. **Fixture B is the only thing that catches its removal.**
2. **A path component named `tests` makes a file test code.** Any component
   named `tests`, `test` or `benches` sets `is_test`
   (`arch-lint-core-0.6.0/src/context.rs:43`), and test code is precisely what
   `allow_in_tests = true` exempts. The self-test fixtures therefore live in
   `gate-selftest/`, not `tests/gate-selftest/` — under the latter every
   fixture passes and the self-test certifies a gate that is proving nothing.
3. **`analyzer.exclude` falls back to a substring match on the absolute path**
   (`arch-lint-core-0.6.0/src/analyzer.rs:527`). Excluding the fixture
   directory would also hide the fixtures when the analyser is pointed straight
   at one, giving a zero-file green run. The fixtures are kept out of the
   normal run with an `include` allowlist instead, which is matched relative to
   the analysis root and therefore does the right thing in both directions.

## Consequences

- **The overlap between the two layering gates is the point, not an oversight
  to be tidied away.** Removing either is a regression, not a simplification.
  Accepted cost: duplicated intent, two things to keep in sync, and a class of
  violation that fails twice with two different messages.
- A cross-feature need costs a port plus an adapter, which is more ceremony
  than a direct call. That is the price of the isolation.
- Every new crate must arrive with its `[[scopes]]` entries. A crate without
  them is a **defect, not an omission**: the layering rules simply would not
  apply to it and the gate would pass in silence. That is the inert-config
  failure in a new dress.
- The hooks are bypassable with `--no-verify`, so **CI is the only
  non-bypassable gate**. This is a conscious position: hooks give fast local
  feedback, CI gives enforcement, and both run the same `just gate` target so
  they cannot disagree.

## Warning to future readers

**An inert config looks exactly like a passing one.** An enforcement tool that
checks nothing and one that finds nothing wrong emit the same exit code. This
repository has already shipped the former once.

Do not "simplify" `arch-lint.toml` — and in particular do not reintroduce
`[[layers]]`, remove a synthetic `src/<layer>/**` glob, move `gate-selftest/`
under a directory named `tests/`, or convert the `include` allowlist back into
an exclude — without running `just gate-selftest` afterwards and watching every
fixture still be rejected.
