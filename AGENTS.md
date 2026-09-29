# AGENTS.md

Engineering guidelines for `styx`, read before writing code in this repository. An
architecture decision record explains why a past decision was made and is never edited
except by superseding it; this document explains how code is written going forward and is
revised in place as conventions are learned. Both are gated as prose by `just gate`;
neither substitutes for the other.

Every rule below was fixed by **Phase 0 — Foundation and gates** before a single line of
DNS code existed, and every phase since is expected to already comply with it. Phase 1 —
the `styx-proto` wire codec — is cited throughout as the worked example, not as something
this document revises.

## Repository conventions

- **Crate per feature; `domain`/`application`/`infrastructure` are modules inside it**, not
  crates of their own. Cargo enforces feature-to-feature isolation; `arch-lint` enforces
  layering within a crate. See `docs/adr/0001-layering-and-arch-lint.md`.
- **Ports are traits declared in a feature crate's `domain` module.** A port names no
  concrete infrastructure and no sibling feature crate. An adapter implements the trait,
  living either in the same crate's `infrastructure` module or in the `styx` binary for
  cross-feature wiring. The `styx` binary is the composition root: it constructs adapters
  and injects them into ports by value at startup, with no runtime service locator.
- **Prefer generics over dynamic dispatch (`dyn`).** Trait consumption in ports and
  adapters favours static dispatch via generics (`<T: Port>`, `impl Port`) rather than
  dynamic dispatch (`dyn Port`, `Arc<dyn Port>`). Static dispatch enables inlining and
  monomorphization, eliminates allocation and vtable indirection, and preserves trait
  flexibility. Dynamic dispatch (`dyn`) is reserved for cases where heterogeneous runtime
  collections or true type erasure are strictly required.
- **Feature crates never depend on each other.** A cross-feature need is a port in the
  consumer's `domain`, implemented by an adapter the `styx` binary wires in.
  `styx-proto` and `styx-core` are shared foundation and the exemptions: every crate may
  depend on them, and they depend on no feature crate. `styx-proto` depends on nothing
  workspace-internal; `styx-core` depends only on `styx-proto`. `styx-web` is presentation
  and may reach a feature's `application` layer; it is not a peer of the feature crates.
- **Errors are `thiserror` enums.** Every fallible operation returns `Result<T, E>` with a
  crate-owned error enum. No `Box<dyn Error>` on a public boundary, no stringly-typed
  errors. `anyhow` is reserved for the composition root (the `styx` binary's own startup
  errors) and for `xtask`, which reports a verdict to a human rather than exposing a
  library boundary.
- **No `unwrap`, `expect`, `panic!`, `todo!` or `unimplemented!` outside tests.** In a
  single process, a panic in a Leptos request handler takes DNS resolution down for the
  whole house. The lint helps; the real mitigation — a `catch_unwind` boundary around the
  web layer and a supervised task model — does not arrive until Phase 12, so this rule
  carries the whole weight of panic safety until then.
- **No indexing, no unchecked arithmetic.** `indexing_slicing` and `arithmetic_side_effects`
  are denied workspace-wide. Route every raw offset computation through one audited,
  bounds-checked primitive per crate — `styx-proto`'s `application::cursor::Cursor` is the
  pattern to follow — rather than scattering `checked_*` calls at every call site.
- **No synchronous I/O in `domain` or `application`.** This is an architectural invariant,
  not a style preference: the hot path touches no I/O, and a database outage must degrade
  logging and admin while resolution keeps working.
- **`tracing`, initialised from the environment.** Instrumentation uses `tracing` spans and
  events; the binary builds its subscriber from `RUST_LOG`. No `println!` or `eprintln!` as
  logging.
- **Dependency and lint versions are declared once**, in `[workspace.dependencies]` and
  `[workspace.lints]`; every member crate opts in with `workspace = true` rather than
  re-declaring either.

## Workspace layout and module structure

To help agents navigate and modify the codebase without needing exploratory searches,
the diagram below maps the currently existing crates and their internal module layers.
Whenever a phase introduces a new crate or significantly reorganizes an existing one,
updating this section is a required deliverable of that phase.

```text
styx/
├── Cargo.toml                  # Workspace virtual manifest, dependencies, lints
├── crates/
│   ├── styx/                   # Composition root binary (startup, CLI, wiring)
│   │   └── src/main.rs
│   ├── styx-proto/             # Shared foundation: DNS wire codec (owned domain types)
│   │   └── src/
│   │       ├── domain/         # Wire types: Header, Question, Name, Record, RData, EDNS
│   │       ├── application/    # Cursor (bounds-checked buffer), Encoder, Decoder
│   │       └── infrastructure/ # Transport-agnostic codec helpers
│   ├── styx-core/              # Shared foundation: cross-resolution contracts and ports
│   │   └── src/
│   │       ├── domain/         # Clock, Upstream, UpstreamId, UpstreamResponse, errors
│   │       ├── infrastructure/ # SystemClock
│   │       └── test_util/      # TestClock (test-support feature)
│   ├── styx-resolution/        # DNS resolution engine and upstream forwarding
│   │   └── src/
│   │       ├── domain/         # Domain logic, circuit breaker, health, ports/
│   │       ├── application/    # Pipeline, selection strategies, probe scheduler
│   │       └── infrastructure/ # UDP/TCP listeners, client transports, port adapters
│   └── styx-filtering/         # Filtering & blocklist policy engine (skeleton)
│       └── src/{domain, application, infrastructure}/
└── xtask/                      # Developer & CI gate tasks (deps, hickory, module-size)
    └── src/main.rs
```

## Object Calisthenics, adapted for Rust

The original nine rules target Java-shaped OOP. Several do not survive translation
unchanged; this section states which do, how, and which are consciously dropped or
downgraded, so a later reader does not "fix" a deliberate omission.

### Wrap primitives that carry domain rules

This is the rule this document cares about most. A primitive is wrapped in a newtype when
a value has a validated range, a checked arithmetic operation, a non-trivial wire encoding,
or named constants attached to it — not merely because it is a primitive. `styx-proto`'s
`Ttl` (checked and saturating decrement, never wrapping to a huge value), `RecordType`
(named constants, `is_pseudo()`), `RecordClass` (an enum over the wire's numeric encoding)
and `ResponseCode` (the 12-bit extended RCODE, unrepresentable as a bare nibble) are the
precedent every later phase generalises from.

A plain named `bool` field on a struct — `Header::authoritative`, say — with no independent
validation and no risk of being confused with an unrelated value at a call site, is **not**
primitive obsession. The test is domain rules attached to the value, not the primitive-ness
of its type. Wrapping every field on principle produces ceremony with no behaviour behind
it, which is the failure mode this rule exists to avoid, not the one it exists to punish.

### Guard clauses over nested conditionals

The classical "one level of indentation" and "no `else`" rules collapse into one
Rust-idiomatic instruction: prefer an early `return`, the `?` operator, or a `match` with
each arm doing one thing, over a pyramid of nested `if`/`else`.

Both halves of "keep it small" are gated: nesting depth by clippy's `excessive_nesting`,
thresholded at 4 (a function's own block plus each control-flow block nested inside it —
a plain function may nest three before a fourth trips it), and function length by
`too_many_lines`, thresholded at 60 code lines. Past either number, restructure — a guard
clause, an extracted function — rather than reach for `#[allow]` or a raised threshold.

### First-class collections

A type that owns a `Vec<T>` or a `HashMap<K, V>` exposes domain-meaningful methods over
that collection rather than being a bag of an unrelated collection field plus other state.
`styx-proto`'s `TypeBitmap` — window-block encoding behind `contains(RecordType) -> bool` —
is the shape to point at.

### Small, single-purpose modules over god-modules

Split a layer's module by concept into its own file rather than letting one file accumulate
every type in a layer. `styx-proto`'s `domain/rdata/basic.rs` and `domain/rdata/dnssec.rs`,
split out of what would otherwise be a single `rdata` catch-all, are the precedent.

Gated at 400 counted lines per `.rs` file by `xtask module-size`, with no per-file
exemption and no marker comment to raise it: a file over the cap is split by concept, not
annotated around.

### No setter that reopens an enforced-at-construction invariant

A type whose invariant is checked in its constructor — `Label::new` rejecting more than 63
octets is the precedent — must not also expose a way to mutate the field back into an
invalid state. Prefer read accessors and reconstruction over in-place mutation for types
with a validated invariant.

Half of this is gated: clippy's `partial_pub_fields` denies a struct that mixes `pub` and
private fields — it either publishes every field or none. What it cannot see is a fully
private struct that still exposes a `&mut` accessor or an unvalidated setter; that half
stays a review item.

### Full words, no abbreviations

Already the repository's naming convention; restated here so this reads as one ruleset
rather than two.

### Downgraded to guidance: one dot per line

Rust's `Result`, `Option` and iterator combinators are idiomatically chained, and forbidding
that outright would fight the standard library. Keep the spirit instead of the letter: do
not let a method chain cross a domain boundary without a named intermediate binding.

### Dropped outright: a field-count ceiling

Some domain types legitimately carry several named fields with no shared substructure to
extract — `styx-proto`'s `Opt` and `Header` are the existing examples. An arbitrary cap on
instance fields would force an artificial wrapper type with no behaviour of its own, which
is the opposite of what this ruleset is for.

## Enforcement

`just gate` runs formatting, the markdown lint, clippy's denied lints, `arch-lint check`,
the link-graph layering gate, the `hickory-dev-only` containment check, the module-size
check, the test suite and the headless build; `just gate-selftest` proves that enforcement
is live rather than silently inert. See `docs/adr/0001-layering-and-arch-lint.md` for why
that proof exists at all.

*(Revised 2026-09-24: this section originally claimed three things an arch-lint rule did
not, in fact, fully cover — see the amendment note at the end of this section.)*

**Mechanically enforced**, each named with the tool that checks it:

- Layering and feature isolation — arch-lint's `[[deny-scope-dep]]` and `[[restrict-use]]`
  rules, corroborated by the independent link-graph gate (`xtask deps`).
- No `unwrap`, `expect`, `panic!`, `todo!` or `unimplemented!` outside tests — arch-lint's
  `no-unwrap-expect` and clippy's panicking-lint set.
- No indexing, no unchecked arithmetic — clippy's `indexing_slicing` and
  `arithmetic_side_effects`.
- No synchronous I/O in `domain` or `application`, in every feature crate, and nowhere in
  `styx-proto` — a `[[restrict-use]]` rule per crate and layer.
- No `anyhow` outside the `styx` binary and `xtask` — a `[[restrict-use]]` rule per library
  crate.
- No print macros as logging — clippy's `print_stdout`, `print_stderr` and `dbg_macro`.
- Nesting depth, at most 4 (Guard clauses, above) — clippy's `excessive_nesting`.
- Function length, at most 60 code lines (Guard clauses, above) — clippy's `too_many_lines`.
- Module length, at most 400 counted lines per file, with no exemption (Small,
  single-purpose modules, above) — `xtask module-size`.
- Mixed field visibility (No setter that reopens an invariant, above) — clippy's
  `partial_pub_fields`.

**Review only** — no lint in this repository checks these the way clippy checks
`.unwrap()`, and generated code can drift from them without turning `just gate` red;
catching that drift is what review is for:

- Wrapping a primitive that carries domain rules.
- First-class collections.
- Full words over abbreviations.
- The "one dot per line" guidance.
- The half of the setter rule `partial_pub_fields` cannot see: a fully private struct that
  still exposes a `&mut` accessor or an unvalidated setter.
- No `Box<dyn Error>` on a public boundary.
- Preferring generics over dynamic dispatch (`dyn`).

**The amendment this section records**: Norms 3, 6 and 7 each claimed an arch-lint rule
already enforced no-synchronous-I/O-by-layer, `tracing`-only logging and no-`anyhow`.
Read against the arch-lint 0.6.0 source, none of the three claims held in full —
`no-sync-io` (AL002) does not reliably reach ordinary, idiomatically-imported sync I/O,
`require-tracing` (AL006) flags only the `log` crate and passes `println!`, and
`require-thiserror` (AL005) says nothing about `anyhow`. The gaps were closed with the
`[[restrict-use]]` rules and clippy lints listed above, each with its own
`gate-selftest` fixture (F through I) proving it actually rejects what it claims to.
