# CLAUDE.md

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
- **Feature crates never depend on each other.** A cross-feature need is a port in the
  consumer's `domain`, implemented by an adapter the `styx` binary wires in.
  `styx-proto` is shared foundation and the sole exemption: every crate may depend on it,
  and it depends on none of them. `styx-web` is presentation and may reach a feature's
  `application` layer; it is not a peer of the feature crates.
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

### First-class collections

A type that owns a `Vec<T>` or a `HashMap<K, V>` exposes domain-meaningful methods over
that collection rather than being a bag of an unrelated collection field plus other state.
`styx-proto`'s `TypeBitmap` — window-block encoding behind `contains(RecordType) -> bool` —
is the shape to point at.

### Small, single-purpose modules over god-modules

Split a layer's module by concept into its own file rather than letting one file accumulate
every type in a layer. `styx-proto`'s `domain/rdata/basic.rs` and `domain/rdata/dnssec.rs`,
split out of what would otherwise be a single `rdata` catch-all, are the precedent.

### No setter that reopens an enforced-at-construction invariant

A type whose invariant is checked in its constructor — `Label::new` rejecting more than 63
octets is the precedent — must not also expose a way to mutate the field back into an
invalid state. Prefer read accessors and reconstruction over in-place mutation for types
with a validated invariant.

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

The repository conventions above are, for the most part, mechanically enforced: `just gate`
runs formatting, clippy's denied lints, `arch-lint check`, the link-graph layering gate, the
`hickory-dev-only` containment check, the test suite and the headless build, and
`just gate-selftest` proves that enforcement is live rather than silently inert. See
`docs/adr/0001-layering-and-arch-lint.md` for why that proof exists at all.

**The Object Calisthenics section is not mechanically enforced.** No lint in this
repository checks "wrap this primitive" the way clippy checks `.unwrap()`. Compliance is a
review discipline, and generated code can drift from this ruleset without turning `just
gate` red. Catching that drift is what review is for.
