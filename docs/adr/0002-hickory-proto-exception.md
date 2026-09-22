# ADR 0002 — `hickory-proto` as the test oracle

- **Status**: accepted
- **Date**: 2026-09-22
- **Phase**: 0 — Foundation and gates (the dependency itself arrives in phase 1)

## Context

**The entire DNS stack in styx is written from scratch**: the wire codec, the
server loop, the caches, the recursion algorithm and the DNSSEC validator. No
`hickory-dns`, and no `domain` crate for the protocol. That is the point of the
project, not an incidental preference.

That rule creates a problem for the tests. The suite needs fake root, TLD and
authoritative servers, and it needs expected-byte fixtures. **All of that has
to encode DNS wire format.** If our own codec encodes it, then the resolver and
the oracle it is tested against share every bug: a malformed name-compression
pointer that our encoder emits and our decoder accepts round-trips perfectly. A
green suite would prove only self-consistency — precisely the property that
does not matter.

This is sharpest in the two hand-written security-critical subsystems. A
recursive resolver and a DNSSEC validator are graded against what the protocol
says, not against what we believed when we wrote the encoder.

## Decision

**`hickory-proto` is permitted as the test oracle, under `[dev-dependencies]`
only, in any crate.**

The from-scratch ban is on **shipping code**, not on the test rig. An
independently-written implementation of the wire format is exactly what makes
the tests evidence rather than a tautology.

This is enforced, not merely stated: `xtask hickory-dev-only` asserts that no
`hickory-*` crate is reachable through any **normal or build** dependency path
of any workspace member, **transitively** — not merely that no manifest lists
one directly. It runs as part of `just gate`, on every commit, every push and
every CI run.

## Consequences

- Without the check, the exception rots into a real dependency. Someone needs
  a type that `hickory-proto` already has, moves one line between two manifest
  sections, and the from-scratch rule quietly stops being true while every test
  still passes. The check is what keeps the exception observable rather than
  aspirational.
- **The check passes vacuously in phase 0**, because the dev-dependency does
  not exist yet. It becomes real at **phase 1** (expected-byte fixtures) and
  **phase 2** (the fake root/TLD/authoritative servers). Until then, Fixture D
  in `gate-selftest/` is the only proof that it works — which is why Fixture D
  exists at all, rather than waiting for the dependency it polices.
- The check keys on the `hickory` name prefix, so it catches the whole family
  rather than `hickory-proto` alone.
- Reading the resolved graph rather than the manifests costs a `cargo metadata`
  invocation in the gate. That is cheap, and it is the only way to see a
  transitive introduction.
- A genuine future need for `hickory-*` in shipping code would require
  superseding this ADR, which is the intended friction.
