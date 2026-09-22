# ADR 0003 — The root trust anchor is pinned

- **Status**: accepted
- **Date**: 2026-09-22
- **Phase**: 0 — Foundation and gates (the validator arrives in phase 6)

## Context

A DNSSEC validator needs the root zone's trust anchor — the IANA root KSK — to
anchor every validation chain. There are two ways to keep it current:

1. **RFC 5011 automated rollover**: track the root key set, observe new keys
   through their hold-down period, and adopt them without operator action.
2. **Pin it**: compile in the current IANA anchor, and allow an operator
   override.

RFC 5011 needs state that **survives restarts** — which key was seen, and for
how long. In styx that state has nowhere to live in phase 6: the storage layer
is phase 9. Implementing rollover in the validator phase means dragging storage
forward into it, and doing so for a key roll that is **pre-announced months in
advance**.

## Decision

**The root trust anchor is pinned**: a compiled-in IANA anchor, with a
`trust-anchor` configuration override naming a file path, both behind a
`TrustAnchorSource` port.

**RFC 5011 automated trust anchor rollover is out of scope for v1.** The
`TrustAnchorSource` port is the seam it slots into later — a rollover
implementation becomes another adapter behind an existing port rather than
surgery on the validator.

## Consequences

**Accepted consequence, stated plainly: a KSK roll needs a release or a file
edit, and missing one SERVFAILs every lookup.**

Every lookup. Not degraded resolution — no resolution, for the whole house,
until the anchor is updated. This is the trade purchased by not building
RFC 5011 in v1, and it is **a monitoring obligation, not code**. Somebody has
to watch for the announcement. The mitigations that make that survivable are
the config override (a file edit, no release needed) and the months of advance
notice a root KSK roll carries.

## Why this is written in phase 0, six phases before the code

A validator that does not implement automated rollover **looks like an
omission** to anyone who does not know the reasoning — including its author, a
year from now. The seam that makes it recoverable (`TrustAnchorSource` as a
port rather than a constant) is a design commitment made now, and the
reasoning is freshest now.

An ADR that states a decision without the trade-off it purchased is not doing
its job: the next reader simply reverses it.
