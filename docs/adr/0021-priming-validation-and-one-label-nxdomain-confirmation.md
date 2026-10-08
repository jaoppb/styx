# ADR 0021 — Priming validation and one-label NXDOMAIN confirmation

- **Status**: accepted
- **Date**: 2026-10-07
- **Phase**: 5 — Recursion

## Context

Two rules in the recursor trusted a single reply more than the reply had earned.

Priming installs the root NS set returned by the first root server that answers, and the
root delegation never expires out of the infrastructure cache. A non-authoritative or
truncated answer, from a cache, a middlebox or a forger, could therefore replace the
hint-seeded root set with one or two chosen servers until the next priming succeeded, and
a short but honest answer could shrink the root pool.

Relaxed QNAME minimisation trusts an NXDOMAIN at an intermediate label (RFC 8020),
because retrying in full would send every typo and tracker subdomain to the parent zone's
servers. The cost is a permanent false NXDOMAIN from a never-seen server with broken
empty-non-terminal handling: that one server hides a name that exists until the cache
entry expires.

## Decision

**Priming accepts only an authoritative, untruncated answer, and installs it unioned
with the hints.** The installed root set is the live set plus every hint server it lacks,
and every hint address a live server lacks. A live answer can add to the root set and
never shrink it below the hints. A server the IANA retires lingers until the hints file
is updated, which is a configuration refresh, not a runtime fault.

**An NXDOMAIN is confirmed with the full qname only when it answers the label directly
above the target.** The server has already seen every label but the leftmost, so the
retry to the same server leaks one label. An NXDOMAIN to an earlier label keeps RFC 8020
trust and is final. The retry is charged to the descent budget like any query, and the
full-qname reply is the one believed; if it succeeds where the minimised question failed,
the server is recorded as mishandling minimisation.

**Only an authoritative server may say NXDOMAIN or name an alias.** A non-authoritative
NXDOMAIN, or a CNAME from a non-authoritative server, classifies as lame and the descent
moves to the next server, as the NOERROR path already did.

## Consequences

- A forged or truncated priming answer cannot touch the root set, and a short live answer
  cannot remove a hint server.
- A first-contact broken server can still return a false NXDOMAIN to an earlier label of
  a deep name once; it is then asked in full.
- A genuine NXDOMAIN one label short of the target costs one extra, charged query.
