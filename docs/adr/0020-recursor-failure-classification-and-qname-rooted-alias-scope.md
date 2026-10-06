# ADR 0020 — Recursor failure classification and the qname-rooted alias scope

- **Status**: accepted
- **Date**: 2026-10-06
- **Phase**: 5 — Recursion

## Context

Two rules written for earlier phases met the recursor and each turned out to be wrong in
a way only an iterative resolver exposes.

First, the pool's circuit breaker counts an `UpstreamFault` against the member that
produced it (ADR 0013, ADR 0014). A forwarder fails for reasons of its own. A recursor
fails for reasons of the *name*: one domain whose authoritative servers all blackhole, or
return undecodable replies, exhausts the four-second wall clock and surfaces as a
timeout. Mapped naively, repeated queries for one broken domain open the breaker on the
whole recursor and every other name stops resolving. Mapped the other way — every
descent failure is the name's fault — a dead uplink burns the wall clock before the
descent ever reports an unreachable root, so the breaker never opens at all.

Second, ADR 0017 admits an answer record whose owner "is reached via a CNAME/DNAME chain
where every link is within bailiwick". The first implementation grew that chain from any
CNAME owned inside the bailiwick zone, not from the chain that starts at the query name.
An in-zone `x.example.com CNAME www.bank.com` unrelated to the question admitted a forged
`www.bank.com A` record. It also rejected a DNAME outright, because the DNAME's owner sits
above the qname, and cached a cross-zone chain without its ending, because the SOA that
closes a chain belongs to another zone than the one that answered.

## Decision

**A descent failure indicts the recursor only when the network has been silent.**
`Recursor::resolve_detailed` reports whether any nameserver answered anything within
`NETWORK_SILENCE` (30 s) before the failure. `to_upstream_error` maps a silent failure to
`UpstreamError::Timeout`, and an unreachable root (`NoReachableNameserver { at_root }`) to
`ServerFailure { is_upstream: true }`. Every other failure — a dead leaf zone, a lame or
looping delegation, malformed or truncated replies, a spent budget or wall clock — is
`ServerFailure { is_upstream: false }`, an answer fault that never trips the breaker.

**The answer scope is the zone's subtree plus the chain walked from the qname.**
`AnswerScope::from_chain` starts at the qname and follows the CNAME owned by each link in
turn, over a map canonicalised once, ending at the first repeated target. A CNAME that is
not a link of that chain extends nothing, so an in-zone alias cannot carry a foreign
owner into the cache.

**A DNAME is admitted only together with the CNAME it explains.** RFC 6672 section 3.1
has the server synthesise that CNAME. A DNAME RRset is admissible exactly when
substituting its target for its owner in a link of the chain gives the next link's target.
Its target's subtree is never permitted.

**A denial that ends a cross-zone chain is cached inside the qname's own composite entry.**
When the answer ends in NXDOMAIN, or in NOERROR with nothing but aliases at the chain's
last name, an SOA whose owner encloses that last name is admitted as authority, with its
TTL clamped by the SOA `MINIMUM` field (RFC 2308 section 5). It is stored only as part of
the entry for the qname and qtype asked. It never becomes a negative entry for the target
name, so a zone that answers for `www.example.com` cannot deny `www.bank.com` to a client
who asks for it directly. This is the one case in which the authority section of an
entry may carry an SOA from outside the bailiwick zone; it supersedes ADR 0017's
authority-section bullet for that case alone and leaves every other rule in force.

## Consequences

- One broken domain no longer removes the recursor from the pool, and a dead uplink
  still does, after at most `NETWORK_SILENCE` of masking while recent replies age out.
- Admission is linear in the number of answer records, instead of cubic in an
  adversarial reversed chain.
- A cross-zone alias chain ending in NXDOMAIN or NODATA is cached once, and replays with
  its chain, its response code and its closing SOA.
- Classification depends on `DiagnosticsState::last_reply`, which every answered exchange
  and every priming query updates. A new transport must go through the same exchange
  path, or it will read as silent.
- The DNAME pairing check compares through `CanonicalName`. A change to name
  canonicalisation must keep it in step, or valid DNAMEs are refused.
