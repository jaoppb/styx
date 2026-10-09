# ADR 0022 — Incomplete alias chains and the forwarder qname scope

- **Status**: accepted
- **Date**: 2026-10-08
- **Phase**: 4 — Answer cache
- **Extends**: [ADR 0017](0017-admission-time-bailiwick-validation-and-forgery-refusal.md),
  [ADR 0020](0020-recursor-failure-classification-and-qname-rooted-alias-scope.md)

## Context

Issue #77 reported that a forwarder's CNAME chain was cached without its target, so the
second query returned a bare CNAME. The chain walk of ADR 0020 had already fixed the
cause, but two things were left open.

A recursive upstream (a public resolver, a router) usually answers with an empty
authority section. `Bailiwick::of_response` then finds no SOA and no NS, and the
bailiwick zone degenerates to the qname. Nothing tested that case through the pipeline.

And nothing stopped a chain that leads nowhere from being stored. An answer that is a
CNAME with no record of the asked type behind it, served from cache, hands a stub a
CNAME with no address, and stubs do not follow chains themselves.

## Decision

**A forwarder's zone is the qname, and that is enough.** The answer scope of ADR 0020
admits each link's target and the records at it by walking the chain from the qname,
whatever zone answered. `www.example.com CNAME cdn.provider.net` is cached together with
`cdn.provider.net A`, and a record off that chain is still refused as `OutOfBailiwick`.

**A positive answer must end its chain in what was asked for.** The name the alias chain
ends at must hold a record of the asked type, or the answer must be a denial closed by an
SOA enclosing that name. Otherwise the whole answer is refused as
`RejectReason::IncompleteChain`: served to the client once and never stored. A question
about the alias itself (CNAME, DNAME) or about every type (ANY) is complete as answered.
A chain that loops back on itself has no ending and is never complete.

**Completeness is judged twice: as received, and on what admission kept.** Admission
drops an RRset whose TTL is zero, or that cannot be represented in the cache, after the
chain looked complete. What is left is a bare alias, an address nothing points to, or a
denial chain with no closing SOA. So once the sections are admitted, the answer is
rebuilt from the admitted RRsets and judged again; if it is no longer complete, nothing
of it is stored. The records that were dropped keep their own reason (`ZeroTtl`,
`Unstorable`), and the records that survived are labelled `IncompleteChain`.

**A refused answer is labelled by the rules of its own section.** The answer section is
held to the answer scope, the authority section to the SOA and NS rule, and the
additional section to the glue rule. A legitimate NS and its glue in an incomplete answer
are therefore labelled `IncompleteChain`, never `OutOfBailiwick`, so the forgery counter
stays a forgery signal. A record the answer had no standing to carry is still reported
as `OutOfBailiwick`.

**A refused answer is one event.** `AdmissionOutcome::refusal` carries the reason the
answer was refused whole, and `CacheStats::rejected_incomplete_chain` counts once per
such answer, including one whose records were all out of bailiwick. It logs one `debug`
line per answer with the number of records, not one per record.

**A positive response with no question is `MalformedResponse`.** It cannot be shown to
answer anything, so it is refused whole and labelled as what it is, not as an incomplete
chain.

## Consequences

- An upstream that answers an alias with no ending, or a NODATA after an alias with no
  SOA, costs one upstream query per request for that name, because nothing is stored.
- **Measured, once.** On 2026-10-08, 40 well-known CNAME-fronted names were asked for A
  and AAAA from 1.1.1.1, 8.8.8.8 and 9.9.9.9 (240 queries). Of the answers with an alias,
  51 per resolver ended in data and 17 per resolver in a denial with an enclosing SOA.
  None would have been refused: no dangling chain, no denial without an SOA, no zero
  TTL. That is a snapshot of three public resolvers, not of a router or an ISP
  forwarder, which is where an omitted SOA is most likely.
- `rejected_incomplete_chain` is the ongoing signal. If it grows against the number of
  upstream queries on a real deployment, the cost above is being paid and this rule
  should be revisited, not silently relaxed.
- `AdmissionOutcome` gains a public `refusal` field, and `RejectReason` gains
  `MalformedResponse` and `Unstorable`.
- `admission.rs` is split by concept: `admission_outcome.rs` holds the outcome types,
  `section_admission.rs` the per-section rules and the labelling of a refused answer, and
  `chain_denial.rs` is only predicates over a message and its answer scope.

## Known gap

`Admission::evaluate` reads the qname and qtype from the question the response echoes,
while the cache key comes from the client's question. They are expected to match, and
`CacheStage` builds the key from the client's question, but nothing in `Admission`
checks it. Checking it changes the public `evaluate` signature and every caller, and is
not part of this decision.

## Alternatives rejected

- **Cache the incomplete answer with a short fallback TTL.** It removes the cost above
  but invents a TTL RFC 2308 gives the SOA to supply, and a stored bare CNAME is the bug
  of #77.
- **Judge completeness only on the received message.** A zero-TTL link then leaves a
  half-cached chain, with the counter still at zero.
- **Refuse whenever any record of the chain was dropped.** It refuses answers whose
  dropped record does not belong to the chain, and the rule it states ("a chain lives as
  long as its shortest link") is not one the cache can check without rebuilding the
  chain anyway.
- **Edit ADR 0017 in place.** `AGENTS.md` says an ADR is never edited except by
  superseding it; this one is a new decision with a cost, so it is a new record.
