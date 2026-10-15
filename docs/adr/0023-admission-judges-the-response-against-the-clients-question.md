# ADR 0023 — Admission judges the response against the client's question

- **Status**: accepted
- **Date**: 2026-10-14
- **Phase**: 4 — Answer cache
- **Extends**: [ADR 0022](0022-incomplete-alias-chains-and-forwarder-qname-scope.md)

## Context

[ADR 0022](0022-incomplete-alias-chains-and-forwarder-qname-scope.md) recorded a known gap
(issue #116): `Admission::evaluate` read the qname and qtype from the question the
*response* echoed, while `CacheStage` stored the result under a `CacheKey` built from the
*client's* question. Nothing checked they match, and the `Bailiwick` the caller passed was
built from the client's question too. A response that echoed another question had its
records judged against that question and then stored under the client's key.

The denial path never looked at the echoed question at all, so a NODATA or NXDOMAIN with an
SOA and an empty question section was admitted under the client's key.

It was not reachable in production: `Do53Client` matches id and question, and the recursor
echoes the original question. But `Admission` is a public domain type, and the invariant was
enforced nowhere it is relied on.

## Decision

**`evaluate` takes an `AdmissionRequest`.** It is built from the client's `&Question`, the
response, its `AnswerSource` and `now`. Its constructor derives the `CacheKey` and the
`Bailiwick` from that question, so the key, the bailiwick and the question admission judges
against cannot disagree. The constructor is fallible: a meta-type question (ANY, AXFR, IXFR,
OPT) has no key and never becomes a request. `CacheStage` reuses the request's key for
`AnswerCache::admit`.

**The response must echo exactly the question that was asked.** The check runs after the
provenance check and before the denial/positive split, for every rcode:

- a response with more than one question is refused whole as
  `RejectReason::MalformedResponse`. [RFC 9619](https://www.rfc-editor.org/rfc/rfc9619)
  says a message with OPCODE 0 and QDCOUNT greater than 1 MUST be treated as incorrectly
  formatted;
- a response with no question, or whose one question differs from the client's in
  canonical qname (letter case ignored), qtype or qclass, is refused whole as the new
  `RejectReason::QuestionMismatch`. RFC 9619 does not call a missing question malformed
  (DNS Cookies are the case), but styx always asks exactly one, so a response that
  echoes none does not show it answers what was asked.

A refused response is served to the client once and never stored.

**A mismatch is loud.** `CacheStats::rejected_question_mismatch` counts once per answer and
the cache logs one `warn` for it. It means an upstream adapter broke the invariant the cache
relies on. `MalformedResponse` stays uncounted, as before.

**ANY is no longer handled in `Admission`.** A question about every type cannot be admitted,
so `chain_is_complete` no longer lists it.

## Consequences

- An upstream that echoes more than one question has its answers served but never cached,
  one upstream query per request. This is stricter than `Do53Client`, which accepts a
  response whose first question matches, but it is what RFC 9619 requires, and it is
  invisible because `MalformedResponse` is not counted. If it shows up on a real
  deployment, count `MalformedResponse` first; do not relax the rule silently.
- A FORMERR or other error response that omits its question is counted and logged as a
  question mismatch, though it is a server complaining rather than an adapter breaking an
  invariant. It carries nothing to cache either way.
- `Admission::evaluate`'s signature changes, `AdmissionRequest` and
  `RejectReason::QuestionMismatch` are public, and `CacheStats` gains a field.
- `Bailiwick::new` stays public but `evaluate` no longer accepts a caller-chosen bailiwick.

## Alternatives rejected

- **Pass the `CacheKey` alone.** It compares against exactly what the entry is stored
  under, but gives no question to derive the bailiwick from, leaving that disagreement
  open.
- **Pass a key and a question unchecked, or verified.** Two inputs that can only differ
  by a caller's mistake; deriving the key from the question makes the mistake
  unrepresentable.
- **Keep the question check on the positive path only.** It leaves the denial path admitting
  a response that answers nothing that was asked.
