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
OPT) has no key and never becomes a request. `CacheStage`, which already derived the key
for its lookup, hands it to `AdmissionRequest::for_key` instead of deriving it again.

**The outcome carries its key.** `evaluate` returns an `AdmissionOutcome` that holds the
`CacheKey` it was judged for, and `AnswerCache::admit` takes the outcome alone and stores
under that key. A caller cannot admit an outcome under a key it was not judged for. That the
response echoes the client's question is still a runtime check, since the response comes off
the network; the types only make it impossible to skip or to run against another key.

**The response must echo exactly the question that was asked.** The check runs after the
provenance check and before the denial/positive split, for NOERROR and NXDOMAIN, the only
rcodes admission judges. Any other rcode (SERVFAIL, REFUSED, FORMERR) returns before it with
nothing admitted, since an error reply may omit its question legitimately and carries
nothing to cache:

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
the cache logs one `warn` for it, naming the questions the response echoed
(`AdmissionOutcome::echoed_questions`). It means an upstream adapter broke the invariant the
cache relies on, so it is not rate limited: the counter is the aggregate signal and the log
is for the rare bug. `MalformedResponse` is counted too, by
`CacheStats::rejected_malformed_response`, but logged at `debug`, since it is the upstream's
fault and not a broken invariant.

**An ineligible source is refused whole.** A forged (`LocalRecord`, `Blocked`) or
inadmissible (`CacheHit`, `Error`) source now sets `AdmissionOutcome::refusal`, like every
other early-out that stops admission, so `refusal.is_some()` means nothing from the response
was admitted.

**ANY is no longer handled in `Admission`.** A question about every type cannot be admitted,
so `chain_is_complete` no longer lists it.

## Consequences

- An upstream that echoes more than one question has its answers served but never cached,
  one upstream query per request. This is stricter than `Do53Client`, which accepts a
  response whose first question matches, but it is what RFC 9619 requires. It shows up in
  `rejected_malformed_response`; do not relax the rule silently.
- An error reply no longer reaches `SectionAdmission`: before, a SERVFAIL carrying
  in-bailiwick records could have them cached, because section admission ignores the rcode.
- `Admission::evaluate`'s signature changes, `AnswerCache::admit` loses its key parameter,
  `AdmissionRequest` and `RejectReason::QuestionMismatch` are public, and `CacheStats`
  gains two fields.
- `AdmissionOutcome` has public fields, so `key` is public too; it is set once by `evaluate`
  and nothing in the crate writes it afterwards.
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
