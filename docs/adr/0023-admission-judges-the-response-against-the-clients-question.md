# ADR 0023 — Admission judges the response against the client's question

- **Status**: accepted
- **Date**: 2026-10-14
- **Phase**: 4 — Answer cache
- **Extends**: [ADR 0022](0022-incomplete-alias-chains-and-forwarder-qname-scope.md)
- **Supersedes in part**: [ADR 0022](0022-incomplete-alias-chains-and-forwarder-qname-scope.md),
  two things. Its "Known gap" section is closed by this record, and its statement that
  "a positive response with no question is `MalformedResponse`" no longer holds: that case is
  `QuestionMismatch`, and `MalformedResponse` is renamed `MultipleQuestions` and means a
  response with more than one question. ADR 0022 is not edited; read it with this record.

## Context

[ADR 0022](0022-incomplete-alias-chains-and-forwarder-qname-scope.md) recorded a known gap
(issue #116): `Admission::evaluate` read the qname and qtype from the question the
*response* echoed, while `CacheStage` stored the result under a `CacheKey` built from the
*client's* question. Nothing checked they match, and the `Bailiwick` the caller passed was
built from the client's question too. A response that echoed another question had its
records judged against that question and then stored under the client's key.

The denial path never looked at the echoed question at all, so a NODATA or NXDOMAIN with
an SOA and an empty question section was admitted under the client's key.

It was not reachable in production for the recursor: `Do53Client` matches id and the
first question, and the recursor echoes the original question. It was reachable for a
forwarder whose reply carries a matching first question followed by more, and for any
adapter behind the `Upstream` port that does not go through `Do53Client`. `Admission` is
a public domain type, and the invariant was enforced nowhere it is relied on.

## Decision

**`evaluate` takes an `AdmissionRequest` by value.** It is built by
`AdmissionRequest::new` from the client's `&Question`, the response, its `AnswerSource`
and `now`, and that is the only constructor. The constructor derives the `CacheKey` from
the question, so the key and the question admission judges against cannot disagree, and
the bailiwick is derived from the key's name and the response only on the positive path
that uses it. The constructor is fallible: a meta-type question (ANY, AXFR, IXFR, OPT)
has no key and never becomes a request. `CacheStage` therefore derives the key a second
time on a cache miss, one `CanonicalName` allocation beside an upstream round trip,
rather than passing a key and a question that could differ.

**The outcome carries its key, and cannot be rebound.** `evaluate` returns an
`AdmissionOutcome` that holds the `CacheKey` it was judged for, moved in from the
request without a copy. Its fields are private and read through accessors (`key`,
`admitted`, `rejected`, `refusal`), and `AnswerCache::admit` consumes the outcome and
stores under that key. A caller outside the crate can neither build an outcome nor
change its key, so an outcome cannot be stored under a key it was not judged for. That
the response echoes the client's question is still a runtime check, since the response
comes off the network.

**One function owns the question rules.** `check_question(question, message)` returns a
`Refusal`, or nothing. It judges NOERROR and NXDOMAIN, the only rcodes that speak for
the question; any other rcode (SERVFAIL, REFUSED, FORMERR) may omit its question
legitimately and is never judged by it:

- a response with more than one question is refused whole as
  `RejectReason::MultipleQuestions`. The conservative reading of [RFC
  9619](https://www.rfc-editor.org/rfc/rfc9619), which says a message with OPCODE 0 and
  QDCOUNT greater than 1 MUST be treated as incorrectly formatted, is that nothing is
  cached from it. The RFC states that rule for a server receiving such a message and
  says nothing about caching, and its Appendix A.5 gives no guidance for interpreting
  such a response, so this is consistent with it and not required by it;
- a response with no question, or whose one question differs from the client's in qname
  (letter case ignored), qtype or qclass, is refused whole as
  `RejectReason::QuestionMismatch`. Styx always asks exactly one question, so a response
  that echoes none does not show it answers what was asked. (RFC 9619 does not call a
  missing question malformed, since DNS Cookies use that shape; the reason here is only
  what styx sends.)

A `Refusal` is the reason together with the questions the response echoed
(`Refusal::echoed`), built in one step, so the evidence cannot go stale against the
reason.

**A reply that does not answer the question is not handed to the client: it becomes
SERVFAIL.** `CacheStage` returns `PipelineError::UntrustedResponse`, which maps to
SERVFAIL, when a reply is refused for its question. The proxy does not vouch for a
message it has just judged it cannot trust, and RFC 9619 gives no guidance for relaying
one. This covers both paths:

- on the cacheable path, `Admission::evaluate` runs the check and the stage reads the
  outcome's refusal after `admit`, so the counters move and nothing is stored;
- on the uncacheable path (ANY, AXFR, IXFR, OPT), which never reaches admission, the stage
  calls `check_question` itself, so the same reply gets the same answer.

`Admission::evaluate` keeps calling `check_question` too, so the public type holds its
guarantee for a caller that is not the stage. The rules live once, in the function.

**A mismatch is counted and logged at `debug`.**
`CacheStats::rejected_question_mismatch` and `CacheStats::rejected_multiple_questions`
count once per answer. The cache logs one `debug` line per refusal naming the echoed
questions. Their data is controlled by the upstream, and a resolver that rewrites the
question on every reply would otherwise log once per query at `warn`, so the counters
are the aggregate signal. A refusal on the uncacheable path is logged the same way but
has no counter, since the cache never sees it.

**An error reply is recorded, not silently dropped.** A SERVFAIL, REFUSED or FORMERR
reply admits nothing, because section admission ignores the rcode and would otherwise
cache its records. Each of its records is recorded as rejected with
`RejectReason::ErrorResponse`, with no refusal and no counter. The cache logs one
`debug` line per record, so an upstream that starts answering SERVFAIL with a payload
shows up in the log and nowhere else.
This is a behaviour change beyond #116, kept in this record because the question check
must skip error rcodes and the two are one decision about which rcodes speak for the
question.

**An ineligible source is refused whole.** A forged (`LocalRecord`, `Blocked`) or
inadmissible (`CacheHit`, `Error`) source now sets the outcome's refusal, like every other
early-out that stops admission, so a refusal means nothing from the response was admitted.

**ANY is no longer handled in `Admission`.** A question about every type cannot be
admitted, so `chain_is_complete` no longer lists it.

## Consequences

- An upstream that echoes more than one question, or another one, now gets SERVFAIL
  where its reply used to be served. For a forwarder this is a visible change. It shows
  up in `rejected_multiple_questions` and `rejected_question_mismatch`; do not relax the
  rule silently.
- The SERVFAIL is returned to the client without telling the upstream pool anything
  about the bad reply, so a misbehaving upstream keeps being selected. No health signal
  is wired in this record; #118 tracks it.
- Refusals on the uncacheable path are logged at `debug` and not counted.
- `Admission::evaluate`'s signature changes, `AnswerCache::admit` loses its key parameter,
  `AdmissionRequest`, `Refusal`, `check_question`, `PipelineError::UntrustedResponse` and
  `RejectReason::{QuestionMismatch, MultipleQuestions, ErrorResponse}` are public, and
  `CacheStats` gains two fields.
- `RejectReason::MalformedResponse` is gone. It was renamed to `MultipleQuestions`
  rather than kept, so every user of the old meaning ("no question") fails to compile
  and is reviewed.
- `Bailiwick::new` stays public but `evaluate` no longer accepts a caller-chosen
  bailiwick.
- Checking the question twice on the cacheable path is avoided: the stage reads
  admission's result and does not call `check_question` again.

## Alternatives rejected

- **Serve the reply and only keep it out of the cache.** It protects the cache but not
  the client, and it makes "served once, never stored" an accident of the code's shape
  instead of a decision.
- **Drop the reply.** The client times out and retries the same upstream round trip.
- **Pass the `CacheKey` alone.** It compares against exactly what the entry is stored
  under, but gives no question to check the response against.
- **Pass a key and a question unchecked, or verified.** Two inputs that can only differ
  by a caller's mistake; deriving the key from the question makes the mistake
  unrepresentable.
- **Keep a second constructor that accepts a ready-made key.** It saves one allocation per
  miss and reopens the hole: the invariant would hold of the tests and not of the stage.
- **Public outcome fields.** `partial_pub_fields` forces all-or-none, and all-public lets any
  caller rebind the key after judgement, so the guarantee was documentation only.
- **Move the question check out of `Admission` into the stage.** One policy for both paths,
  but `Admission` is public and would again accept a response for another question.
- **Keep the question check on the positive path only.** It leaves the denial path admitting
  a response that answers nothing that was asked.
