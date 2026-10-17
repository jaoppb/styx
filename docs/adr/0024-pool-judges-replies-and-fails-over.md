# ADR 0024 — The pool judges each reply against the question and fails over

- **Status**: accepted
- **Date**: 2026-10-15
- **Phase**: 3 — Upstream pool and Do53 forwarder
- **Extends**: [ADR 0023](0023-admission-judges-the-response-against-the-clients-question.md),
  [ADR 0014](0014-passive-ewma-and-circuit-breaker.md)
- **Supersedes in part**: [ADR 0023](0023-admission-judges-the-response-against-the-clients-question.md),
  three things. Its decision that a reply refused for its question "becomes SERVFAIL" at
  `CacheStage` as `PipelineError::UntrustedResponse`, its decision that the `CacheStats`
  question counters are the aggregate signal, and its Consequences line "no health signal
  is wired in this record; #118 tracks it". ADR 0023 is not edited; read it with this record.

## Context

[ADR 0023](0023-admission-judges-the-response-against-the-clients-question.md) made
`CacheStage` answer SERVFAIL when an upstream reply does not answer the client's question.
It did so after `UpstreamPool::resolve` had returned `Ok`, and the pool had already recorded
`Outcome::Success` for the member. Issue #118 asked for that reply to count against the
member's health. Three facts about the code made a feedback call from the stage insufficient:

- `record_success` resets the consecutive-failure count, so a failure recorded afterwards
  alternates with it (success, failure, success, ...) and never reaches `failure_threshold`.
- `try_sequential` returns the first `Ok`, so a healthy second member was never tried and,
  under `OrderedFailover`, every client got SERVFAIL while the bad member stayed first.
- `ProbeScheduler::execute_probe` recorded `Success` on any `Ok(_)`, so a member that
  rewrites the question passed its canary and was reinstated from Open.

The `Upstream` port is fixed at three methods ([ADR 0012](0012-unified-upstream-port.md)),
and has no way to report a bad reply back.

## Decision

**The pool judges the reply before it records an outcome.** `reply_judge::judge_reply` runs
the existing `check_question` on an `Ok` reply and turns a refusal into
`UpstreamError::UntrustedReply`. One function is used by `dispatch_member`, by each task of a
raced fanout, and by `execute_probe`, so real traffic, a race and a probe cannot disagree
about what a member may be credited for. An error from the upstream passes through untouched.

**A refused reply is an upstream fault of that member, and the query fails over.**
`UntrustedReply` classifies as `FailureClass::UpstreamFault`. Sequential strategies try the
next member within the deadline, a fanout takes the first good reply, and the client gets
SERVFAIL (through `PoolError::Exhausted`) only when every member failed. The rcode a client
sees when every member is bad is unchanged.

**`styx-core` carries the reason.** `ReplyFault { QuestionMismatch, MultipleQuestions }` is a
small enum in `styx-core`, which cannot name resolution's `RejectReason`.
`RejectReason::reply_fault` maps the two question reasons onto it and returns `None` for all
others; it replaces `RejectReason::concerns_question`.

**Health records it once and tallies it by reason.** `Outcome::Refused { reason, was_probe }`
is folded as an upstream fault with no latency sample. `HealthState` owns a `RefusedReplies`
tally (one saturating count per `ReplyFault`), and `MemberView::refused_replies` shows it in
`UpstreamPool::snapshot()`. This is the per-member aggregate signal: it says which member
misbehaves, which the global cache counters never could.

**Only question-level refusals count.** Record-level rejections (out of bailiwick, incomplete
alias chain, error-rcode payload) remain admission's business. They can be legitimate
name-specific behaviour, and judging them in the pool would put the cache's `TtlPolicy` and
`AnswerSource` on the dispatch path.

**The stage's own check is deleted.** `CacheStage` no longer calls `check_question`,
`PipelineError::UntrustedResponse` is gone, and the stage runs `admit` on every reply as
before. `Admission::evaluate` keeps calling `check_question`, so the public type still holds
its own guarantee and the cache cannot store a reply for another question.

**A refusal is logged at `debug`** by the judge with the member and the echoed questions, as
the stage did. A circuit that opens still logs `warn`.

## Consequences

- A member that echoes another, no, or several questions now fails over for the query and
  trips its breaker after `failure_threshold` such replies. Before, it stayed selected and
  served SERVFAIL indefinitely.
- A canary probe is judged like real traffic: a rewriting member stays Open instead of flapping
  Open to HalfOpen to Closed. A canary answered legitimately but with an odd question section
  keeps its member Open.
- `CacheStats::rejected_question_mismatch` and `rejected_multiple_questions` no longer move on
  the production path, since a refused reply never reaches admission. They still move for
  a direct caller of `Admission`. Anything alerting on them must read
  `MemberView::refused_replies` instead.
- Failover can multiply upstream load when several members rewrite the question. It is bounded
  by the member list and the deadline, not by a budget.
- Public surface: `ReplyFault`, `UpstreamError::UntrustedReply`, `Outcome::Refused`,
  `RefusedReplies` and `MemberView::refused_replies` are added; `PipelineError::UntrustedResponse`
  and `RejectReason::concerns_question` are removed. A `match` on `Outcome` or `UpstreamError`
  elsewhere fails to compile until it chooses an arm.
- The `Upstream` port is unchanged.

## Alternatives rejected

- **Keep SERVFAIL and call back into the pool from the stage.** The success is already
  recorded, so the sequence alternates and the breaker never trips, and the first queries
  per cooldown still fail for clients.
- **A new method on the `Upstream` port to report a bad reply.** Widens a port every forwarder,
  recursor and test double implements, to carry a verdict the pool can reach itself.
- **Keep the stage check as defence in depth.** The pool always fails over first, so it cannot
  be exercised through real wiring and the same rule would run twice per miss. ADR 0023
  rejected duplicated ownership of this rule for the same reason.
- **Reuse `UpstreamError::Mismatched`.** No change to `styx-core`, but it loses which of the
  two reasons applied, which the per-member tally needs.
- **Feed the cache counters from the pool.** Couples the pool to the cache, and the counters
  stay global with no per-member attribution.
- **Judge bailiwick and forgery rejections in the pool too.** Requires running `Admission` on
  the dispatch path; left to a follow-up if wanted.
- **Leave probes transport-only.** A rewriting member would flap, and the next probe would
  erase the signal this record adds.
