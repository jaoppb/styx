# Issue #118: an untrusted reply counts against the member's health

**Status: implemented.** Deviations from the plan are listed at the end.

Source: issue #118, a follow-up to #117 (BGLuis's review comment on `cache_stage.rs`).
Grilled 2026-10-15; the decisions below are the answers, in the words they settled on.

## Problem

`CacheStage` turns a reply that does not answer the client's question into SERVFAIL
(`PipelineError::UntrustedResponse`), but only after `pool.resolve` has returned `Ok` and
recorded `Outcome::Success`. Three things follow, all from code as of `5211a10`:

- The member is credited with a success, and `record_success` resets its consecutive-failure
  count. A stage-side failure recorded afterwards would alternate with it
  (success, failure, success, ...) and never reach `failure_threshold`.
- `try_sequential` returns the `Ok` at once, so a healthy second member is never tried. Under
  `OrderedFailover` every client gets SERVFAIL while the bad member stays first.
- `execute_probe` records `Success` on any `Ok(_)` without looking at the reply, so a
  question-rewriting member passes its canary and is reinstated (Open to HalfOpen to Closed).

## Decisions

1. **A reply that does not answer the question is a failure of that member and the query
   fails over.** The pool judges the reply before it records an outcome. Sequential
   strategies try the next member within the deadline, fanout takes the first good reply,
   and the client gets SERVFAIL only when every member failed.
2. **A new styx-core variant carries the reason.** `UpstreamError` gains a variant for an
   untrusted reply (it classifies as `UpstreamFault`, so it trips the breaker). styx-core
   cannot name resolution's `RejectReason`, so the variant carries its own small reason
   type, and the pool maps `RejectReason` onto it.
3. **The aggregate signal is a per-member counter in the pool.** `HealthState` and
   `MemberView` gain a refused-reply count by reason, shown in `snapshot()`. It supersedes
   ADR 0023's claim that the `CacheStats` question counters are the aggregate signal.
4. **One shared judge, used by real dispatch, fanout and probes.** A single pool-owned
   function takes the question and the `Result<UpstreamResponse, UpstreamError>` and returns
   the judged result. `dispatch_member`, `collect_fanout_results` and `execute_probe` all
   call it, so a probe cannot reinstate a member that real traffic would reject.
5. **Only question-level refusals count as a member fault**: `QuestionMismatch` and
   `MultipleQuestions`, from the existing `check_question`. Record-level rejections
   (bailiwick, incomplete alias chain, error-rcode payload) stay admission's business.
6. **The stage's own question check is deleted**, along with
   `PipelineError::UntrustedResponse` and the `concerns_question` filter.
   `Admission::evaluate` keeps calling `check_question`, so the public type still holds its
   own guarantee and the cache never stores a bad reply. A bad reply now surfaces as
   `PoolError::Exhausted` (SERVFAIL, the same rcode as before).
7. **A new ADR (0024) records this**, superseding in part ADR 0023: its "becomes SERVFAIL"
   and "counted at the cache" decisions, and the Consequences line "no health signal is
   wired in this record; #118 tracks it". ADR 0023 is not edited. The `Upstream` port stays
   at three methods; nothing is added to it.

## Non-goals

- Feeding record-level admission rejections (bailiwick, forged chains) into health.
- Any new method on the `Upstream` port, or a feedback channel from the stage to the pool.
- Injecting the judge as a pluggable policy; it calls `check_question` directly.
- Rate-limited `warn` summaries per upstream (the circuit-opened `warn!` and the per-member
  counter are the signals).
- A per-query retry budget beyond the existing deadline.

## Open questions

- **Shape of the styx-core reason type.** Trade-off: a small enum in styx-core
  (`QuestionMismatch`, `MultipleQuestions`) duplicates the vocabulary of `RejectReason` and
  must be kept in sync, against a string, which loses the by-reason counter.
  The by-reason counter in decision 3 leans towards the enum. Confirm while planning.
- **Whether a refused reply feeds the SRTT.** `Failure { UpstreamFault }` takes no latency
  sample, which is the proposal. Trade-off: a member whose bad replies are fast looks no
  slower, and its latency is simply not learned from.

## Risks

- **Failover multiplies upstream load.** One client query can now hit every member when
  several rewrite the question. Bounded by the member list and the deadline, not by a budget.
- **Observability moves.** `rejected_question_mismatch` and `rejected_multiple_questions`
  stop moving on the production path and survive only for direct `Admission` callers.
  Anything alerting on them goes quiet.
- **A canary question a member answers legitimately but oddly** (for example NXDOMAIN with
  an empty question section) would now fail its probe and keep the member Open.
- **Behaviour change for forwarders** that echo extra questions: they now trip the breaker
  after `failure_threshold` such replies, where before they served SERVFAIL indefinitely.
- **Test fixtures.** Existing stage tests that assert `UntrustedResponse` must be rewritten
  against the pool, and the testkit's `MismatchedQuestion*` behaviours only cover a wrong
  first question, so a multiple-question behaviour has to be added.

## Deviations from the plan

- The tests were written after the implementation, not before it, so none was seen failing
  against the old code first. The old behaviour is established by reading `pool.rs` and the
  ADR 0023 stage tests it replaces, not by a red run.
- `RefusedReplies` is built by value (`with(reason)` returns a new tally) and reuses
  `FailureCount` for each saturating count; there is no `&mut` accessor.
- The fanout judges inside each spawned task, where the query clone already lives, so the
  collector needed no extra query.
- `record_span_outcome` takes `Option<&UpstreamError>` instead of `Option<FailureClass>`, so
  a refused reply reads `outcome = "untrusted_reply"` on its span.
- Both open questions are closed: the reason type is the enum, and a refused reply takes no
  SRTT sample.
