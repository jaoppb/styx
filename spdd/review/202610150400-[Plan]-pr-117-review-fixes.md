# PR #117 review fixes (issue #116)

**Status: implemented.** Deviations from the plan below are listed at the end.

Source: BGLuis's review of PR #117, posted 2026-10-15T03:50Z, after the last commit on
`bug/116` (`d1c35db`, 02:05Z). 11 inline comments plus a summary; none addressed yet.
Grilled 2026-10-15; the decisions below are the answers, in the words they settled on.

## Decisions

1. **A response refused for its question gets SERVFAIL**, not the upstream message and
   not silence. The stage reads the outcome's `refusal` instead of discarding it.
2. **The check covers the uncacheable (meta-type) path too.** `resolve_uncacheable` also
   SERVFAILs a reply that echoes another question, more than one, or none.
3. **One shared domain function owns the rules**
   (`check_question(&Question, &Message) -> Option<Refusal>`). `CacheStage` calls it on
   every upstream reply; `Admission::evaluate` still calls it, so the public type keeps
   its own guarantee (ADR 0023's claim stays true).
4. **Refusal evidence is one value**: `Refusal { reason, echoed: Arc<[Question]> }`, private
   fields with accessors, built in a single step. `Arc` and not `Rc` because the stage's
   futures run on tokio. If nothing clones an outcome, `Box<[Question]>` is equivalent.
   `AdmissionOutcome::echoed_questions` is deleted.
5. **`AdmissionOutcome` has private fields and read accessors**; `AnswerCache::admit`
   consumes it. The "cannot be stored under a key it was not judged for" guarantee becomes
   real (AGENTS.md: no setter that reopens an enforced-at-construction invariant).
6. **The error-rcode change (`b1c4e9c`) stays in #117 but becomes visible.** New
   `RejectReason::ErrorResponse`: the records of a SERVFAIL/REFUSED/FORMERR reply go into
   `rejected` with that reason, so they are counted. The test that pins `refusal == None`
   is updated. PR body and ADR describe the change under its own heading.
7. **One constructor**: `AdmissionRequest::new(question, ..)`. `for_key` is deleted;
   `resolve_and_admit` drops its `key` parameter and builds the request from `question`
   (one extra `CanonicalName` allocation per miss, accepted).
8. **Hot path**: `evaluate` takes the request by value so the key moves into the outcome
   (no clone); the bailiwick is computed lazily, only for the positive path.
9. **`RejectReason::MalformedResponse` is renamed `MultipleQuestions`**, so every use of
   the old meaning is forced into review.
10. **Logging**: a question-level refusal logs at `debug` per event with the echoed
    questions; the `CacheStats` counters are the aggregate signal. No rate limiter.
11. **ADR**: ADR 0023 declares what it supersedes in part of ADR 0022 (the Known-gap
    section and the `MalformedResponse` meaning), as ADR 0020 did for ADR 0017; 0022 is not
    edited. The "what RFC 9619 requires" wording becomes "consistent with / the
    conservative reading of"; the QDCOUNT = 0 half is justified by "styx always asks
    exactly one", not by the RFC.

## Plan

Each step is one commit, tests first (`superpowers:test-driven-development`).

1. **Regression tests that fail today.**
   - A named test for the exact #116 case: NODATA with an SOA and an empty question
     section is not admitted under the client's key.
   - `CacheStage`-level tests on the existing stage fixtures (`upstream_wiring_tests.rs`,
     `answer_cache_tests.rs`): an upstream echoing a wrong / two / no question yields
     SERVFAIL, a second identical query goes upstream again, the counters move.
   - Same for a meta-type (ANY) question through `resolve_uncacheable`.
   - A SERVFAIL carrying in-bailiwick records: a follow-up lookup misses.
2. **`Refusal` and `check_question`** in domain; rename `MalformedResponse` to
   `MultipleQuestions`; delete `echoed_questions`.
3. **Encapsulate `AdmissionOutcome`**: private fields, accessors, `admit(outcome)` by
   value; `evaluate(request)` by value; lazy bailiwick; delete `for_key`; drop the `key`
   parameter of `resolve_and_admit`.
4. **`RejectReason::ErrorResponse`** and the counter/record path for error replies.
5. **Stage policy**: map a question-level refusal to SERVFAIL on both paths. Call
   `evaluate` and `admit` first on the cacheable path so the counters still move, then
   return the error. Pick the `PipelineError` variant here.
6. **Logging**: move the refusal line to `debug`.
7. **Docs**: ADR 0023 (supersession, the SERVFAIL policy and its reach, the RFC wording,
   the error-rcode section); PR #117 body; sync the Phase 04 prompt with `spdd-sync`.
8. **`just gate`** green before pushing.

## Non-goals

- A general response-validation stage beyond the question check.
- The failing `gate` run on the push event (`AddrInUse` in `cname_chain_cache_tests`,
  untouched by this PR; the `pull_request` run passed). Separate port-flake issue.
- Rate-limited `warn` summaries per upstream.
- Changing `styx-proto`'s `Message.questions` to a shared pointer to avoid the one copy on
  the refusal path.

## Open questions

- **Counting refusals on the uncacheable path.** Counters live in `cache.admit`, which
  that path never reaches. Either add a counter outside the cache or leave these
  refusals visible only through the `debug` line. Trade-off: a new stat for a path where
  nothing is cached versus a refusal that SERVFAILs a client and leaves no aggregate
  signal.
- **`Arc<[Question]>` or `Box<[Question]>`**: decided by whether anything clones an
  outcome; check during step 2.

## Risks

- **Behaviour change for forwarders.** Extra questions after a matching first one pass
  `Do53Client`, so a forwarder doing this now yields SERVFAIL where it used to be served.
  The review calls the path unreachable only for the recursor.
- **Double check on the cacheable path** (stage and admission): cheap, but if the two
  copies ever diverge in rules. Mitigated by both calling the one function.
- **ADR 0023 is edited in place.** Acceptable because it is unmerged; once merged it is
  only changed by superseding.
- **The SERVFAIL returns before the pool learns anything** about the bad reply, so a
  misbehaving upstream keeps being selected. No health signal is wired in this PR.

## Deviations from the plan

- The cacheable path does not call `check_question` twice. The stage reads the refusal from
  admission's outcome after `admit`; only the uncacheable path calls the function directly.
- `ErrorResponse` records are recorded in `rejected` and logged nowhere and counted nowhere;
  there is no new counter.
- The open question about counting uncacheable-path refusals is closed as "log at `debug`,
  no counter" and recorded in ADR 0023.
- `Arc<[Question]>` was kept; nothing was measured to prefer `Box`.
- Accumulation during `evaluate` moved into a crate-private `Tally` so the key can move into
  the outcome at the end without a clone.
