# ADR 0026 — A cancelled half-open trial releases its slot

- **Status**: accepted
- **Date**: 2026-10-16
- **Phase**: 3 — Upstream pool and Do53 forwarder
- **Supersedes in part**: [ADR 0014](0014-passive-ewma-and-circuit-breaker.md), one thing.
  Its `HalfOpen` mechanism, "a single probe query or trial request at a time
  (`in_flight: true`)", a flag that only a recorded outcome could clear. ADR 0014 carries only a
  superseded-by link; read it with this record.

## Context

`HealthState::try_admit` and `try_admit_probe` moved a recovering member to
`HalfOpen { in_flight: true }` before the query or probe was dispatched, and only
`Outcome` folding cleared the flag. Three paths drop a trial without recording anything:

- **A race loser.** `try_fanout` calls `set.abort_all()` once the first reply wins, and a
  half-open member among the losers is cancelled mid-flight.
- **The query deadline.** `Pipeline::race_deadline` drops the whole terminal future when
  `query_timeout` expires, and whatever trial was in flight goes with it.
- **A cancelled probe.** `ProbeScheduler::execute_probe` is dropped with its caller.

After any of these `is_available`, `try_admit` and `try_admit_probe` all refused the
member, and `HealthState::mark_half_open`, the only other writer of the flag, had no
caller. The member stayed out of rotation until the process restarted, with nothing
logged: one upstream fewer, silently and permanently (issue #79, a follow-up to the
single-trial flag added for #25).

## Decision

**A trial holds its slot through a guard that releases it on drop.**
`UpstreamPool::try_admit` and `try_admit_probe` return `Option<TrialGuard>` instead of
`bool`. Dropping the guard before the outcome is recorded puts the circuit back to
`HalfOpen` with no trial in flight, so the next query or probe may take the slot. A
probe that took the slot from `Open`, before the cool-down had elapsed, puts the circuit
back to that `Open`, so the cool-down it skipped is still owed.
`try_sequential`, `try_fanout` and `execute_probe` each hold the guard for the length of
the dispatch. The fan-out collector owns the guards of every member it admitted, not the
spawned tasks, so an abort and a dropped future both release them.

**A cancelled trial says nothing about the upstream.** Releasing counts no failure,
re-arms no cool-down, tallies no refused reply and takes no latency sample. A race loser
and a trial cut short by the query deadline are treated the same: the guard does not learn
why it was dropped.

**Each trial has an identity.** `CircuitState::HalfOpen { in_flight: bool }` becomes
`HalfOpen { trial: Option<TrialId> }`, `None` meaning no trial in flight. `HealthState`
mints a `TrialId` on every admission into `HalfOpen`, and `HealthState::release_trial`
frees the slot only when it still holds that identity. A guard whose trial already
recorded an outcome, or whose slot has since passed to a newer trial, therefore releases
nothing. That removes the need for a disarm call: every outcome clears the slot itself,
and a late guard is harmless. `CircuitAdmission { Regular, Trial(TrialId) }` is what the
admission methods return; `Regular` is a closed circuit, which holds no slot.

**`mark_half_open` is removed.** It had no caller, set `HalfOpen` without an identity and
reset `half_open_successes`, so it was a second way to reach the state this record makes
owned.

## Consequences

- A member can no longer be locked out by a cancelled trial under `race`, at the query
  deadline, or by a cancelled probe.
- A member that hangs forever is retried by the next query, because a deadline drop
  re-arms no cool-down. Each retry can spend the full `query_timeout`. If this shows up in
  practice, the follow-up is to re-arm `Open { since: now }` for deadline drops only,
  leaving race losses neutral.
- Under `race`, a recovering member that is always the slower racer is cancelled before it
  reports. It stays `HalfOpen` and is retried on every query without ever reaching
  `half_open_successes`: available, but never confirmed.
- Public surface: `CircuitState::HalfOpen` changes shape, so an external `match` on
  `in_flight` fails to compile. `TrialId`, `CircuitAdmission` and `TrialGuard` are added;
  `UpstreamPool::try_admit` and `try_admit_probe` change their return type;
  `HealthState::mark_half_open` is removed.

## Alternatives rejected

- **Keep the flag and reset it from a `Drop` guard.** A guard that outlives its trial can
  clear the flag of a newer one, for example when a slow trial is still cancelled after
  its member reopened and was admitted again, leaving two trials in flight.
- **Keep `TrialId` in `HealthState` and leave `HalfOpen` alone.** Smaller diff, but state
  and identity could then disagree. Putting the identity in the enum makes a free slot and
  an occupied one the only two states.
- **Re-arm `Open` when a trial is cancelled.** Never hammers a hung member, but a race
  winner would keep pushing a recovering member back for another cool-down, so under
  `race` a recovering member could never finish a trial while its peers are faster.
- **Record a `Cancelled` outcome.** It needs the caller to know the trial was cancelled,
  which is exactly what a dropped future cannot say.
