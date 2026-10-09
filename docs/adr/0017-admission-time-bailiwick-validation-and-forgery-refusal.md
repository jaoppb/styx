# ADR 0017 — Admission-time bailiwick validation and forgery refusal

- **Status**: accepted
- **Date**: 2026-09-27
- **Phase**: 4 — Answer cache

## Context

Cache poisoning (the Kaminsky attack and related variants) exploits DNS resolvers by
injecting unauthorized records into the authority and additional sections of responses.
A resolver serving an entire household must guarantee that out-of-bailiwick records never
contaminate subsequent resolutions.

Resolvers typically face a choice of when and where to enforce bailiwick checks:
at retrieval time (verifying records each time they are read from cache) or at admission
time (verifying records before they enter storage). Additionally, resolvers must decide
how to handle forged answers synthesized locally (such as local record overrides and
ad-blocking responses).

## Decision

**Enforce the bailiwick rule strictly at admission time on ingest into the store, apply
section-dependent validation rules, and categorically refuse forged answers.**

- **Admission-time gating**: `AnswerCache::admit` accepts an `AdmissionOutcome`, never a
  raw wire `Message`. Records failing bailiwick checks are recorded in
  `AdmissionOutcome::rejected` with `RejectReason::OutOfBailiwick` and are discarded before
  reaching storage.
- **Section strictness**:
  - *Answer section*: Admissible if the owner name matches the query name, or is reached
    via a CNAME/DNAME chain where every link is within bailiwick.
  - *Authority section*: Admissible only for SOA or NS records of a zone at or above the
    bailiwick zone.
  - *Additional section*: The strictest rule — address records (A/AAAA) are admitted only
    as glue for names at or below the zone whose NS records appeared in the authority
    section of the *same* response.
- **Partial admission**: A response containing both valid in-bailiwick records and invalid
  out-of-bailiwick records admits the valid subset and rejects the rest.
- **Refusal of forged answers**: `Admission::evaluate` explicitly rejects
  `AnswerSource::LocalRecord` and `AnswerSource::Blocked` with `RejectReason::ForgedAnswer`.

## Consequences

- No out-of-bailiwick data is ever stored in memory, eliminating retrieval-path
  vulnerabilities.
- Poisoning attempts can be directly asserted by inspecting store contents in unit and
  integration tests (verifying absence from the cache rather than merely absence from a
  single response).
- Every out-of-bailiwick rejection is explicitly tracked and observable via `CacheStats`
  counters and `tracing::warn` events.
- Legitimate in-bailiwick answers in mixed-validity responses remain usable.
