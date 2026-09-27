# ADR 0010 — Request pipeline ordering and DNSSEC honesty for forged answers

- **Status**: accepted
- **Date**: 2026-09-26
- **Phase**: 2 — Server loop and test harness

## Context

A filtering DNS resolver processes client requests across distinct stages: query
syntax validation, local record matching, blocklist filtering, cache evaluation,
upstream forwarding or recursion, and terminal fallback.

The execution ordering of these stages is a correctness and security property:

1. **Ordering integrity**:
   - Local records must be evaluated before caching and upstream resolution to
     ensure authoritative local definitions take immediate precedence without
     waiting for external cache eviction.
   - Filtering policies must execute before caching and upstream queries to
     prevent blocked domains from generating outbound network traffic or leaking
     through cache hits.
   - The answer cache must precede upstream resolution to short-circuit repeated
     lookups.

2. **DNSSEC honesty on synthetic/forged answers**:
   - Both local records and filter block verdicts produce synthetic DNS answers
     directly within the resolver without consulting authoritative zone servers.
   - RFC 4035 §3.2.2 dictates that a security-aware resolver must never assert
     the Authenticated Data (`AD`) bit on responses that have not been validated
     against cryptographic trust chains.
   - Synthesizing bogus RRSIG signatures or asserting the `AD` bit on local
     records or block responses misleads downstream validating stub resolvers
     (causing SERVFAIL errors, as reported in pi-hole#2686) and violates DNSSEC
     integrity.
   - Synthetic answers must never be inserted into the shared answer cache, as
     they are not authentic public zone records.

## Decision

**Enforce a strict stage execution order in `Pipeline` and mandate DNSSEC honesty
for all forged answers via `ForgedAnswer::build`.**

- **Fixed stage order**: The resolution pipeline in
  `styx_resolution::application::Pipeline` strictly enforces:
  `validation -> local_records -> filter -> cache -> upstream -> terminal`
- **Short-circuiting**: A match in `local_records` or a block verdict in `filter`
  immediately terminates resolution and bypasses downstream stages (cache and
  upstream).
- **DNSSEC honesty invariants**: Synthetic responses constructed by
  `ForgedAnswer::build` enforce:
  - The `AD` (Authenticated Data) header flag is explicitly cleared (`0`).
  - No synthetic or forged RRSIG signatures are attached.
  - The resolution outcome is classified as `ResolutionOutcome::ForgedLocal` or
    `ResolutionOutcome::Blocked`, ensuring the response is marked uncacheable
    and never reaches the answer cache or validator.

## Consequences

- The pipeline ordering is structural and consistent across all query types.
- Downstream validating clients correctly observe synthetic responses as
  unauthenticated/insecure without cryptographic verification failures.
- Local records configured under signed public domains (e.g. `nas.example.com`)
  remain Insecure by design; validating clients querying such names under DNSSEC
  validation will reject them if a parent DS record exists, an accepted
  protocol consequence documented for local records.
- Synthetic block and local responses are isolated from the answer cache,
  preventing cache pollution.
