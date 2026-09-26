# ADR 0005 — Compression pointer cycle detection and expansion budget

- **Status**: accepted
- **Date**: 2026-09-26
- **Phase**: 1 — Wire codec

## Context

RFC 1035 §4.1.4 allows domain names to be compressed using 2-octet pointer sequences that
reference prior label offsets within the message buffer. Malicious or corrupt messages can
exploit name compression to mount denial-of-service attacks against a decoder in two
distinct ways:

1. **Cyclic pointer loops**: A pointer references itself or an ancestor pointer, creating
   an infinite loop.
2. **Acyclic quadratic expansion**: A message contains a web of valid, non-looping
   pointers where multiple names and suffixes repeatedly reference shared label chains. A
   crafted packet of a few hundred bytes can expand into megabytes of decompressed label
   data. Simple cycle detection (such as tracking visited offsets per name) fails to
   prevent this because no single pointer loops, yet CPU execution and heap allocations
   grow quadratically relative to packet size.

## Decision

**The decoder enforces both iterative cycle detection and an explicit expansion budget.**

- **Cycle detection**: An iterative pointer resolution loop maintains a bitset of visited
  byte offsets within each decompression pass. Re-visiting an offset within a single name
  decompression immediately halts and returns
  `DecodeError::CompressionLoopOrBudgetExceeded`.
- **Forward and self pointer rejection**: Pointers targeting an offset equal to or greater
  than their own wire location, or pointing past buffer boundaries, are rejected.
- **Expansion budget**: The decoder maintains an overall expansion budget per message,
  defaulting to `DEFAULT_EXPANSION_BUDGET = 4096` octets. Every decompressed label octet
  decrements this budget. If cumulative decompressed label bytes exceed the budget, the
  decoder aborts with `DecodeError::CompressionLoopOrBudgetExceeded`.

## Consequences

- Packets engineered to trigger algorithmic complexity or memory exhaustion attacks are
  deterministically rejected before allocating significant memory or consuming CPU cycles.
- Legitimate messages requiring more than 4096 octets of decompressed name data across all
  sections are rejected. Given that standard UDP packets are capped at 512 bytes (or
  typically 1232–4096 bytes with EDNS0) and full TCP messages are capped at 65535 bytes, a
  4096-byte budget offers ample headroom for genuine responses while strictly bounding
  quadratic expansion.
