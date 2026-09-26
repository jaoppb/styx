# ADR 0004 — Decoded domain types are owned, not zero-copy borrowed views

- **Status**: accepted
- **Date**: 2026-09-26
- **Phase**: 1 — Wire codec

## Context

In high-throughput network applications, zero-copy deserialization (borrowing `&'a [u8]`
slices directly from the incoming packet buffer) is frequently chosen to eliminate memory
allocations on the request path.

In DNS, however, names are compressed using pointer offsets (RFC 1035 §4.1.4). As a
result, domain names in a wire packet are rarely contiguous in memory. Representing a
borrowed compressed name requires either a custom rope structure or eager decompression.
Furthermore, lifetime annotations on borrowed slices would permeate the entire domain
model and every downstream crate.

Most crucially, downstream subsystems in styx retain DNS records far longer than the
ephemeral lifecycle of an inbound UDP or TCP packet buffer:

- **Answer Cache (Phase 4)** caches parsed `Message` and `ResourceRecord` entries for the
  duration of their TTL — seconds to days beyond the packet buffer's lifetime.
- **Filter Matcher (Phase 8)** evaluates names against memory-resident adlists and rule
  tries.
- **Query Log (Phase 10)** asynchronously dispatches query and answer records across an
  actor channel.

If domain types borrowed from the wire buffer, every cached, filtered, or logged message
would require an explicit conversion into an owned counterpart, or else force packet
buffers to remain pinned in memory.

Finally, styx's stated posture is correctness first on a home network (targeting a
Raspberry Pi), rather than maximum throughput for a high-volume authoritative server.

## Decision

**All decoded domain types (`Message`, `Name`, `Label`, `ResourceRecord`, `RData`, `Opt`)
are fully owned structures.**

- `Name` owns its sequence of labels (`Vec<Label>`).
- `Label` owns its octets in a bounded array representation.
- Variable-length record data (such as `TXT` character-strings and unknown RR payload
  octets) owns its storage (`Vec<u8>`).

## Consequences

- Packet decoding incurs allocation overhead for names, record vectors, and
  variable-length RDATA.
- Downstream subsystems (`cache`, `resolution`, `filtering`, `telemetry`) can store,
  transfer, and cache domain types across thread and task boundaries without lifetime
  contagion.
- Cached records can be stored directly without an intermediate copying or transformation
  step.
- If profiling in cutover hardening (Phase 12) demonstrates that decode-time allocation is
  a critical bottleneck under home network load, this decision can be superseded with
  targeted arena allocators or small-buffer optimizations without altering domain
  ownership semantics.
