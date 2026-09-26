# ADR 0006 — EDNS(0) OPT pseudo-RR as a first-class Message field

- **Status**: accepted
- **Date**: 2026-09-26
- **Phase**: 1 — Wire codec

## Context

RFC 6891 defines Extension Mechanisms for DNS (EDNS0), specifying an `OPT` pseudo-Resource
Record transmitted within the Additional Data section.

On the wire, the OPT record shares the structural framing of a regular resource record
(NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA), but radically reinterprets standard fields:

- **NAME** must be the root domain (0).
- **TYPE** is 41 (`OPT`).
- **CLASS** is repurposed to encode the sender's maximum UDP payload size (e.g. 4096),
  rather than a network class (`IN`, `CH`).
- **TTL** is partitioned into bitfields carrying the upper 8 bits of the 12-bit extended
  RCODE, the EDNS version, the DNSSEC OK (`DO`) bit, and reserved zero bits.
- **RDATA** contains variable-length TLV-encoded options (`EdnsOption`).

RFC 6891 §6.1.1 mandates that at most one OPT record may appear in any DNS message.

If `Opt` were treated as an ordinary `ResourceRecord` with an `RData::OPT` variant stored
in `Message::additional`, downstream callers could accidentally read `record.class` as a
DNS class or `record.ttl` as a cache TTL. Furthermore, the presence of duplicate OPT
records would have to be checked by every consumer rather than enforced at the codec
boundary.

## Decision

**`Opt` is modeled as a distinct domain type and represented as `opt: Option<Opt>` directly
on `Message`.**

- During decoding, any OPT record in the additional section is parsed into `Opt`, assigned
  to `Message::opt`, and stripped from `Message::additional`.
- If more than one OPT record is detected during decode, the decoder immediately returns
  `DecodeError::MultipleOptRecords`.
- During encoding, if `Message::opt` is populated, the encoder serializes the OPT record
  into the wire additional section and increments the additional record count (`arcount`)
  transparently.
- Extended RCODE handling is cleanly separated: `Header::rcode` reflects the wire 4-bit
  RCODE, while `Header::split()` and `Header::from_parts()` compute and assemble the full
  12-bit `ResponseCode` across `Header` and `Opt`.

## Consequences

- `Message::additional` contains exclusively semantic resource records; callers cannot
  mistakenly query or manipulate pseudo-fields through generic RR accessors.
- RFC 6891's exactly-one OPT invariant is enforced at decode time, eliminating defensive
  checks in subsequent resolution and caching phases.
- Converting between wire framing and domain representation requires lifting on decode and
  injection on encode, introducing a minor structural transformation in the codec.
