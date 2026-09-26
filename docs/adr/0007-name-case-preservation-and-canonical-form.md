# ADR 0007 — Name case preservation and RFC 4034 canonical form

- **Status**: accepted
- **Date**: 2026-09-26
- **Phase**: 1 — Wire codec

## Context

RFC 1035 §2.3.3 establishes that domain names are compared case-insensitively. However,
two conflicting requirements dictate how case must be handled across the system:

1. **Case preservation**: In response messages, the Question section must reflect the
   exact casing used by the querying client (RFC 1035 §4.1.2). Modern resolvers also
   depend on preserving query casing to implement 0x20 bit randomisation
   (draft-vixie-dnsext-dns0x20) as an anti-spoofing defence against cache poisoning.
2. **Canonical lowercasing**: DNSSEC signature validation (RFC 4034 §6.1) requires that
   all domain names in signed RRsets and RRSIG records be converted to uncompressed,
   lowercased wire form before computing cryptographic hashes. Additionally, the Answer
   Cache (Phase 4) and Filter Matcher (Phase 8) require consistent hashing and lookup keys
   regardless of whether a domain was queried as `Example.COM` or `example.com`.

Normalizing domain names to lowercase on decode would destroy client query casing and
break 0x20 defences. Conversely, performing case-sensitive storage would risk cache
poisoning and duplicate entries.

## Decision

**`Name` preserves original wire casing while enforcing case-insensitive equality and
hashing, and `styx-proto` provides an explicit RFC 4034 canonical encoding mode.**

- **Preserved casing**: `Name` stores its constituent `Label` components exactly as
  received over the wire, preserving ASCII casing.
- **Case-insensitive comparison**: `PartialEq`, `Eq`, and `Hash` implementations for
  `Label` and `Name` operate case-insensitively using ASCII lowercase comparisons.
  `example.com` and `ExAmPlE.cOm` compare equal and hash to identical buckets.
- **Canonical encoding in Phase 1**: The codec provides an explicit canonical encoding
  mode (`Encoder::encode_canonical` and `Name::to_canonical_bytes`) that outputs names
  uncompressed and lowercased according to RFC 4034 canonical ordering rules.

## Consequences

- Full fidelity is preserved for client questions and future 0x20 randomisation schemes.
- The Answer Cache (Phase 4) and Filter Matcher (Phase 8) can index and look up names
  directly without manual pre-normalization.
- DNSSEC validation (Phase 6) does not require a separate or divergent wire encoder to
  generate canonical digests for RRSIG verification; the canonical path is built into the
  shared foundation codec from day one.
- Byte-level slice equality (`a.as_bytes() == b.as_bytes()`) cannot be used to compare
  domain names; comparisons must always use the `PartialEq` implementation.
