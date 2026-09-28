# ADR 0019 — RFC 2308 negative caching with SOA TTL

- **Status**: accepted
- **Date**: 2026-09-27
- **Phase**: 4 — Answer cache

## Context

RFC 2308 specifies requirements for DNS negative caching (storing and re-serving NXDOMAIN
and NODATA responses). Clients frequently issue repeated queries for nonexistent domains or
unsupported record types (e.g. AAAA queries on IPv4-only domains). Forwarding every
repeated query upstream wastes bandwidth and adds unnecessary latency.

However, caching negative responses poses unique risks:

1. NXDOMAIN (nonexistent domain) and NODATA (domain exists, but requested type does not)
   mean different things and must be distinguished when synthesizing cached responses.
2. Negative responses carry no answer records, so their lifetime cannot be taken from an
   answer TTL.
3. Unclamped negative TTLs can allow a misconfigured or malicious zone to inflict prolonged
   denial of service against legitimate domains.

## Decision

**Implement RFC 2308 negative caching storing NXDOMAIN and NODATA as distinct entries,
derive negative lifetimes strictly from the authority SOA record, and clamp to a negative
TTL ceiling.**

- **Distinct denial kinds**: `NegativeEntry` models `DenialKind::NxDomain` and
  `DenialKind::NoData` explicitly. When synthesizing a cached response, `to_response` sets
  RCODE `NXDOMAIN` for nonexistent names, and RCODE `NOERROR` with an empty answer section
  for NODATA.
- **Mandatory SOA**: Negative caching requires the presence of an SOA record in the
  authority section of the denial response. Denials lacking an SOA are answered but
  discarded (`RejectReason::NoSoaInDenial`).
- **TTL calculation**: The effective negative TTL is computed per RFC 2308 as
  `min(soa.ttl, soa.rdata.minimum)`, clamped by `TtlPolicy::negative_ceiling` (default
  300s).
- **Independent keying**: Because keys are `(qname, qtype, qclass)`, a NODATA entry for one
  record type (e.g. AAAA) does not suppress or mask positive entries for other types (e.g.
  A) at the same owner name.

## Consequences

- Prevents negative query floods and protects upstream bandwidth while respecting RFC
  2308.
- Synthesized negative responses accurately recreate the original DNS response codes and
  authority sections with recomputed remaining TTLs.
- Stale or broken negative responses are bounded by the negative ceiling clamp.
- Queries for negative responses lacking authoritative SOA justification are not cached,
  preventing ambiguous or unauthenticated state pollution.
