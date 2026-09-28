# ADR 0016 — Answer cache global key and egress filtering

- **Status**: accepted
- **Date**: 2026-09-27
- **Phase**: 4 — Answer cache

## Context

`styx` enforces per-client and per-group blocking policies (Phase 8), with clients,
groups, and adlists modeled as first-class domain concepts. A natural design inclination
when introducing an answer cache in a multi-tenant or group-aware resolver is to namespace
the cache per group (or include the client/group identity in the cache key).

However, `styx` targets single-process home network deployments (such as a Raspberry Pi).
Multiplying cached DNS state across $N$ client groups would multiply memory consumption by
$N$ and fragment the cache, severely degrading the cache hit rate. Furthermore, DNS
answers from upstream authoritative nameservers or recursors are universally identical
regardless of which client queried them.

## Decision

**The answer cache remains strictly global, indexed only by `(qname, qtype, qclass)`
without client, group, or client-subnet dimensions; group policy is evaluated as an egress
filter on the way out.**

- **Key dimensions**: `CacheKey` contains `CanonicalName`, `RecordType`, and `RecordClass`
  only. No client identifiers, group bitmasks, or EDNS Client Subnet (ECS) scope prefixes
  are incorporated into the key.
- **Egress filtering**: Filtering policy is applied over the resolution result *after*
  cache retrieval, prior to responding to the client. The per-group verdict is evaluated
  via a fast bitmask walk (`!(allow & g) && (block & g)`).
- **Prohibition on caching forged responses**: Responses synthesized by local records or
  blocking policies are forged answers and are categorically barred from entering the
  global cache.

## Consequences

- Cache hit rates are maximized across all household devices querying identical domains.
- Memory consumption remains strictly bounded and independent of the number of configured
  client groups or client devices.
- Because forged blocked answers never enter the cache, unblocking a domain takes effect
  immediately on subsequent queries without requiring a cache flush.
- Group filtering must run on every cache hit before returning the message to the client,
  adding a negligible bitmask check on the retrieval path.
