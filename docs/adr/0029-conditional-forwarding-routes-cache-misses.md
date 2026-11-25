# ADR 0029 — Conditional forwarding is file-owned and routes cache misses by suffix

- **Status**: accepted
- **Date**: 2026-11-24
- **Phase**: 3 — Upstream pool and Do53 forwarder
- **Extends**: [ADR 0012](0012-unified-upstream-port.md),
  [ADR 0016](0016-answer-cache-global-key-and-egress-filtering.md)

## Context

The pool picks a member per query, never per name, so every question went to the same
upstreams. On a home network the router that runs DHCP owns the local names (`*.lan`,
`*.home.arpa`) and the LAN's reverse zone (`1.168.192.in-addr.arpa`). Sent to a public
upstream, those names leak and come back NXDOMAIN, and the query log shows addresses
instead of hostnames. Pi-hole (`dns.revServers`), AdGuard Home (`[/domain/]` upstreams),
Technitium (Conditional Forwarder zones) and Blocky (`conditional.mapping`) all route by
name (issue #96).

Issue #96 proposed a pipeline stage between the filter and the cache that dispatches to a
small pool, and also asked that the answers be cached like any other. A stage before the
cache that resolves a question skips the cache, so the two cannot both hold as written.

## Decision

**Conditional forwarding is infrastructure, owned by the TOML file.** Entries live under
`[upstream]` as `[[upstream.conditional]]`, each a `domains` list and its
`[[upstream.conditional.members]]`. Phase 9's boundary puts "upstreams and pools" in the
file, and a conditional entry is an upstream pool for some names, so it belongs there. It
is not a local-records concern: local records answer from rows, while a conditional entry
asks a server that learns names at run time from its own DHCP leases. Changing one needs a
restart, like any other upstream.

**Each entry is its own `UpstreamPool`.** Its members reuse the pool member schema and are
built by the same factory, but only forwarders are accepted: a recursor walks down from
the root, which knows nothing of private names. The pool uses `ordered_failover`, and the
circuit and probe settings of `[upstream]`. The binary runs one `ProbeScheduler` per pool,
so each conditional member's health is tracked like a main member's. `query_timeout_secs`
must outlast the conditional members' timeouts as well.

**Routing happens in `CacheStage`, on a cache miss.** `CacheStage::with_conditional` takes a
`ConditionalRoutes` table, and a miss asks the pool of the route whose domain is the longest
suffix of the question name, or the main pool when none matches. An uncacheable question
(`ANY`, `AXFR`, `IXFR`, `OPT`) is routed the same way by `CacheStage::resolve_uncacheable`.
The stage order of ADR 0010 and ADR 0028 is unchanged. The reply judgement of ADR 0024
still runs inside whichever pool answers, and everything after the pool call applies
unchanged too: admission and bailiwick checks of ADR 0017 and ADR 0023, and the global
cache key of ADR 0016. A name has one route, so a cached answer was always asked of the
same pool that would be asked again.

**A domain appears once, and the root and `*` labels are refused.** A domain repeated,
whether across entries or within one, is refused in any letter case. Distinct domains make
the longest match unique; the root as a domain would replace `[upstream].members`; a `*`
label would match only a literal `*`, since a domain already covers every name below it.
An entry with an empty `domains` or `members` is refused, since it routes nothing or
routes to no one. A member `weight` is refused too, because members are tried in order and
it would have no effect.

## Consequences

- A file with no `[[upstream.conditional]]` behaves exactly as before: the table is empty
  and every miss goes to the main pool.
- When every member of a conditional pool fails, the client gets SERVFAIL. The name never
  falls back to the main pool, which would leak it.
- A conditional answer can outlive a change on the router by up to its TTL, as any cached
  answer can.
- The locally served zones of RFC 6303 (#97) must check this table first, so a configured
  reverse zone wins over the built-in NXDOMAIN.
- Public surface: `PoolConfig` gains the field `conditional`, so a struct literal of it
  stops compiling; `ConditionalConfig`, `ConditionalRoute`, `ConditionalRoutes` and
  `CacheStage::with_conditional` are new.

## Alternatives rejected

- **A pipeline stage before the cache, as the issue proposed.** It skips the cache for
  every local name and duplicates the stage's admission path.
- **Members tagged with domains inside one pool.** Selection, failover and the circuit
  would have to filter members by name on every query, and an unhealthy router would fail
  over to a public upstream, which leaks the name.
- **A per-entry `strategy`.** One or two router addresses need no strategy beyond
  failover; the key can be added when someone needs it.
