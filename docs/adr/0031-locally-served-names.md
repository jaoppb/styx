# ADR 0031 — styx answers locally served zones, special-use names and the DoH canary itself

- **Status**: accepted
- **Date**: 2026-11-26
- **Phase**: 2 — Server loop and test harness
- **Supersedes in part**: [ADR 0010](0010-pipeline-ordering-and-dnssec-honesty.md) and
  [ADR 0028](0028-aaaa-filter-stage.md), one thing. Their fixed stage order gains a stage
  between `local_records` and `filter`. Both carry only a superseded-by link; read them
  with this record.
- **Extends**: [ADR 0029](0029-conditional-forwarding-routes-cache-misses.md)

## Context

No name was special to styx. Every reverse lookup of a private address, every
`localhost.` and every `*.invalid` went to the public upstream, which leaks the LAN's
addresses and answers what it cannot know. RFC 6303 §3 tells an iterative resolver to
answer the zones of its §4 (the RFC 1918, loopback, link-local, documentation and
locally assigned reverse zones) as empty zones of its own, and RFC 6761 §6.3–6.4 tells a
caching server to answer `localhost.` with the loopback address and `invalid.` with
NXDOMAIN, without asking anyone. Firefox reads a non-NOERROR answer for
`use-application-dns.net` as the network's signal to keep its default DNS over HTTPS off;
without it, a browser that enabled DoH by default skips a filtering resolver silently
(issue #97).

## Decision

**A built-in `LocallyServed` table is a pipeline stage, always on.** The stage order
becomes `validation -> local_records -> locally_served -> filter -> aaaa_filter -> cache ->
upstream -> terminal`. A name in the table, or below one, is answered by
`ForgedAnswer::locally_served` under the new `ForgedSource::LocallyServed`, and
short-circuits like the stages before it.

- *After local records*: a record the operator configured for a name is an explicit choice
  and wins over a built-in default.
- *Before the filter*: the answers are protocol behaviour, not policy, so a blocklist that
  lists the canary does not count it as a blocked name.
- *Before the cache*: the stage needs nothing the cache holds, and no question leaves styx.

**The answers.**

- The 33 zones of RFC 6303 §4 are empty zones: a name below the apex is NXDOMAIN; at the
  apex, SOA and NS are answered and every other type is NODATA. A negative reply carries
  the zone's SOA in its authority section, as RFC 6303 §3 recommends it: MNAME and the NS
  target are the zone, RNAME is `nobody.invalid.`, and the timers are the RFC's example's.
- `localhost.` and every name below it answer A with `127.0.0.1`, AAAA with `::1`, and any
  other type with NODATA (RFC 6761 §6.3).
- `invalid.` and every name below it are NXDOMAIN for every type (RFC 6761 §6.4).
- `use-application-dns.net` and every name below it are NXDOMAIN while the top-level
  `doh_canary` switch is on. It is infrastructure, like `filter_aaaa`, so it lives in
  `styx.toml`, parsed by `ServerConfig`, and is `true` when the key is absent.

The forged-answer rules of ADR 0010 apply unchanged: AD is cleared, no RRSIG is attached,
and admission refuses `AnswerSource::LocallyServed` as a forged answer.

**A conditional domain wins over an RFC 6303 zone.** `ServerConfig::locally_served` passes
every `[[upstream.conditional]]` domain to the table, and a name under one of them is not
answered as an empty zone, so the cache stage routes it to that entry's forwarders
(ADR 0029). The carve-out works both ways: `1.168.192.in-addr.arpa` sends only the
router's reverse names to it while the rest of `168.192.in-addr.arpa` stays local, and
`in-addr.arpa` hands every IPv4 reverse zone over. The special-use names and the canary
never yield: `localhost` and `invalid` are never delegated (RFC 6761), and an entry for
`net` must not turn the canary off as a side effect.

**Every locally served record has a 60-second TTL, and the SOA's negative TTL is the
same.** RFC 6303 §3 asks only that the two match and lets the rest be chosen; its example
uses 10800 seconds. A short TTL follows ADR 0010's forged-answer rule and lets a client
see a conditional entry added later within a minute rather than three hours.

## Consequences

- Private reverse lookups, `localhost` and `*.invalid` stop reaching the upstream, and
  clients that asked through styx stop getting public answers to them.
- RFC 6303 §3 says an implementation MUST provide a mechanism to disable the empty zones,
  and SHOULD allow it per zone. The override is per zone, through
  `[[upstream.conditional]]`; there is no switch that turns them all off, and a
  recursor-only file has no way to send a zone to the main pool. A switch can be added when
  someone needs it.
- RFC 6303 §3 asks for AA=1 on these answers. `conform_to_query` clears AA on every reply,
  since styx is a recursive resolver, and this stage does not change that.
- The zones added to the IANA registry after RFC 6303 (`64.100.in-addr.arpa` to
  `127.100.in-addr.arpa` by RFC 7793, `home.arpa` by RFC 8375, `resolver.arpa`,
  `service.arpa`) are not served. `home.arpa` in particular belongs to the home router,
  which a conditional entry reaches today.
- Probes are not affected: the default forwarder canary `probe.canary.invalid.` is sent
  to the member by the probe scheduler, not through the pipeline.
- Public surface: `ServerConfig` gains the public field `doh_canary: bool`, so a struct
  literal of it stops compiling; `Pipeline` gains `with_locally_served`, `ForgedAnswer`
  gains `locally_served`, `LocallyServed`, `LocallyServedReply` and `LOCALLY_SERVED_TTL` are
  new, and `AnswerSource` and `ForgedSource` gain the `LocallyServed` variant, so an
  exhaustive external `match` on either fails to compile until it handles it.

## Alternatives rejected

- **Answer them through the `LocalRecords` port.** The port returns answer records for a
  NOERROR reply; it cannot say NXDOMAIN or carry an authority section, and its Phase 9
  adapter reads operator rows, which these defaults are not.
- **Reuse `ForgedSource::LocalRecord`.** The query log would count protocol defaults as
  operator records.
- **Place the stage after the cache, or in `CacheStage` beside the conditional routes.**
  The cache would be consulted for names it can never hold, and the conditional decision
  would be split between two stages that each need the other's table.
- **Let a conditional domain win over every built-in name.** One rule, but an entry for a
  parent of the canary would silently re-enable Firefox's DoH.
