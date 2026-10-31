# ADR 0028 — A file-owned switch answers every AAAA question NODATA

- **Status**: accepted
- **Date**: 2026-10-31
- **Phase**: 2 — Server loop and test harness
- **Supersedes in part**: [ADR 0010](0010-pipeline-ordering-and-dnssec-honesty.md), one thing.
  Its fixed stage order, `validation -> local_records -> filter -> cache -> upstream ->
  terminal`, gains a stage between `filter` and `cache`. ADR 0010 carries only a
  superseded-by link; read it with this record.

## Context

The README gives styx's motivation as a recursive DNS "that lets you disable IPv6". On a
network whose IPv6 path is broken or half-configured, a client that gets an AAAA answer
tries it first and stalls; answering AAAA with no records makes it fall back to IPv4
without touching the client. AdGuard Home (`aaaa_disabled`), Technitium (Filter AAAA),
Blocky (`filtering.queryTypes`) and Pi-hole (`;querytype=AAAA`) all offer the switch.
Nothing in styx did: `use_ipv6` under `[recursion]` controls only the recursor's own
transport, and the planned `IpNoDataAaaa` blocking mode applies only to blocked names
(issue #94).

## Decision

**A top-level `filter_aaaa` key, `false` by default, sets an `AaaaPolicy` on the
pipeline.** It is infrastructure, like the listeners, so it lives in `styx.toml` and is
parsed by `ServerConfig`, not stored in the database. It is global; a per-client or
per-group version belongs with query-type filtering rules (#107).

**The stage order becomes `validation -> local_records -> filter -> aaaa_filter -> cache
-> upstream -> terminal`.** With the policy set to `Filter`, an AAAA question that got
past local records and the block filter is answered by `ForgedAnswer::build_with_source`
with NOERROR and an empty answer section, under the new `ForgedSource::AaaaFiltered`.
It short-circuits like the stages before it, so the question never reaches the cache or
an upstream.

- *After local records*: an AAAA record the operator configured is an explicit choice for
  that name and wins over a global switch.
- *After the block filter*: a blocked name keeps its blocked answer and its `Blocked`
  provenance in telemetry, whatever its query type.
- *Before the cache*: the stage needs nothing the cache holds, and no AAAA question
  leaves styx.

**The reply carries no SOA.** styx asks no one, so it knows no zone apex to cite. Per
RFC 2308 a client does not cache a NODATA reply without an SOA and simply asks again,
which costs one round trip to styx and nothing upstream.

The forged-answer rules of ADR 0010 apply unchanged: AD is cleared, no RRSIG is
attached, and the outcome is uncacheable. Admission refuses `AnswerSource::AaaaFiltered`
as a forged answer, like `LocalRecord` and `Blocked`.

## Consequences

- With the switch off, the pipeline behaves exactly as before: `AaaaPolicy::Resolve` is
  the default for `Pipeline::new` and for a file that omits the key.
- HTTPS and SVCB answers can still carry `ipv6hint`, so a client that uses them may still
  learn an IPv6 address. Stripping it needs SVCB parsing in `styx-proto`, where type 65
  is still opaque, and is left for a follow-up.
- `ANY` questions are not filtered; the switch names one query type.
- Public surface: `AaaaPolicy` is added, `ServerConfig` gains the public field
  `aaaa_policy`, `Pipeline` gains `with_aaaa_policy`, and `AnswerSource` and
  `ForgedSource` gain the `AaaaFiltered` variant, so an exhaustive external `match` on
  either fails to compile until it handles it.

## Alternatives rejected

- **Reuse `ForgedSource::Blocked`.** Smaller surface, but the query log would count every
  AAAA as a blocked name, and the dashboard's block rate would measure the switch rather
  than the blocklists.
- **Implement it as a `FilterPolicy` adapter.** The port's verdict is `Block`, which the
  pipeline answers NXDOMAIN; NXDOMAIN on AAAA tells the client the name has no A record
  either. A NODATA verdict would widen a port that `styx-filtering` implements, for a
  switch that is not a filtering rule.
- **Filter after the cache, on the way out.** The upstream would still be asked, which
  is the traffic the switch exists to remove.
