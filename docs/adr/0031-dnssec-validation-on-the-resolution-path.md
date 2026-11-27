# ADR 0031 — DNSSEC validation on the resolution path

- **Status**: accepted
- **Date**: 2026-11-27
- **Phase**: 6 — DNSSEC validation (group 6d)

## Context

Groups 6a to 6c delivered `styx-dnssec`: a validator that walks the chain of trust from a
pinned anchor and proves denial of existence over NSEC and NSEC3. Nothing called it.
Wiring it in raised questions the crate could not answer on its own. How do DNSSEC records
reach it when the forwarder asked with DO=0? Where does the verdict meet the reply, when
`styx-resolution` may not name `styx-dnssec`? What does a client's CD bit mean? How long
may a validated answer stay in the cache? And how does the validator get chain material
without widening the `Upstream` port (ADR 0012)?

## Decision

**Upstream queries always ask for DNSSEC records, whatever the client set.** The forwarder
sends DO=1 (RFC 4035 §3.2.1 makes it a MUST of the resolver side) and CD=1 (RFC 6840
§5.9), so an upstream that validates hands over the data it judges bogus instead of a
SERVFAIL: the verdict is styx's to reach. The `Upstream` port carries no request flags for
this, so issue #86's proposal to add them is not taken. The pipeline exit then shapes the
reply for the client. A DO=0 client loses the RRSIG, NSEC and NSEC3 records it did not ask
for, live or cached. The reply's DO bit is the query's (RFC 6840 §5.6). AD survives only
when the query set DO or AD (RFC 6840 §5.8).

**The verdict meets the reply in the cache stage, through a port.** `styx-resolution`
declares `ResponseValidator` in its domain; the binary implements it over `styx-dnssec`.
Every upstream answer passes it before it is admitted or served. Forged answers leave the
pipeline earlier and never reach it (ADR 0010). AD reflects only styx's verdict: RFC 4035
§4.6 has a resolver disregard the AD of a reply it did not get over a secure channel. A
verdict the failure mode refuses is SERVFAIL. `ValidationOutcome::refuses_under` states
which verdicts those are, once. The no-op `NoValidation` is the stage's default type
parameter and sits in `application`, like `RefusedTerminal`, because that layer may not
name `infrastructure`, where ADR 0011 keeps the other no-op adapters.

**Validation always runs; CD only lifts enforcement.** A CD=1 client gets the data a CD=0
client would be refused, without AD (RFC 4035 §3.2.2), and that answer is not cached.
Every answer that is cached was validated the same way, so one cache serves both kinds of
client.

**A validated entry never outlives its signatures.** Of the two options 6d.6 allowed —
recompute the verdict on every hit, or bound the entry — styx bounds it. A Secure answer's
TTLs are capped at its earliest RRSIG expiration (RFC 4035 §5.3.3). An answer signed for
less time than the cache's TTL floor is served but not cached, since the floor would
otherwise stretch the entry past its signatures. So an expired signature is never served
with AD, without a second validation on the hit path.

**Conditional routes are not validated.** A conditional route keeps a local domain off the
public upstreams (ADR 0029). Building its chain would ask those upstreams for the DS and
DNSKEY of that very domain, and a private zone under a signed parent could only end Bogus
or Indeterminate. Its answers are served unvalidated: no AD, never refused. This is the
`domain-insecure` list a validating resolver keeps beside its forward zones.

**Chain material: pushed when the recursor has it, pulled otherwise.** Recursors send the
DS RRsets their DO=1 referrals carried to a store in the binary, which keeps one only for
a child strictly below the zone that gave it, and only DS records owned by that child
under RRSIGs that parent made. The validator's chain source takes a pushed DS first. It
asks the main pool for everything else: the DNSKEY RRsets, and a DS that was not pushed. A
DS NODATA is an unsigned delegation or "not a cut", decided from the parent's signed NSEC
or NSEC3 records. The validator then authenticates them and checks the proof again. A
reply missing the RRSIGs or denial records DNSSEC requires is a `ChainSourceError`, so
`Indeterminate/ChainMaterialUnavailable`, never `Insecure`. Fetched material is kept for
its shortest TTL, at most an hour, in a bounded store.

**The failure mode stays `WarnOnly`.** The flip to `HardFail` (6d.9) waits for the
differential run against unbound (6d.8) to be run and read. Its corpus, with the expected
outcome of every name, is in `crates/styx-dnssec/differential/corpus.txt`.

## Consequences

- Upstream answers are larger: they carry RRSIGs and denial records, and the cache stores
  the RRSIG RRsets of positive answers.
- A validated cache miss costs extra round trips to the pool for the DS and DNSKEY RRsets
  not already held, one zone cut at a time. Two concurrent validations of one zone each
  ask. Sharing that work is left to a later change.
- A negative cache entry keeps the SOA and not the NSEC or NSEC3 proof, so a cached denial
  carries no proof and no AD for a DO=1 client, while the live one does.
- A wall clock set back after admission can keep an entry past its signatures by as much
  as the clock moved: the TTL cap reads the wall clock, the entry's deadline the monotonic
  one.
- Validation of a recursor's answer is exercised over sockets only through the pull path.
  The push store is tested on its own, and with the pull source it feeds.
