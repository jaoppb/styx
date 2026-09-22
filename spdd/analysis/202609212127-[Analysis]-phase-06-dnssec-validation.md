# SPDD Analysis: Phase 6 — DNSSEC Validation (`styx-dnssec`)

> Project: **styx** — a filtering DNS resolver written from scratch in Rust, replacing
> Pi-hole's role on a home network (recursive/forwarding resolution, per-client blocking
> policy, Leptos admin UI). Single process, single binary, one box.
>
> **Codebase context: greenfield, no existing implementation.** At the time of this
> analysis the repository contains no git history, no Cargo workspace and no source
> code — only the design record and the phase specs. Every statement below is therefore
> grounded in the project's recorded design decisions rather than in code that exists.
> Everything this document asserts about prior phases describes contracts those phases
> are specified to deliver, not contracts already written.

---

## Original Business Requirement

The following is the phase specification, reproduced verbatim and unmodified.

```markdown
# Phase 6 — DNSSEC (`styx-dnssec`)

> Part of [ROADMAP.md](../../ROADMAP.md) · Previous: [Phase 5 — Recursion](05-recursion.md) · Next: [Phase 7 — Encrypted inbound](07-encrypted-inbound.md)

Four sub-phases. Do not merge them.

## Scope

- **6a** Positive chain: RRSIG verification, DNSKEY/DS linkage, the pinned root
  anchor behind `TrustAnchorSource` (decision 12), the algorithm set. Warn-only.
- **6b** NSEC denial-of-existence proofs.
- **6c** NSEC3: closest-encloser proofs, opt-out, and a **mandatory iterations
  cap**. Uncapped NSEC3 is a CPU denial of service.
- **6d** The `ChainSource` port with both feeding strategies — recursion *pushes*
  DS material collected during DO=1 descent, forwarder paths *pull* on demand
  (decision 6). Then flip warn → **hard-fail SERVFAIL** (decision 11).

## Exit criteria

Differential AD-bit agreement with `unbound` across signed, unsigned, bogus and
NXDOMAIN cases; the `rootcanary.org` and `dnssec-failed.org` families behave as
expected.
```

### Inlined design decisions the requirement refers to

The phase spec cites two design decisions by number. Because the source design record
is being retired, both are reproduced here in full, with their rationale, so this
document stands alone.

**"Decision 6" — DNSSEC validation is its own crate behind a `ChainSource` port.**
Verbatim: *"DNSSEC validation is its own crate behind a `ChainSource` port:
`styx-recursion` pushes chain material it already collected during descent (DS RRsets
arrive unasked in DO=1 referrals, per RFC 4035 §3.1.4), while forwarder paths pull
DS/DNSKEY on demand. One validator, two feeding strategies. This avoids widening the
`Upstream` port with a 'chain material observed en route' field that would be
permanently empty for forwarders."*

**"Decision 11" — validation means positive chains *and* denial of existence, with
hard failure.** Verbatim: *"DNSSEC validation means positive chains and denial of
existence, with hard failure. RRSIG chains, DS/DNSKEY linkage, NSEC and NSEC3 proofs
including opt-out, SERVFAIL on bogus. A validator that accepts an unsigned NXDOMAIN is
downgradeable by any on-path attacker, so 'positive answers only' is not a smaller
version of this feature — it is a different, insecure one. NSEC3 carries a mandatory
iterations cap; uncapped it is a CPU denial of service."*

**"Decision 12" — the root trust anchor is pinned, overridable by a file path in
config.** Verbatim: *"A compiled-in IANA anchor with a `trust-anchor` config override,
behind a `TrustAnchorSource` port. RFC 5011 automated rollover needs state that
survives restarts, which would drag the storage layer into the validator phase for a
rollover that is pre-announced months ahead. Accepted consequence: a KSK roll needs a
release or a file edit, and missing one SERVFAILs every lookup — this is a monitoring
obligation, not code."*

---

## Domain Concept Identification

### Existing Concepts (delivered by earlier phases; none yet implemented)

The repository is greenfield, so "existing" here means *contracted by a phase that
precedes this one in the build order*. Phase 6 consumes these; it does not redefine
them.

- **`styx-proto` wire codec** (Phase 1 — Wire codec): header, question, RR and RDATA
  for every v1 rrtype, name compression on encode *and* decode, compression-pointer
  loop detection, EDNS(0) OPT. This is the one shared-foundation crate rather than a
  feature crate — every crate parses through it, so the otherwise-absolute rule that
  feature crates never depend on each other explicitly does not reach it. Phase 6's
  DNSKEY, DS, RRSIG, NSEC and NSEC3 record types and their canonical wire forms come
  from here. Relationship: the validator is a *reader* of decoded records and a
  *producer* of canonical wire bytes for signature input; it owns no parsing of its
  own.
- **Injectable `Clock`** (Phase 2 — Server loop and test harness): specified as
  *"the injectable `Clock` … It cannot be retrofitted later."* The recorded reason is
  precisely this phase: *"RRSIGs carry inception and expiration timestamps, so any
  recorded signature fixture expires on a date you did not choose. Time injection
  cannot be retrofitted into a validator; it is a rewrite."* Relationship: every
  RRSIG validity-window check reads the clock through this port, never a system call.
- **The fixed request pipeline order** (Phase 2): *local records → filter → cache →
  upstream*, fixed early because it is a correctness property and not a detail. Local
  records and blocks are both forged answers, so both clear AD, forge no signature,
  and never enter the answer cache. Relationship: this is where validation sits
  relative to filtering — **filtering runs before validation, because a block is not
  a validation verdict.**
- **`Upstream` port and the pool** (Phase 3 — `Upstream` port, forwarding, pool): an
  upstream is *either* a forwarder or a recursor; recursion is an implementation of
  the same port, not a separate server mode. Relationship: Phase 6 deliberately does
  **not** touch this port (see Strategic Approach).
- **Answer cache** (Phase 4 — Answer cache): global RRset/message cache keyed
  `(qname, qtype, qclass)`, TTL handling, RFC 2308 negative caching, bailiwick rules
  governing what is cacheable at all. Relationship: validation verdicts and cached
  data interact — a cached RRset's remaining TTL is not its signature's remaining
  validity.
- **`styx-recursion` descent and infrastructure cache** (Phase 5 — Recursion): the
  descent with relaxed QNAME minimisation present from the first test, CNAME chasing,
  glue handling, bailiwick enforcement, loop and depth limits; the infrastructure
  cache holding delegations, NS sets, per-nameserver RTT and EDNS capability keyed by
  zone and nameserver. Relationship: this is the *push* side of `ChainSource` — the
  descent already walks root → TLD → zone and already sees DS RRsets in DO=1
  referrals.
- **Local records, always Insecure**: A/AAAA/CNAME/PTR rows matched ahead of the
  answer cache and ahead of any upstream; *"They never enter the answer cache and
  never reach the validator: AD cleared, no forged signature."* Relationship: a class
  of answers that bypasses this phase entirely, by design.
- **`hickory-proto` as test oracle, `[dev-dependencies]` only**: the fake
  root/TLD/authoritative servers and expected-byte fixtures must encode DNS wire
  format; *"if our own codec encodes them, the resolver and its oracle share every bug
  and a green suite proves only self-consistency."* A CI check asserts it appears in
  no normal or build dependency path. Relationship: Phase 6's signed test zones are
  built with it, and the shipped validator must not name it.

### New Concepts Required

- **`styx-dnssec`** — the validator as its own feature crate, with `domain`,
  `application` and `infrastructure` as modules *inside* it. New: it does not exist.
  Relationship: like every feature crate it may not depend on another feature crate;
  cross-feature needs are expressed as a port in its own `domain` and wired by an
  adapter in the `styx` binary.
- **`ChainSource`** — the port through which the validator obtains the material it
  needs to build a chain of trust (DS and DNSKEY RRsets, and their signatures) for a
  given owner name. New. Two adapters satisfy it, with structurally different
  behaviour: a **push** adapter fed by the recursive descent, and a **pull** adapter
  that issues explicit DS/DNSKEY lookups when the answer came from a forwarder.
  Relationship: this is the seam between the validator and *how* an answer was
  obtained, and it exists specifically so the validator is agnostic to that.
- **Chain material** — the aggregate of DS RRsets, DNSKEY RRsets and the RRSIGs over
  them, per zone cut, that a validation attempt consumes. New. Relationship: produced
  by either `ChainSource` adapter, consumed by the positive-chain validator; the
  push adapter accumulates it as a side effect of descent, the pull adapter
  synthesises it on demand.
- **`TrustAnchorSource`** — the port supplying the root trust anchor. New. Two
  implementations: the compiled-in pinned IANA anchor (default) and a file-backed
  one selected by a `trust-anchor` path in the TOML config. Relationship: the root of
  every chain; also the documented seam that RFC 5011 automated rollover would slot
  into later, if it ever stops being a non-goal.
- **Validation verdict / validation state** — the tri-state outcome of a validation
  attempt: Secure, Insecure, Bogus (with, at minimum, a distinguished Indeterminate
  or equivalent for "no path to an anchor"). New. Relationship: drives the AD bit on
  the response and, after the warn→hard-fail flip, drives SERVFAIL.
- **NSEC proof** — a denial-of-existence proof built from NSEC records: name does not
  exist, or name exists but the type does not, or a wildcard was correctly applied.
  New.
- **NSEC3 proof** — the hashed equivalent, requiring closest-encloser derivation, next
  closer name, and wildcard handling, plus **opt-out** semantics where an unsigned
  delegation is provably permitted to be unproven. New. Relationship: the same three
  proof obligations as NSEC, over a hash space, which is where the difficulty lives.
- **NSEC3 iterations cap** — a mandatory, non-optional ceiling on the iteration count
  the validator will compute before refusing. New, and load-bearing.
- **Algorithm set** — the explicit, closed set of DNSKEY/RRSIG algorithms and digest
  algorithms the validator accepts, including which are treated as unknown (rendering
  a chain Insecure rather than Bogus) and which are refused outright. New.
- **Warn-only mode → hard-fail mode** — an explicit staged behaviour of the validator
  itself: during 6a–6c it computes verdicts and records them without affecting the
  response; at the end of 6d the switch flips and Bogus becomes SERVFAIL. New.

### Key Business Rules

- **Validation means positive chains *and* denial of existence.** Governs: validation
  verdict, NSEC proof, NSEC3 proof. A validator that accepts an unsigned NXDOMAIN is
  downgradeable by any on-path attacker — an attacker who can forge a bare NXDOMAIN
  can make any signed name disappear. "Positive answers only" is therefore not a
  smaller version of this feature; it is a different and insecure one. This is why
  6b and 6c are not deferrable and why 6d's hard-fail flip comes only after them.
- **Bogus hard-fails as SERVFAIL.** Governs: validation verdict, response path. Not a
  warning, not a downgrade to Insecure.
- **The NSEC3 iterations cap is mandatory.** Governs: NSEC3 proof. Uncapped NSEC3 is a
  CPU denial of service: the iteration count is attacker-chosen data carried in a
  record the validator is asked to process, and each iteration is a hash. A cap is
  not a tuning knob; it is the control that prevents a remote party from spending our
  CPU.
- **One validator, two feeding strategies.** Governs: `ChainSource`. The validator
  must not know whether the answer arrived from a recursive descent or a forwarder.
- **The `Upstream` port is not widened.** Governs: `ChainSource`, `Upstream`. A "chain
  material observed en route" field on `Upstream` would be permanently empty for every
  forwarder, i.e. a field that lies about the abstraction for one of its two kinds.
  The port exists instead.
- **The root anchor is pinned at compile time, overridable by file.** Governs:
  `TrustAnchorSource`. Config has a hard two-store boundary — the TOML file owns
  infrastructure (listen addresses, upstreams and pools, selection strategy, TLS
  material, **trust anchor**, DB path, log mode) and the database owns policy. So the
  trust anchor is a file-side concern, and changing it needs a restart, by
  construction.
- **RFC 5011 automated trust anchor rollover is a non-goal.** Governs:
  `TrustAnchorSource`. It requires state that survives restarts, which drags the
  storage layer into the validator phase for a rollover that is pre-announced months
  in advance. Accepted consequence, recorded as such: a KSK roll needs a release or a
  file edit, and missing one SERVFAILs every lookup. That is a monitoring obligation,
  not code.
- **Filtering is applied before validation; a block is not a validation verdict.**
  Governs: the pipeline, blocked replies, validation verdict. Blocked replies always
  clear AD and never forge an RRSIG, in all five blocking modes.
- **Local records never reach the validator and are always Insecure.** Governs: local
  records, validation verdict.
- **Signature time is injected, never read from the system clock.** Governs: RRSIG
  validity checks. Recorded rationale: recorded signature fixtures expire on a date
  nobody chose, and retrofitting time injection into a validator is a rewrite.
- **The four sub-phases are not to be merged.** Governs: the whole phase. This is
  stated in the requirement itself as a standing instruction, not a suggestion.

---

## Strategic Approach

### Solution Direction

`styx-dnssec` is a standalone feature crate holding a *pure* validator: given an
answer message, the chain material for its zone cuts, a trust anchor and a point in
time, it produces a verdict. Everything that makes validation *possible* — fetching
DS and DNSKEY, or remembering what the descent already saw — sits behind two ports
declared in the crate's own `domain` and implemented outside it, with the `styx`
binary doing the wiring. The crate itself performs no I/O and holds no knowledge of
forwarders, recursion or the pool.

The data flow is: an answer arrives on the resolution hot path *after* local-record
lookup and *after* filtering (a block short-circuits and is never validated), the
validator is handed the message plus a `ChainSource` and a `TrustAnchorSource`, it
builds and checks the chain from the anchor downward, and it returns a verdict that
the response path turns into an AD bit and — once 6d flips the switch — possibly into
SERVFAIL.

The phase is built in four strictly separated increments, in the given order, with
the validator running **warn-only** for the first three. That ordering is the design:
it lets positive-chain machinery, NSEC proofs and NSEC3 proofs each be measured
against reality before any of them can take resolution down for the whole house.

### Key Design Decisions

- **Own crate behind ports, rather than a module inside `styx-recursion`.**
  Trade-off: a port plus two adapters plus binary wiring is more moving parts than a
  function call inside the recursor. → **Recommended: own crate.** Validation is not
  a recursion concern — a forwarded answer needs validating too, and a validator that
  lives inside the recursor either cannot serve the forwarder path or grows a second,
  divergent code path for it. The crate boundary is also what Cargo enforces: feature
  crates cannot name each other, so the dependency *cannot* silently form.

- **`ChainSource` with two feeding strategies, push and pull.** Trade-off: one port
  with two structurally different adapters is harder to reason about than one uniform
  fetch-on-demand interface. → **Recommended: two strategies.** The recursive descent
  already collects DS RRsets it never asked for — RFC 4035 §3.1.4 has referrals in
  DO=1 carry the DS RRset alongside the NS set — so making the recursor re-fetch what
  it just held would be both slower and a second chance to get bailiwick wrong. The
  forwarder has no descent and no referrals, so it has nothing to push and must ask.
  One validator consuming one port keeps the *validation logic* single, which is the
  part that must not fork.

- **Do not widen the `Upstream` port.** Trade-off: a "chain material observed en
  route" field on `Upstream` would need no new port at all. → **Recommended: reject.**
  That field is permanently empty for every forwarder upstream, which is half the
  kinds the port exists to unify. An abstraction with a member that is structurally
  meaningless for one of its implementations has stopped abstracting; and because the
  pool holds upstreams of mixed kinds behind that single port, the emptiness would be
  invisible at the call site.

- **Pinned compiled-in IANA root anchor with a config-file override, behind
  `TrustAnchorSource`.** Trade-off: pinning means a KSK roll requires shipping a
  release or editing a file, and missing one SERVFAILs every lookup on the network.
  → **Recommended: pin, with the override, and treat the roll as an operational
  obligation.** The alternative, RFC 5011 automated rollover, needs anchor state that
  survives process restarts — which means the storage layer, which belongs to a much
  later phase, would have to be pulled into the validator phase to serve a rollover
  that IANA pre-announces months ahead. The port is the recorded seam for adding 5011
  later without disturbing the validator.

- **Warn-only through 6a–6c, hard-fail at the end of 6d.** Trade-off: warn-only means
  that for three sub-phases the validator's verdict is unobservable to clients, so a
  bug hides longer. → **Recommended: warn-only first.** With hard failure on from 6a,
  every incomplete piece of the validator is an outage of the resolver rather than a
  wrong log line, and the denial-of-existence code — the part most likely to be
  subtly wrong — would be landing into a live hard-fail path. The verdict is still
  fully computed and recorded throughout, so the differential gate can be run against
  warn-only output.

- **Mandatory iterations cap, with the value left to implementation.** Trade-off: a
  low cap can render some real, badly-configured zones Insecure or Bogus that a more
  permissive validator would resolve. → **Recommended: cap unconditionally.** The cost
  of a wrong cap value is some zones behaving conservatively; the cost of no cap is a
  remote party choosing how much of our CPU to spend, on a box that is the whole
  household's resolver. **The cap *value* is an explicitly open implementation-level
  choice, to be decided at the keyboard** — it is recorded as such alongside SRTT
  decay constants and blocked-reply TTLs; the *existence* of the cap is not open.

- **Time comes from the injected `Clock`.** Trade-off: none worth the name; it is
  marginally more plumbing. → **Recommended: unconditionally.** RRSIG inception and
  expiration make every signature fixture a time bomb with a date nobody chose, and
  retrofitting time injection into a validator is not a refactor, it is a rewrite.
  The `Clock` was put into the server-loop phase for exactly this phase.

- **The differential run against `unbound` is the real gate.** Trade-off: it depends
  on the live internet, so it is flaky by nature and a genuine regression can hide
  behind a shrug. → **Recommended: keep it as a per-phase gate, never a per-push
  gate.** In-process fakes only prove the validator does what *we* think DNSSEC means;
  an independent implementation disagreeing is the only signal that catches a shared
  misreading, and denial-of-existence proofs are exactly where a shared misreading is
  likely.

### Alternatives Considered

- **Use an existing DNSSEC implementation (`hickory-dns`, the `domain` crate).**
  Rejected: the entire DNS stack is written from scratch — wire codec, server loop,
  caches, recursion algorithm, DNSSEC validation — and that is the project's premise,
  not an incidental choice. `hickory-proto` is admitted as a **test oracle only**, in
  `[dev-dependencies]`, precisely so that fixtures are not encoded by the same code
  they are meant to test; a CI check asserts it appears in no normal or build
  dependency path.
- **Positive chains only, skipping NSEC/NSEC3.** Rejected explicitly and on security
  grounds: a validator that accepts an unsigned NXDOMAIN is downgradeable by any
  on-path attacker. It is a different feature, not a smaller one.
- **Soft-fail / permissive mode on Bogus.** Rejected: hard failure with SERVFAIL is
  the stated behaviour. A validator that reports Bogus and serves the answer anyway
  has done arithmetic, not security.
- **RFC 5011 automated trust anchor rollover.** Rejected as an explicit v1 non-goal,
  for the restart-surviving-state reason above. The port is the seam.
- **A "chain material observed en route" field on `Upstream`.** Rejected: permanently
  empty for forwarders (see above).
- **Validating blocked or local-record answers.** Rejected by construction: blocks and
  local records are forged answers that clear AD and forge no signature, and never
  reach the validator. Filtering runs before validation because a block is not a
  validation verdict.
- **Merging the four sub-phases.** Rejected by the requirement itself.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **The NSEC3 iterations cap value is unspecified.** The requirement mandates the cap
  and gives no number. This is deliberate and recorded as an open implementation-level
  choice to be decided at the keyboard — but it must be decided, documented, and
  reachable from config or a constant, not left implicit in a loop bound.
- **The algorithm set is named but not enumerated.** 6a says "the algorithm set"
  without listing which signing and digest algorithms are supported, which are treated
  as *unknown* (making a chain Insecure rather than Bogus), and which are refused. The
  distinction matters for verdict correctness, not just coverage — an unsupported
  algorithm must not be reported as Bogus.
- **"Warn-only" is not defined operationally.** It is clear the verdict must not affect
  the response, but the requirement does not say where the warning goes. The project's
  observability posture makes structured `tracing` output the natural answer, and the
  validator will need a verdict that is legible in logs for the differential run to be
  interpretable at all.
- **The relationship between a cached answer and its validation verdict is not
  stated.** The answer cache is global and keyed `(qname, qtype, qclass)`; nothing in
  the requirement says whether verdicts are cached with entries, recomputed on serve,
  or whether validated and unvalidated forms of the same RRset can coexist. Signature
  validity and record TTL are different clocks.
- **The `rootcanary.org` and `dnssec-failed.org` "families" are not enumerated.** The
  exit criterion says they "behave as expected" without listing which names, which
  algorithms, or what the expected outcome is per name. The corpus needs writing down
  or the gate is unfalsifiable.
- **CD (Checking Disabled) handling is not mentioned anywhere in the phase.** A
  validating resolver must decide what a client's CD=1 query means for its own
  validation and for the returned AD bit.

### Edge Cases

- **Unsigned zones under a signed parent, proven by a DS-absence NSEC/NSEC3 proof.**
  The Insecure verdict must itself be *proved*, not assumed from missing records —
  that proof is the whole point of denial-of-existence validation, and it is the case
  most easily short-circuited by accident.
- **NSEC3 opt-out.** An opt-out span provably permits an unsigned delegation to go
  unproven. Handling it too permissively silently re-opens the downgrade hole that
  denial-of-existence validation exists to close; handling it too strictly breaks
  large legitimate TLDs.
- **Closest-encloser derivation with wildcards.** The three-part NSEC3 proof (closest
  encloser, next closer, wildcard) is where validators are recorded as getting subtly
  wrong, and a wildcard-expanded answer needs its own proof that no closer match
  existed.
- **Expired or not-yet-valid RRSIGs.** Inception in the future and expiration in the
  past both mean Bogus, and both are reachable through clock skew on a home box as
  well as through attack.
- **Multiple DNSKEYs, multiple RRSIGs, key rollover in progress.** Any one valid
  signature suffices; a validator that requires all of them breaks every zone
  mid-roll.
- **A local record under a signed public zone.** Recorded, accepted and documented:
  a name like `nas.example.com` where `example.com` is signed is unprovable, and
  validating clients may SERVFAIL it. The documented guidance is to keep local names
  under an unsigned or internal suffix. This is precisely the failure reported as
  pi-hole#2686, and it is expected to be diagnosed at least once on the author's own
  network.
- **A blocked name in a signed zone.** With CD=0 a validating client receives an
  unsigned answer for a signed name. Recorded as a deliberate lie, documented as one
  — five blocking modes each need proving not to set AD and not to forge a signature,
  which is exactly the kind of plural that hides an untested combination.
- **Chain material arriving out of bailiwick.** DS RRsets pushed from descent must
  still be subject to the bailiwick rules the descent and cache already enforce; push
  is a shortcut around a fetch, not around validation of provenance.
- **A forwarder that strips DNSSEC records or ignores DO=1.** The pull strategy has to
  tell "this upstream cannot serve me chain material" apart from "this zone is
  unsigned" — conflating them is a downgrade.
- **A KSK roll that was missed.** The accepted consequence of a pinned anchor is that
  every lookup SERVFAILs. The mitigation is monitoring and a visible failure mode, not
  code.

### Technical Risks

- **Denial-of-existence validation is the fiddliest code in the project.** Recorded
  verbatim as a project risk: NSEC3 closest-encloser proofs are where validators get
  subtly wrong, and the iterations cap is load-bearing against CPU exhaustion. The
  differential gate against `unbound` exists mostly for this. Mitigation direction:
  keep 6b and 6c strictly separate, land them warn-only, and let an independent
  implementation disagree with us before any of it can hard-fail.
- **Uncapped NSEC3 is a remote CPU denial of service.** Mitigation: the mandatory cap,
  checked before any hashing loop begins, with a defined verdict for exceeding it.
- **The differential gate depends on the live internet.** Real DNS changes underneath
  the corpus, so the job will sometimes fail for reasons that are not a bug here. It
  gates a phase and never a push for that reason — but a genuine regression can hide
  behind a shrug, so failures need reading rather than re-running.
- **Hand-written cryptographic and wire handling under `indexing_slicing = deny` and
  `arithmetic_side_effects = deny`.** Every label offset and every arithmetic step
  becomes a checked operation. That is the intended tax; it makes canonical-form
  construction verbose. Fuzzing is not optional, and the fuzzing effort extends from
  the codec onto the validator from this phase.
- **`panic = "deny"` is load-bearing and its real mitigation arrives last.** This is a
  single process: a panic anywhere takes DNS down for the whole house, and the
  `catch_unwind` boundary is a later phase. Until then the lint is the mitigation,
  which makes a panicking path in freshly written proof code a household outage.
- **Time injection cannot be retrofitted.** If the validator reads the system clock
  anywhere, the fix later is a rewrite, not a patch. Mitigation: the injected `Clock`
  is used from the first signature check.
- **Flipping warn → hard-fail is a behavioural cliff.** Every latent false-Bogus that
  was a log line during 6a–6c becomes SERVFAIL at the end of 6d. Mitigation: the flip
  is the *last* thing in the phase, after the differential run has been read.
- **No operational feedback until the cutover.** The cutover is last by design — the
  household's resolver stays on the old one until v1 is complete — so this phase
  produces nothing a human can look at except `dig` output and the differential diff.
  Accepted cost of not doing a live migration under two hand-written
  security-critical subsystems.
- **Verdict/cache interaction.** If verdicts are cached, a signature that expires
  before the record TTL does must not be served as Secure; if they are not cached,
  every hit re-validates and pays for it.

### Acceptance Criteria Coverage

Derived from the phase's exit criteria and from the mandatory scope statements in the
requirement.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | Differential AD-bit agreement with `unbound` on **signed** names | Yes | Needs the positive chain of 6a complete and the anchor wired via `TrustAnchorSource`. Corpus of signed names needs curating and pinning. |
| 2 | Differential AD-bit agreement with `unbound` on **unsigned** names | Yes | Requires the Insecure verdict to be *proved* via DS-absence denial, i.e. depends on 6b/6c, not only on 6a. |
| 3 | Differential agreement on **bogus** names (SERVFAIL) | Yes | Only observable after the 6d warn→hard-fail flip. Until then the verdict is log-only; the gate must read verdicts, not just RCODEs, during 6a–6c. |
| 4 | Differential AD-bit agreement on **NXDOMAIN** cases | Yes | The core of 6b and 6c. Expect both NSEC and NSEC3 zones in the corpus, including an opt-out TLD, or the criterion is only half-tested. |
| 5 | The `rootcanary.org` family behaves as expected | Partial | Addressable, but the requirement does not enumerate the names or the per-name expectation, and this family is chosen for **algorithm** coverage — so it also pins down the currently-unenumerated algorithm set. Both need writing down. |
| 6 | The `dnssec-failed.org` family behaves as expected | Partial | Same enumeration gap. "As expected" means SERVFAIL after the 6d flip and a Bogus verdict before it; that dual expectation should be explicit. |
| 7 | Four sub-phases 6a/6b/6c/6d remain separate and unmerged | Yes | Stated as a standing instruction in the requirement. Must survive into the canvas as separated operation groups, not as a note. |
| 8 | `ChainSource` supports both push (recursion) and pull (forwarder) feeding | Yes | Both adapters must be exercised; a test suite that only runs the recursive path leaves the forwarder strategy unproven, which is the strategy most likely to be added last and tested least. |
| 9 | NSEC3 iterations cap is present and mandatory | Yes | Cap value is an open implementation-level choice. Needs an explicit test that an over-cap NSEC3 is refused rather than computed. |
| 10 | Blocked and local-record answers never reach the validator, clear AD, forge no signature | Partial | The validator side (never reached) is in scope here; the five blocking modes are asserted in the filtering phase. This phase should establish the contract the filtering phase asserts against. |
| 11 | RRSIG validity windows evaluated against the injected `Clock` | Yes | Inherited from the server-loop phase; the risk is omission, not feasibility. |
| 12 | Fuzzing extends from the codec onto the validator | Yes | Stated project-wide: `cargo fuzz` continuously from the codec phase, later on the validator. Targets for proof parsing and chain building need defining here. |

---

## Phase Position

- **Depends on**: Phase 0 (Foundation and gates), Phase 1 (Wire codec), Phase 2
  (Server loop and test harness), Phase 3 (`Upstream` port, forwarding, pool),
  Phase 4 (Answer cache), Phase 5 (Recursion).
- **Depended on by**: Phase 7 (Encrypted inbound), Phase 8 (Filtering), and
  transitively Phase 12 (Cutover hardening), where the validator must hold under the
  panic boundary and the musl release artifacts.
