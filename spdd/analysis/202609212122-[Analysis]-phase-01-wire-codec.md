# SPDD Analysis: Phase 1 — Wire codec (`styx-proto`)

> Project: **styx** — a filtering DNS resolver written from scratch in Rust, intended to
> replace Pi-hole's role on a home network (recursive/forwarding resolution, per-client
> blocking policy, Leptos admin UI). This analysis is **self-contained**: all governing
> decisions, rationale, accepted consequences and risks that bear on Phase 1 are inlined
> below rather than cited.

## Original Business Requirement

(verbatim, from the Phase 1 spec)

```markdown
# Phase 1 — Wire codec (`styx-proto`)

> Part of [ROADMAP.md](../../ROADMAP.md) · Previous: [Phase 0 — Foundation](00-foundation.md) · Next: [Phase 2 — Server loop](02-server-loop.md)

The crate every other crate parses through, and per decision 40 the one crate that
is shared foundation rather than a feature.

## Scope

- Header, question, RR, RDATA for every v1 rrtype, name compression on **both**
  encode and decode, compression-pointer loop detection, EDNS(0) OPT.
- Every label offset and TTL decrement under `indexing_slicing` and
  `arithmetic_side_effects = deny`. That is the intended tax.
- Fixtures generated with `hickory-proto` (decision 38), plus hand-assembled byte
  vectors for the pathological cases.
- `cargo fuzz` targets: decode-arbitrary-bytes, and decode→encode roundtrip.

## Exit criteria

Fuzz clean overnight; differential encode/decode agreement with `hickory-proto`
over generated messages.
```

### Governing decisions inlined (the requirement's external references, resolved)

The requirement above cites three decisions by number. Their full text and rationale,
which must survive the deletion of the source documents:

- **"decision 40" — `styx-proto` is shared foundation, not a feature crate.**
  *Every crate parses through the wire codec, so the "feature crates never depend on
  each other" rule does not reach it. This is the one explicit exception, and
  `[[restrict-use]]` must be written so as not to forbid it.*
  The rule it is exempt from reads: *"Feature crates never depend on each other.
  Cross-feature needs are expressed as a port in the consumer's `domain`, implemented by
  an adapter in the binary — e.g. `styx-resolution` declares a `FilterPolicy` port and
  `styx` wires `styx-filtering` into it. `styx-web` may depend on a feature's
  `application` layer, because it is presentation, not a peer."*
  Rationale for the exemption: the isolation rule exists to stop *features* coupling to
  each other's business logic. A wire codec is not a feature — it is the vocabulary in
  which every feature speaks. Forcing a `Message` type through a port in each consumer's
  `domain` would mean N structurally identical ports and N conversions of the same bytes,
  with no isolation gained. The exemption is explicit precisely so the architecture lint
  does not have to guess.

- **"decision 38" — `hickory-proto` is the test oracle, `[dev-dependencies]` only.**
  *The fake root/TLD/authoritative servers and the expected-byte fixtures have to encode
  DNS wire format; if our own codec encodes them, the resolver and its oracle share every
  bug and a green suite proves only self-consistency. The from-scratch ban is on shipping
  code, not the test rig. A CI check asserts `hickory-proto` appears in no normal or build
  dependency path, or the exception rots into a real dependency.*

- **The from-scratch mandate itself.** *The entire DNS stack is written from scratch —
  wire codec, server loop, caches, recursion algorithm, DNSSEC validation. No
  `hickory-dns`, no `domain` crate for the protocol.* This sits inside a stated project
  posture: *"This is a build-it-properly project, not a ship-it-this-quarter project. v1
  contains two hand-written security-critical subsystems (a recursive resolver and a
  DNSSEC validator), so the repo optimises for a long correctness grind: spec-first,
  socket-level behaviour tests, aggressive lints, CI from the first commit."*

### Position in the build order

Phases are ordered by dependency and risk, not usability; taking them out of order is the
stated way this project stalls.

- **Depends on: Phase 0 — Foundation and gates.** Delivers the git repo, the Cargo
  workspace skeleton, a *working* (syn-engine) `arch-lint.toml`, an independent
  `cargo tree --edges normal` layering gate, the `hickory-dev-only` dependency check,
  `clippy.toml` with the 15 denied lints and 4 `allow-*-in-tests` entries, lefthook
  pre-commit/pre-push hooks, GitHub Actions, and the `just gate` aggregate target.
  Phase 0's own exit criterion is that an *empty* workspace passes `just gate` **and**
  that a deliberate `.unwrap()` in a `domain` module plus a deliberate cross-layer `use`
  both fail it. Phase 1 is the first code that gate is pointed at for real.

- **Depended on by: every subsequent phase.** Directly and immediately:
  - **Phase 2 — Server loop and test harness** (UDP/TCP listeners, TC bit and TCP
    fallback, injectable `Clock`, in-process fake root/TLD/authoritative servers built on
    `hickory-proto`, and the hot-path ports `FilterPolicy` / `LocalRecords` / query-log
    observer declared with no-op implementations).
  - **Phase 3 — `Upstream` port, forwarding, pool** (Do53 forwarder over UDP and TCP,
    `HealthState`, four selection strategies).
  - **Phase 4 — Answer cache** (RRset/message cache keyed `(qname, qtype, qclass)`, TTL
    handling, RFC 2308 negative caching, bailiwick rules).
  - **Phase 5 — Recursion** (`styx-recursion`: infrastructure cache, descent with relaxed
    QNAME minimisation, CNAME chasing, glue handling, bailiwick enforcement).
  - **Phase 6 — DNSSEC** (`styx-dnssec`: RRSIG/DNSKEY/DS chains, NSEC and NSEC3 denial of
    existence, hard-fail SERVFAIL).
  - **Phase 7 — Encrypted inbound** (DoT/DoH listeners — same wire format, different
    framing).
  - **Phase 8 — Filtering** (`styx-filtering`: matcher, allow/block precedence, and
    **blocked-reply construction** in five modes).
  - **Phase 9 — Storage**, **Phase 10 — Query log pipeline**, **Phase 11 — Web UI**,
    **Phase 12 — Cutover hardening** all render or persist decoded message material.

  Because the cutover is last and nothing mid-build has to be shippable, breaking changes
  to this crate stay free right up to v1 — but *only* in the sense of API churn. A
  correctness bug here is invisible and propagates into two hand-written
  security-critical subsystems.

---

## Domain Concept Identification

### Existing Concepts (from codebase)

**None. Greenfield, no existing implementation.** The repository at analysis time contains
only `SPEC.md`, `ROADMAP.md`, `docs/specs/` and an inert upstream-template
`arch-lint.toml`. There is no git repository, no Cargo workspace, no source file, no
schema, no migration and no prior SPDD artefact. Every concept below is new. Architecture
conventions are therefore taken from the project's stated decisions rather than inferred
from code:

- **One crate per feature; `domain` / `application` / `infrastructure` are modules inside
  it.** *Cargo enforces feature-to-feature isolation; arch-lint enforces layering within a
  crate.* `styx-proto` is the standing exception to the crate-isolation half of that rule
  (see above), not to the layering half.
- **Single process, single binary.** DNS listeners, Leptos SSR and background workers
  share state via `Arc`; the web UI is a compile-time Cargo feature (`web`, default on) so
  a headless resolver can be built, and CI builds/tests `--no-default-features` on every
  commit *"or the headless build rots within a month."*
- **`thiserror` error enums, `Result<T, E>`, `tracing` for instrumentation, traits as
  ports** — the lint config enables `no-unwrap-expect` (allowed in tests),
  `require-tracing`, `tracing-env-init`, `no-sync-io` and `require-thiserror`.
- **The hot path touches no I/O.** *Matcher state is in memory, built at boot and on
  reload. Turso holds config, adlist definitions, clients/groups and history only. A DB
  outage degrades logging and admin, never resolution.* For this phase the consequence is
  simple and absolute: the codec is pure, allocating-at-most, synchronous computation over
  byte buffers. No I/O, no clock, no global state.

### New Concepts Required

All of these are new, and all live in `styx-proto`.

#### Message structure

- **Message** — the unit every other crate parses through: a header plus four sections
  (question, answer, authority, additional). Both a decoded form and an encoded byte form
  are first-class, because the resolver forwards, caches, filters and re-serialises the
  same material at different layers.
- **Header** — ID, the flag word, and the four section counts. Its flag bits are not
  incidental detail; several are load-bearing policy signals elsewhere in the system:
  - **QR, Opcode, AA, TC, RD, RA, Z, RCODE** — ordinary protocol machinery. **TC** is
    consumed immediately by the next phase, which owns *"TC bit and TCP fallback"*.
  - **AD (Authentic Data)** — must be independently settable and, critically, *clearable*.
    Three separate rules in the project converge on this bit. Blocked replies: *"AD is
    always cleared and no RRSIG is ever forged, and filtering is applied before
    validation — a block is not a validation verdict."* Local records: *"Local records are
    answered before the cache and are always Insecure … AD cleared, no forged signature,
    same honesty rule as a blocked reply."* And validation: AD is the DNSSEC validator's
    only outward signal, asserted only on a verified chain.
  - **CD (Checking Disabled)** — carried through because the accepted consequence of the
    blocking design is explicitly stated in terms of it: *"a client validating with CD=0
    gets an unsigned answer for a signed name. That is a deliberate lie, documented as
    one."* The bit must survive decode and be reproducible on encode.
  - **Extended RCODE** — RCODE is 4 bits in the header and 12 bits once EDNS(0) is in
    play. The header type must not model RCODE as a 4-bit-only value, or `BADVERS` and
    anything above 15 becomes unrepresentable.
- **Question** — `(qname, qtype, qclass)`. This triple is not just a wire structure: it is
  verbatim the answer cache's key — *"The answer cache stays global, keyed
  `(qname, qtype, qclass)`."* Whatever equality and hashing semantics this type exposes
  become the cache's semantics two phases later.
- **ResourceRecord** — owner name, type, class, TTL, RDLENGTH, RDATA.
- **RData** — a variant per v1 rrtype, plus an **opaque/unknown** variant. The unknown
  variant is not optional polish: a forwarding resolver and a caching resolver must both
  relay rrtypes they do not model, byte-exact (RFC 3597 semantics). Without it, any
  rrtype the project has not enumerated becomes a decode failure and the resolver silently
  breaks for whole classes of query.

#### Names and labels

- **Name** — a sequence of labels, wire-limited to 255 octets total with each label ≤ 63
  octets. DNS comparison is case-insensitive but the question section must be echoed with
  the client's original case, so the type must decide, once, whether it preserves case and
  compares case-insensitively, or normalises. This is a foundational decision: the matcher
  in Phase 8 walks *reversed labels* right-to-left through a radix trie, the answer cache
  keys on the name, the recursion descent in Phase 5 compares names for bailiwick
  enforcement, and DNSSEC canonical form in Phase 6 requires lowercase owner names. Four
  downstream consumers inherit whatever is chosen here.
- **Label** — a single length-prefixed component, with its length ceiling and the
  reservation of the top two length bits (0b11) for compression pointers.
- **Compression context, encode side** — the map from already-emitted name suffix to its
  offset, used to emit pointers. Bounded at 14 bits: no pointer can address past offset
  16383, so long messages must degrade to uncompressed names rather than emit a corrupt
  pointer.
- **Compression state, decode side** — pointer following with **loop detection**, called
  out explicitly by the requirement. The classic attack is a pointer that targets itself
  or forms a cycle; the classic second attack is a legal acyclic pointer chain that still
  expands quadratically. Both are decoder-side denial of service.

#### EDNS(0)

- **Opt** — the EDNS(0) OPT pseudo-RR, modelled explicitly rather than as a generic RR,
  because its fields are overloaded: owner name is root, CLASS carries the **requestor's
  UDP payload size**, and TTL carries **extended RCODE bits, EDNS version, and the flag
  word containing DO**. Treating it as an ordinary RR is how implementations produce
  garbage payload sizes and lost DO bits.
- **DO (DNSSEC OK) bit** — the single most consequential EDNS flag in this project. The
  DNSSEC design depends on it: *"`styx-recursion` pushes chain material it already
  collected during descent (DS RRsets arrive unasked in DO=1 referrals, per RFC 4035
  §3.1.4), while forwarder paths pull DS/DNSKEY on demand."* If DO does not round-trip
  correctly, the push half of that design receives nothing and the failure looks like a
  validator bug three phases later.
- **EdnsOption** — a code/length/value triple with an unknown-option passthrough. Note the
  standing non-goal: **EDNS Client Subnet (RFC 7871) is deliberately omitted; it leaks
  client topology.** styx never *generates* ECS. The codec must still be able to represent
  an option it does not understand, and the project must decide (see Ambiguities) whether
  ECS arriving from a client is preserved, stripped, or refused.
- **UDP payload size and truncation** — the encoder needs a size budget so the server loop
  can set TC and fall back to TCP. Recursion additionally caches *"per-nameserver RTT and
  EDNS capability"*, which means the codec must let a caller distinguish "this server
  did not understand EDNS" from "this server failed".

#### RRtype coverage for v1

Driven by what later phases demonstrably need, not by completeness for its own sake:

- **Resolution and forwarding**: `A`, `AAAA`, `CNAME`, `NS`, `SOA`, `PTR`, `MX`, `TXT`,
  `SRV`.
- **Local records** specifically: *"A/AAAA/CNAME/PTR rows in Turso, editable in the UI,
  matched ahead of the answer cache and ahead of any upstream."* Those four must
  round-trip and must be *constructible* from scratch, since styx forges them.
- **Negative caching** (RFC 2308) needs `SOA` minimum-TTL semantics.
- **DNSSEC**: `DNSKEY`, `DS`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`. Phase 6 is split
  into four sub-phases that must not be merged — positive chain, NSEC, NSEC3 with a
  mandatory iterations cap, then the `ChainSource` port and the flip from warn to
  hard-fail. Every one of those sub-phases needs these types decoded faithfully, and NSEC3
  in particular needs its iterations field and salt exposed so the cap can be enforced.
- **Pseudo-types**: `OPT` (modelled separately, above), and query-only types such as `ANY`
  as qtype values rather than RData variants.
- **Unknown**: opaque bytes, preserved exactly.

#### Errors

- **A decode error enum** — a `thiserror` enum distinguishing truncated input, bad label
  length, name too long, compression pointer out of range, compression loop detected,
  bad RDLENGTH (including RDLENGTH that disagrees with the parsed RDATA), unknown class,
  malformed OPT, and section-count mismatch. The distinctions matter downstream: a
  truncated UDP response is a retry-over-TCP signal, a malformed OPT is an
  EDNS-capability signal for the infrastructure cache, and genuine garbage is a
  drop-and-count signal for the query log.
- **An encode error enum** — buffer/budget exceeded, name too long to encode, label too
  long, and message-would-not-fit (which is the encoder's contribution to the TC decision
  rather than a failure).

Both are `Result<T, E>` returns. Neither may panic, for reasons given under Technical
Risks.

### Key Business Rules

- **No `hickory-dns` and no `domain` crate in shipping code.** The whole DNS stack is
  hand-written. *Why:* the project is explicitly a build-it-properly correctness grind
  containing two hand-written security-critical subsystems; using someone else's protocol
  stack would hollow out the exercise and, more practically, would mean the recursion and
  DNSSEC code is reasoning about a parse it does not own. Governs: the entire crate.

- **`hickory-proto` is permitted in `[dev-dependencies]` only, as the test oracle.**
  *Why this specific exception exists:* *"The fake root/TLD/authoritative servers and the
  expected-byte fixtures have to encode DNS wire format; if our own codec encodes them,
  the resolver and its oracle share every bug and a green suite proves only
  self-consistency."* This is the crux of the phase's exit criteria. A fixture that styx
  encoded and styx decoded proves that styx is internally consistent — it proves nothing
  about whether styx agrees with the DNS protocol, because a single misreading of an RFC
  produces a matching encoder and decoder that are both wrong and agree with each other
  perfectly. An independent implementation is the only cheap source of disagreement.
  *Enforcement:* a CI check asserts `hickory-proto` appears in **no normal and no build**
  dependency path, *"or the exception rots into a real dependency"* — delivered in
  Phase 0 as the `hickory-dev-only` check, backed by an independent
  `cargo tree --edges normal` gate, because arch-lint reads source text while `cargo tree`
  reads the real link graph and *"they catch different mistakes."*
  Governs: `Cargo.toml`, every fixture, every fake server.

- **`styx-proto` may be depended upon by every crate.** It is shared foundation, the one
  explicit exception to feature-crate isolation, and `[[restrict-use]]` must be written so
  as not to forbid it. Correspondingly, **`styx-proto` depends on no feature crate** — the
  exception runs one way only, or the dependency graph acquires a cycle.

- **Every label offset and every TTL decrement is a checked operation.**
  `indexing_slicing = deny` and `arithmetic_side_effects = deny` are workspace-wide among
  the 15 denied clippy lints. The project states this plainly: *"That is the intended
  tax."* Governs: every buffer read, every offset computation, every length arithmetic,
  every TTL adjustment.

- **The codec must never panic.** *"`panic = "deny"` is load-bearing. In a single process,
  a panic in a Leptos request handler takes DNS down for the whole house."* The codec sits
  on the path of every inbound packet from the LAN and every response from the internet,
  so it is the single most attacker-reachable surface in the binary. The `catch_unwind`
  boundary that is the real mitigation *does not arrive until Phase 12* — everything
  before it relies on the lint alone. Governs: no `unwrap`, no `expect`, no indexing, no
  unchecked arithmetic, no `assert!` on untrusted input.

- **AD is cleared and no RRSIG is ever forged on any synthesised answer.** The codec does
  not decide policy, but it must make the honest path easy and the dishonest path require
  deliberate effort: constructing a reply must not implicitly carry AD forward, and there
  must be no convenience constructor that fabricates a signature. Governs: header
  construction, response-building helpers.

- **Unknown rrtypes and unknown EDNS options round-trip byte-exact.** A forwarder that
  drops what it does not understand is a broken forwarder.

- **Fuzzing is continuous from this phase onward.** *"Hand-written wire parsing under
  `indexing_slicing = deny` and `arithmetic_side_effects = deny`. Every label offset and
  TTL decrement becomes a checked operation. That is the intended tax, but it makes the
  codec verbose and compression-pointer loop detection fiddly. Fuzzing is not optional."*
  The acceptance model runs `cargo fuzz` on the codec continuously from Phase 1, and later
  on the validator.

- **The per-push gate is hermetic and fast; the per-phase gate may be neither.**
  Per push: formatting, the 15 denied clippy lints, `arch-lint check`, the `cargo tree`
  layering gate, the `hickory-dev-only` check, socket-level tests, and the
  `--no-default-features` headless build. Per phase: this phase's own exit criteria.

---

## Strategic Approach

### Solution Direction

Build `styx-proto` as a **pure, panic-free, zero-I/O crate** that owns the DNS wire
vocabulary for the entire workspace, and prove it against an independent implementation
rather than against itself.

Shape, in the project's own layering idiom — `domain` / `application` / `infrastructure`
as *modules inside the crate*, with traits as ports, `thiserror` enums for errors,
`Result<T, E>` everywhere and `tracing` for instrumentation:

- **`domain`** carries the protocol vocabulary and its invariants: `Message`, `Header` and
  its flags, `Question`, `ResourceRecord`, the `RData` variants, `Name`/`Label` with their
  length ceilings, `Opt`/`EdnsOption` with the DO bit and payload size, and the two error
  enums. These types enforce what is *true of DNS* — a label cannot exceed 63 octets, a
  name cannot exceed 255 — independently of how bytes are laid out.
- **`application`** carries the codec itself: the decoder walking a byte cursor with
  compression-pointer resolution and loop detection, and the encoder walking an output
  buffer with a compression offset table and a size budget. This is where the checked-
  arithmetic tax is paid.
- **`infrastructure`** is minimal to empty for this crate. There is no I/O, no clock, no
  persistence. If anything lands here it is framing helpers (the TCP two-octet length
  prefix) that the server loop consumes — and even that is arguably application-layer.

Data flow, as the rest of the system will use it:
*bytes in → decode → `Message` → (policy layers operate on the decoded form) → encode →
bytes out*, with a separate *construct-from-scratch → encode* path for synthesised answers
(blocked replies in five modes, local records, SERVFAIL on bogus).

Testing strategy, which is the substance of this phase rather than an afterthought:

1. **Oracle fixtures** — messages encoded by `hickory-proto` in `[dev-dependencies]`,
   decoded by styx, asserted field-by-field.
2. **Differential round-trip** — generated messages encoded by both implementations and
   compared, and bytes decoded by both and compared. This is the exit criterion:
   *"differential encode/decode agreement with `hickory-proto` over generated messages."*
3. **Hand-assembled pathological byte vectors** — self-referential compression pointers,
   pointer cycles, forward pointers, pointers past the buffer, 64-octet labels, 256-octet
   names, RDLENGTH that overruns the section, section counts that disagree with the
   payload, a zero-length message, OPT with a truncated option. These are hand-written
   because no well-behaved oracle will produce them.
4. **`cargo fuzz` targets** — decode-arbitrary-bytes (never panics, always returns
   `Ok` or a typed error), and decode→encode→decode round-trip (stable fixpoint).
   Run to *"fuzz clean overnight"* for the phase gate; run continuously thereafter.

### Key Design Decisions

- **Decoded-owned types vs. zero-copy borrowed views.**
  *Trade-offs:* borrowing from the input buffer avoids allocation on the hot path, which
  matters for a resolver, but it ties every downstream type's lifetime to the packet
  buffer. The answer cache stores messages and RRsets for their TTL — long past the
  buffer's life — so cached entries would need owned copies anyway; and compression means
  a name is not contiguous in the input, so a borrowed name is not a slice but a rope.
  → **Recommendation: owned decoded types.** The cache and the filter both outlive the
  packet, name compression defeats the simple borrow, and the project's stated posture is
  correctness first with a Raspberry Pi as the target — not maximum throughput. Revisit
  only if measurement in a later phase demands it; breaking changes stay free until the
  cutover.

- **Case handling on `Name`: preserve-and-compare-insensitively vs. normalise-to-lower.**
  *Trade-offs:* the question section must be echoed back with the client's original case
  (and a future 0x20 randomisation defence, should it ever be wanted, depends on
  preservation). But DNSSEC canonical form requires lowercase owner names, the matcher
  trie and the answer cache both want a single canonical key, and two representations of
  "the same name" is exactly the kind of subtlety that produces a cache poisoning bug.
  → **Recommendation: preserve the original case in the type, expose case-insensitive
  equality and hashing as the *only* comparison, and provide an explicit canonical
  (lowercased, uncompressed) form as a separate operation.** This gives Phase 4 a safe
  cache key, Phase 8 a safe trie key, and Phase 6 the canonical form it needs, without
  losing the client's bytes.

- **Modelling OPT as a distinct type vs. an `RData` variant.**
  *Trade-offs:* a variant is uniform and keeps the additional section homogeneous; a
  distinct type refuses to let OPT's overloaded CLASS and TTL fields be read as an
  ordinary record's class and TTL.
  → **Recommendation: a distinct `Opt` type, lifted out of the additional section during
  decode and re-inserted during encode.** The DO bit and the extended RCODE are too
  load-bearing — the entire push-side DNSSEC chain-material design rests on DO=1 referrals
  — to be reachable only through a generic accessor that a caller might read wrong.

- **Where truncation lives: in the encoder or in the server loop.**
  *Trade-offs:* the encoder knows byte counts; the server loop knows transport and EDNS
  payload size.
  → **Recommendation: the encoder accepts a size budget and reports "did not fit, here is
  what did", and the server loop (Phase 2, which owns *"TC bit and TCP fallback"*) sets
  TC.** The codec supplies the fact; policy stays in the phase that owns policy.

- **How much of DNSSEC canonical form belongs in Phase 1.** *Trade-offs:* RRSIG
  verification in Phase 6 requires re-encoding an RRset in RFC 4034 canonical form — names
  uncompressed and lowercased, records sorted by canonical RDATA ordering, original TTL
  substituted. If Phase 1 ships only a compressing encoder, Phase 6 must either reach back
  into this crate or grow a second, divergent encoder — and two encoders that must agree
  byte-for-byte on a security boundary is a bug factory. → **Recommendation: Phase 1 ships
  an explicit *uncompressed, canonical* encode mode for names and RDATA alongside the
  normal compressing encode, even though the phase spec does not name it.** It is cheap
  now, it is the same code path with compression disabled and names lowercased, and it is
  precisely the kind of thing the project's own warning covers:
  *"Time injection cannot be retrofitted into a validator; it is a rewrite."* The same
  logic applies to canonical form. This is flagged again under Gaps, because it is the one
  scope judgement in this analysis that goes beyond the literal phase spec.

- **Error granularity.** *Trade-offs:* one coarse `MalformedMessage` is simpler; a
  fine-grained enum is more code but carries information the resolver actually branches
  on. → **Recommendation: fine-grained, `thiserror`-derived, with truncation,
  compression-loop and malformed-OPT as *distinct* variants.** Phase 3's forwarder needs
  truncation to mean "retry over TCP", Phase 5's infrastructure cache records
  *"per-nameserver EDNS capability"* and needs malformed-OPT to mean "this server does not
  do EDNS", and Phase 10's query log wants to count decode failures by reason. Collapsing
  them now costs three later phases the signal they need.

- **Section representation.**
  *Trade-offs:* trusting the header's count fields is simpler; treating them as a hint and
  parsing until the buffer is consumed is more defensive.
  → **Recommendation: parse exactly the declared counts, and treat a disagreement between
  declared counts and available bytes as a typed decode error rather than a silent
  truncation.** Declared-count-driven allocation must additionally be bounded — a header
  can claim 65535 records in a 12-byte packet, and pre-allocating on an attacker-supplied
  count is a trivial memory amplification.

### Alternatives Considered

- **Use `hickory-proto` (or the `domain` crate) as a real dependency and build only the
  resolver logic.** Rejected outright by the from-scratch mandate. The mandate is not
  arbitrary: the project's value is a long correctness grind over two hand-written
  security-critical subsystems, and a recursor and validator built on a parse the project
  does not own would be reasoning about someone else's interpretation of the wire at
  exactly the points where interpretation is security-relevant.

- **Generate the codec from a table/DSL of rrtype definitions.** Rejected for v1. It
  trades verbose-but-auditable hand-written parsing — which is what fuzzing and the
  differential oracle are aimed at — for a generator whose output nobody reads. Under
  `indexing_slicing = deny` the generator would also have to emit the checked-arithmetic
  tax correctly, which is the hard part.

- **Make `styx-proto` a feature crate and express the codec through ports in each
  consumer's `domain`.** Rejected explicitly by the project: it is the one stated
  exception to feature-crate isolation, because *"every crate parses through the wire
  codec"*. N ports of identical shape plus N conversions of the same bytes buys no
  isolation.

- **Skip `OPT`/EDNS in Phase 1 and add it with DNSSEC in Phase 6.** Rejected. DO=1 is what
  makes referrals carry DS RRsets unasked, which is the entire basis of the push-side
  chain-material strategy; EDNS payload size is what the Phase 2 TC/TCP-fallback logic
  budgets against; and per-nameserver EDNS capability is a Phase 5 infrastructure-cache
  field. The phase spec lists EDNS(0) OPT in scope for good reason.

- **Prove the codec with self-encoded fixtures and skip the `hickory-proto`
  dev-dependency.** Rejected, and this is the load-bearing rejection of the phase. A
  fixture that styx encodes and styx decodes demonstrates that the encoder and decoder are
  inverses of each other. It cannot demonstrate that either one matches the protocol,
  because a single misreading of a field layout yields an encoder and a decoder that are
  both wrong in the same direction and agree perfectly. The suite would be green and the
  resolver would be unable to talk to the internet. An independent implementation is the
  only cheap oracle that can disagree.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **"every v1 rrtype" is not enumerated anywhere.** The phase spec says "every v1 rrtype"
  without a list. *Needs clarification:* the concrete set. This analysis derives it from
  downstream need — `A`, `AAAA`, `CNAME`, `NS`, `SOA`, `PTR`, `MX`, `TXT`, `SRV`,
  `DNSKEY`, `DS`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `OPT`, plus opaque unknown —
  and notes that `CAA`, `DNAME`, `SVCB`/`HTTPS`, `NAPTR` and `TLSA` are *not* required by
  any named phase and can safely fall through the unknown variant. The unknown variant is
  what makes this ambiguity survivable.

- **ECS handling on the inbound path is undefined.** EDNS Client Subnet is a stated
  non-goal — *"deliberately omitted; it leaks client topology"* — which settles that styx
  never *originates* ECS. It does not settle what happens to an ECS option arriving from a
  client or an upstream: preserve it in the decoded message and drop it on re-encode,
  strip it at decode, or refuse the message. *Needs clarification.* The privacy rationale
  argues for strip-on-forward at minimum; the codec should at least represent it so the
  decision can be made in a policy layer rather than forced here.

- **Case-sensitivity policy on `Name` is not stated anywhere.** Four later phases depend
  on it (cache key, matcher trie key, bailiwick comparison, DNSSEC canonical form). A
  recommendation is given above, but it is a recommendation, not a recorded decision.

- **Whether the message type retains the original bytes.** DNSSEC verification and any
  future signed-response handling benefit from access to the exact octets as received;
  owned decoded types alone discard them. *Needs clarification* — most cheaply resolved by
  the canonical-encode recommendation above, which removes the need to retain raw bytes.

- **TTL decrement is named in scope without saying who owns it.** The phase spec says
  *"every label offset and TTL decrement"* must be checked, but TTL decrement is a *cache*
  behaviour (Phase 4: *"TTL handling, RFC 2308 negative caching"*), not a codec behaviour.
  *Needs clarification:* whether `styx-proto` exposes a checked TTL-adjustment operation
  on its TTL type (recommended — it keeps the arithmetic tax paid in one place and gives
  Phase 4 a saturating primitive) or whether the phrase is simply pointing at the lint
  regime rather than assigning ownership.

- **"Fuzz clean overnight" has no defined duration, corpus or machine.** *Needs
  clarification:* a concrete wall-clock figure, whether it is run on CI or locally, and
  whether the corpus is seeded from the oracle fixtures. As written it is unfalsifiable.

- **"over generated messages" does not say how messages are generated.** *Needs
  clarification:* whether the generator is property-based (e.g. `proptest`/`arbitrary`
  producing structurally valid messages), a fixed corpus, or fuzzer-derived — and what the
  agreement predicate is when the two implementations legitimately differ (compression
  choices, for instance, are not unique; two correct encoders may emit different bytes for
  the same message).

### Edge Cases

- **Compression pointer to itself, and pointer cycles of length > 1.** Named in scope.
  Must terminate with a typed error, not recursion, not a loop bound that is merely large.
- **Acyclic but quadratic pointer chains.** Legal, non-looping, and still a decode-side
  denial of service via expansion. Loop detection alone does not cover it; a total
  expansion budget does.
- **Forward pointers and pointers into the middle of a label.** Both are producible by a
  hostile sender and neither is covered by "does it loop".
- **Pointer offset ≥ 16384 on encode.** The 14-bit pointer field cannot address it; the
  encoder must emit the name uncompressed rather than truncate the offset.
- **Name exactly 255 octets, and 256.** Boundary; the wire limit includes the root label
  and the length octets, which is where off-by-one lives.
- **Label of exactly 63 octets, and 64.** 64 sets the top bits and becomes a malformed
  pointer, which is why the boundary is security-relevant rather than cosmetic.
- **RDLENGTH disagreeing with parsed RDATA** — both shorter (trailing bytes) and longer
  (overrun). Compression pointers *inside* RDATA of legacy types make the "parsed length"
  differ from the "wire length", which is exactly where re-encoding goes wrong.
- **Header counts claiming more records than the packet contains** — and the
  pre-allocation amplification that follows if counts are trusted for capacity.
- **Zero-length and 12-byte-exact messages;** a header with QDCOUNT 0.
- **Multiple OPT records in the additional section** — a protocol violation that must be
  rejected rather than silently last-wins.
- **OPT with version ≠ 0**, which requires `BADVERS` in the extended RCODE and therefore
  requires the extended-RCODE representation to exist.
- **EDNS option with a length field overrunning the OPT RDATA.**
- **Message at exactly the EDNS payload size, and one octet over.** The truncation
  boundary the server loop depends on.
- **TCP messages at the 65535 two-octet-length-prefix ceiling.**
- **A record whose RDATA is empty** (NODATA-adjacent shapes) and a TXT record with zero
  character-strings vs. one empty character-string — distinct on the wire, frequently
  conflated.
- **TXT with multiple character-strings**, each length-prefixed; flattening them loses
  information that matters to upstream consumers.
- **NSEC3 with a large iterations count.** The codec does not enforce the *"mandatory
  iterations cap"* — that is Phase 6c's job, and *"uncapped NSEC3 is a CPU denial of
  service"* — but the codec must expose the field plainly so the cap can be applied.
- **Unknown rrtype whose RDATA happens to contain bytes resembling a compression
  pointer.** RFC 3597 forbids compression in unknown RDATA; treating it as opaque is
  correct and treating it as a name is a vulnerability.

### Technical Risks

- **Hand-written wire parsing under `indexing_slicing = deny` and
  `arithmetic_side_effects = deny`.** Recorded verbatim as a project risk: *"Every label
  offset and TTL decrement becomes a checked operation. That is the intended tax, but it
  makes the codec verbose and compression-pointer loop detection fiddly. Fuzzing is not
  optional."* *Impact:* the codec is significantly more code than an unchecked equivalent,
  and the verbosity itself hides bugs. *Mitigation direction:* a small, audited cursor/
  reader abstraction that pays the checked-access tax once and is used everywhere, rather
  than checked arithmetic sprinkled at each call site; plus the fuzz targets named in the
  requirement.

- **`panic = "deny"` is load-bearing and its real mitigation arrives eleven phases
  later.** *"In a single process, a panic in a Leptos request handler takes DNS down for
  the whole house. The lint helps; a `catch_unwind` boundary around the web layer and a
  supervised task model are the real mitigation."* Those land in Phase 12 — Cutover
  hardening. *Impact:* between Phase 1 and Phase 12, the lint is the only thing standing
  between a malformed packet from the LAN and a dead resolver. *Mitigation direction:*
  treat the decode-arbitrary-bytes fuzz target as a panic-freedom proof, not a crash hunt;
  forbid `unwrap`/`expect` outside tests via the `no-unwrap-expect` rule Phase 0 enables.

- **The oracle can rot into a real dependency.** If `hickory-proto` ever migrates from
  `[dev-dependencies]` to `[dependencies]` — through a transitive path, a feature flag, or
  a careless edit — the from-scratch mandate is silently void and the differential test
  becomes a test of a crate against itself. *Mitigation direction:* the `hickory-dev-only`
  check plus the independent `cargo tree --edges normal` gate, both from Phase 0, both in
  `just gate`, both run on every push.

- **The architecture gate may be silently inert.** A recorded project risk, spiked
  2026-09-21 against arch-lint 0.5.0: the committed `arch-lint.toml` contains
  `[[layers]]`, which routes arch-lint to its tree-sitter engine; that engine ships
  exactly one grammar, `tree-sitter-kotlin-ng`, and filters discovery to `.kt`/`.kts`. On
  a Rust repo it analyses **zero files and exits 0** — including the AL001–AL013 rules.
  Without `[[layers]]`, the **syn** engine runs AL001–AL013 plus `[[scopes]]`,
  `[[deny-scope-dep]]` and `[[restrict-use]]`, which do enforce layering on Rust by path
  glob. *Impact on Phase 1:* if Phase 0's replacement is incomplete, this phase's layering
  and its `no-unwrap-expect` enforcement are theatre, and an inert config looks identical
  to a passing one. *Mitigation direction:* Phase 0's exit criterion already requires
  proving the gate with a deliberate violation; Phase 1 should not begin until that proof
  exists.

- **`[[restrict-use]]` may accidentally forbid the one legitimate shared dependency.** The
  same config that stops feature crates naming each other must explicitly permit every
  crate to name `styx-proto`. *Impact:* either a false positive that blocks all work, or —
  worse — a rule written so loosely to accommodate `styx-proto` that it stops enforcing
  feature isolation at all. *Mitigation direction:* assert both directions with deliberate
  violations, as Phase 0 does for layering.

- **A codec bug is invisible and compounds.** Phases 1 through 7
  *"produce nothing a human can look at except `dig` output"*, and because the cutover is
  last there is no operational feedback and *"no one is waiting on it either"* — the
  project records this as concentrating scope risk
  *"into one long stretch with neither visible progress nor external pressure."* A subtle
  misparse here surfaces as an inexplicable recursion or validation failure several phases
  downstream. *Mitigation direction:* the differential oracle is the entire answer; treat
  any disagreement with `hickory-proto` as a defect in styx until proven otherwise.

- **Two correct encoders can emit different bytes.** Name compression admits choices, so
  byte-for-byte equality against the oracle is too strong a predicate for the encode
  direction. *Mitigation direction:* compare semantically — decode both outputs with both
  implementations and compare the decoded structures — and reserve byte equality for the
  hand-assembled fixtures where the expected bytes are pinned deliberately.

- **DNSSEC canonical form retrofitted later becomes a second encoder.** See the
  corresponding design decision. Two encoders that must agree on a security boundary is a
  structural hazard; the project's own precedent for this class of problem is the
  injectable `Clock` —
  *"Time injection cannot be retrofitted into a validator; it is a rewrite."*

- **Memory amplification from attacker-controlled counts and lengths.** Header counts,
  RDLENGTH, and EDNS option lengths are all attacker-supplied numbers that could drive
  allocation on a Raspberry Pi-class target.

### Acceptance Criteria Coverage

The phase spec's exit criteria, **preserved verbatim**:

> Fuzz clean overnight; differential encode/decode agreement with `hickory-proto`
> over generated messages.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | Fuzz clean overnight | Partial | Addressable via the two required `cargo fuzz` targets (decode-arbitrary-bytes; decode→encode roundtrip). **Gap:** "overnight" is not a defined duration, the corpus seeding is unspecified, and no machine/CI placement is named. Needs a concrete figure to be falsifiable. Note this is the *phase* gate — continuous fuzzing thereafter is a separate, ongoing obligation. |
| 2 | Differential encode/decode agreement with `hickory-proto` over generated messages | Partial | Addressable with `hickory-proto` in `[dev-dependencies]`. **Gaps:** (a) "generated messages" does not name a generation strategy or a rrtype distribution — without steering, a generator will under-sample DNSSEC types and pathological names, which are exactly the interesting cases; (b) byte-for-byte encode equality is the wrong predicate because name compression admits multiple correct outputs — a semantic comparison is needed; (c) the oracle cannot generate the pathological cases at all, which is why the requirement separately mandates hand-assembled byte vectors — those are in scope but are not covered by either exit criterion. |

**Scope items in the requirement not covered by any exit criterion** (addressable, but
they pass the gate silently if not separately asserted):

| Scope item | Addressable? | Gaps/Notes |
|---|---|---|
| Header, question, RR, RDATA for every v1 rrtype | Partial | The rrtype set is never enumerated; derived here from downstream phase need, with the opaque-unknown variant as the safety net. |
| Name compression on **both** encode and decode | Yes | Encode-side correctness is only weakly covered by the differential criterion, since correct encoders may compress differently. |
| Compression-pointer loop detection | Yes | Covered by fuzzing and by the hand-assembled vectors, *not* by the oracle — a well-behaved oracle never produces a loop. |
| EDNS(0) OPT | Yes | DO bit, payload size and extended RCODE each need an explicit assertion; they are trivially under-sampled by a naive generator. |
| Every label offset and TTL decrement checked | Yes | Enforced by `indexing_slicing`/`arithmetic_side_effects` in the per-push gate, not by the phase exit criteria. TTL-decrement *ownership* between this crate and the Phase 4 cache is unresolved. |
| Hand-assembled byte vectors for pathological cases | Yes | Required by the scope, asserted by neither exit criterion. Recommend promoting to an explicit gate. |
| `styx-proto` depended on by all crates, depending on none | Yes | Enforced by the Phase 0 `[[restrict-use]]` config and the `cargo tree` gate — which must be proven with a deliberate violation, since an inert config looks identical to a passing one. |
| `hickory-proto` confined to `[dev-dependencies]` | Yes | Enforced by the Phase 0 `hickory-dev-only` check on every push. |
| DNSSEC canonical (uncompressed, lowercased) encode | **Not in stated scope** | Flagged as a recommended scope addition; retrofitting it in Phase 6 means a second encoder that must agree byte-for-byte with this one on a security boundary. |
