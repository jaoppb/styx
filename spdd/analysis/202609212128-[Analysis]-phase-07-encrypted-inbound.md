# SPDD Analysis: Phase 7 — Encrypted inbound (DoT / DoH)

> Project: **styx** — a filtering DNS resolver written from scratch in Rust, replacing
> Pi-hole's role on a home network (recursive/forwarding resolution, per-client
> blocking policy, Leptos admin UI). Single process, single binary, one box.
>
> Codebase context: **greenfield, no existing implementation.** At the time of this
> analysis the repository contains only the decision record, the roadmap, the phase
> specs and a placeholder `arch-lint.toml`. There is no git repository, no Cargo
> workspace and no source code. Every "existing" concept named below is therefore a
> *commitment made by an earlier phase of this same build*, not code that can be
> read today. All analysis is grounded in the project's settled decisions, which are
> inlined here in full so this document stands on its own.

---

## Original Business Requirement

The following is the phase specification verbatim and unmodified.

```markdown
# Phase 7 — Encrypted inbound (DoT / DoH)

> Part of [ROADMAP.md](../../ROADMAP.md) · Previous: [Phase 6 — DNSSEC](06-dnssec.md) · Next: [Phase 8 — Filtering](08-filtering.md)

## Scope

- TLS listeners and an HTTP/2 DoH endpoint.
- Certificates are operator-supplied via a TOML path, with a self-signed cert
  generated at first boot and its SPKI pin printed once to the log (decision 43).
  styx owns no PKI and no ACME client.

## Exit criteria

`kdig +tls` and `curl` DoH both succeed against an operator-supplied cert; the
self-signed path prints a usable pin and is documented as adequate for
DoH-with-pin and inadequate for Android Private DNS.
```

### The decision the phase spec cites, inlined in full

The phase spec's "decision 43" is the following entry in the project's decision
record. It is reproduced here in full, with its rationale and its accepted
consequence, because the decision record is being retired and this reasoning must
survive:

> **DoT/DoH certificates are operator-supplied, with a self-signed fallback.**
> The TOML points at a cert/key path. If absent, styx generates a self-signed cert
> at first boot and prints the SPKI pin once to the log. styx owns no PKI and
> implements no ACME client — bring a cert from whatever pipeline you already have.
> **Accepted consequence:** self-signed is usable for `curl` and DoH clients that
> accept a pin, and largely unusable for DoT clients like Android Private DNS,
> which want a publicly-valid name. The real answer for those is "bring a cert".

### Surrounding decisions that bind this phase

These are the other settled decisions this phase must honour. They are inlined
rather than cited, with the reason each was taken.

1. **Config has two stores with a hard boundary: the file owns infrastructure, the
   database owns policy.** A TOML file owns everything needed before the database
   exists or in order to reach it — listen addresses, upstreams and pools,
   selection strategy, **TLS material**, trust anchor, DB path, log mode. Turso
   owns everything a human edits at runtime — clients, groups, adlists, allow/block
   rules, local records, privacy level, blocking mode. The UI can change only
   DB-backed things; **file changes need a restart.** *Why:* no overlap means no
   precedence rule, and it guarantees that a dead database cannot touch resolution,
   because nothing resolution needs lives there. *Accepted consequence:* changing
   infrastructure config requires SSH and a restart, which is the thing people most
   want to do from the UI. **For this phase this is load-bearing: TLS certificate
   paths live in the TOML file, not the database, so rotating a certificate is a
   restart, not a UI edit.**

2. **Single process, single binary.** DNS listeners, Leptos SSR and background
   workers share state via `Arc`. The web UI is a compile-time Cargo feature
   (`web`, default on) so a headless resolver can be built, and CI builds and tests
   `--no-default-features` on every commit — otherwise the headless build rots
   within a month. **For this phase: the DoH endpoint is a DNS listener, not part of
   the admin UI, so it must build and serve with `--no-default-features`.**

3. **One crate per feature; `domain` / `application` / `infrastructure` are modules
   inside it.** Cargo enforces feature-to-feature isolation; arch-lint enforces
   layering within a crate.

4. **Feature crates never depend on each other.** Cross-feature needs are expressed
   as a port (a trait) in the consumer's `domain`, implemented by an adapter in the
   binary. `styx-web` may depend on a feature's `application` layer, because it is
   presentation, not a peer.

5. **`styx-proto` is shared foundation, not a feature crate.** Every crate parses
   through the wire codec, so the "feature crates never depend on each other" rule
   does not reach it. This is the one explicit exception.

6. **The pipeline order is fixed and is a correctness property, not a detail:**
   local records → filter → cache → upstream. Local records and blocked replies are
   both forged answers, so both clear AD, forge no signature, and never enter the
   answer cache. **For this phase: an encrypted-transport query must enter exactly
   this pipeline at exactly the same point a plaintext UDP/TCP query does.**

7. **The hot path touches no I/O.** Matcher state is in memory; the database holds
   config, adlist definitions, clients/groups and history only. A database outage
   degrades logging and admin, never resolution.

8. **The cutover is last.** styx runs on a dev box until everything works; the
   household's resolver stays on Pi-hole until v1 is complete. Nothing mid-build has
   to be shippable, breaking changes stay free, and phases are ordered by dependency
   and risk rather than usability.

9. **Lint policy:** 15 denied clippy lints workspace-wide including
   `indexing_slicing`, `arithmetic_side_effects` and a deny-level panic lint, with
   four `allow-*-in-tests` entries. arch-lint additionally enforces
   `no-unwrap-expect` (allowed in tests), `require-tracing`, `tracing-env-init`,
   `no-sync-io` and `require-thiserror`, and is run by lefthook on pre-commit and
   pre-push *and* by GitHub Actions — a lint that only runs locally is not
   enforcement.

10. **TDD cycles run at socket level by default.** Feature tests drive real UDP/TCP
    against an ephemeral-port server, with in-process fake servers and an injectable
    `Clock`. `hickory-proto` is the test oracle and a `[dev-dependencies]`-only
    entry; a CI check asserts it appears in no normal or build dependency path.

### Non-goals that bear directly on this phase

- **DNS-over-QUIC (DoQ, RFC 9250) is an explicit v1 non-goal, inbound *and*
  outbound.** This phase delivers DoT and DoH only. No QUIC listener, no HTTP/3
  DoH, no `h3` ALPN advertisement.
- **EDNS Client Subnet (RFC 7871) is deliberately omitted; it leaks client
  topology.** Encrypted inbound must not reintroduce a client-locating header by
  another route.
- **No DHCP server.** Clients are identified by IP plus optional manual naming, so
  client identity is best-effort and breaks on DHCP churn. This constrains what an
  encrypted listener can hand the policy layer as a client identity.
- **Authoritative zone serving is a non-goal.** This phase adds transports, not
  zones.
- **Multi-node or replicated deployment is a non-goal.** One box, one binary, local
  DB file — so there is no cluster-wide certificate distribution problem to solve.
- **Multi-user admin, roles and audit trail are non-goals.** There is no per-user
  identity to bind a TLS session to.

### Phase dependencies

**This phase depends on:**

- **Phase 0 — Foundation and gates.** The workspace skeleton, the working syn-engine
  `arch-lint.toml` with `[[scopes]]` / `[[deny-scope-dep]]` / `[[restrict-use]]`,
  `clippy.toml` with the 15 denied lints, lefthook, GitHub Actions, and the
  `just gate` target. Also the `hickory-dev-only` check and the independent
  `cargo tree --edges normal` layering gate.
- **Phase 1 — Wire codec (`styx-proto`).** Encode/decode of DNS messages, fuzzed.
  Both DoT and DoH carry the identical wire-format message this codec produces and
  consumes.
- **Phase 2 — Server loop and test harness.** This is the phase this one extends.
  It delivers the UDP and TCP listeners, the TC bit and TCP fallback, the **request
  pipeline skeleton**, the injectable `Clock`, the in-process fake root/TLD/
  authoritative servers, and the declared hot-path ports (`FilterPolicy`, the
  `LocalRecords` lookup, the query-log observer) with no-op implementations. Phase 7
  adds two new transports in front of that same pipeline and must add nothing to the
  pipeline itself.
- **Phase 3 — `Upstream` port, forwarding, pool**, **Phase 4 — Answer cache**,
  **Phase 5 — Recursion**, **Phase 6 — DNSSEC.** These stand behind the pipeline.
  Phase 7 consumes them transitively and changes none of them; a DoT query must
  produce byte-identical resolution behaviour to a Do53 query, including the AD bit.

**Phases that depend on this one:**

- **Phase 8 — Filtering (`styx-filtering`).** Per-client groups mean the verdict
  depends on a client identity, and the identity of a DoT/DoH client is whatever
  this phase extracts from the encrypted connection. Phase 8's five blocked-reply
  modes must behave identically over an encrypted transport.
- **Phase 10 — Query log pipeline.** Rollup buckets are keyed per (client, decision,
  qtype); the client attribution this phase produces flows straight into them, and
  the transport is a thing the live view will plausibly want to show.
- **Phase 11 — Web UI (`styx-web`, Leptos SSR).** Introduces a second HTTP surface
  in the same process. Whether it shares a listener, a port or a TLS configuration
  with the DoH endpoint is decided here, before the UI exists.
- **Phase 12 — Cutover hardening.** Adds the `catch_unwind` boundary and the
  supervised task model, then points the household at styx. Until phase 12, the
  deny-level panic lint is the only guard.

### The risks recorded against this phase

Inlined from the project's risk register, with the reasoning intact:

- **The deny-level panic lint is load-bearing, and its real mitigation arrives
  last.** In a single process, a panic in a request handler takes DNS down for the
  whole house. The lint helps; a `catch_unwind` boundary around the web layer and a
  supervised task model are the real mitigation, and they are **Phase 12 — Cutover
  hardening**. Everything before phase 12, including every TLS handshake path, every
  HTTP/2 stream handler and every certificate-loading path written in this phase,
  relies on the lint alone. **A panic on a malformed ClientHello or a malformed DoH
  request body would take the household's DNS down, and nothing structural stops
  it yet.**
- **Hand-written wire parsing under `indexing_slicing = deny` and
  `arithmetic_side_effects = deny`.** Every offset and length computation becomes a
  checked operation. That is the intended tax. It applies directly to this phase's
  DoT two-octet length prefix framing and to DoH body length handling.
- **Resolution-first plus a last cutover removes every feedback loop.** Phases 1
  through 7 produce nothing a human can look at except `dig` output, and the cutover
  being last means no one is waiting on it either. **This phase is the last of that
  stretch**, and it is the first that produces something an ordinary client
  (a phone, a browser) could talk to — which makes its own exit criteria the only
  feedback available.
- **v1 scope is large.** Two from-scratch security-critical subsystems, plus groups,
  adlists, encrypted inbound and a UI. The phasing exists for this reason; taking
  the phases out of order is how the project stalls.
- **Client identity is unreliable by construction** (the DHCP non-goal). Per-client
  groups keyed on IP will silently misattribute after a lease change. Manual naming
  and a visible "last seen" are mitigations, not fixes. Encrypted transports do not
  improve this and may make it worse, since a DoH client can sit behind a proxy.

---

## Domain Concept Identification

### Existing Concepts

Greenfield: none of these exist as code. Each is a commitment made by an earlier
phase of this build that phase 7 attaches to. They are listed as "existing" because
phase 7 must not redefine them.

- **DNS message (wire format)**: the encoded question/answer unit. Owned by
  `styx-proto` (Phase 1). Identical bytes on Do53, DoT and DoH — the transport
  changes the envelope, never the payload.
- **Request pipeline**: the fixed ordering local records → filter → cache → upstream,
  delivered as a skeleton by Phase 2. It is the single place a query is answered.
  Phase 7 adds entry points to it and adds nothing inside it.
- **Listener**: the existing notion of a socket-bound accept loop serving the
  pipeline. Phase 2 delivers UDP and TCP variants. DoT and DoH are two further
  variants of the same concept.
- **TCP DNS framing**: the two-octet big-endian length prefix that precedes each
  message on a TCP stream, plus the TC-bit-and-retry-over-TCP behaviour, delivered
  by Phase 2. DoT reuses this framing unchanged inside the TLS stream; DoH does not
  use it at all.
- **Client identity**: an IP address, optionally hand-named. Best-effort by
  construction, because DHCP is a non-goal. It is what per-client group policy will
  key on in Phase 8 and what query-log rollups will bucket on in Phase 10.
- **File configuration (TOML)**: the infrastructure-owning config store. Already
  owns listen addresses, upstreams, pools, selection strategy, trust anchor path, DB
  path and log mode. **TLS material joins it here.**
- **Injectable `Clock`**: the time port introduced in Phase 2 because signature
  inception and expiration timestamps make recorded fixtures expire on a date nobody
  chose. Certificate validity windows are the same class of problem, so a
  self-signed certificate's notBefore/notAfter must come from this `Clock` and not
  from the system clock directly.
- **Hot-path ports**: `FilterPolicy`, the `LocalRecords` lookup and the query-log
  observer, declared in Phase 2 with no-op implementations. Phase 7 touches none of
  them but must ensure encrypted requests reach them with a correctly populated
  client identity.
- **`Result<T, E>` with `thiserror` enums, and `tracing`**: the project's mandated
  error and observability idiom, enforced by arch-lint's `require-thiserror` and
  `require-tracing` rules.

### New Concepts Required

- **TLS listener configuration**: the block in the TOML file that says whether
  encrypted inbound is enabled, on which addresses and ports DoT and DoH listen, and
  where the certificate and key live. Lives in the file store because it is
  infrastructure, which by the hard config boundary means changing it requires a
  restart. Relates to the existing file-configuration concept as one more section of
  it.
- **Certificate source**: the abstraction over *where the serving identity comes
  from* — an operator-supplied path, or the generated self-signed fallback. This is
  the conceptual heart of the phase. It has exactly two variants and no third:
  styx owns no PKI and implements no ACME client, so there is deliberately no
  "obtain a certificate from an authority" variant and no renewal concept.
- **Self-signed certificate generator**: the first-boot fallback that mints a
  key pair and a self-signed certificate when no operator path is configured.
  Produces material that must persist across restarts, or every restart invalidates
  every pin the operator distributed.
- **SPKI pin**: the Subject Public Key Info fingerprint of the serving certificate,
  printed once to the log so the operator can distribute it to clients that pin.
  This is the *only* usable trust path for the self-signed variant. It relates to
  the certificate source as a derived, publishable property of whichever certificate
  is in use. Note the deliberate symmetry with the existing admin-credential
  behaviour, where a generated first-boot secret is likewise printed once to the log
  and never again.
- **DoT listener (DNS-over-TLS)**: a TLS-wrapped TCP accept loop whose inner stream
  carries exactly the existing TCP DNS framing. Conceptually it is the existing TCP
  listener with a TLS layer interposed, and it should share the framing code rather
  than restate it.
- **DoH endpoint (DNS-over-HTTPS over HTTP/2)**: an HTTP service whose single
  resource accepts a wire-format DNS message — as a request body, or base64url-
  encoded in a query parameter — and returns a wire-format DNS message. It is a
  *DNS listener that happens to speak HTTP*, not a piece of the admin UI, and this
  distinction has a hard consequence: it must compile and serve in the headless
  `--no-default-features` build where the web UI crate is absent.
- **Encrypted connection context**: what the transport knows about a request that
  the pipeline needs — principally the peer address that becomes the client
  identity, and for DoH the fact that it arrived over HTTP. This is the seam where
  the two new transports converge on the one existing pipeline.
- **TLS listener lifecycle / connection budget**: the notion that a TLS connection
  is long-lived, expensive to establish, and must be bounded — idle timeout, maximum
  concurrent connections, maximum queries per connection. Do53 over UDP has no such
  concept; introducing stateful encrypted transports introduces it.

### Key Business Rules

- **The certificate is operator-supplied by path, or self-signed. There is no third
  option.** styx owns no PKI and implements no ACME client. Governs: certificate
  source, TLS listener configuration. *Why:* certificate issuance is a solved
  problem with existing pipelines; owning one would add an unbounded,
  security-critical surface to a project that already contains two hand-written
  security-critical subsystems.
- **When no certificate path is configured, generate a self-signed certificate at
  first boot and print its SPKI pin once to the log.** Governs: self-signed
  generator, SPKI pin. *Why:* the feature must be usable out of the box by an
  operator who has no certificate, without inventing a trust authority.
- **Self-signed is documented as adequate for `curl` and DoH clients that accept a
  pin, and inadequate for DoT clients such as Android Private DNS, which want a
  publicly-valid name.** The documented answer for those clients is "bring a
  certificate." Governs: the documentation deliverable, which the exit criteria make
  a first-class output of this phase rather than an afterthought.
- **TLS material lives in the TOML file, never in the database.** Governs:
  TLS listener configuration. *Why:* the hard config boundary — the file owns
  infrastructure, the database owns policy; no overlap means no precedence rule, and
  it keeps a dead database from being able to touch resolution. *Consequence:*
  changing a certificate is a restart, not a UI edit, and the UI must not offer to
  edit it.
- **DNS-over-QUIC (RFC 9250) is not implemented, inbound or outbound.** Governs: the
  listener inventory and the ALPN set. No `doq` listener, no HTTP/3, no `h3`
  advertisement.
- **Encrypted transports change the envelope, never the answer.** A query arriving
  over DoT or DoH enters the same pipeline in the same order — local records →
  filter → cache → upstream — and produces the same bytes as the same query over
  Do53. Governs: the encrypted connection context and both listeners. *Why:* the
  pipeline order is a correctness property; a second, divergent path through it is
  how blocked replies or AD-bit handling start differing by transport.
- **Blocked and locally-answered replies still clear AD and forge no signature over
  an encrypted transport.** Governs: the interaction with Phase 8. TLS authenticates
  the channel, not the data; it must not be allowed to imply the answer is
  DNSSEC-validated.
- **Client identity over an encrypted transport is still an IP address, and is still
  best-effort.** Governs: encrypted connection context, and the per-client group
  policy in Phase 8. No client-identifying header is introduced, consistent with the
  EDNS Client Subnet non-goal.
- **The headless build must still work.** The DoH endpoint is a resolver feature and
  cannot be gated behind the `web` Cargo feature. Governs: crate layout and
  dependency direction. *Why:* CI builds and tests `--no-default-features` on every
  commit precisely so the headless build cannot rot.
- **No unwrap, no expect, no panic, no synchronous I/O outside the permitted layer,
  errors as `thiserror` enums, instrumentation via `tracing`.** Governs: every new
  module. *Why:* in a single process a panic in a request handler takes DNS down for
  the whole house, and the structural mitigation is three phases away.

---

## Strategic Approach

### Solution Direction

Treat this phase as **two new transport adapters in front of an unchanged request
pipeline, plus one small certificate-provisioning concern shared between them.**

The shape follows the project's own layering rule — one crate per feature, with
`domain` / `application` / `infrastructure` as modules inside it, ports as traits in
`domain`, adapters in `infrastructure`, wiring in the `styx` binary:

- **`domain`** holds the pure concepts: the TLS listener configuration value type,
  the certificate-source enumeration (operator path vs. self-signed), the SPKI pin
  as a derived value type, and a `CertificateSource`-style port describing "hand me
  serving material" without naming a file or a TLS library. Errors are a
  `thiserror` enum; every fallible step returns `Result`.
- **`application`** holds the resolution of that port into an actual serving
  identity at startup — read the configured path, or fall back to generating and
  persisting self-signed material — and the one-time emission of the SPKI pin
  through `tracing`. It also owns connection-budget policy (idle timeout, concurrent
  connection ceiling) as plain values, not as library configuration.
- **`infrastructure`** holds the two accept loops and the TLS/HTTP plumbing: the
  DoT loop (TLS over TCP, inner stream carrying the existing two-octet length
  prefix framing) and the DoH endpoint (HTTP/2, one resource, wire-format message in
  and out), plus the concrete filesystem certificate reader and the concrete
  self-signed generator.
- **The `styx` binary** wires both listeners to the same pipeline handle it already
  wires UDP and TCP to.

**Data flow, DoT:** TCP accept → TLS handshake (ALPN `dot`) → read two-octet length
prefix → read message → existing `styx-proto` decode → **existing pipeline** → encode
→ write length prefix + message → keep the connection open under the idle budget.

**Data flow, DoH:** TCP accept → TLS handshake (ALPN `h2`) → HTTP/2 stream → route
the single DNS resource → take the wire-format message from the request body or the
base64url query parameter → existing `styx-proto` decode → **existing pipeline** →
encode → respond with the wire-format media type.

The single most important property of both flows is that they converge on the
*same* pipeline entry point Phase 2 built, carrying a client identity in the same
shape Phase 2 established. Anything a listener needs to tell the pipeline travels in
the existing request context, not in a parallel encrypted-only path.

Testing follows the project's socket-level default: drive a real TLS client against
an ephemeral-port listener, with the injectable `Clock` controlling certificate
validity windows, and assert that a question resolved over DoT, over DoH and over
plaintext Do53 produces identical answer bytes. `hickory-proto` remains the
`[dev-dependencies]`-only oracle for constructing and reading the wire messages the
test client sends.

### Key Design Decisions

- **Reuse a vetted TLS implementation rather than writing one.** *Not settled by the
  decision record; proposed here.* Trade-off: the project's from-scratch commitment
  is explicitly scoped to *the DNS stack* — wire codec, server loop, caches,
  recursion, DNSSEC validation — and equally explicitly excludes the test oracle. It
  says nothing about TLS. Writing a TLS stack would add a third hand-written
  security-critical subsystem to a v1 whose scope is already listed as a top risk.
  → **Recommendation: use an established pure-Rust TLS implementation for both
  listeners.** The from-scratch rule protects the DNS protocol work, whose value is
  correctness under a hand-written recursor and validator; it is not a rule against
  using a cryptographic library, and the project already assumes established
  cryptography elsewhere (Argon2id for the admin password, signature verification
  for DNSSEC).

- **One certificate, both listeners.** Trade-off: separate certificates per
  transport would allow a publicly-valid name for DoT and a pinned self-signed
  certificate for DoH, but it doubles the configuration surface, doubles the
  rotation procedure and doubles the pin-printing story, on a single-box deployment
  that has exactly one name. → **Recommendation: one certificate source feeding both
  listeners.** The decision record speaks of "the TOML points at a cert/key path" in
  the singular, and the accepted consequence is written as one posture ("bring a
  cert") rather than a per-transport one.

- **Self-signed material must be persisted, not regenerated per boot.** Trade-off:
  regenerating on every boot is trivially stateless but invalidates every pin the
  operator distributed, every restart — which would make the pin useless and the
  printed-once behaviour actively misleading. Persisting means writing key material
  to disk and owning its file permissions. → **Recommendation: generate once,
  persist, reuse; print the pin on generation and make the pin re-derivable from the
  stored material.** The decision says "generated at first boot", which is a
  first-boot event, not a per-boot one.

- **The pin is printed once, but must be recoverable.** Trade-off: printing once
  matches the project's existing precedent for the generated first-boot admin
  secret, and avoids leaving credentials scrolling through the log forever. But an
  operator who misses the line has no recourse if the pin is unrecoverable. →
  **Recommendation: print once on generation as specified, and provide a
  non-interactive way to re-derive the pin from the stored certificate** (the pin is
  a public value derived from a public key, so re-deriving it leaks nothing). This
  respects the decision while not stranding the operator; it differs from the admin
  password, which is a secret and genuinely cannot be reprinted.

- **Fail loudly on a broken operator certificate; fall back to self-signed only when
  no path is configured.** Trade-off: silently falling back when a configured path
  is missing or malformed would keep the daemon up, but would swap a publicly-valid
  identity for one no client trusts — turning a config error into a silent,
  household-wide DoT outage that looks like a client bug. → **Recommendation: the
  self-signed path triggers on *absence of configuration*, never on *failure to load
  configured material*.** A configured-but-unloadable certificate is a startup
  error. The decision's wording is "If absent", which is the absence of a configured
  path.

- **TLS failures must never take down plaintext resolution.** Trade-off: the
  simplest startup aborts the process if any listener fails to bind. But encrypted
  inbound is an addition to a resolver whose core job is Do53, and in a single
  process there is no supervisor yet. → **Recommendation: a certificate or TLS
  binding failure is a hard, loud startup failure *before* the resolver begins
  serving, so the operator sees it immediately; but a per-connection TLS error is
  logged and drops that connection only.** The distinction matters because the
  supervised task model and `catch_unwind` boundary do not arrive until Phase 12.

- **The DoH endpoint is independent of the `web` Cargo feature.** Trade-off: reusing
  whatever HTTP stack the Leptos admin UI will bring in Phase 11 would avoid a second
  HTTP dependency, but it would make DoH vanish from the headless build, which CI
  compiles and tests on every commit. → **Recommendation: DoH owns its own HTTP
  serving, gated by its own configuration and not by `web`.** This is a decision that
  must be taken now, before the UI exists, because reversing it later means moving a
  DNS listener across a feature boundary.

- **DoH and the admin UI do not share a listener.** Trade-off: sharing one HTTPS port
  is tidier for firewall rules, but it couples a DNS transport's availability and
  TLS configuration to a UI that is compiled out of the headless build, and it would
  put an unauthenticated resolver resource and an authenticated admin surface behind
  one origin — which interacts badly with the admin session's origin check. →
  **Recommendation: separate listeners, separate configuration.** Revisit only if
  Phase 11 surfaces a concrete need.

- **DoT reuses the existing TCP framing code rather than restating it.** Trade-off:
  a standalone DoT reader is simpler to write in isolation, but the two-octet length
  prefix is exactly the code already under `indexing_slicing`/`arithmetic_side_effects`
  scrutiny and already fuzzed. Duplicating it duplicates the risk. →
  **Recommendation: factor the framing so the plaintext TCP listener and the DoT
  listener share one implementation over a generic stream.**

- **Connection budgets are explicit configuration, not library defaults.** Trade-off:
  relying on defaults is less to specify, but TLS makes connection establishment the
  expensive operation and an unbounded connection count on a Raspberry Pi is a
  resource-exhaustion path with no equivalent on UDP. → **Recommendation: idle
  timeout, concurrent connection ceiling and per-connection query ceiling are named
  TOML values with documented defaults.** This mirrors the project's existing
  instinct on the NSEC3 iterations cap: an uncapped resource is a denial of service.

### Alternatives Considered

- **Implement an ACME client so certificates are automatic.** Rejected: explicitly
  excluded by the decision — "styx owns no PKI and implements no ACME client — bring
  a cert from whatever pipeline you already have." An ACME client needs inbound
  reachability or DNS-01 control, persistent renewal state and a renewal scheduler,
  all inside a project whose scope is already flagged as its largest risk, and all
  to solve a problem every operator already solves somewhere else.
- **Add DNS-over-QUIC alongside DoT and DoH.** Rejected: DoQ (RFC 9250) is an
  explicit v1 non-goal, inbound and outbound.
- **Ship encrypted inbound after filtering (Phase 8) instead of before it.**
  Rejected: phases are ordered by dependency and risk, and the encrypted transports
  must exist before per-client group policy is written so that the client-identity
  seam is designed once, with both transport shapes visible, rather than retrofitted.
  Taking the phases out of order is recorded as how this project stalls.
- **Store the certificate and key in the database so the UI can manage them.**
  Rejected: it breaks the hard config boundary that the file owns infrastructure and
  the database owns policy. That boundary is what guarantees a dead database cannot
  touch resolution; putting serving material behind the database would make the
  resolver's encrypted transports depend on it. The accepted cost — rotation needs
  SSH and a restart — is the same cost already accepted for upstreams.
- **Fall back to self-signed whenever the configured certificate fails to load.**
  Rejected: it converts a visible configuration error into a silent trust downgrade,
  which is the failure mode hardest to diagnose from the client side.
- **Terminate TLS in a reverse proxy in front of styx.** Rejected implicitly by the
  phase existing at all: the scope says "TLS listeners and an HTTP/2 DoH endpoint",
  and the deployment model is one box, one binary, with no external components.

---

## Risk & Gap Analysis

### Requirement Ambiguities

- **Where the self-signed material is stored, and whether it persists.** The
  requirement says "generated at first boot" but does not name a location or state
  that it survives a restart. This must be settled, because a per-boot regeneration
  makes the printed pin worthless.
- **Whether the pin can ever be seen again.** "Printed once to the log" is
  unambiguous about the emission, silent about recovery for an operator who missed
  it.
- **The pin's exact format.** "SPKI pin" does not say which digest or which encoding.
  The operator-facing value only works if it matches what the clients that consume
  pins expect, so the format has to be one those clients accept, not one chosen
  freely.
- **Listen addresses and ports for DoT and DoH.** The requirement names neither. The
  hard config boundary says listen addresses live in the TOML file, so this is a
  configuration-shape gap rather than an open question about *where* — but the
  defaults are undecided.
- **Whether DoH shares the admin UI's HTTPS surface.** The requirement does not say,
  and the admin UI does not exist yet. Decided above as "separate", but it is an
  ambiguity in the source requirement and the decision must be recorded.
- **Whether encrypted inbound is on or off by default.** Unstated. Given that the
  self-signed path generates material on first boot, "on by default" would mean every
  fresh install mints a key pair whether or not the operator wants encrypted inbound.
- **Whether HTTP/1.1 is accepted on the DoH endpoint.** The requirement says
  "HTTP/2 DoH endpoint". The exit criterion is `curl`, which will negotiate HTTP/2
  when offered but may fall back. Whether fallback is permitted is unspecified.
- **Whether DoH must support both the GET-with-query-parameter and POST-with-body
  forms.** The requirement says only "a `curl` DoH" call succeeds. Supporting only
  one form would satisfy the letter of the criterion and disappoint real clients.
- **What "documented" means as a deliverable.** The exit criteria make documentation
  a gate ("is documented as adequate for DoH-with-pin and inadequate for Android
  Private DNS") without naming the artifact it lands in.
- **Client identity for DoH behind a proxy or a browser.** Unspecified, and it
  matters because Phase 8's per-client groups depend on it.

### Edge Cases

- **Configured certificate path exists but the key does not match the certificate.**
  Detected only at TLS configuration time; must be a startup failure with a message
  naming which file is wrong, not a runtime handshake failure repeated per
  connection.
- **Configured certificate is expired, or not yet valid.** styx is not the validator
  here — clients are — so styx will serve happily while every client refuses. Worth a
  loud startup warning, since the symptom is otherwise indistinguishable from a
  network fault.
- **Certificate file replaced on disk while styx is running.** Under the hard config
  boundary this is not picked up; the restart is the mechanism. The edge case matters
  because operators with existing certificate pipelines have renewal automation that
  *will* rewrite the file, and a silently stale certificate becomes an outage at
  expiry.
- **Self-signed material already exists at the expected location on a non-first
  boot.** Must be reused silently, not regenerated, and the pin not reprinted — or
  the "printed once" property becomes "printed on every boot".
- **Both an operator path and pre-existing self-signed material are present.** The
  operator path must win; the stale self-signed material must not be silently
  preferred, and ideally its presence is noted.
- **A DoT client opens a connection and sends nothing.** Idle connections accumulate;
  without an idle timeout this is a trivial resource-exhaustion path that Do53 over
  UDP simply does not have.
- **A DoT client sends a length prefix larger than the message it then sends, or a
  zero-length message.** Framing must reject without panicking, under
  `indexing_slicing = deny` and `arithmetic_side_effects = deny`.
- **A DoH request with a body that is not a DNS message, an empty body, a
  wrong media type, or a malformed base64url parameter.** Each must produce an HTTP
  error, never a panic, and never a half-formed DNS response.
- **A DoH request whose declared length is enormous.** Body size must be capped
  before allocation.
- **Many concurrent HTTP/2 streams on one DoH connection.** HTTP/2 multiplexing means
  one connection can carry many in-flight queries; the per-connection query budget
  must account for streams, not just connections.
- **TLS handshake flood.** Handshakes are the expensive operation; an attacker who
  never completes one costs far more than they spend. This is a real exposure on the
  modest hardware this project targets.
- **A DoT or DoH query for a blocked name, a locally-answered name, or a
  DNSSEC-bogus name.** Each must behave exactly as it does over Do53: AD cleared and
  no forged signature for blocked and local answers, SERVFAIL for bogus. The
  transport must not become a second, untested path through the response
  construction that Phase 8's five blocked-reply modes will add.
- **A truncation-eligible large answer over DoT.** DoT is a stream transport, so the
  TC bit and UDP-size logic that applies to Do53 must not be applied; getting this
  wrong produces a truncated answer a DoT client cannot retry usefully.
- **ALPN mismatch.** A client offering only `h2` reaching the DoT port, or only
  `dot` reaching the DoH port. Must be a clean handshake rejection, not an
  ambiguous hang.
- **A client offering `h3` / attempting QUIC.** Must simply not be served; DoQ is a
  non-goal and must not be half-advertised.

### Technical Risks

- **A panic in a TLS or HTTP handler takes DNS down for the whole house.** This is
  the single largest risk in this phase. It is a single process; the `catch_unwind`
  boundary and the supervised task model are **Phase 12 — Cutover hardening**, and
  until then the deny-level panic lint is the only guard. Every new parsing surface
  added here — ClientHello handling delegated to the TLS library, DoT length-prefix
  framing, DoH body and query-parameter handling — is a new place that guard has to
  hold. *Mitigation direction:* keep hand-written parsing minimal and shared with the
  already-fuzzed TCP framing; return `Result` everywhere with `thiserror` enums; no
  `unwrap`, no `expect`, no slicing or unchecked arithmetic; extend fuzzing to the
  DoH request-extraction path; and treat this phase as an argument for pulling the
  panic boundary earlier if the surface feels large once written.
- **Resource exhaustion via stateful connections.** TLS introduces per-connection
  memory and CPU cost where UDP had none, on hardware chosen to be modest. Unbounded
  connections, unbounded idle time and unbounded HTTP/2 streams are three separate
  exhaustion paths. *Mitigation direction:* explicit, configured, documented budgets
  for each — the same instinct already applied to the NSEC3 iterations cap.
- **Two transports quietly diverging from the shared pipeline.** The risk is not that
  DoT fails; it is that DoT succeeds while answering slightly differently — a
  different AD bit, a different blocked-reply mode, a different client attribution.
  *Mitigation direction:* the socket-level test suite should assert byte-identical
  answers across Do53, DoT and DoH for the same question, and that assertion should
  be extended, not rewritten, when Phase 8 adds blocking.
- **Self-signed is a dead end for the most likely real client.** Android Private DNS
  is the dominant reason a home network wants DoT at all, and it requires a
  publicly-valid name — so the self-signed fallback is, for that client, unusable.
  This is an accepted consequence, not a defect, but it means the phase can pass its
  own exit criteria and still leave the operator's actual use case unmet.
  *Mitigation direction:* the documentation deliverable is not decoration — it is the
  thing that stops this being discovered as a bug six months later. Say plainly:
  bring a certificate.
- **Certificate rotation requires a restart, and a restart drops DNS.** The hard
  config boundary makes this structural. On a household resolver a restart is a brief
  outage for everyone. *Mitigation direction:* accept it, document it, and make the
  restart fast and the startup failure modes loud enough that a botched rotation is
  caught immediately rather than at the next expiry.
- **The from-scratch rule could be misread as forbidding a TLS library.** If it were
  read that way, this phase would add a third hand-written security-critical
  subsystem to a v1 already carrying two. *Mitigation direction:* record explicitly
  that the from-scratch commitment is scoped to the DNS stack and that established
  cryptographic libraries are in use elsewhere in the project.
- **New dependencies must not violate the layering and dependency gates.** The
  workspace enforces feature-crate isolation through arch-lint's `[[restrict-use]]`,
  an independent `cargo tree --edges normal` gate, and a check asserting
  `hickory-proto` appears in no normal or build dependency path. A TLS or HTTP crate
  that transitively pulls in a DNS library would trip the last of those. *Mitigation
  direction:* check the dependency tree when the crates are chosen, not after.
- **Adding an HTTP stack now pre-empts a Phase 11 choice.** Phase 11 brings Leptos
  SSR and its own HTTP serving. Two HTTP stacks in one binary is compile-time and
  binary-size cost. *Mitigation direction:* prefer an HTTP stack the Leptos SSR
  integration is likely to sit on, so the second arrival shares rather than adds.
- **This phase is the last of the long no-feedback stretch.** Phases 1–7 produce
  nothing a human can look at but `dig` output, and the cutover being last means no
  external pressure either. *Mitigation direction:* the exit criteria here are
  deliberately hands-on — `kdig +tls` and `curl` by hand — and that manual
  confirmation is the only feedback available; do not substitute it with an automated
  test alone.
- **Client identity over encrypted transports may be worse, not better.** A DoH
  client behind any intermediary presents the intermediary's address. Combined with
  the existing DHCP non-goal, per-client group policy over DoH may misattribute
  silently. *Mitigation direction:* surface the transport alongside the client in the
  query log so misattribution is at least visible; do not introduce a
  client-identifying header, which would reintroduce the leak the EDNS Client Subnet
  non-goal exists to prevent.

### Acceptance Criteria Coverage

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | `kdig +tls` succeeds against an operator-supplied cert | Yes | Requires the DoT listener, the operator-path certificate source, and `dot` ALPN. The test needs a fixture certificate whose validity window is driven by the injectable `Clock`, for the same reason signature fixtures are — otherwise the fixture expires on a date nobody chose. Gap: the criterion does not fix a listen port, so the test harness must take an ephemeral one, consistent with the project's socket-level testing default. |
| 2 | `curl` DoH succeeds against an operator-supplied cert | Yes | Requires the DoH endpoint over HTTP/2 with the wire-format media type. Gap: `curl` can exercise either the GET or the POST form; the criterion does not say which, so both should be covered or the choice recorded. Gap: whether HTTP/1.1 fallback is permitted is unstated. |
| 3 | The self-signed path prints a usable pin | Partial | The emission is straightforward. "Usable" is the gap: it requires a specific digest and encoding that real pinning clients accept, and it requires the self-signed material to persist so the pin stays valid across restarts — neither of which the requirement states. Both are resolved in Strategic Approach above and must be carried into the design. |
| 4 | Self-signed is documented as adequate for DoH-with-pin and inadequate for Android Private DNS | Yes | A documentation deliverable, gated by the exit criteria and therefore not optional. Gap: the artifact is not named. It must state plainly that a DoT client wanting a publicly-valid name is not served by the self-signed path and that the answer is "bring a cert" — this is the accepted consequence of the certificate decision, and leaving it undocumented is how it resurfaces as a bug report. |

**Coverage assessment: 3 of 4 fully addressable, 1 partial.** No criterion is
unaddressable. The partial is a specification gap (pin format and persistence), not
a technical obstacle, and it is resolved in this document's recommendations.

**Scope beyond the acceptance criteria.** The exit criteria are transport smoke
tests; they do not assert that DoT and DoH answer *identically* to Do53, do not
assert that connection budgets exist, and do not assert that malformed input on
either transport fails without panicking. Given that a panic here takes DNS down for
the whole house and the structural mitigation is five phases away, those three
belong in the phase's test suite regardless of not appearing in its stated criteria.

---

## Summary

- Project type: backend — a single-binary Rust DNS resolver (greenfield; no existing
  implementation).
- Existing concepts identified: 9 (all commitments of Phases 0–6, none yet written).
- New concepts required: 8.
- Key design decisions: 10.
- Alternatives considered and rejected: 6.
- Acceptance criteria coverage: 4 assessed — 3 fully addressable, 1 partial.
- Open ambiguities surfaced: 10. Edge cases surfaced: 16. Technical risks surfaced: 9.
