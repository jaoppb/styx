# ADR 0028 — Encrypted inbound transports and the serving certificate

- **Status**: accepted
- **Date**: 2026-10-28
- **Phase**: 7 — Encrypted inbound (DoT / DoH)

## Context

Phase 7 adds DNS over TLS (RFC 7858) and DNS over HTTPS over HTTP/2 (RFC 8484) in front
of the request pipeline Phases 2 to 6 built. The risk is not that an encrypted transport
fails, which is obvious, but that it succeeds while answering slightly differently from
Do53: another AD bit, another truncation rule, another client attribution. The phase also
needs a certificate, and the project decided early that styx owns no PKI and implements no
ACME client.

## Decision

**Two transports, one query path.** DoT is a TLS handshake in front of the connection
handler plaintext TCP uses: the same two-octet framing in `infrastructure::framing`, the
same pipelining, idle timer and pipeline entry. DoH answers each stream through the same
query task (decode, early FORMERR and BADVERS, pipeline, encode). Both build the same
`RequestContext`; only `Transport` gains `Dot` and `Doh`, and both size a response like a
stream: 65535 octets, never the TC bit. `RequestContext` and `ClientId` gain no field, and
the client is the peer address: no header is read.

**An established TLS and HTTP/2 stack.** rustls and hyper, with the ring provider. The
from-scratch commitment covers the DNS stack; a hand-written TLS stack would be a third
security-critical subsystem in a v1 whose scope is already its largest risk. ring, not
aws-lc-rs, because aws-lc-rs needs cmake and a C toolchain under the musl `cross` build.
hyper is also what axum, and so Leptos SSR, sits on, so Phase 11 shares the stack.

**One certificate, two sources, no third.** `CertificateSource` is `OperatorSupplied` or
`SelfSigned`. Self-signed is chosen only by the absence of both paths in `[tls]`, never
because configured material failed to load: that would turn a config typo into a silent
trust downgrade. A configured pair that is missing, malformed or mismatched stops startup
naming the file. Self-signed material is generated once, persisted owner-only, and
reused, so the pin the operator distributed survives restarts. The pin is SHA-256 over the
DER SubjectPublicKeyInfo in the `pin-sha256="…"` form, logged at info only on the boot that
generated it, and re-derivable with `styx pin`.

**Every stateful resource has a named bound.** Per listener: a connection ceiling checked
before the handshake, a handshake deadline and an idle timeout. Per connection: a query
ceiling (counted per stream on DoH) and, on DoH, the HTTP/2 stream ceiling in SETTINGS.
Per request: the DoH body cap, judged on the declared length before anything is read.
These are `[tls]` values, not library defaults.

**DoH is a DNS listener, not part of the admin UI.** It builds without the `web` feature,
has its own listener and configuration, and shares no port or origin with the UI.
ALPN offers `h2` (and `http/1.1` only when enabled) for DoH, `dot` for DoT, never `h3`.

**Encrypted inbound is off by default**, so an install that never asked for it mints no
key pair.

## Consequences

- Self-signed works for curl and DoH clients that accept a pin, and not for DoT clients
  such as Android Private DNS, which want a publicly-valid name. The operator page says
  so: bring a certificate.
- Rotating a certificate is an edit and a restart, and a certificate replaced on disk is
  not picked up while styx runs. Both follow from the file owning infrastructure.
- styx writes key material and owns its permissions: a persisted key readable by group or
  others is refused.
- A DNSSEC-bogus answer over DoT or DoH cannot be tested yet: the validator is not on the
  resolution path (#133). The cross-transport test compares AD bits and is written so
  #133 and Phase 8 add questions to it, not new tests.
- Until Phase 12 installs the panic boundary, the lints and the fuzzed, pure DoH request
  extraction are the only guards over the new parsing surface.
