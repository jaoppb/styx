# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- DNS over TLS and DNS over HTTPS (HTTP/2, `GET` and `POST`) listeners, configured in a new
  `[tls]` section and off by default. They answer through the same pipeline as UDP and TCP.
  An operator certificate is named with `cert_path` and `key_path`; without them styx
  generates a self-signed certificate once, keeps it in `self_signed_dir`, and logs its SPKI
  pin on that first boot. `styx pin [config]` prints the pin again. Connection, handshake,
  idle, stream, per-connection query and request-body bounds are `[tls]` keys.
  `allow_networks` and `deny_networks` apply to both, closing a refused client's
  connection before the TLS handshake. See `docs/operator/encrypted-inbound.md`.
- `[cache]` takes `ttl_floor_secs`, `ttl_ceiling_secs` and `negative_ttl_ceiling_secs`,
  defaulting to 5, 86400 and 300 seconds. A floor above the ceiling is a startup error.
  An answer whose TTL is 0 after the clamp is served but not stored, so
  `negative_ttl_ceiling_secs = 0` turns negative caching off.
- The answer cache's counters are logged at `debug` every 60 seconds.
- `filter_aaaa = true` at the top of `styx.toml` answers every AAAA question NOERROR with
  no records, without asking an upstream and without caching the reply, so clients fall
  back to IPv4. Local records and blocked names keep their own answers. Off by default.
  HTTPS and SVCB answers may still carry an `ipv6hint`.
- Recursion settings can be overridden per recursor member: a
  `[recursion.members.<name>]` table sets any `[recursion]` key for that member alone,
  and unset keys fall back to `[recursion]`, then to the built-in defaults. A member that
  sets its own `root_hints` needs no `[recursion]` section. An override table that names no
  recursor member of the pool is a startup error. Recursion diagnostics are kept per
  member name, so recursors with distinct names no longer overwrite each other's
  snapshot.
- `allow_networks` and `deny_networks` at the top of `styx.toml` decide which client
  addresses are answered. A source outside the allowed networks, or inside a denied one,
  gets no UDP reply and has its TCP connection closed. The default allows loopback, the
  RFC 1918 and RFC 4193 private ranges and link-local; allowing public addresses (a `/0`,
  or the same space in pieces) on a non-loopback address logs a warning at startup. A
  network written in IPv4-mapped form (`::ffff:10.0.0.0/104`) matches as its IPv4 network.
- `[[upstream.conditional]]` entries send the names under their `domains` (such as `lan` or
  `1.168.192.in-addr.arpa`) to their own forwarders, usually the router, instead of the
  main pool. The longest matching domain wins, answers are cached as usual, and a name
  whose forwarders all fail gets SERVFAIL rather than leaking to the main pool.

### Changed

- **Breaking:** styx no longer answers public source addresses by default. That includes
  IPv6 clients on your own LAN that use a global address (the usual case with an IPv6
  prefix from the ISP) and CGNAT or Tailscale peers in `100.64.0.0/10`: they now time
  out until your delegated prefix or those networks are in `allow_networks`.
- **Breaking:** `udp_timeout_ms`, `tcp_timeout_ms` and `edns_buffer` on an
  `[[upstream.members]]` entry with `kind = "recursor"` are now a startup error naming
  every such key the member sets. The recursor never read them; set timeouts under `[recursion]` or
  `[recursion.members.<name>]`, and remove `edns_buffer` (which has no recursor
  equivalent). `query_timeout_secs` is now checked against each recursor member's merged
  `udp_timeout_ms` and `tcp_timeout_ms` rather than the unused pool-member defaults.
- **Breaking:** the default `query_timeout_secs` is now 5 (it was 2). A dead upstream can
  take up to 5 seconds to answer SERVFAIL, and graceful shutdown can wait up to 5
  seconds. The deadline still has to exceed every pool member's own timeout.
- **Breaking:** a misspelled key is now a startup error instead of being ignored. The
  server, `[supervisor]`, `[upstream]`, member, canary, probe and circuit tables reject
  unknown keys, and so does the top level of the file, except for tables, which belong to
  other features' parsers (`[recursion]`).
- A recursor canary table that omits `timeout_ms` now uses 5 seconds (it was 2), the same
  default as a recursor with no canary table. A forwarder canary keeps 2 seconds.
- A pool member's default weight is one, as documented. The weight type's derived
  default was zero, but nothing used it.
