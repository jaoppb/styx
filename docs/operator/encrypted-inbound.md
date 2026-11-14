# Encrypted inbound: DNS over TLS and DNS over HTTPS

styx can answer DNS over TLS (DoT, RFC 7858) and DNS over HTTPS over HTTP/2 (DoH,
RFC 8484) next to plain UDP and TCP. Both reach the same pipeline: an encrypted query is
answered exactly as the same query over port 53, and the client is identified by its IP
address only.

Encrypted inbound is off until you enable it in the `[tls]` section of `styx.toml`.

## The short version

- **Android Private DNS, or any DoT client that checks the server name, needs a
  certificate from a public CA for a name you own. Bring a certificate.** The self-signed
  fallback is adequate for `curl` and for DoH clients that accept a pin, and inadequate
  for those clients.
- Changing the certificate means editing or replacing the files and **restarting** styx.
  A certificate replaced on disk is not picked up while styx runs.

## Bring a certificate

Point `cert_path` and `key_path` at PEM files from whatever pipeline you already have
(certbot, acme.sh, your own CA). styx owns no PKI and has no ACME client.

```toml
[tls]
enabled = true
dot_listen_addrs = ["0.0.0.0:853"]
doh_listen_addrs = ["0.0.0.0:443"]
cert_path = "/etc/styx/tls/fullchain.pem"
key_path = "/etc/styx/tls/privkey.pem"
```

- Set **both** paths, or neither. One without the other is a configuration error.
- `cert_path` holds the leaf certificate first, then any intermediates (a "fullchain").
- `key_path` holds the private key: PKCS#8, PKCS#1 (RSA) or SEC1 (EC).
- A path that is missing, a file that does not parse, or a key that does not belong to the
  certificate **stops styx at startup**, with the file named in the error. This is on
  purpose: styx never falls back to a self-signed certificate when the configured one
  fails, because a silent switch to a certificate no client trusts looks like a network
  fault from every phone in the house.
- A certificate that has expired or is not valid yet logs a warning at startup and is still
  served. Clients will refuse it.

### Rotating the certificate

The file owns infrastructure settings, so a new certificate needs a restart:

1. Replace the files at `cert_path` and `key_path`.
2. Restart styx. DNS is down for every client for the few moments the restart takes.
3. Check the log: a broken pair stops startup, with the file named.

Renewal tools that rewrite the files in place do **not** take effect until that restart.
Hook the restart into your renewal tool, or the old certificate keeps being served until it
expires and every client fails at once.

## The self-signed fallback

With `enabled = true` and neither `cert_path` nor `key_path`, styx generates a self-signed
certificate the first time it starts and keeps it in `self_signed_dir`
(`/var/lib/styx/tls` unless you set another directory):

- `cert.pem`, and `key.pem`, which is created readable by its owner only. styx refuses to
  start if it finds `key.pem` readable by group or others.
- The certificate names come from `self_signed_names` (`["localhost"]` by default). It is
  valid for ten years and reused on every boot. Delete both files to get a new one, and a
  new pin.

### The pin

On the boot that generates the certificate, styx logs its SPKI pin once, at info level:

```text
INFO … generated a self-signed certificate for DoT/DoH; this pin is printed once …
pin=pin-sha256="kOZp9k+E1pOYtz/U7ErIoDgFjDZQUQzX1FF1Wa6AKuI=" source="self-signed" …
```

(Example value from a test run, not a real deployment.) The pin is the base64 of the
SHA-256 of the certificate's DER SubjectPublicKeyInfo, the format `curl --pinnedpubkey`,
HTTP public-key pinning and DoT SPKI pinsets use. It depends only on the public key, so it
is safe to publish and survives a re-issue with the same key.

Later boots reuse the certificate and do not print the pin again. To see it at any time:

```sh
styx pin /etc/styx/styx.toml
```

`styx pin` reads the configuration, prints the `pin-sha256="…"` line to stdout and exits.
It opens no socket and never generates a certificate: if none exists yet it says so and
exits with an error. With an operator certificate configured, it prints that certificate's
pin.

To query DoH with the pin:

```sh
curl --http2 -k --pinnedpubkey 'sha256//kOZp9k+E1pOYtz/U7ErIoDgFjDZQUQzX1FF1Wa6AKuI=' \
  -H 'content-type: application/dns-message' --data-binary @query.bin \
  https://192.0.2.10/dns-query
```

`-k` skips the name and chain check, which a self-signed certificate cannot pass; the pin
is what authenticates the server.

## What is served

- **DoT** on each `dot_listen_addrs` entry (conventionally port 853). The TLS ALPN
  protocol is `dot`; a client that offers only other protocols is refused during the
  handshake, and a client that offers none is served.
- **DoH** on each `doh_listen_addrs` entry (conventionally port 443), at `doh_path`
  (`/dns-query` by default), over HTTP/2. Both `GET /dns-query?dns=<base64url>` and
  `POST` with an `application/dns-message` body work. Answers carry
  `Cache-Control: max-age` equal to their smallest TTL. HTTP/1.1 is offered only with
  `allow_http1 = true`.
- Set either list to `[]` to turn that transport off.
- DNS over QUIC (DoQ, HTTP/3) is not supported.
- DoH has its own listener. It does not share a port, a certificate setting or an origin
  with the admin web UI, and it is available in the headless build.
- A DoH client behind a proxy is seen as the proxy's address. styx reads no forwarding
  header, so per-client policy over DoH applies to whatever address connects.

## Limits

Each limit applies per listener, so a flood on DoH cannot starve DoT. Refusals are logged
at most once a second.

| Key | Default | Bounds |
|---|---|---|
| `handshake_timeout_secs` | 5 | Time a client has to finish the TLS handshake |
| `idle_timeout_secs` | 30 | Time a connection may stay open with no query in flight |
| `max_connections` | 128 | Open connections per listener; more are closed before the handshake |
| `max_streams_per_connection` | 100 | Concurrent HTTP/2 streams per DoH connection |
| `max_queries_per_connection` | 10000 | Queries one connection carries before styx closes it |
| `max_request_body_bytes` | 65535 | Largest DNS message a DoH request may carry |

Encrypted queries also share the server-wide `max_in_flight_queries` budget with UDP and
TCP.

## Every `[tls]` key

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turn encrypted inbound on |
| `dot_listen_addrs` | `["127.0.0.1:853"]` | DoT listen addresses |
| `doh_listen_addrs` | `["127.0.0.1:443"]` | DoH listen addresses |
| `cert_path`, `key_path` | unset | Operator certificate chain and key, both or neither |
| `self_signed_dir` | `/var/lib/styx/tls` | Where self-signed material is kept |
| `self_signed_names` | `["localhost"]` | Names in a generated certificate |
| `doh_path` | `/dns-query` | The DoH resource |
| `allow_http1` | `false` | Also offer HTTP/1.1 for DoH |

Ports 443 and 853 are privileged: run styx with `CAP_NET_BIND_SERVICE` or choose
unprivileged ports.
