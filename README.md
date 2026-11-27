<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/header/graph.svg?title=styx&subtitle=A+filtering+DNS+resolver+written+from+scratch+in+Rust&align=left&font=geist-mono&mode=dark&logo=rust" /><img alt="styx" src="https://shieldcn.dev/header/graph.svg?title=styx&subtitle=A+filtering+DNS+resolver+written+from+scratch+in+Rust&align=left&font=geist-mono&mode=light&logo=rust" /></picture>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/github/stars/jaoppb/styx.svg?variant=secondary&size=sm&mode=dark" /><img alt="GitHub Stars" src="https://shieldcn.dev/github/stars/jaoppb/styx.svg?variant=secondary&size=sm&mode=light" /></picture>
  <picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/github/forks/jaoppb/styx.svg?variant=secondary&size=sm&mode=dark" /><img alt="GitHub Forks" src="https://shieldcn.dev/github/forks/jaoppb/styx.svg?variant=secondary&size=sm&mode=light" /></picture>
  <picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/github/watchers/jaoppb/styx.svg?variant=secondary&size=sm&mode=dark" /><img alt="Watchers" src="https://shieldcn.dev/github/watchers/jaoppb/styx.svg?variant=secondary&size=sm&mode=light" /></picture>
  <picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/github/contributors/jaoppb/styx.svg?theme=emerald&size=sm&mode=dark" /><img alt="Contributors" src="https://shieldcn.dev/github/contributors/jaoppb/styx.svg?theme=emerald&size=sm&mode=light" /></picture>
  <picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/github/license/jaoppb/styx.svg?variant=ghost&size=sm&mode=dark" /><img alt="License" src="https://shieldcn.dev/github/license/jaoppb/styx.svg?variant=ghost&size=sm&mode=light" /></picture>
</p>

<p align="center">
  <img alt="Rust" src="https://shieldcn.dev/badge/Language-Rust-000000.svg?logo=rust&variant=branded&size=sm" />
  <img alt="Tokio" src="https://shieldcn.dev/badge/Runtime-Tokio-000000.svg?logo=tokio&variant=branded&size=sm" />
  <img alt="TOML" src="https://shieldcn.dev/badge/Config-TOML-9C4121.svg?logo=toml&variant=branded&size=sm" />
  <img alt="Just" src="https://shieldcn.dev/badge/Tool-Just-000000.svg?logo=just&variant=branded&size=sm" />
  <img alt="GitHub Actions" src="https://shieldcn.dev/badge/CI-GitHub_Actions-2088FF.svg?logo=githubactions&variant=branded&size=sm" />
</p>

## 📖 About

styx is a filtering DNS resolver written from scratch in Rust, built to take over
Pi-hole's role on a home network: recursive and forwarding resolution, per-client blocking
policy and a web admin UI, all in a single binary on top of Tokio.

The project is in early development. v1 is planned as 12 phases in the
[ROADMAP](ROADMAP.md), and the tree currently covers the first ones: the `styx-proto`
DNS wire codec (fuzzed, bounds-checked), the UDP/TCP server loop with its socket-level
test harness, the upstream pool with the Do53 forwarder, health tracking and circuit
breaker, the sharded answer cache, the iterative recursor, and encrypted inbound (DoT and
DoH) listeners. DNSSEC validation, filtering, storage and the admin UI are still ahead, so
styx is not yet ready to replace a running resolver.

Correctness is enforced mechanically: each feature is its own crate with
`domain`/`application`/`infrastructure` layers, and `just gate` checks formatting,
markdown, a strict clippy lint set (no panics, no unchecked indexing or arithmetic),
layering through arch-lint and the link graph, module size, the test suite and the headless
build. See [AGENTS.md](AGENTS.md) for the engineering guidelines and
[docs/adr](docs/adr) for the architecture decisions.

## 📋 Motivation

A complete Pi-hole alternative in Rust, with an interface and a recursive DNS that doesn't
cause problems, and that lets you disable IPv6.

## 💻 Getting Started

### Requirements

- [Rust](https://www.rust-lang.org/tools/install) 1.96.0

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/jaoppb/styx.git
   ```

2. Enter the project directory:

   ```sh
   cd styx
   ```

3. Copy the example configuration. It sets up the iterative recursor with Quad9 as a
   standby and listens on `127.0.0.1:5300`, so it needs no elevated rights:

   ```sh
   cp config/styx.example.toml styx.toml
   ```

4. Build and start the server. Without arguments it reads `styx.toml` from the current
   directory; a different config file can be passed as the first argument:

   ```sh
   cargo run --release --package styx
   ```

   styx has no built-in fallback: with no `styx.toml` and no argument it exits at startup
   with "no configuration file found". A config that sets no `listen_addrs` listens on
   `127.0.0.1:53`, which needs elevated rights on most systems. The whole-query deadline,
   `query_timeout_secs`, defaults to 5 seconds and must exceed every upstream member's own
   timeout. A misspelled key is a startup error, not a silently ignored line.
   `config/styx.example.toml` lists every key the server, supervisor, upstream, recursion,
   cache and tls sections accept, with its built-in default. Its `root_hints` path is relative
   to the directory styx is started from, so run styx from the repository root or change
   the path to an absolute one.
   DoT and DoH are off until `[tls]` enables them; the
   [encrypted inbound guide](docs/operator/encrypted-inbound.md) covers the certificate,
   the limits and `styx pin [config]`, which prints the certificate's SPKI pin.

### Running as a service

Both packagings read `/etc/styx/styx.toml`, and both start from
[`packaging/styx.toml`](packaging/styx.toml): only the iterative recursor, so no
third-party resolver is chosen for you, listening on `0.0.0.0:53`, with its root hints at
`/etc/styx/named.root`. A recursor needs outbound port 53 to the internet's nameservers;
on a network that intercepts it, add a forwarder member (see `config/styx.example.toml`).

**Container.** Each `v*` release publishes `ghcr.io/jaoppb/styx` for `linux/amd64` and
`linux/arm64`. The image holds the static binary, that default config and `named.root`,
and runs as an unprivileged user, so it starts with nothing mounted:

```sh
docker run -d --name styx -p 53:53/udp -p 53:53/tcp ghcr.io/jaoppb/styx:<version>
```

To change anything, mount your own file over the default:
`-v "$PWD/styx.toml:/etc/styx/styx.toml:ro"`.

`docker stop` sends SIGINT, on which styx stops accepting queries and finishes the ones in
flight. The healthcheck runs `styx health [address]`, which exits 0 when a resolver answers
at `127.0.0.1:53` (or the address given); with another port, override the healthcheck. A
self-signed `[tls]` certificate is written to `/var/lib/styx/tls`, so mount a volume the
container's user (`65532`) can write there before enabling it.

**systemd.** Install the musl binary from the release tarball as `/usr/local/bin/styx`, the
default config and root hints (`cp -n` keeps a config you already have), and
[`packaging/systemd/styx.service`](packaging/systemd/styx.service):

```sh
sudo install -d /etc/styx
sudo cp -n packaging/styx.toml config/named.root /etc/styx/
sudo install -m 0644 packaging/systemd/styx.service /etc/systemd/system/
sudo systemctl daemon-reload
```

On a host running systemd-resolved, which holds `127.0.0.53:53`, the default
`0.0.0.0:53` fails with "Address already in use": set `listen_addrs` in
`/etc/styx/styx.toml` to the host's LAN address, such as `"192.168.1.2:53"`, then start
it with `sudo systemctl enable --now styx`.

The unit runs styx as a transient unprivileged user that holds only the capability to bind
port 53, restarts it on failure, and keeps `/var/lib/styx` as its only writable path.

## 🤝 Contributors

<a href="https://github.com/jaoppb/styx/graphs/contributors">
  <picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/contributors/jaoppb/styx.svg?title=false&preset=transparent&border=false&mode=dark" /><img alt="Contributors" src="https://shieldcn.dev/contributors/jaoppb/styx.svg?title=false&preset=transparent&border=false&mode=light" /></picture>
</a>

## 📄 License

Distributed under the [AGPL-3.0-or-later](LICENSE) license.
