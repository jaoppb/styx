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
test harness, and the upstream pool with the Do53 forwarder, health tracking and circuit
breaker. The answer cache, recursion, DNSSEC validation, DoT/DoH listeners, filtering,
storage and the admin UI are still ahead, so styx is not yet ready to replace a running
resolver.

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

3. Build and start the server. Without arguments it reads `styx.toml` from the current
   directory if present, and otherwise listens on `127.0.0.1:1053`; a different config
   file can be passed as the first argument:

   ```sh
   cargo run --release --package styx
   ```

## 🤝 Contributors

<a href="https://github.com/jaoppb/styx/graphs/contributors">
  <picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/contributors/jaoppb/styx.svg?title=false&preset=transparent&border=false&mode=dark" /><img alt="Contributors" src="https://shieldcn.dev/contributors/jaoppb/styx.svg?title=false&preset=transparent&border=false&mode=light" /></picture>
</a>

## 📄 License

Distributed under the [AGPL-3.0-or-later](LICENSE) license.
