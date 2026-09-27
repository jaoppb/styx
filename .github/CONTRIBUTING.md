# Contributing to styx

Thanks for your interest in contributing! This guide explains how to propose changes.

## Code of conduct

By participating, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting bugs and suggesting improvements

- Search the [issues](https://github.com/jaoppb/styx/issues) to see if the topic is
  already open.
- If not, open an issue using the matching template (bug or feature).
- Security vulnerabilities must **not** be opened as issues: see the
  [Security Policy](SECURITY.md).

## Setting up the environment

Follow the "Getting Started" section of the [README](../README.md) to install and run the
project. Before writing code, read [AGENTS.md](../AGENTS.md): it holds the engineering
guidelines every change is expected to follow.

## Contribution workflow

1. Fork the repository and create a branch from `main`.
2. Make your changes in small commits with clear messages.
3. Run the checks below before opening the Pull Request.
4. Open the Pull Request against `main` and fill in the template.

## Commit convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.

## Checks

Install the pinned tooling from `mise.toml` once, then run the full gate:

```sh
just install-tools
just gate
```
