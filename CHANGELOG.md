# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Recursion settings can be overridden per recursor member: a
  `[recursion.members.<name>]` table sets any `[recursion]` key for that member alone,
  and unset keys fall back to `[recursion]`, then to the built-in defaults. A member that
  sets its own `root_hints` needs no `[recursion]` section. Recursion diagnostics are kept
  per member, so several recursors no longer overwrite each other's snapshot.

### Changed

- **Breaking:** a recursor whose `wall_clock_ms` is not below the whole-query deadline
  (`query_timeout_secs`) is now a startup error naming the member. An override table that
  names no recursor member of the pool is a startup error too.
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
