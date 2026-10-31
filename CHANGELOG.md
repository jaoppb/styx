# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `[cache]` takes `ttl_floor_secs`, `ttl_ceiling_secs` and `negative_ttl_ceiling_secs`,
  defaulting to 5, 86400 and 300 seconds. A floor above the ceiling is a startup error.
- The answer cache's counters are logged at `debug` every 60 seconds.

### Changed

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
