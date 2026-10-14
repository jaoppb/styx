# SPDD Analysis: Config defaults review fixes

## Original Business Requirement

The requirement is the decision record produced by a `/code-review medium` pass over
commit `a7943a2` (`fix(config): make default timeouts accept a minimal config`) and the
`/grill-me` session that followed. It is reproduced verbatim from
`SPEC-review-fixes.md`.

```markdown
# Review fixes after a7943a2 (config defaults)

Source: `/code-review medium` findings on `fix(config): make default timeouts accept a minimal config`.

## Decisions

- Default `query_timeout_secs` stays a fixed 5s. It is a breaking change for configs that omit the key (slower SERVFAIL on dead upstreams, longer `shutdown_grace`), and the README says so. The invariant "query_timeout > longest member timeout" is unchanged.
- Every default resolves through its type's `Default` impl (probe, circuit, weight, EDNS, canary per member kind), one literal per default. The raw-table parsers stop carrying their own copies.
- The example's commented-out values are asserted against those same `Default` impls. The canary block shows the correct per-kind defaults (forwarder: A/2s, recursor: NS/5s).
- The "lists every schema key" test moves in-crate, next to the `Raw*` structs, and destructures each one exhaustively (no `..`). A new field is a compile error until the key list is updated. It also covers `[recursion]`, `supervisor` and `upstream`.
- The example-scanning helpers become parse-based: uncomment a candidate line and keep it only if it parses as TOML in its section. A candidate that fails to parse is reported by line number.
- README: one sentence that `root_hints = "config/named.root"` is resolved from the working directory.

## Non-goals

- No derived or pool-dependent query timeout default.
- No change to the member timeout defaults (UDP 2s, TCP 3s).
- No macro-generated config structs and no serde field-capture machinery.
- No marker-prefix convention in the example file.

## Open questions

- None the user refused to close.

## Risks

- Parse-based scanning gives poor diagnostics unless failures name the offending line.
- A user who raises a member timeout past 5s still hits the startup refusal. The message names both durations, but the default does not adapt.
- The in-crate destructure test means the config test leaves `tests/`. Check the 400-line module cap in `xtask module-size` when splitting it.
```

## Domain Concept Identification

### Existing Concepts (from codebase)

- Server configuration: the top-level keys (listeners, query deadline, TCP idle timeout,
  concurrency caps) plus the optional `[supervisor]` table. Owned by `styx-resolution`'s
  infrastructure layer. It also hosts the cross-check that the query deadline outlasts
  every pool member's timeout.
- Pool configuration: the `[upstream]` table with its members, probe policy and circuit
  policy. Owned by `styx-resolution`'s domain layer and handed over as a raw TOML value
  by the server configuration.
- Member timeouts: a validated pair of UDP and TCP budgets that already has a single
  `Default` and is already consumed through it. It is the one default that the previous
  commit centralised.
- Probe policy, circuit policy and EDNS buffer size: each already carries a `Default`
  that states the documented value, while the parser repeats the same number next to
  it.
- Member weight: a newtype whose derived `Default` is zero, while the documented and
  parsed default is one.
- Canary: a per-kind default already exists as a single constructor on the canary type
  (forwarder: A, 2s; recursor: NS, 5s). The parser ignores it when a canary table is
  present and substitutes 2s for any kind.
- Recursion configuration: a separate section parsed by `styx-recursion` from the same
  file, rejecting unknown keys, with its defaults as named constants.
- Example configuration and its guard tests: `config/styx.example.toml`, plus an
  integration test that scans it line by line against a hand-maintained key list.
- Changelog and README: the user-facing record where a breaking default belongs. The
  changelog exists with an empty *Unreleased* section.

### New Concepts Required

- Schema key manifest: the authoritative list of keys per table, kept in step with the
  raw structs by construction (an exhaustive destructure) rather than by discipline.
- Example parse check: a notion of a "live-able" commented line, one that becomes valid
  TOML once uncommented in its section, replacing the guess about what looks like a key.
- Defaults audit: a statement that every number the example calls a built-in default is
  compared with the value the code actually applies.

### Key Business Rules

- The query deadline must be strictly greater than the longest member timeout: governs
  server configuration and member timeouts. Unchanged by this work.
- A config with only one member and no timeout keys must start: governs the default
  query deadline against the default member timeouts.
- The example is a reference for what happens when a key is omitted, so each "built-in
  default" it states is a claim the code must keep true.
- The `[recursion]` table is owned by a different feature crate, and a feature crate may
  not depend on another one. This governs where its key coverage can be tested.
- Test code may panic freely, but nothing under `src/` may, and each `.rs` file stays
  within 400 counted lines with no exemption. This governs where new tests can live.

## Strategic Approach

### Solution Direction

The work is a consolidation of existing facts, not new behaviour, apart from the
documented 5s deadline and one canary timeout question. The defaults already live in the
domain types. The fix routes the parsers through them and makes the example and its
tests consume the same source, so a changed default turns a test red instead of leaving
a stale comment.

- Defaults: owned by the domain types in `styx-resolution`. The raw-to-domain parsing
  asks each type for its default instead of restating it. The example's commented values
  are compared with the same types in a test.
- Schema coverage: owned next to the raw structs inside each crate that parses a table.
  `styx-resolution` covers the server, supervisor and upstream tables. `styx-recursion`
  covers its own table.
- Example scanning: stays a test concern, rebuilt on parsing instead of pattern
  guessing, and kept outside `src/` production paths.
- Data flow: example file → test-side scanner → raw structs and `Default` impls. No
  runtime path changes.
- Documentation: a README sentence on the working directory, and a breaking-change entry
  for the 5s deadline.

### Key Design Decisions

- Where the "default" comes from for weight: the type's derived `Default` is zero, which
  contradicts the documented default of one. → Settled: a manual `Default` of one on the
  newtype. Verified that nothing calls the derived default; every construction site
  passes an explicit value.
- Canary timeout when a table is present: the parser defaults to 2s for every kind. The
  decision says the example shows A/2s for a forwarder and NS/5s for a recursor, which
  describes the *absent-table* default. → Settled: resolve the omitted `timeout_ms` from
  the per-kind default so both paths agree, and record the behaviour change for a
  recursor canary that omitted the key.
- Where the key-coverage test for `[recursion]` lives: it cannot sit in `styx-resolution`
  without a forbidden dependency edge. → Split the guarantee by owner: each feature crate
  destructures its own raw structs, and the composition root keeps one test that the
  whole example parses through both parsers.
- Test placement under the module cap: `server.rs` is at 387 of 400 lines and
  `domain/config.rs` at 297. → Put the in-crate tests in child test modules in their own
  files, never inline in those two files.
- Dispatch and errors: no new traits are introduced, so generics versus `dyn` does not
  arise. Failures in the scanner are test-only and may panic with a message naming the
  line. No new error types in production code.

### Alternatives Considered

- Derive the query default from the members: rejected earlier as a non-goal. It makes
  the effective value depend on the pool and moves `shutdown_grace` with it.
- Lower the member timeout defaults: rejected earlier. It halves upstream patience and
  changes behaviour for every member.
- Macro-generated structs and serde field capture for the key list: rejected earlier as
  heavier than a compile-time destructure.
- Marker prefix for commented-out keys in the example: rejected earlier because the file
  users copy would carry an unusual convention.
- A single test in `styx-resolution` that covers all three crates' sections: rejected
  here because it needs the dependency edge that the layering gate forbids.

## Risk & Gap Analysis

### Requirement Ambiguities

- Weight default (resolved): "every default resolves through its type's `Default`"
  collided with a derived zero default on the weight type. Decision: the weight type
  gets a manual `Default` of one, replacing the derived zero. No code relies on the zero
  default, and the parser calls the type's default instead of repeating the literal.
- Canary timeout default (resolved): the parser's 2s fallback for a present canary table
  disagreed with the per-kind default used when no table is given. Decision: an omitted
  `timeout_ms` takes the per-kind default (forwarder 2s, recursor 5s). `qname` and
  `qtype` stay required. This is a second user-visible change, a recursor canary table
  without `timeout_ms` going from 2s to 5s, and the changelog entry names it beside the
  5s query deadline.
- Scope of `[recursion]` coverage: "also covers `[recursion]`" cannot be met in
  `styx-resolution`. The requirement does not say whether the guarantee moves to
  `styx-recursion` and the binary.
- Server-level defaults: the UDP payload size, TCP idle timeout and concurrency caps are
  constants outside any `Default` impl. The requirement lists "probe, circuit, weight,
  EDNS, canary" and does not say whether these count.
- Supervisor defaults already exist as named constants. It is unclear whether those
  satisfy "one literal per default" or need the same treatment as the pool tables.
- Where the breaking-change note goes: the requirement says "the README says so", and a
  changelog with an *Unreleased* section also exists.

### Edge Cases

- Unknown keys are silently ignored by the server and pool raw structs, so "the example
  still parses with every key switched on" proves syntax, not that each key is
  recognised. The exhaustive destructure closes this for keys that exist and does not
  catch a typo in the example.
- A commented line that is valid TOML only in a different section, such as a key
  repeated under two tables, passes a parse check in the wrong place. The check has to
  parse in the section where the line sits.
- Array-of-tables sections: the member keys appear under a repeated header, so
  "uncomment and parse in its section" has to handle the live member table that the
  example already contains.
- A commented value that is a deliberate illustration, not a default, such as the
  canary `qname`, must be excluded from the "equals the default" assertion.
- Explicit zero values: probe and circuit fields accept zero today. Routing through
  `Default` does not change that, and the requirement does not ask for validation.

### Technical Risks

- Parse-based scanning produces vague failures when a line is rejected. → The scanner
  reports the line number and section, as already decided.
- Module-size cap: `server.rs` has 13 lines of headroom. Any inline addition breaches
  the gate. → Child test modules in separate files.
- Test-only access to private raw structs forces either child modules or widened
  visibility. Widening to crate visibility is acceptable, but a public widening would
  expose the raw schema. → Prefer child modules.
- A recursor canary with a longer default timeout may exceed the pool's other timeouts.
  Probe timeouts do not take part in the query-deadline check today. → Confirm during
  design that a 5s canary is not constrained by the 5s query deadline.
- Behaviour change outside the stated one: correcting the canary fallback is a second
  user-visible change that the changelog entry has to name.
- A mismatch between the example text and a code default fails only when the check
  compares against the type. Values that appear only in prose are not compared.

### Acceptance Criteria Coverage

The requirement has no numbered acceptance criteria, so each decision is taken as one.

| AC# | Description | Addressable? | Gaps/Notes |
|-----|-------------|--------------|------------|
| 1 | Default query deadline stays 5s, documented as breaking | Yes | Changelog and README both exist. Pick the home. |
| 2 | Every default resolves through its type's `Default` | Partial | Weight default is zero. Server and supervisor constants unclear. |
| 3 | Example values asserted against the `Default` impls, canary per kind | Partial | Canary fallback in the parser differs from the per-kind default. |
| 4 | Exhaustive destructure test, including `[recursion]` | Partial | `[recursion]` is owned by `styx-recursion`. Split by crate. |
| 5 | Parse-based example scanning with line-numbered failures | Yes | Needs section-aware parsing for the repeated member table. |
| 6 | README sentence on the working directory | Yes | The example's `root_hints` path is relative. |
