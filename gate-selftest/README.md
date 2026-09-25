# Gate self-test fixtures

**These directories are supposed to fail.** Each one is a deliberate violation
of a rule the gate enforces, and `just gate-selftest` asserts that the
corresponding gate step *rejects* it. A fixture that stops failing is not a
fixture that got fixed — it is enforcement that went inert.

They are excluded from the styx workspace (`exclude` in the root `Cargo.toml`)
and fall outside arch-lint's `analyzer.include` allowlist, so `just gate` stays
green while these stay committed and reviewable.

## Two things about this directory are load-bearing

**It is not called `tests/`.** arch-lint marks a file as test code when *any*
component of its path is named `tests`, `test` or `benches`
(`arch-lint-core-0.6.0/src/context.rs:43`) — and test code is exactly what
`allow_in_tests = true` exempts from the rules these fixtures exist to prove.
Housed under `tests/`, every fixture here passes, and the self-test reports
that the gate is alive while proving nothing.

**The fixtures are hidden from the normal run by an include allowlist, not by
an exclude.** `analyzer.exclude` falls back to a substring match against the
absolute path (`arch-lint-core-0.6.0/src/analyzer.rs:527`), so an exclude would
also hide these fixtures when the analyser is pointed straight at one.

Both were found the only way they can be found: by the self-test failing.

## The same trap, a third time

Fixture E is excluded from the normal `rumdl` run so the clean gate stays green.
But **rumdl does not lint an excluded file just because it was named on the
command line** — an explicitly-passed excluded path is still filtered out, and
the run exits 0 reporting that it filtered something. A self-test that simply
pointed rumdl at this fixture would pass without reading a line of it.

`just gate-selftest` passes `--no-exclude` for exactly that reason. Dropping the
flag does not fail anything; it just stops the fixture from being checked, which
is the failure this whole directory exists to catch.

| Fixture | Violation | Rejected by |
|---|---|---|
| A | `.unwrap()` in a `domain` module | arch-lint `no-unwrap-expect` (AL001) **and** clippy `unwrap_used` |
| B | cross-layer `use`: `domain` names `infrastructure` | arch-lint `[[deny-scope-dep]]` (ALD003) |
| C | `styx-resolution` names `styx-filtering`, in source and in manifest | arch-lint `[[restrict-use]]` (ALD001) **and** the link-graph check |
| D | `hickory-proto` on a normal dependency path | the `hickory-dev-only` containment check |
| E | markdown: unlabelled fence, heading punctuation, over-long line | `rumdl`, via the repository's own `rumdl.toml` |
| F | synchronous `std::fs::read_to_string` in a non-async `application` fn | arch-lint `[[restrict-use]]` `no-sync-io-resolution-application` |
| G | `anyhow::Result` in a feature crate's `domain` module | arch-lint `[[restrict-use]]` `no-anyhow-filtering` |
| H | one violation each of the six `AGENTS.md` clippy lints | clippy, asserted to name each of the six by its doc anchor |
| I | a `.rs` file with 401 counted lines | `xtask module-size` |

## Why nine, when the exit criteria name two

The phase's stated exit criteria name A and B. C through I are here because:

- **C** exercises `[[restrict-use]]`, a rule family a cross-layer `use` does
  not reach. It is also the rule most likely to be silently wrong, because of
  its `styx-proto` and `styx-web` exemptions: phrased as "no crate may name
  another workspace crate" it breaks the entire build; phrased too loosely it
  never fires. Only a fixture tells those apart.
- **D** exercises the containment check, which otherwise passes vacuously
  until phase 2 adds the fake root/TLD/authoritative servers — it would be
  entirely unproven at exactly the moment it first matters.
- **E** exercises the markdown gate. That gate once carried a per-path
  exemption — `spdd/**` had the line-length rule switched off — and it was
  retired by teaching the `/spdd-*` commands the norms and reflowing the 26
  existing contracts, rather than by widening it. Adding a new exemption is
  still the cheap fix every time a generated document trips a rule, and an
  exemption list that quietly grows until it covers everything is
  indistinguishable from a clean repository by exit code. E is what notices.
- **F through I** were added by the 2026-09-24 amendment, because each
  mechanises an `AGENTS.md` rule that previously had no check behind it at
  all. Norms 3, 6 and 7 each claimed an existing arch-lint rule already
  enforced synchronous-I/O-by-layer, `tracing`-only logging and
  `anyhow`-never-in-libraries; read against the arch-lint 0.6.0 source, none
  of the three claims held in full. A new check without a fixture is the
  founding failure repeated on purpose, so each of the four new checks
  (two `[[restrict-use]]` families, six clippy lints, one `xtask` check) gets
  one:
  - **F**'s violating function is deliberately **non-async**. Inside an
    `async fn`, arch-lint's built-in `no-sync-io` (AL002) would reject the
    same call too, and F would keep passing even with the new
    `[[restrict-use]]` rules deleted — proving nothing about the rule it
    exists to guard.
  - **G** needs no manifest dependency on `anyhow`, because arch-lint reads
    source text, not the resolved dependency graph.
  - **H** is asserted more strictly than "rejected": one exit code covers
    six lints, and a lint silently dropped from the root manifest would
    still leave the other five failing. `just gate-selftest` greps clippy's
    output for each lint's documentation anchor to prove all six actually
    fired, and that the two thresholds in `clippy.toml` were read (an
    unset `excessive-nesting-threshold` leaves the lint silent even though
    it is still denied).
  - **I** is checked with `xtask module-size --root`, pointed at the
    fixture directly rather than at the repository, so the check runs
    against a file the cap must reject without disturbing the real scan.

An inert config and a passing config emit the same exit code. This directory is
the only thing that distinguishes them, which is why `just gate-selftest` runs
in CI on every push rather than once at the end of phase 0.
