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

| Fixture | Violation | Rejected by |
|---|---|---|
| A | `.unwrap()` in a `domain` module | arch-lint `no-unwrap-expect` (AL001) **and** clippy `unwrap_used` |
| B | cross-layer `use`: `domain` names `infrastructure` | arch-lint `[[deny-scope-dep]]` (ALD003) |
| C | `styx-resolution` names `styx-filtering`, in source and in manifest | arch-lint `[[restrict-use]]` (ALD001) **and** the link-graph check |
| D | `hickory-proto` on a normal dependency path | the `hickory-dev-only` containment check |

## Why four, when the exit criteria name two

The phase's stated exit criteria name A and B. C and D are here because:

- **C** exercises `[[restrict-use]]`, a rule family a cross-layer `use` does
  not reach. It is also the rule most likely to be silently wrong, because of
  its `styx-proto` and `styx-web` exemptions: phrased as "no crate may name
  another workspace crate" it breaks the entire build; phrased too loosely it
  never fires. Only a fixture tells those apart.
- **D** exercises the containment check, which otherwise passes vacuously
  until phase 2 adds the fake root/TLD/authoritative servers — it would be
  entirely unproven at exactly the moment it first matters.

An inert config and a passing config emit the same exit code. This directory is
the only thing that distinguishes them, which is why `just gate-selftest` runs
in CI on every push rather than once at the end of phase 0.
