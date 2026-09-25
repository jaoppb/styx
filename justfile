# styx — the per-push gate.
#
# ONE target, THREE callers: the developer, the lefthook hooks (pre-commit and
# pre-push) and GitHub Actions all run `just gate`. Neither the hooks nor the
# workflows re-list its steps — any drift between what CI runs and what the
# hooks run makes the hooks theatre.
#
# Nothing in `gate` touches the network. The non-hermetic differential run
# against a local unbound — resolving a corpus of real domains through both and
# diffing RCODE, AD bit and rrset contents — gates a PHASE, never a push,
# because it depends on the live internet and is flaky by nature. It does not
# belong anywhere in this file's `gate` target.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Pinned exactly, not a range: a minor bump can change a rule name or a config
# key and turn enforcement into silence.
ARCH_LINT_VERSION := "0.6.0"

# Pinned exactly. rumdl is pre-1.0: a minor bump can rename a rule or change a
# default, which makes this gate noisy rather than silently inert — the milder
# of the two failure modes, but still a change to verify rather than absorb.
RUMDL_VERSION := "0.2.75"

SELFTEST := "gate-selftest"

_default:
    @just --list --unsorted

# ---------------------------------------------------------------------------
# The gate. Fail-fast, cheapest step first.
# ---------------------------------------------------------------------------
[doc("The complete per-push gate. Hermetic, fail-fast.")]
gate: fmt-check md lint arch deps hickory-dev-only module-size test headless
    @echo ""
    @echo "gate: GREEN"

# 1. Formatting — cheapest, fails fastest.
[doc("Verify formatting.")]
fmt-check:
    @echo "── fmt ────────────────────────────────────────────────────────────"
    cargo fmt --all -- --check

# 2. The fifteen denied lints, workspace-wide, every target, every feature.
[doc("Lint every markdown file in the repository.")]
md: _rumdl-version
    @echo "── markdown ───────────────────────────────────────────────────────"
    rumdl check .

[doc("Apply structural markdown auto-fixes. NOT part of the gate — it writes to files.")]
md-fix: _rumdl-version
    rumdl fmt .

# Rewraps prose to the configured width. Separate from md-fix because it is a
# bigger hammer and should be named as one: it rewrites paragraphs wholesale.
#
# Verified safe on the 26 SPDD contracts before the one-off reflow that retired
# the spdd/** exemption: tables and mermaid blocks came through byte-identical,
# and only prose was rewrapped. Still not part of `gate` — a gate that edits the
# working tree is not a gate.
[doc("Rewrap markdown prose to the configured width. NOT part of the gate.")]
md-reflow: _rumdl-version
    rumdl fmt . --config 'MD013.reflow = true'

_rumdl-version:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v rumdl >/dev/null 2>&1; then
        echo "rumdl is not installed. Run: just install-tools" >&2
        exit 1
    fi
    found="$(rumdl --version | awk '{print $2}')"
    if [[ "$found" != "{{ RUMDL_VERSION }}" ]]; then
        echo "rumdl {{ RUMDL_VERSION }} is pinned, found $found." >&2
        echo "Run: just install-tools" >&2
        exit 1
    fi

[doc("Clippy's fifteen denied lints, workspace-wide.")]
lint:
    @echo "── clippy ─────────────────────────────────────────────────────────"
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# 3. arch-lint: scopes, layer denials, use-restrictions and the rule set.
#
# The version check is not ceremony. arch-lint selects between two engines by
# the presence of a [[layers]] block, and the tree-sitter engine analyses zero
# .rs files and exits 0. An unexpected version is a reason to re-verify, not to
# carry on. See docs/adr/0001.
[doc("arch-lint: scopes, layer denials, use-restrictions, rule set.")]
arch: _arch-version
    @echo "── arch-lint ──────────────────────────────────────────────────────"
    arch-lint check .

_arch-version:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v arch-lint >/dev/null 2>&1; then
        echo "arch-lint is not installed. Run: just install-tools" >&2
        exit 1
    fi
    found="$(arch-lint --version | awk '{print $2}')"
    if [[ "$found" != "{{ ARCH_LINT_VERSION }}" ]]; then
        echo "arch-lint {{ ARCH_LINT_VERSION }} is pinned, found $found." >&2
        echo "Run: just install-tools" >&2
        exit 1
    fi

# 4. The link-graph layering gate — reads what the build links, not the source
#    text. Deliberately overlaps with arch-lint: a tool that fails open must be
#    caught by a neighbour. Removing either gate is a regression.
[doc("Link-graph layering gate (independent of arch-lint).")]
deps:
    @echo "── link-graph layering ────────────────────────────────────────────"
    cargo run --quiet --package xtask -- deps

# 5. Containment: the test oracle stays out of the shipping binary.
[doc("Keep the DNS test oracle out of the shipping binary.")]
hickory-dev-only:
    @echo "── hickory containment ────────────────────────────────────────────"
    cargo run --quiet --package xtask -- hickory-dev-only

# 6. Module size: no .rs file past 400 counted lines. No per-file exemption —
#    the remedy for a failing file is to split it, never to raise the cap.
[doc("Cap every .rs file at 400 counted lines (xtask module-size).")]
module-size:
    @echo "── module size ────────────────────────────────────────────────────"
    cargo run --quiet --package xtask -- module-size

# 7. Tests. Socket-level by default from phase 2: real UDP/TCP against an
#    ephemeral-port server with in-process fakes and an injectable Clock. In
#    phase 0 there is nothing to run, but the target is already wired.
[doc("The test suite (socket-level by default from phase 2).")]
test:
    @echo "── tests ──────────────────────────────────────────────────────────"
    cargo test --workspace --all-features

# 8. The headless build: styx without the web UI.
#
#    Passes near-vacuously until phase 11, when the `web` feature actually
#    gates code. It is wired now because its cost is lowest now and rises with
#    every phase, and because an unexercised configuration rots within about a
#    month.
[doc("Build and test with --no-default-features.")]
headless:
    @echo "── headless (--no-default-features) ───────────────────────────────"
    cargo build --workspace --no-default-features
    cargo test --workspace --no-default-features

# ---------------------------------------------------------------------------
# The self-test: proof that the gate is alive.
#
# "The config is inert" and "the config passes" are observationally identical
# from an exit code. This is the deliverable of phase 0 — the empty workspace
# is not. It runs in CI on every push, so a change that weakens enforcement
# fails the build rather than passing quietly.
# ---------------------------------------------------------------------------
[doc("Prove the gate rejects real violations. Run this after ANY gate change.")]
gate-selftest: _arch-version _rumdl-version
    #!/usr/bin/env bash
    set -uo pipefail
    failures=0

    # Asserts that a command FAILS. A zero exit is a self-test failure.
    expect_rejected() {
        local label="$1"; shift
        if "$@" >/dev/null 2>&1; then
            echo "  ✗ $label — ACCEPTED a violation it must reject"
            failures=$((failures + 1))
        else
            echo "  ✓ $label"
        fi
    }

    echo "── gate self-test ─────────────────────────────────────────────────"
    echo "Each fixture below is a deliberate violation. Every one must be rejected."
    echo ""

    echo "Fixture A — .unwrap() in a domain module:"
    expect_rejected "arch-lint no-unwrap-expect" \
        arch-lint check {{ SELFTEST }}/fixture-a-unwrap-in-domain --config arch-lint.toml
    expect_rejected "clippy unwrap_used" \
        cargo clippy --quiet --manifest-path {{ SELFTEST }}/fixture-a-unwrap-in-domain/Cargo.toml -- -D warnings

    echo ""
    echo "Fixture B — cross-layer use (domain names infrastructure):"
    expect_rejected "arch-lint deny-scope-dep" \
        arch-lint check {{ SELFTEST }}/fixture-b-cross-layer --config arch-lint.toml

    echo ""
    echo "Fixture C — one feature crate naming another:"
    expect_rejected "arch-lint restrict-use" \
        arch-lint check {{ SELFTEST }}/fixture-c-cross-feature --config arch-lint.toml
    expect_rejected "link-graph layering" \
        cargo run --quiet --package xtask -- deps \
            --manifest-path {{ SELFTEST }}/fixture-c-cross-feature/Cargo.toml

    echo ""
    echo "Fixture D — hickory-proto on a normal dependency path:"
    expect_rejected "hickory containment" \
        cargo run --quiet --package xtask -- hickory-dev-only \
            --manifest-path {{ SELFTEST }}/fixture-d-hickory-in-deps/Cargo.toml

    echo ""
    echo "Fixture E — markdown with structural violations:"
    # --no-exclude is LOAD-BEARING. rumdl does not lint an excluded file just
    # because it was named on the command line: an explicitly-passed excluded
    # path is still filtered out and the run exits 0 reporting "filtered out".
    # Without this flag the check below would pass while proving nothing.
    expect_rejected "rumdl structural rules" \
        rumdl check {{ SELFTEST }}/fixture-e-markdown/bad-document.md --no-exclude

    echo ""
    echo "Fixture F — synchronous std::fs call in a non-async application function:"
    expect_rejected "arch-lint no-sync-io restrict-use" \
        arch-lint check {{ SELFTEST }}/fixture-f-sync-io-application --config arch-lint.toml

    echo ""
    echo "Fixture G — anyhow imported in a feature crate's domain:"
    expect_rejected "arch-lint no-anyhow restrict-use" \
        arch-lint check {{ SELFTEST }}/fixture-g-anyhow-in-feature --config arch-lint.toml

    # Fixture H is asserted more strictly than "rejected": clippy's output
    # must NAME each of the six lints, using the documentation anchor it
    # prints once per lint (#print_stdout and so on). One exit code covers
    # six lints, and a lint silently dropped from the root manifest would
    # still leave the others failing — only naming each one proves all six
    # fired, and that the two thresholds in clippy.toml were actually read
    # (excessive_nesting stays silent without its threshold).
    echo ""
    echo "Fixture H — the six CLAUDE.md clippy lints, one violation each:"
    fixture_h_log="$(mktemp)"
    cargo clippy --quiet \
        --manifest-path {{ SELFTEST }}/fixture-h-claude-md-lints/Cargo.toml \
        -- -D warnings >"$fixture_h_log" 2>&1
    fixture_h_status=$?
    if [[ "$fixture_h_status" -eq 0 ]]; then
        echo "  ✗ clippy CLAUDE.md lints — ACCEPTED a violation it must reject"
        failures=$((failures + 1))
    else
        echo "  ✓ clippy CLAUDE.md lints — rejected"
    fi
    for anchor in print_stdout print_stderr dbg_macro partial_pub_fields too_many_lines excessive_nesting; do
        if grep -q "#${anchor}" "$fixture_h_log"; then
            echo "  ✓ names clippy::${anchor}"
        else
            echo "  ✗ does not name clippy::${anchor} — cannot prove this lint fired"
            failures=$((failures + 1))
        fi
    done
    rm -f "$fixture_h_log"

    echo ""
    echo "Fixture I — a 401-line module:"
    expect_rejected "xtask module-size" \
        cargo run --quiet --package xtask -- module-size \
            --root {{ SELFTEST }}/fixture-i-oversized-module

    # Fixture A carries its own copy of the clippy lints, and Fixture H
    # carries a second, disjoint copy of six more — both because a standalone
    # workspace cannot inherit the real one's table. Assert the root manifest
    # still denies every one of these names, so neither copy can drift out of
    # agreement unnoticed.
    echo ""
    echo "Drift check — fixtures A and H's lints still match the root manifest:"
    for lint in unwrap_used expect_used panic print_stdout print_stderr dbg_macro partial_pub_fields too_many_lines excessive_nesting; do
        if grep -qE "^${lint} = \"deny\"" Cargo.toml; then
            echo "  ✓ root Cargo.toml denies ${lint}"
        else
            echo "  ✗ root Cargo.toml no longer denies ${lint}"
            failures=$((failures + 1))
        fi
    done

    echo ""
    if [[ "$failures" -ne 0 ]]; then
        echo "gate-selftest: FAILED — $failures check(s) did not reject their violation."
        echo ""
        echo "The gate is not enforcing what it claims to enforce. An enforcement tool"
        echo "that checks nothing and one that finds nothing wrong emit the same exit"
        echo "code — that is the failure this repository has already had once."
        exit 1
    fi
    echo "gate-selftest: GREEN — every fixture was rejected."

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Installs the pinned tooling. The toolchain itself comes from
# rust-toolchain.toml and needs no command.
[doc("Install the pinned arch-lint.")]
install-tools:
    cargo install arch-lint-cli --version {{ ARCH_LINT_VERSION }} --locked
    cargo install rumdl --version {{ RUMDL_VERSION }} --locked

# Installs the git hooks.
[doc("Install the lefthook git hooks.")]
install-hooks:
    lefthook install

# Applies formatting rather than checking it.
[doc("Apply formatting.")]
fmt:
    cargo fmt --all
