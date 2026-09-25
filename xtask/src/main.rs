//! Repository gates that read the **resolved dependency graph** rather than
//! source text, plus the module-size check for the file-length cap.
//!
//! Three checks live here, each invoked by `just gate`:
//!
//! - `deps` ([`deps`]) — the link-graph layering gate. arch-lint reads source
//!   text; this reads what the build actually links. A misconfiguration in
//!   one is not a misconfiguration in the other, and a tool that fails open
//!   is caught by its neighbour. This project's enforcement has already been
//!   silently inert once, so the overlap is bought on purpose. **It is the
//!   point, not an oversight to be tidied away.**
//! - `hickory-dev-only` ([`hickory`]) — the containment check that keeps the
//!   test oracle out of the shipping binary.
//! - `module-size` ([`module_size`]) — caps a `.rs` file at
//!   [`module_size::MAX_MODULE_LINES`] counted lines, with no per-file
//!   exemption. No clippy lint measures a file, only a function, so this is
//!   the only tool that can turn "split a layer's module by concept" into a
//!   verdict.
//!
//! Every check produces a **verdict**, not a report: non-zero exit on the
//! first violation (`deps`, `hickory-dev-only`) or after listing every one
//! (`module-size`), naming the invariant that was broken. Informational
//! output nobody reads is not a gate.
//!
//! This is a workspace member so that it is bound by the same pinned
//! toolchain and the same denied lints as the shipping code. `anyhow` is used
//! here, and only here outside the composition root: this is tooling that
//! reports a verdict to a human, not a library with a public error boundary.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "xtask's output IS the verdict it reports to a human, not a library boundary. \
              This is the repository's one standing lint exemption — see AGENTS.md's \
              Enforcement section."
)]

mod deps;
mod hickory;
mod module_size;

use std::collections::HashMap;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use cargo_metadata::{CargoOpt, Metadata, MetadataCommand, PackageId};

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("xtask: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Parses the arguments and dispatches to a check.
///
/// # Errors
///
/// Returns an error if the arguments are unrecognised, or if `cargo metadata`
/// cannot be run for a check that needs it.
fn run() -> Result<bool> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut rest = args.iter();

    let Some(command) = rest.next() else {
        bail!(
            "usage: xtask <deps|hickory-dev-only> [--manifest-path <path>]\n   \
             or: xtask module-size [--root <path>]"
        );
    };

    if command == "module-size" {
        let root = parse_flag_value(rest, "--root")?;
        return module_size::run(root.as_deref());
    }

    let manifest_path = parse_flag_value(rest, "--manifest-path")?;
    let metadata = load_metadata(manifest_path.as_deref())?;

    match command.as_str() {
        "deps" => deps::check(&metadata),
        "hickory-dev-only" => hickory::check(&metadata),
        other => bail!(
            "unrecognised command `{other}`; expected `deps`, `hickory-dev-only` or \
             `module-size`"
        ),
    }
}

/// Parses a single optional `--flag <value>` pair from the remaining
/// arguments. Any other flag is an error, which keeps a typo loud rather than
/// silently ignored.
///
/// # Errors
///
/// Returns an error if an unrecognised flag is given, or if `flag` appears
/// with no following value.
fn parse_flag_value<'a>(
    mut rest: impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<Option<String>> {
    let Some(seen) = rest.next() else {
        return Ok(None);
    };
    if seen != flag {
        bail!("unrecognised argument `{seen}`");
    }
    let value = rest
        .next()
        .with_context(|| format!("{flag} requires a path argument"))?;
    Ok(Some(value.clone()))
}

/// Resolves the dependency graph with every feature enabled.
///
/// All features, because a containment violation hidden behind an off-by-
/// default feature is still a containment violation — it merely waits for the
/// build that turns the feature on.
///
/// # Errors
///
/// Returns an error if `cargo metadata` fails or returns no resolved graph.
fn load_metadata(manifest_path: Option<&str>) -> Result<Metadata> {
    let mut command = MetadataCommand::new();
    command.features(CargoOpt::AllFeatures);
    if let Some(path) = manifest_path {
        command.manifest_path(path);
    }
    command
        .exec()
        .context("failed to run `cargo metadata`; is this a Cargo workspace?")
}

/// Maps every package id in the graph to its crate name.
pub(crate) fn names(metadata: &Metadata) -> HashMap<&PackageId, &str> {
    metadata
        .packages
        .iter()
        .map(|package| (&package.id, package.name.as_str()))
        .collect()
}
