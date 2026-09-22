//! Repository gates that read the **resolved dependency graph** rather than
//! source text.
//!
//! Two checks live here, both invoked by `just gate`:
//!
//! - `deps` — the link-graph layering gate. arch-lint reads source text; this
//!   reads what the build actually links. A misconfiguration in one is not a
//!   misconfiguration in the other, and a tool that fails open is caught by
//!   its neighbour. This project's enforcement has already been silently inert
//!   once, so the overlap is bought on purpose. **It is the point, not an
//!   oversight to be tidied away.**
//! - `hickory-dev-only` — the containment check that keeps the test oracle out
//!   of the shipping binary.
//!
//! Both produce a **verdict**, not a report: they exit non-zero on the first
//! violation and name the invariant that was broken. Informational output
//! nobody reads is not a gate.
//!
//! This is a workspace member so that it is bound by the same pinned toolchain
//! and the same fifteen denied lints as the shipping code. `anyhow` is used
//! here, and only here outside the composition root: this is tooling that
//! reports a verdict to a human, not a library with a public error boundary.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use cargo_metadata::{CargoOpt, DependencyKind, Metadata, MetadataCommand, PackageId};

/// Crate name prefix reserved for the DNS test oracle.
const ORACLE_PREFIX: &str = "hickory";

/// The shared foundation crate every other crate may name.
const SHARED_FOUNDATION: &str = "styx-proto";

/// The composition root: the only crate that may name every feature crate.
const COMPOSITION_ROOT: &str = "styx";

/// The presentation crate. Not a peer of the feature crates.
const PRESENTATION: &str = "styx-web";

/// Repository tooling, outside the layering model entirely.
const TOOLING: &str = "xtask";

/// What a workspace member is, for the purposes of the layering rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// `styx-proto`: everyone may name it, it names no one.
    SharedFoundation,
    /// `styx-<feature>`: may not name another feature crate.
    Feature,
    /// `styx-web`: may reach a feature's `application` layer.
    Presentation,
    /// `styx`: may name every feature crate.
    CompositionRoot,
    /// `xtask`: bound by the lints, not by the scopes.
    Tooling,
}

impl Class {
    /// Classifies a workspace member by name.
    ///
    /// Anything else named `styx-*` is a feature crate. That default is
    /// deliberate: a new feature crate is covered by this gate the moment it
    /// joins the workspace, rather than when somebody remembers to list it.
    fn of(name: &str) -> Self {
        match name {
            SHARED_FOUNDATION => Self::SharedFoundation,
            COMPOSITION_ROOT => Self::CompositionRoot,
            PRESENTATION => Self::Presentation,
            TOOLING => Self::Tooling,
            _ => Self::Feature,
        }
    }
}

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
/// Returns an error if the arguments are unrecognised or `cargo metadata`
/// cannot be run.
fn run() -> Result<bool> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut rest = args.iter();

    let Some(command) = rest.next() else {
        bail!("usage: xtask <deps|hickory-dev-only> [--manifest-path <path>]");
    };

    let mut manifest_path: Option<String> = None;
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--manifest-path" => {
                let value = rest
                    .next()
                    .context("--manifest-path requires a path argument")?;
                manifest_path = Some(value.clone());
            }
            other => bail!("unrecognised argument `{other}`"),
        }
    }

    let metadata = load_metadata(manifest_path.as_deref())?;

    match command.as_str() {
        "deps" => check_layering(&metadata),
        "hickory-dev-only" => check_oracle_containment(&metadata),
        other => bail!("unrecognised command `{other}`; expected `deps` or `hickory-dev-only`"),
    }
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
fn names(metadata: &Metadata) -> HashMap<&PackageId, &str> {
    metadata
        .packages
        .iter()
        .map(|package| (&package.id, package.name.as_str()))
        .collect()
}

/// Returns true when an edge of this kind is linked into the shipping binary.
///
/// Normal and build edges are; dev edges are not, which is the entire basis of
/// the `hickory-proto` exception.
fn is_shipping_edge(kinds: &[cargo_metadata::DepKindInfo]) -> bool {
    kinds
        .iter()
        .any(|kind| matches!(kind.kind, DependencyKind::Normal | DependencyKind::Build))
}

/// Returns true when an edge is a plain `[dependencies]` edge.
fn is_normal_edge(kinds: &[cargo_metadata::DepKindInfo]) -> bool {
    kinds
        .iter()
        .any(|kind| matches!(kind.kind, DependencyKind::Normal))
}

/// The link-graph layering gate: no feature crate may link another.
///
/// A violation is a **normal** edge from one feature crate to another. Edges
/// into `styx-proto`, edges out of the `styx` binary, edges from `styx-web`
/// into a feature crate, and dev edges of any shape are all permitted.
///
/// # Errors
///
/// Returns an error if the resolved graph is missing from the metadata.
fn check_layering(metadata: &Metadata) -> Result<bool> {
    let resolve = metadata
        .resolve
        .as_ref()
        .context("`cargo metadata` returned no resolved dependency graph")?;
    let names = names(metadata);
    let members: HashSet<&PackageId> = metadata.workspace_members.iter().collect();

    let mut violations: Vec<String> = Vec::new();

    for node in &resolve.nodes {
        if !members.contains(&node.id) {
            continue;
        }
        let Some(from) = names.get(&node.id) else {
            continue;
        };
        if Class::of(from) != Class::Feature {
            continue;
        }

        for dep in &node.deps {
            if !members.contains(&dep.pkg) || !is_normal_edge(&dep.dep_kinds) {
                continue;
            }
            let Some(to) = names.get(&dep.pkg) else {
                continue;
            };
            if to == from || Class::of(to) != Class::Feature {
                continue;
            }
            violations.push(format!("  {from} -> {to}   (normal dependency edge)"));
        }
    }

    if violations.is_empty() {
        println!("link-graph layering: OK — no feature crate links another.");
        return Ok(true);
    }

    eprintln!("link-graph layering: FAILED\n");
    for violation in &violations {
        eprintln!("{violation}");
    }
    eprintln!(
        "\nInvariant: feature crates never depend on each other.\n\
         A cross-feature need is a trait (a port) declared in the CONSUMER's domain\n\
         module, implemented by an adapter in the styx binary — which is the one crate\n\
         permitted to name every feature crate at once.\n\n\
         Without this, features reach into each other and the isolation becomes a\n\
         rewrite to recover rather than a rule to follow.\n\n\
         This gate reads the resolved link graph. arch-lint reads source text and\n\
         enforces the same invariant independently; if only one of the two fired,\n\
         the other has failed open — fix that too."
    );
    Ok(false)
}

/// The containment gate: the test oracle stays out of the shipping binary.
///
/// Walks the **full transitive** normal and build dependency paths of every
/// workspace member, so a `hickory-*` crate pulled in indirectly is caught as
/// surely as one written into a manifest. Presence under `[dev-dependencies]`
/// at any depth is permitted and is the entire point of the exception.
///
/// **Known limitation**: until Phase 1 adds the expected-byte fixtures and
/// Phase 2 the fake root/TLD/authoritative servers, there is no
/// `hickory-proto` dev-dependency at all and this check passes vacuously.
/// Fixture D in `tests/gate-selftest/` is the only proof it works until then.
///
/// # Errors
///
/// Returns an error if the resolved graph is missing from the metadata.
fn check_oracle_containment(metadata: &Metadata) -> Result<bool> {
    let resolve = metadata
        .resolve
        .as_ref()
        .context("`cargo metadata` returned no resolved dependency graph")?;
    let names = names(metadata);

    let edges: HashMap<&PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|node| (&node.id, node)).collect();

    let mut violations: BTreeSet<String> = BTreeSet::new();

    for member in &metadata.workspace_members {
        let Some(origin) = names.get(member) else {
            continue;
        };

        // Breadth-first over shipping edges only, carrying the path that got
        // us here so a transitive introduction is diagnosable rather than
        // merely reported.
        let mut seen: HashSet<&PackageId> = HashSet::new();
        let mut queue: VecDeque<(&PackageId, Vec<&str>)> = VecDeque::new();
        seen.insert(member);
        queue.push_back((member, vec![origin]));

        while let Some((id, path)) = queue.pop_front() {
            let Some(node) = edges.get(id) else {
                continue;
            };
            for dep in &node.deps {
                if !is_shipping_edge(&dep.dep_kinds) || !seen.insert(&dep.pkg) {
                    continue;
                }
                let Some(name) = names.get(&dep.pkg) else {
                    continue;
                };

                let mut next = path.clone();
                next.push(name);

                if name.starts_with(ORACLE_PREFIX) {
                    violations.insert(format!("  {}", next.join(" -> ")));
                    continue;
                }
                queue.push_back((&dep.pkg, next));
            }
        }
    }

    if violations.is_empty() {
        println!(
            "hickory-dev-only: OK — no `{ORACLE_PREFIX}*` crate is reachable through a normal or build path."
        );
        return Ok(true);
    }

    eprintln!("hickory-dev-only: FAILED\n");
    for violation in &violations {
        eprintln!("{violation}");
    }
    eprintln!(
        "\nInvariant: `hickory-proto` is the TEST ORACLE, permitted under\n\
         [dev-dependencies] only — never on a normal or build path.\n\n\
         The entire DNS stack is written from scratch: wire codec, server loop, caches,\n\
         recursion algorithm, DNSSEC validation. The fake root/TLD/authoritative servers\n\
         and the expected-byte fixtures have to encode DNS wire format, and if OUR codec\n\
         encodes them then the resolver and its oracle share every bug — a green suite\n\
         would prove only self-consistency.\n\n\
         The ban is on shipping code, not the test rig. Move this back to\n\
         [dev-dependencies]. See docs/adr/0002-hickory-proto-exception.md."
    );
    Ok(false)
}
