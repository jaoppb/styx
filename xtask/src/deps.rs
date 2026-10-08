//! The link-graph layering gate: reads what the build actually links, not
//! what the source text says.
//!
//! Deliberately overlaps with arch-lint's `[[restrict-use]]` feature-isolation
//! rules. A tool that fails open is caught by its neighbour, and this
//! project's enforcement has already been silently inert once. **The overlap
//! is the point, not an oversight to be tidied away.**

use std::collections::HashSet;

use anyhow::{Context, Result};
use cargo_metadata::{DependencyKind, Metadata, PackageId};

use crate::names;

/// The shared foundation crates every other crate may name.
const SHARED_FOUNDATIONS: &[&str] = &["styx-proto", "styx-core", "styx-net"];

/// The dev-only test-support crate. Like a foundation it may name no feature crate,
/// and the `hickory-dev-only` gate keeps it off every shipping path.
const TEST_SUPPORT: &str = "styx-testkit";

/// The composition root: the only crate that may name every feature crate.
const COMPOSITION_ROOT: &str = "styx";

/// The presentation crate. Not a peer of the feature crates.
const PRESENTATION: &str = "styx-web";

/// Repository tooling, outside the layering model entirely.
const TOOLING: &str = "xtask";

/// What a workspace member is, for the purposes of the layering rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// `styx-proto`, `styx-core` and `styx-net`: everyone may name them, they name
    /// no feature.
    SharedFoundation,
    /// `styx-testkit`: named only under `[dev-dependencies]`, names no feature.
    TestSupport,
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
        if SHARED_FOUNDATIONS.contains(&name) {
            return Self::SharedFoundation;
        }
        match name {
            COMPOSITION_ROOT => Self::CompositionRoot,
            TEST_SUPPORT => Self::TestSupport,
            PRESENTATION => Self::Presentation,
            TOOLING => Self::Tooling,
            _ => Self::Feature,
        }
    }
}

/// Returns true when an edge is a plain `[dependencies]` edge.
fn is_normal_edge(kinds: &[cargo_metadata::DepKindInfo]) -> bool {
    kinds
        .iter()
        .any(|kind| matches!(kind.kind, DependencyKind::Normal))
}

/// Returns true when a crate of this class must not link any feature crate.
///
/// Feature crates are isolated from each other; foundation and test-support crates
/// sit beneath every feature, so naming one would be a layering inversion — and for
/// `styx-testkit`, a dependency cycle through the dev edges of the crates it serves.
fn names_no_feature(class: Class) -> bool {
    matches!(
        class,
        Class::Feature | Class::SharedFoundation | Class::TestSupport
    )
}

/// The link-graph layering gate: no feature crate may link another, and no
/// foundation or test-support crate may link a feature crate.
///
/// A violation is a **normal** edge from such a crate into a feature crate. Edges
/// into shared foundation crates, edges out of the `styx` binary, edges from `styx-web`
/// into a feature crate, and dev edges of any shape are all permitted.
///
/// # Errors
///
/// Returns an error if the resolved graph is missing from the metadata.
pub(crate) fn check(metadata: &Metadata) -> Result<bool> {
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
        if !names_no_feature(Class::of(from)) {
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
