//! The containment gate: keeps the DNS test oracle out of the shipping
//! binary, so the from-scratch rule stays observable rather than
//! aspirational.
//!
//! **Known limitation**: until Phase 1 adds the expected-byte fixtures and
//! Phase 2 the fake root/TLD/authoritative servers, there is no
//! `hickory-proto` dev-dependency at all and this check passes vacuously.
//! Fixture D in `gate-selftest/` is the only proof it works until then.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use anyhow::{Context, Result};
use cargo_metadata::{DependencyKind, Metadata, Node, PackageId};

use crate::names;

/// Crate name prefix reserved for the DNS test oracle.
const ORACLE_PREFIX: &str = "hickory";

/// Workspace crates that exist only to be dev-dependencies: they may link the
/// oracle themselves, so they are never a walk's origin, and reaching one through a
/// shipping edge is the same violation as reaching the oracle directly.
const DEV_ONLY: &[&str] = &["styx-testkit"];

/// Returns true when a crate must never be reachable through a shipping edge.
fn is_contained(name: &str) -> bool {
    name.starts_with(ORACLE_PREFIX) || DEV_ONLY.contains(&name)
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

/// Breadth-first search over shipping edges only, starting from one workspace
/// member, carrying the path that got to each node so a transitive
/// introduction is diagnosable rather than merely reported.
///
/// Extracted so that [`check`] itself nests no more than a `for` loop over
/// the workspace members. `excessive_nesting`'s threshold of 4 counts a
/// function's own block plus each control-flow block nested inside it; this
/// traversal's `while` and its inner `for` bring a plain function to depth 3,
/// leaving room for the one guard clause nested inside without tripping the
/// lint. The first version of this check nested three blocks past the
/// threshold, all in this traversal, before it was split this way.
fn walk_from<'a>(
    start: &'a PackageId,
    origin: &'a str,
    edges: &HashMap<&'a PackageId, &'a Node>,
    names: &HashMap<&'a PackageId, &'a str>,
) -> BTreeSet<String> {
    let mut violations: BTreeSet<String> = BTreeSet::new();
    let mut seen: HashSet<&PackageId> = HashSet::from([start]);
    let mut queue: VecDeque<(&PackageId, Vec<&str>)> = VecDeque::from([(start, vec![origin])]);

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

            if is_contained(name) {
                violations.insert(format!("  {}", next.join(" -> ")));
                continue;
            }
            queue.push_back((&dep.pkg, next));
        }
    }

    violations
}

/// The containment gate: the test oracle stays out of the shipping binary.
///
/// Walks the **full transitive** normal and build dependency paths of every
/// workspace member, so a `hickory-*` crate pulled in indirectly is caught as
/// surely as one written into a manifest. Presence under `[dev-dependencies]`
/// at any depth is permitted and is the entire point of the exception. The same
/// holds for the [`DEV_ONLY`] crates that carry the oracle: they are not walked
/// from, and reaching one through a shipping edge is a violation.
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
    let edges: HashMap<&PackageId, &Node> =
        resolve.nodes.iter().map(|node| (&node.id, node)).collect();

    let mut violations: BTreeSet<String> = BTreeSet::new();
    for member in &metadata.workspace_members {
        let Some(origin) = names.get(member) else {
            continue;
        };
        if DEV_ONLY.contains(origin) {
            continue;
        }
        violations.extend(walk_from(member, origin, &edges, &names));
    }

    if violations.is_empty() {
        println!(
            "hickory-dev-only: OK — no `{ORACLE_PREFIX}*` or dev-only crate is reachable through a normal or build path."
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
         The ban is on shipping code, not the test rig. `styx-testkit` carries the\n\
         oracle and is held to the same rule. Move this back to [dev-dependencies].\n\
         See docs/adr/0002-hickory-proto-exception.md."
    );
    Ok(false)
}
