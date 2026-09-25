//! Domain layer of the fixture crate.
//!
//! DELIBERATE VIOLATION. `anyhow::Result` named in a library crate's domain
//! module. Norm 3 reserves `anyhow` for the composition-root binary and for
//! `xtask`; `require-thiserror` does not reach this, because it only checks
//! that a type named `*Error` derives `thiserror::Error` and says nothing
//! about `anyhow`. This fixture needs no manifest dependency: arch-lint reads
//! source text, not the resolved dependency graph.

/// Stands in for a fallible domain operation that should return a
/// crate-owned `thiserror` enum instead of `anyhow::Result`.
///
/// # Errors
///
/// Always returns `Ok`; the violation is the return type, not the body.
pub fn load() -> anyhow::Result<()> {
    Ok(())
}
