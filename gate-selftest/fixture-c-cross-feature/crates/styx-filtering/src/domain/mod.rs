//! Domain layer of the sibling fixture crate.

/// Stands in for a real filtering decision.
#[derive(Debug)]
pub enum Verdict {
    /// The query is permitted.
    Allow,
    /// The query is blocked by policy.
    Block,
}
