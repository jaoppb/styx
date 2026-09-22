//! Domain layer of the fixture crate.
//!
//! DELIBERATE VIOLATION. A feature crate naming a sibling feature crate. The
//! real thing declares a `FilterPolicy` port here and lets the `styx` binary
//! wire `styx-filtering` into it.
//!
//! `[[restrict-use]]` is the rule most likely to be silently wrong, because of
//! its `styx-proto` and `styx-web` exemptions: written as "no crate may name
//! another workspace crate" it breaks the whole build, and written too loosely
//! it never fires. This fixture is what tells the two apart.

use styx_filtering::domain::Verdict;

/// Consumes a sibling feature crate's type directly.
#[must_use]
pub fn decide(verdict: Verdict) -> Verdict {
    verdict
}
