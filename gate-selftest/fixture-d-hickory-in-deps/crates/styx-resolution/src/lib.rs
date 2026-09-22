//! Fixture D: rejected by the `hickory-dev-only` containment check.
//!
//! DELIBERATE VIOLATION. `hickory-proto` is the test oracle and is permitted
//! under `[dev-dependencies]` only. On a normal path it becomes part of the
//! shipping binary, and the from-scratch rule quietly stops being true.
