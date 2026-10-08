//! Fixture J: rejected by the `hickory-dev-only` containment check.
//!
//! DELIBERATE VIOLATION. `styx-testkit` carries the test oracle and is permitted
//! under `[dev-dependencies]` only. On a normal path it drags `hickory-proto`
//! into the shipping binary through a crate whose name does not say "hickory".
