//! Fixture H: one module per `AGENTS.md` clippy lint (amendment,
//! 2026-09-24), each with exactly one deliberate violation. `just
//! gate-selftest` asserts that `cargo clippy` on this crate names every one
//! of the six lints, using the documentation anchor clippy prints once per
//! lint — one exit code covers six lints, and a lint silently dropped from
//! the root manifest would still leave the others failing.

pub mod dbg_macro;
pub mod excessive_nesting;
pub mod partial_pub_fields;
pub mod print_stderr;
pub mod print_stdout;
pub mod too_many_lines;
