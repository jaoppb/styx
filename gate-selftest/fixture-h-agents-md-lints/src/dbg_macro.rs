//! DELIBERATE VIOLATION: a leftover `dbg!`. Rejected by clippy's `dbg_macro`.
//! Unlike the print macros, there is no `allow-dbg-in-tests`: a `dbg!` is a
//! leftover in any file, test or not.

/// Leaves a debugging macro in place.
#[must_use]
pub fn inspect(value: i32) -> i32 {
    dbg!(value)
}
