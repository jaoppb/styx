//! DELIBERATE VIOLATION: a block nested past depth 4. Rejected by clippy's
//! `excessive_nesting`, silent at its default threshold of 0 and turned on
//! by `clippy.toml`'s `excessive-nesting-threshold = 4`.
//!
//! Four different control-flow kinds, not four nested `if`s, so the
//! violation is `excessive_nesting` itself rather than `collapsible_if`
//! noise from stacking conditions that could be merged with `&&`.

/// Nests an `if`, a `for` and a `while` inside a plain function, with one
/// more `if` past what the threshold allows.
#[must_use]
pub fn deeply_nested(values: &[i32]) -> i32 {
    let mut total = 0;
    if !values.is_empty() {
        for value in values {
            let mut remaining = *value;
            while remaining > 0 {
                if remaining % 2 == 0 {
                    total += 1;
                }
                remaining -= 1;
            }
        }
    }
    total
}
