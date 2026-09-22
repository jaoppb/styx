//! Domain layer of the fixture crate.
//!
//! DELIBERATE VIOLATION. `.unwrap()` on a non-test path must be rejected twice
//! over: by arch-lint's `no-unwrap-expect` (AL001) and by clippy's
//! `unwrap_used`. If `just gate-selftest` stops failing on this file, the
//! enforcement has gone inert — do not "fix" the fixture.

/// Returns the inner value, panicking when there is none.
#[must_use]
pub fn ttl_or_panic(ttl: Option<u32>) -> u32 {
    ttl.unwrap()
}
