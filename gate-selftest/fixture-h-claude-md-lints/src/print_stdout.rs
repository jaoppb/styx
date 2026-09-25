//! DELIBERATE VIOLATION: `println!` used as logging. Rejected by clippy's
//! `print_stdout`. `tracing` is the repository's actual logging mechanism.

/// Prints instead of emitting a `tracing` event.
pub fn announce() {
    println!("styx starting");
}
