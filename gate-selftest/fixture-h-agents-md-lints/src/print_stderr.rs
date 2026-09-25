//! DELIBERATE VIOLATION: `eprintln!` used as logging. Rejected by clippy's
//! `print_stderr`. `tracing` is the repository's actual logging mechanism.

/// Prints to stderr instead of emitting a `tracing` event.
pub fn warn_operator() {
    eprintln!("something went wrong");
}
