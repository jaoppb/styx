//! Application layer of the fixture crate.
//!
//! DELIBERATE VIOLATION. A synchronous `std::fs::read_to_string` call in a
//! plain, **non-async** function. The function is deliberately synchronous:
//! inside an `async fn`, arch-lint's built-in `no-sync-io` (AL002) would
//! reject this too, and the fixture would keep passing even with the
//! `[[restrict-use]]` no-sync-io rules deleted — proving nothing about the
//! rule this fixture exists to guard.

use std::fs::read_to_string;

/// Reads a config file synchronously from the application layer.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn read_config_sync(path: &str) -> std::io::Result<String> {
    read_to_string(path)
}
