//! Domain layer of the fixture crate.
//!
//! DELIBERATE VIOLATION. `domain` is the innermost layer and must not name
//! `infrastructure`. This is the fixture that also guards the synthetic
//! `src/<layer>/**` glob in arch-lint.toml: remove that glob and
//! `[[deny-scope-dep]]` silently matches nothing, this file stops being
//! rejected, and the layering rules become decoration.

use crate::infrastructure::UpstreamSocket;

/// Names an infrastructure type from the innermost layer.
#[must_use]
pub fn leak(socket: UpstreamSocket) -> UpstreamSocket {
    socket
}
