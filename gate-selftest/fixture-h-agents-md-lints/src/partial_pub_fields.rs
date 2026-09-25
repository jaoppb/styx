//! DELIBERATE VIOLATION: a struct mixing `pub` and private fields. Rejected
//! by clippy's `partial_pub_fields`. A struct either publishes every field
//! (plain data, no invariant) or none (an abstract type guarding one behind
//! its constructor) — this mixes the two.

/// Mixes a public field with a private one.
pub struct Mixed {
    /// Publicly readable and writable.
    pub name: String,
    secret: u32,
}

impl Mixed {
    /// Builds a new value.
    #[must_use]
    pub fn new(name: String, secret: u32) -> Self {
        Self { name, secret }
    }

    /// Returns the private field.
    #[must_use]
    pub fn secret(&self) -> u32 {
        self.secret
    }
}
