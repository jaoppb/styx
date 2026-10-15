//! Unknown top-level keys.
//!
//! The configuration file is shared: `[recursion]` belongs to `styx-recursion` and later
//! features add tables of their own, so the server's raw struct cannot reject every key it
//! does not know. A table is some other parser's business; a scalar or an array left over
//! after the server took its own keys can only be a misspelling.

use crate::domain::error::ConfigError;

/// Rejects the first leftover key (in key order) whose value is not a table.
pub(super) fn reject_stray_keys(leftover: &toml::Table) -> Result<(), ConfigError> {
    let stray = leftover.iter().find(|(_, value)| !value.is_table());
    match stray {
        Some((key, _)) => Err(ConfigError::UnknownKey(key.clone())),
        None => Ok(()),
    }
}
