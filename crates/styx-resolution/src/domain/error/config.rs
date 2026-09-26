//! Server configuration error taxonomy.

use thiserror::Error;

/// Errors arising during configuration loading or validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read the configuration file from disk.
    #[error("configuration I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse TOML configuration syntax or structure.
    #[error("configuration TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// A configuration value failed validation invariants.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}
