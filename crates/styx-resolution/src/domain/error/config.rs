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

    /// Upstream pool has no configured members.
    #[error("upstream pool must contain at least one member")]
    EmptyPool,

    /// Advertised EDNS buffer size is below the 512-octet minimum floor.
    #[error("EDNS buffer size {0} is below 512-octet floor")]
    EdnsBufferTooSmall(u16),

    /// Advertised EDNS buffer size is above the 4096-octet maximum ceiling.
    #[error("EDNS buffer size {0} is above 4096-octet ceiling")]
    EdnsBufferTooLarge(u16),

    /// A recursor canary question does not require full root descent.
    #[error("recursor canary must test full root descent")]
    CanaryNotDescending,
}
