//! The `[cache]` section of the TOML file.
//!
//! The answer cache is sized at startup: the bounds cover the whole cache, and the budget
//! is split across the shards once. Changing them means editing the file and restarting.

use serde::Deserialize;

use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::capacity::{CacheCapacity, DEFAULT_SHARDS};
use crate::domain::error::ConfigError;

/// The answer cache's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
    /// Entry and byte bounds for the cache as a whole.
    pub capacity: CacheCapacity,
    /// How many shards the bounds are split across.
    pub shards: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: CacheCapacity::default(),
            shards: DEFAULT_SHARDS,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawFile {
    cache: Option<RawCache>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCache {
    max_entries: Option<usize>,
    max_bytes: Option<usize>,
    shards: Option<usize>,
}

impl CacheConfig {
    /// Reads the `[cache]` section of a whole styx TOML file. A file without the section
    /// gets the defaults.
    ///
    /// # Errors
    /// Returns [`ConfigError::Toml`] for malformed TOML or an unknown key, and
    /// [`ConfigError::Invalid`] when the bounds cannot be split across the shards: no
    /// shards, fewer entries than shards, or a byte share too small for one answer.
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        let file: RawFile = toml::from_str(content)?;
        let defaults = Self::default();
        let Some(raw) = file.cache else {
            return Ok(defaults);
        };
        let config = Self {
            capacity: CacheCapacity::new(
                raw.max_entries.unwrap_or(defaults.capacity.max_entries()),
                raw.max_bytes
                    .map_or(defaults.capacity.max_bytes(), HeapBytes::new),
            ),
            shards: raw.shards.unwrap_or(defaults.shards),
        };
        config
            .capacity
            .partition(config.shards)
            .map_err(|error| ConfigError::Invalid(format!("[cache]: {error}")))?;
        Ok(config)
    }
}

#[cfg(test)]
mod schema_keys;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::cache::capacity::MIN_SHARD_BYTES;

    #[test]
    fn a_file_without_the_section_gets_the_defaults() {
        assert_eq!(
            CacheConfig::from_toml_str("listen_addrs = []").expect("parses"),
            CacheConfig::default()
        );
    }

    #[test]
    fn keys_override_the_defaults_one_by_one() {
        let config =
            CacheConfig::from_toml_str("[cache]\nmax_entries = 500\nshards = 4").expect("parses");
        assert_eq!(config.capacity.max_entries(), 500);
        assert_eq!(
            config.capacity.max_bytes(),
            CacheConfig::default().capacity.max_bytes()
        );
        assert_eq!(config.shards, 4);
    }

    #[test]
    fn a_byte_budget_below_the_floor_is_refused_with_the_minimum_named() {
        let content = format!(
            "[cache]\nmax_bytes = {}\nshards = 4",
            4 * MIN_SHARD_BYTES - 1
        );
        let error = CacheConfig::from_toml_str(&content).expect_err("below the floor");
        let message = error.to_string();
        assert!(matches!(error, ConfigError::Invalid(_)), "{message}");
        assert!(
            message.contains(&(4 * MIN_SHARD_BYTES).to_string()),
            "{message}"
        );
    }

    #[test]
    fn zero_shards_and_fewer_entries_than_shards_are_refused() {
        assert!(CacheConfig::from_toml_str("[cache]\nshards = 0").is_err());
        assert!(CacheConfig::from_toml_str("[cache]\nmax_entries = 31").is_err());
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let error = CacheConfig::from_toml_str("[cache]\nmax_entry = 5").expect_err("typo");
        assert!(matches!(error, ConfigError::Toml(_)));
    }
}
