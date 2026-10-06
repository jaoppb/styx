//! Loads root hints from the path the TOML file names.

use std::path::Path;

use crate::domain::error::ConfigError;
use crate::domain::root_hints::RootHints;

impl RootHints {
    /// Reads and parses the `named.root`-style file at `path`. The file is the
    /// only source of root hints: there is no compiled-in copy.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::RootHintsUnreadable`] if the file cannot be read, and
    /// the errors of [`RootHints::parse`] for its contents.
    pub async fn from_config_path(path: &Path) -> Result<Self, ConfigError> {
        let text = tokio::fs::read_to_string(path).await.map_err(|error| {
            ConfigError::RootHintsUnreadable(format!("{}: {error}", path.display()))
        })?;
        Self::parse(&text)
    }
}
