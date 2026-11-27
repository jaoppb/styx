//! Server configuration error taxonomy.

use styx_core::format_toml_key;
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

    /// A top-level key is not one the server reads, and is not a table another feature
    /// could own, so it is most likely a misspelling.
    #[error("unknown top-level key `{0}`; check it for a typo")]
    UnknownKey(String),

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

    /// A recursor pool member sets keys the recursor never reads; timeouts belong in
    /// `[recursion.members.<name>]`, while `edns_buffer` has no recursor equivalent.
    #[error(
        "upstream member `{member}` is a recursor, which ignores {}; {}",
        quoted_keys(keys),
        recursor_key_advice(member, keys)
    )]
    RecursorMemberKeys {
        /// The pool member's name.
        member: String,
        /// Every rejected key the member sets, so one restart reports them all.
        keys: Vec<&'static str>,
    },
}

fn quoted_keys<'a>(keys: impl IntoIterator<Item = &'a &'static str>) -> String {
    keys.into_iter()
        .map(|key| format!("`{key}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn recursor_key_advice(member: &str, keys: &[&'static str]) -> String {
    let mut advice = Vec::new();
    let timeouts: Vec<_> = keys.iter().filter(|key| **key != "edns_buffer").collect();
    if !timeouts.is_empty() {
        let formatted = format_toml_key(member);
        advice.push(format!(
            "set {} under [recursion.members.{formatted}] instead",
            quoted_keys(timeouts)
        ));
    }
    if keys.contains(&"edns_buffer") {
        advice.push("edns_buffer has no recursor equivalent and should be removed".to_owned());
    }
    advice.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursor_key_advice_quotes_non_bare_toml_member_names() {
        let dotted = ConfigError::RecursorMemberKeys {
            member: "rec.v4".to_owned(),
            keys: vec!["udp_timeout_ms"],
        }
        .to_string();
        assert!(
            dotted.contains(r#"[recursion.members."rec.v4"]"#),
            "{dotted}"
        );

        let bare = ConfigError::RecursorMemberKeys {
            member: "recursor-v4_1".to_owned(),
            keys: vec!["tcp_timeout_ms"],
        }
        .to_string();
        assert!(bare.contains("[recursion.members.recursor-v4_1]"), "{bare}");
    }
}
