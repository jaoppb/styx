//! First-run configuration: a minimal config is accepted with every default left alone, and
//! `config/styx.example.toml` stays parseable and lists every key the resolution schema accepts.

use std::collections::BTreeSet;
use std::time::Duration;

use styx_resolution::{ServerConfig, Timeouts};

const MINIMAL_CONFIG: &str = r#"
[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "a"
kind = "forwarder"
addr = "9.9.9.9:53"
"#;

/// Top-level keys accepted by `RawConfig` (`server.rs`).
const SERVER_KEYS: &[&str] = &[
    "listen_addrs",
    "udp_payload_size_default",
    "tcp_idle_timeout_secs",
    "query_timeout_secs",
    "max_in_flight_queries",
    "max_tcp_connections",
];

/// Keys accepted by `RawSupervisorConfig` (`server.rs`), under `[supervisor]`.
const SUPERVISOR_KEYS: &[&str] = &[
    "initial_backoff_ms",
    "max_backoff_secs",
    "healthy_threshold_secs",
];

/// Keys accepted by `RawPoolConfig` (`domain/config.rs`), under `[upstream]`.
const POOL_KEYS: &[&str] = &["strategy"];

/// Keys accepted by `RawUpstreamConfig` (`domain/config.rs`), under `[[upstream.members]]`.
const MEMBER_KEYS: &[&str] = &[
    "name",
    "kind",
    "addr",
    "weight",
    "edns_buffer",
    "udp_timeout_ms",
    "tcp_timeout_ms",
];

/// Keys accepted by `RawCanaryConfig` (`domain/config.rs`), under `[upstream.members.canary]`.
const CANARY_KEYS: &[&str] = &["qname", "qtype", "timeout_ms"];

/// Keys accepted by `RawProbeConfig` (`domain/config.rs`), under `[upstream.probe]`.
const PROBE_KEYS: &[&str] = &["idle_window_secs", "down_retry_secs", "tick_secs"];

/// Keys accepted by `RawCircuitConfig` (`domain/config.rs`), under `[upstream.circuit]`.
const CIRCUIT_KEYS: &[&str] = &[
    "failure_threshold",
    "open_cooldown_secs",
    "half_open_successes",
];

/// Each table of the schema the example must cover, and the keys it accepts. The empty header is
/// the top level of the file.
const SCHEMA: &[(&str, &[&str])] = &[
    ("", SERVER_KEYS),
    ("[supervisor]", SUPERVISOR_KEYS),
    ("[upstream]", POOL_KEYS),
    ("[[upstream.members]]", MEMBER_KEYS),
    ("[upstream.members.canary]", CANARY_KEYS),
    ("[upstream.probe]", PROBE_KEYS),
    ("[upstream.circuit]", CIRCUIT_KEYS),
];

const EXAMPLE_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

/// The line with a leading comment marker removed, if it has one.
fn uncommented(line: &str) -> &str {
    let trimmed = line.trim_start();
    trimmed
        .strip_prefix('#')
        .map_or(trimmed, |rest| rest.trim_start())
}

/// The table header a line starts, and whether it is a live header rather than a commented-out
/// schema header.
fn header_of(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    if trimmed.starts_with('[') {
        return Some((trimmed.to_string(), true));
    }
    let candidate = uncommented(line).trim_end();
    SCHEMA
        .iter()
        .any(|(header, _)| !header.is_empty() && candidate == *header)
        .then(|| (candidate.to_string(), false))
}

fn key_of(line: &str) -> Option<String> {
    let (key, _) = uncommented(line).split_once(" =")?;
    (!key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
        .then(|| key.to_string())
}

/// The `header:key` entries the example mentions, live or commented out.
fn mentioned_keys(text: &str) -> BTreeSet<String> {
    let mut section = String::new();
    let mut found = BTreeSet::new();
    for line in text.lines() {
        if let Some((header, _)) = header_of(line) {
            section = header;
        } else if let Some(key) = key_of(line) {
            found.insert(format!("{section}:{key}"));
        }
    }
    found
}

fn is_schema_key(section: &str, key: &str) -> bool {
    SCHEMA
        .iter()
        .any(|(header, keys)| *header == section && keys.contains(&key))
}

/// The example with every commented-out schema key and table header switched on.
fn with_schema_keys_enabled(text: &str) -> String {
    let mut section = String::new();
    let mut lines = Vec::new();
    for line in text.lines() {
        if let Some((header, _)) = header_of(line) {
            lines.push(header.clone());
            section = header;
            continue;
        }
        let enable = key_of(line).is_some_and(|key| is_schema_key(&section, &key));
        lines.push(if enable { uncommented(line) } else { line }.to_string());
    }
    lines.join("\n")
}

#[test]
fn minimal_config_with_one_member_and_no_timeout_keys_is_accepted() {
    let config = ServerConfig::from_toml_str(MINIMAL_CONFIG)
        .expect("one member with only name, kind and addr is a valid config");
    assert_eq!(config.upstream.map(|pool| pool.members.len()), Some(1));
}

#[test]
fn default_query_timeout_outlasts_every_default_member_timeout() {
    let config = ServerConfig::from_toml_str(MINIMAL_CONFIG).expect("minimal config");
    let defaults = Timeouts::default();
    assert!(config.query_timeout > defaults.udp.max(defaults.tcp));
    assert!(config.query_timeout > Duration::from_secs(4));
}

#[test]
fn member_without_timeout_keys_takes_the_documented_defaults() {
    let config = ServerConfig::from_toml_str(MINIMAL_CONFIG).expect("minimal config");
    let pool = config.upstream.expect("upstream section");
    let member = pool.members.first().expect("one member");
    assert_eq!(member.timeouts, Timeouts::default());
}

#[test]
fn example_config_parses() {
    let config = ServerConfig::from_toml_str(EXAMPLE_CONFIG).expect("example config parses");
    assert!(config.upstream.is_some());
}

#[test]
fn example_config_lists_every_schema_key() {
    let mentioned = mentioned_keys(EXAMPLE_CONFIG);
    let missing: Vec<String> = SCHEMA
        .iter()
        .flat_map(|(header, keys)| keys.iter().map(move |key| format!("{header}:{key}")))
        .filter(|entry| !mentioned.contains(entry))
        .collect();
    assert!(missing.is_empty(), "example is missing: {missing:?}");
}

#[test]
fn example_config_still_parses_with_every_schema_key_switched_on() {
    let enabled = with_schema_keys_enabled(EXAMPLE_CONFIG);
    let config = ServerConfig::from_toml_str(&enabled)
        .expect("the commented keys in the example parse once switched on");
    let canary = config
        .upstream
        .and_then(|pool| pool.members.into_iter().find_map(|member| member.canary));
    assert!(
        canary.is_some(),
        "the commented canary table was not enabled"
    );
}
