//! A misspelled key is a startup error, not a silently ignored line. The file is shared with
//! other features, so a top-level table the server does not own must still pass.

use styx_resolution::{ConfigError, ServerConfig};

const MEMBER: &str =
    "[[upstream.members]]\nname = \"a\"\nkind = \"forwarder\"\naddr = \"9.9.9.9:53\"\n";

fn upstream_with(extra_pool_lines: &str, extra_member_lines: &str) -> String {
    format!(
        "[upstream]\nstrategy = \"ordered_failover\"\n{extra_pool_lines}\n{MEMBER}{extra_member_lines}\n"
    )
}

fn unknown_field_named(config: &str, field: &str) {
    let message = match ServerConfig::from_toml_str(config) {
        Err(ConfigError::Toml(error)) => error.to_string(),
        other => format!("not a TOML schema error: {other:?}"),
    };
    assert!(
        message.contains("unknown field") && message.contains(field),
        "{message}"
    );
}

#[test]
fn a_misspelled_top_level_key_is_rejected_by_name() {
    match ServerConfig::from_toml_str("query_timeout_sec = 5") {
        Err(ConfigError::UnknownKey(key)) => assert_eq!(key, "query_timeout_sec"),
        other => panic!("expected UnknownKey, got {other:?}"),
    }
}

#[test]
fn a_misspelled_top_level_array_is_rejected_too() {
    let result = ServerConfig::from_toml_str("listen_addr = [\"127.0.0.1:5300\"]");
    assert!(
        matches!(result, Err(ConfigError::UnknownKey(_))),
        "{result:?}"
    );
}

#[test]
fn top_level_tables_owned_by_other_features_still_parse() {
    let config = "[recursion]\nroot_hints = \"x\"\n\n[filtering]\nanything = 1\n";
    assert!(ServerConfig::from_toml_str(config).is_ok());
}

#[test]
fn a_misspelled_supervisor_key_is_rejected() {
    unknown_field_named("[supervisor]\ninitial_backoff = 5\n", "initial_backoff");
}

#[test]
fn a_misspelled_pool_key_is_rejected() {
    unknown_field_named(&upstream_with("stratgy = 1", ""), "stratgy");
}

#[test]
fn a_misspelled_member_key_is_rejected() {
    unknown_field_named(&upstream_with("", "udp_timeout = 5"), "udp_timeout");
}

#[test]
fn a_misspelled_canary_key_is_rejected() {
    let canary = "[upstream.members.canary]\nqname = \"a.\"\nqtype = \"A\"\ntimeout = 5\n";
    unknown_field_named(&upstream_with("", canary), "timeout");
}

#[test]
fn a_misspelled_probe_key_is_rejected() {
    unknown_field_named(
        &upstream_with("[upstream.probe]\ntick_sec = 1", ""),
        "tick_sec",
    );
}

#[test]
fn a_misspelled_circuit_key_is_rejected() {
    unknown_field_named(
        &upstream_with("[upstream.circuit]\nfailures = 1", ""),
        "failures",
    );
}
