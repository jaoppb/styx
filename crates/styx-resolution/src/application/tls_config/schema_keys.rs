//! The `[tls]` keys, tracked against the raw struct that parses them.
//!
//! `tls_fields` destructures `RawTls` with no `..`, so a field added to the struct stops
//! this module compiling until it is listed here too. The `SCHEMA` manifest is then
//! checked against `config/styx.example.toml`, which must mention every key, and the
//! example's commented limits must equal the defaults.

use styx_testkit::{ExampleDocument, SchemaTable};

use super::{tls_config_from_toml_str, RawTls};
use crate::domain::tls::{CertificateSource, EncryptedLimits};

const EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

const SCHEMA: &[SchemaTable] = &[SchemaTable {
    header: "[tls]",
    keys: &[
        "enabled",
        "dot_listen_addrs",
        "doh_listen_addrs",
        "cert_path",
        "key_path",
        "self_signed_dir",
        "self_signed_names",
        "doh_path",
        "allow_http1",
        "handshake_timeout_secs",
        "idle_timeout_secs",
        "max_connections",
        "max_streams_per_connection",
        "max_queries_per_connection",
        "max_request_body_bytes",
    ],
}];

fn tls_fields(raw: &RawTls) {
    let RawTls {
        enabled: _,
        dot_listen_addrs: _,
        doh_listen_addrs: _,
        cert_path: _,
        key_path: _,
        self_signed_dir: _,
        self_signed_names: _,
        doh_path: _,
        allow_http1: _,
        handshake_timeout_secs: _,
        idle_timeout_secs: _,
        max_connections: _,
        max_streams_per_connection: _,
        max_queries_per_connection: _,
        max_request_body_bytes: _,
    } = raw;
}

const _: fn(&RawTls) = tls_fields;

#[test]
fn tls_schema_keys_match_the_example() {
    let mismatches: Vec<String> = ExampleDocument::parse(EXAMPLE)
        .check(SCHEMA)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn switched_on_example_keeps_encrypted_inbound_off_by_default() {
    let enabled = ExampleDocument::parse(EXAMPLE).enabled();
    assert_eq!(tls_config_from_toml_str(&enabled).ok(), Some(None));
}

#[test]
fn commented_tls_limits_equal_the_defaults_once_enabled() {
    let enabled = ExampleDocument::parse(EXAMPLE)
        .enabled()
        .replace("enabled = false", "enabled = true");
    let config = tls_config_from_toml_str(&enabled)
        .expect("switched-on [tls] parses")
        .expect("enabled");
    assert_eq!(config.limits(), EncryptedLimits::default());
    assert!(matches!(
        config.certificate_source(),
        CertificateSource::OperatorSupplied { .. }
    ));
}
