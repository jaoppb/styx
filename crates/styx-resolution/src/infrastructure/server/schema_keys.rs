//! The server and supervisor keys, tracked against the raw structs that parse them.
//!
//! Each `*_fields` function destructures a raw struct with no `..`, so a field added to
//! the struct stops this module compiling until it is listed here too. The `SCHEMA`
//! manifest below is then checked against `config/styx.example.toml`, which must mention
//! every key. The `supervisor` and `upstream` fields are tables, not leaf keys, and are
//! covered by their own manifests; `other` is the catch-all for other features' tables.

use styx_testkit::{ExampleDocument, SchemaTable};

use super::{RawConfig, RawSupervisorConfig};

const EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

const SCHEMA: &[SchemaTable] = &[
    SchemaTable {
        header: "",
        keys: &[
            "listen_addrs",
            "udp_payload_size_default",
            "tcp_idle_timeout_secs",
            "query_timeout_secs",
            "max_in_flight_queries",
            "max_tcp_connections",
            "filter_aaaa",
        ],
    },
    SchemaTable {
        header: "[supervisor]",
        keys: &[
            "initial_backoff_ms",
            "max_backoff_secs",
            "healthy_threshold_secs",
        ],
    },
];

fn server_fields(raw: &RawConfig) {
    let RawConfig {
        listen_addrs: _,
        udp_payload_size_default: _,
        tcp_idle_timeout_secs: _,
        query_timeout_secs: _,
        max_in_flight_queries: _,
        max_tcp_connections: _,
        filter_aaaa: _,
        supervisor: _,
        upstream: _,
        other: _,
    } = raw;
}

fn supervisor_fields(raw: &RawSupervisorConfig) {
    let RawSupervisorConfig {
        initial_backoff_ms: _,
        max_backoff_secs: _,
        healthy_threshold_secs: _,
    } = raw;
}

const _: fn(&RawConfig) = server_fields;
const _: fn(&RawSupervisorConfig) = supervisor_fields;

#[test]
fn server_schema_keys_match_the_example() {
    let mismatches: Vec<String> = ExampleDocument::parse(EXAMPLE)
        .check(SCHEMA)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}
