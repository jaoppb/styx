//! The pool tables' keys, tracked against the raw structs that parse them.
//!
//! Each `*_fields` function destructures a raw struct with no `..`, so a field added to
//! the struct stops this module compiling until it is listed here too. The `SCHEMA`
//! manifest below is then checked against `config/styx.example.toml`, which must mention
//! every key.

use styx_testkit::{ExampleDocument, SchemaTable};

use super::{RawCanaryConfig, RawCircuitConfig, RawPoolConfig, RawProbeConfig, RawUpstreamConfig};

const EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

const SCHEMA: &[SchemaTable] = &[
    SchemaTable {
        header: "[upstream]",
        keys: &["strategy"],
    },
    SchemaTable {
        header: "[[upstream.members]]",
        keys: &[
            "name",
            "kind",
            "addr",
            "weight",
            "edns_buffer",
            "udp_timeout_ms",
            "tcp_timeout_ms",
        ],
    },
    SchemaTable {
        header: "[upstream.members.canary]",
        keys: &["qname", "qtype", "timeout_ms"],
    },
    SchemaTable {
        header: "[upstream.probe]",
        keys: &["idle_window_secs", "down_retry_secs", "tick_secs"],
    },
    SchemaTable {
        header: "[upstream.circuit]",
        keys: &[
            "failure_threshold",
            "open_cooldown_secs",
            "half_open_successes",
        ],
    },
];

fn pool_fields(raw: &RawPoolConfig) {
    let RawPoolConfig {
        strategy: _,
        members: _,
        probe: _,
        circuit: _,
    } = raw;
}

fn member_fields(raw: &RawUpstreamConfig) {
    let RawUpstreamConfig {
        name: _,
        kind: _,
        addr: _,
        weight: _,
        canary: _,
        edns_buffer: _,
        udp_timeout_ms: _,
        tcp_timeout_ms: _,
    } = raw;
}

fn canary_fields(raw: &RawCanaryConfig) {
    let RawCanaryConfig {
        qname: _,
        qtype: _,
        timeout_ms: _,
    } = raw;
}

fn probe_fields(raw: &RawProbeConfig) {
    let RawProbeConfig {
        idle_window_secs: _,
        down_retry_secs: _,
        tick_secs: _,
    } = raw;
}

fn circuit_fields(raw: &RawCircuitConfig) {
    let RawCircuitConfig {
        failure_threshold: _,
        open_cooldown_secs: _,
        half_open_successes: _,
    } = raw;
}

const _: fn(&RawPoolConfig) = pool_fields;
const _: fn(&RawUpstreamConfig) = member_fields;
const _: fn(&RawCanaryConfig) = canary_fields;
const _: fn(&RawProbeConfig) = probe_fields;
const _: fn(&RawCircuitConfig) = circuit_fields;

#[test]
fn pool_schema_keys_match_the_example() {
    let mismatches: Vec<String> = ExampleDocument::parse(EXAMPLE)
        .check(SCHEMA)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}
