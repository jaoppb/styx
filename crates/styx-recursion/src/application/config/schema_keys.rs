//! The `[recursion]` keys, tracked against the raw struct that parses them.
//!
//! `recursion_fields` destructures `RawRecursion` with no `..`, so a field added to the
//! struct stops this module compiling until it is listed here too. The `SCHEMA` manifest
//! is then checked against `config/styx.example.toml`, which must mention every key, and
//! the example's commented values must equal the defaults.

use styx_testkit::{ExampleDocument, SchemaTable};

use super::{InfraCapacity, RawRecursion, RecursionConfig};

const EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

const SCHEMA: &[SchemaTable] = &[SchemaTable {
    header: "[recursion]",
    keys: &[
        "root_hints",
        "max_depth",
        "max_outbound_queries",
        "max_cname_chain",
        "wall_clock_ms",
        "udp_timeout_ms",
        "tcp_timeout_ms",
        "use_ipv6",
        "max_delegations",
        "max_servers",
    ],
}];

fn recursion_fields(raw: &RawRecursion) {
    let RawRecursion {
        root_hints: _,
        max_depth: _,
        max_outbound_queries: _,
        max_cname_chain: _,
        wall_clock_ms: _,
        udp_timeout_ms: _,
        tcp_timeout_ms: _,
        use_ipv6: _,
        max_delegations: _,
        max_servers: _,
    } = raw;
}

const _: fn(&RawRecursion) = recursion_fields;

#[test]
fn recursion_schema_keys_match_the_example() {
    let mismatches: Vec<String> = ExampleDocument::parse(EXAMPLE)
        .check(SCHEMA)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn commented_recursion_keys_equal_the_defaults() {
    let enabled = ExampleDocument::parse(EXAMPLE).enabled();
    let parsed = RecursionConfig::from_toml_str(&enabled);
    assert!(
        matches!(&parsed, Ok(Some(config)) if config.capacity == InfraCapacity::default()),
        "switched-on example must parse with the default capacity: {parsed:?}"
    );
}
