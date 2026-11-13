//! The `[recursion]` and `[recursion.members.<name>]` keys, tracked against the raw
//! structs that parse them.
//!
//! `recursion_section_fields` and `recursion_fields` destructure `RawRecursion` and
//! `RawSettings` with no `..`, so a field added to either stops this module compiling until
//! it is listed here too. The `SCHEMA` manifest is then checked against
//! `config/styx.example.toml`, which must mention every key under `[recursion]`, every
//! key in a `[recursion.members.<name>]` override must belong to `SETTINGS_KEYS`, and the
//! example's commented `[recursion]` values must equal the defaults.

use styx_testkit::{ExampleDocument, SchemaTable};

use super::raw::RawSettings;
use super::{InfraCapacity, RawRecursion, RecursionSection};

const EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

const SETTINGS_KEYS: &[&str] = &[
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
];

const SCHEMA: &[SchemaTable] = &[SchemaTable {
    header: "[recursion]",
    keys: SETTINGS_KEYS,
}];

fn recursion_section_fields(raw: &RawRecursion) {
    let RawRecursion {
        members: _,
        defaults: _,
    } = raw;
}

fn recursion_fields(raw: &RawSettings) {
    let RawSettings {
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

const _: fn(&RawRecursion) = recursion_section_fields;
const _: fn(&RawSettings) = recursion_fields;

#[test]
fn recursion_schema_keys_match_the_example() {
    let document = ExampleDocument::parse(EXAMPLE);
    let mismatches: Vec<String> = document
        .check(SCHEMA)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");

    let member_entries: Vec<_> = document
        .entries()
        .filter(|entry| entry.table.starts_with("[recursion.members."))
        .collect();
    assert!(
        !member_entries.is_empty(),
        "example must document a [recursion.members.<name>] override"
    );
    for entry in member_entries {
        assert!(
            SETTINGS_KEYS.contains(&entry.key.as_str()),
            "example line {}: {} is not a key of [recursion.members.<name>]",
            entry.line,
            entry.key
        );
    }
}

#[test]
fn commented_recursion_keys_equal_the_defaults() {
    let enabled = ExampleDocument::parse(EXAMPLE).enabled();
    let parsed = RecursionSection::from_toml_str(&enabled)
        .and_then(|section| section.for_member("recursor"));
    assert!(
        matches!(&parsed, Ok(config) if config.capacity == InfraCapacity::default()),
        "switched-on example must parse with the default capacity: {parsed:?}"
    );
}
