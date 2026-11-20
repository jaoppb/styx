//! The `[cache]` keys, tracked against the raw struct that parses them.
//!
//! `cache_fields` destructures `RawCache` with no `..`, so a field added to the struct
//! stops this module compiling until it is listed here too. The `SCHEMA` manifest is then
//! checked against `config/styx.example.toml`, which must mention every key, and the
//! example's commented values must equal the defaults.

use styx_testkit::{ExampleDocument, SchemaTable};

use super::{CacheConfig, RawCache};

const EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

const SCHEMA: &[SchemaTable] = &[SchemaTable {
    header: "[cache]",
    keys: &[
        "max_entries",
        "max_bytes",
        "shards",
        "ttl_floor_secs",
        "ttl_ceiling_secs",
        "negative_ttl_ceiling_secs",
    ],
}];

fn cache_fields(raw: &RawCache) {
    let RawCache {
        max_entries: _,
        max_bytes: _,
        shards: _,
        ttl_floor_secs: _,
        ttl_ceiling_secs: _,
        negative_ttl_ceiling_secs: _,
    } = raw;
}

const _: fn(&RawCache) = cache_fields;

#[test]
fn cache_schema_keys_match_the_example() {
    let mismatches: Vec<String> = ExampleDocument::parse(EXAMPLE)
        .check(SCHEMA)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn commented_cache_keys_equal_the_defaults() {
    let enabled = ExampleDocument::parse(EXAMPLE).enabled();
    let parsed = CacheConfig::from_toml_str(&enabled);
    assert_eq!(
        parsed.as_ref().ok(),
        Some(&CacheConfig::default()),
        "switched-on example must parse with the default cache: {parsed:?}"
    );
}
