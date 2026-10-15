//! The example-config scanner: what it keeps, what it drops, and what it reports.

use styx_testkit::{ExampleDocument, ExampleEntry, SchemaMismatch, SchemaTable};

const SAMPLE: &str = r#"
# Top-level prose that mentions weight = heavy but is not a pair.
listen_addrs = ["127.0.0.1:5300"]
# udp_payload_size_default = 1232

# [supervisor]
# initial_backoff_ms = 50

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "first"
kind = "recursor"
# weight = 1
# [upstream.members.canary]
# qname = "root-canary.iana.org."

[[upstream.members]]
name = "second"
kind = "forwarder"
# weight = 2
# [upstream.members.canary]
# qname = "probe.canary.invalid."

[recursion]
root_hints = "config/named.root"
"#;

fn entries_of(document: &ExampleDocument, table: &str) -> Vec<ExampleEntry> {
    document
        .entries()
        .filter(|entry| entry.table == table)
        .cloned()
        .collect()
}

#[test]
fn prose_that_contains_an_equals_sign_but_is_not_toml_produces_no_entry() {
    let document = ExampleDocument::parse(SAMPLE);
    assert!(document.entries().all(|entry| entry.line != 2));
    assert!(!document
        .entries()
        .any(|entry| entry.value.as_str() == Some("heavy")));
}

#[test]
fn commented_pair_becomes_a_commented_entry_in_the_table_above_it() {
    let document = ExampleDocument::parse(SAMPLE);
    let top = entries_of(&document, "");
    let payload = top
        .iter()
        .find(|entry| entry.key == "udp_payload_size_default");
    assert_eq!(payload.map(|entry| entry.commented), Some(true));
    assert_eq!(payload.map(|entry| entry.line), Some(4));
}

#[test]
fn commented_header_switches_the_table_for_the_entries_after_it() {
    let document = ExampleDocument::parse(SAMPLE);
    let supervisor = entries_of(&document, "[supervisor]");
    assert_eq!(supervisor.len(), 1);
    assert_eq!(
        supervisor.first().map(|e| e.key.as_str()),
        Some("initial_backoff_ms")
    );
}

#[test]
fn members_with_the_same_key_carry_different_owners() {
    let document = ExampleDocument::parse(SAMPLE);
    let owners: Vec<Option<String>> = document
        .entries()
        .filter(|entry| entry.key == "weight")
        .map(|entry| entry.owner.clone())
        .collect();
    assert_eq!(
        owners,
        vec![Some("first".to_owned()), Some("second".to_owned())]
    );
}

#[test]
fn a_member_sub_table_keeps_the_owner_of_its_member() {
    let document = ExampleDocument::parse(SAMPLE);
    let canaries: Vec<Option<String>> = entries_of(&document, "[upstream.members.canary]")
        .into_iter()
        .map(|entry| entry.owner)
        .collect();
    assert_eq!(
        canaries,
        vec![Some("first".to_owned()), Some("second".to_owned())]
    );
}

#[test]
fn entries_after_the_member_tables_have_no_owner() {
    let document = ExampleDocument::parse(SAMPLE);
    let recursion = entries_of(&document, "[recursion]");
    assert_eq!(recursion.len(), 1);
    assert_eq!(
        recursion.first().and_then(|entry| entry.owner.clone()),
        None
    );
}

#[test]
fn commented_key_unknown_to_the_schema_is_reported_with_its_line() {
    const SCHEMA: &[SchemaTable] = &[SchemaTable {
        header: "",
        keys: &["listen_addrs"],
    }];
    let document = ExampleDocument::parse(SAMPLE);
    assert_eq!(
        document.check(SCHEMA),
        vec![SchemaMismatch::UnknownKey {
            line: 4,
            table: String::new(),
            key: "udp_payload_size_default".to_owned(),
        }]
    );
}

#[test]
fn schema_key_absent_from_the_file_is_reported() {
    const SCHEMA: &[SchemaTable] = &[SchemaTable {
        header: "[supervisor]",
        keys: &["initial_backoff_ms", "max_backoff_secs"],
    }];
    let document = ExampleDocument::parse(SAMPLE);
    assert_eq!(
        document.check(SCHEMA),
        vec![SchemaMismatch::MissingKey {
            table: "[supervisor]".to_owned(),
            key: "max_backoff_secs".to_owned(),
        }]
    );
}

#[test]
fn entries_in_a_table_the_schema_does_not_name_are_ignored() {
    const SCHEMA: &[SchemaTable] = &[SchemaTable {
        header: "[supervisor]",
        keys: &["initial_backoff_ms"],
    }];
    let document = ExampleDocument::parse(SAMPLE);
    assert_eq!(document.check(SCHEMA), Vec::new());
}

#[test]
fn enabled_text_parses_as_toml_and_contains_every_commented_entry() {
    let document = ExampleDocument::parse(SAMPLE);
    let enabled = document.enabled();
    let parsed = toml::from_str::<toml::Table>(&enabled);
    assert!(parsed.is_ok(), "enabled text must parse: {parsed:?}");
    let reparsed = ExampleDocument::parse(&enabled);
    assert!(reparsed.entries().all(|entry| !entry.commented));
    assert_eq!(reparsed.entries().count(), document.entries().count());
}
