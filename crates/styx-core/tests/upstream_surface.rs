//! The `Upstream` port carries no DNSSEC chain material (Phase 06, task 6d.4).
//!
//! A pool hands back forwarders and recursors behind this one port, so a "chain material
//! observed en route" member would be permanently empty for every forwarder, and nothing at
//! the call site would say so. The validator gets its material through its own
//! `ChainSource` port instead. These checks fail the moment the port grows such a member:
//! the first two at compile time for any new method or response field, the third for a
//! DNSSEC-shaped name anywhere in the port's source, default methods included.

use std::time::{Duration, Instant};

use styx_core::{Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse};
use styx_proto::{Header, Message, Opcode, Question};

const PORT_SOURCE: &str = include_str!("../src/domain/upstream.rs");

/// Words that name DNSSEC chain material. Request flags (DO, CD) are inputs every
/// upstream kind honours, so they are not on the list.
const CHAIN_MATERIAL_WORDS: &[&str] = &[
    "anchor",
    "chain",
    "delegation",
    "dnskey",
    "dnssec",
    "ds",
    "material",
    "nsec",
    "nsec3",
    "proof",
    "referral",
    "rrsig",
    "signature",
    "trust",
];

/// Implements exactly the port's three methods: a fourth required method fails to compile.
struct ThreeMethods;

impl Upstream for ThreeMethods {
    fn id(&self) -> UpstreamId {
        UpstreamId::new("three-methods")
    }

    fn kind(&self) -> UpstreamKind {
        UpstreamKind::Forwarder
    }

    async fn resolve(
        &self,
        _query: &Question,
        _deadline: Instant,
    ) -> Result<UpstreamResponse, UpstreamError> {
        Err(UpstreamError::Timeout)
    }
}

#[test]
fn the_port_has_exactly_three_required_methods() {
    let upstream = ThreeMethods;
    assert_eq!(upstream.id(), UpstreamId::new("three-methods"));
    assert_eq!(upstream.kind(), UpstreamKind::Forwarder);
}

/// Names every field: a new field on the response fails to compile here.
#[test]
fn the_response_has_exactly_its_six_fields() {
    let response = UpstreamResponse {
        message: Message::new(Header::new_query(0, Opcode::Query, false)),
        answered_by: UpstreamId::new("forwarder"),
        kind: UpstreamKind::Forwarder,
        elapsed: Duration::ZERO,
        via_tcp: false,
        raced_count: 1,
    };

    let UpstreamResponse {
        message,
        answered_by,
        kind,
        elapsed,
        via_tcp,
        raced_count,
    } = response;

    assert!(message.answers.is_empty());
    assert_eq!(answered_by.as_str(), "forwarder");
    assert_eq!(kind, UpstreamKind::Forwarder);
    assert_eq!(elapsed, Duration::ZERO);
    assert!(!via_tcp);
    assert_eq!(raced_count, 1);
}

#[test]
fn no_identifier_in_the_port_names_chain_material() {
    let offending: Vec<String> = code_words(PORT_SOURCE)
        .into_iter()
        .filter(|word| CHAIN_MATERIAL_WORDS.contains(&word.as_str()))
        .collect();

    assert!(
        offending.is_empty(),
        "the Upstream port names DNSSEC chain material ({offending:?}); \
         give the validator a ChainSource adapter instead"
    );
}

#[test]
fn the_scan_finds_a_chain_material_member() {
    let widened = "pub trait Upstream { fn chain_material(&self) -> Vec<DsRecord>; }";

    let words = code_words(widened);

    assert!(words.iter().any(|word| word == "chain"));
    assert!(words.iter().any(|word| word == "ds"));
}

/// The lower-case words of every identifier outside comments, split at underscores and
/// at camel-case humps, so `chain_material` and `DsRecord` both yield their parts.
fn code_words(source: &str) -> Vec<String> {
    let mut words = Vec::new();
    for line in source.lines() {
        let code = line.split("//").next().unwrap_or_default();
        for identifier in code.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            for part in identifier.split('_') {
                words.extend(camel_parts(part));
            }
        }
    }
    words
}

fn camel_parts(part: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    for c in part.chars() {
        if c.is_ascii_uppercase() && !current.is_empty() {
            parts.push(std::mem::take(&mut current));
        }
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}
