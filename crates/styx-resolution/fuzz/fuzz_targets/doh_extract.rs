#![no_main]

//! Drives the DoH request extraction over arbitrary heads and bodies: the largest
//! attacker-reachable parser of the encrypted listeners. Any outcome but a panic is fine.

use libfuzzer_sys::fuzz_target;
use styx_resolution::infrastructure::doh::{accept_body, extract_head, DohHead, DohRequestForm};
use styx_resolution::{DohResourcePath, StreamMessageLimit};

/// Splits `data` into five NUL-separated text fields and a trailing body.
fn fields(data: &[u8]) -> Option<([&str; 5], &[u8])> {
    let mut parts = data.splitn(6, |byte| *byte == 0);
    let mut text = [""; 5];
    for slot in &mut text {
        *slot = std::str::from_utf8(parts.next()?).ok()?;
    }
    Some((text, parts.next().unwrap_or_default()))
}

fuzz_target!(|data: &[u8]| {
    let Some(([method, path, query, content_type, content_length], body)) = fields(data) else {
        return;
    };
    let Ok(resource) = DohResourcePath::new("/dns-query".into()) else {
        return;
    };
    let Ok(limit) = StreamMessageLimit::from_configured(4096) else {
        return;
    };
    let head = DohHead {
        method,
        path,
        query: (!query.is_empty()).then_some(query),
        content_type: (!content_type.is_empty()).then_some(content_type),
        content_length: (!content_length.is_empty()).then_some(content_length),
    };
    match extract_head(&head, &resource, limit) {
        Ok(DohRequestForm::GetQueryParameter(wire)) => {
            assert!(!wire.is_empty() && wire.len() <= 4096);
        }
        Ok(DohRequestForm::PostBody) => {
            let _ = accept_body(body, limit);
        }
        Err(error) => {
            let _ = error.status();
        }
    }
});
