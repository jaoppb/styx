//! Getting a wire-format DNS message out of an HTTP request, or failing cleanly.
//!
//! The single largest attacker-reachable parser this phase adds, so it is pure — strings
//! and bytes in, a message or a [`DohError`] out — and fuzzed. A declared or encoded
//! length is compared against the cap before anything is allocated for it. No header that
//! could identify the client is read: client identity is the peer address only.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::domain::error::DohError;
use crate::domain::tls::{DohResourcePath, StreamMessageLimit};

/// The DNS wire-format media type (RFC 8484 §6).
pub const DNS_MESSAGE_MEDIA_TYPE: &str = "application/dns-message";

/// The parts of a request head the endpoint looks at.
#[derive(Debug, Clone, Copy)]
pub struct DohHead<'a> {
    /// The HTTP method.
    pub method: &'a str,
    /// The request path, without the query.
    pub path: &'a str,
    /// The raw query string, if any.
    pub query: Option<&'a str>,
    /// The `Content-Type` header, if any.
    pub content_type: Option<&'a str>,
    /// The `Content-Length` header, if any.
    pub content_length: Option<&'a str>,
}

/// How a request carries its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohRequestForm {
    /// `GET` with the message base64url-encoded in the `dns` parameter, already decoded.
    GetQueryParameter(Vec<u8>),
    /// `POST` with the message as the body, still to be read under the cap.
    PostBody,
}

/// Judges a request head against the configured resource and cap.
///
/// # Errors
/// Returns the [`DohError`] the request is answered with: a wrong path, a method other than
/// `GET` and `POST`, a `POST` that is not `application/dns-message` or declares more than
/// the cap, or a `GET` whose `dns` parameter is absent, not unpadded base64url, or larger
/// than the cap.
pub fn extract_head(
    head: &DohHead<'_>,
    resource: &DohResourcePath,
    limit: StreamMessageLimit,
) -> Result<DohRequestForm, DohError> {
    if !resource.matches(head.path) {
        return Err(DohError::PathNotFound);
    }
    match head.method {
        "GET" => decode_parameter(head.query, limit).map(DohRequestForm::GetQueryParameter),
        "POST" => check_post_head(head, limit).map(|()| DohRequestForm::PostBody),
        _ => Err(DohError::MethodNotAllowed),
    }
}

/// Accepts a `POST` body that was read under the cap.
///
/// # Errors
/// Returns [`DohError::EmptyBody`] for no bytes and [`DohError::BodyTooLarge`] above the
/// cap.
pub fn accept_body(body: &[u8], limit: StreamMessageLimit) -> Result<(), DohError> {
    if body.is_empty() {
        return Err(DohError::EmptyBody);
    }
    let length = u64::try_from(body.len()).map_err(|_| DohError::BodyTooLarge)?;
    if !limit.admits(length) {
        return Err(DohError::BodyTooLarge);
    }
    Ok(())
}

fn check_post_head(head: &DohHead<'_>, limit: StreamMessageLimit) -> Result<(), DohError> {
    if !head.content_type.is_some_and(is_dns_message) {
        return Err(DohError::UnsupportedMediaType);
    }
    let Some(declared) = head.content_length else {
        return Ok(());
    };
    let declared: u64 = declared
        .trim()
        .parse()
        .map_err(|_| DohError::BodyTooLarge)?;
    if declared == 0 {
        return Err(DohError::EmptyBody);
    }
    if !limit.admits(declared) {
        return Err(DohError::BodyTooLarge);
    }
    Ok(())
}

/// Compares the media type, ignoring case and any parameters.
fn is_dns_message(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case(DNS_MESSAGE_MEDIA_TYPE)
}

fn decode_parameter(query: Option<&str>, limit: StreamMessageLimit) -> Result<Vec<u8>, DohError> {
    let encoded = query
        .unwrap_or_default()
        .split('&')
        .find_map(|pair| pair.strip_prefix("dns="))
        .ok_or(DohError::MissingDnsParameter)?;
    if encoded.is_empty() {
        return Err(DohError::MissingDnsParameter);
    }
    if !encoded_fits(encoded.len(), limit) {
        return Err(DohError::BodyTooLarge);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DohError::MalformedBase64Url)?;
    accept_body(&decoded, limit)?;
    Ok(decoded)
}

/// Whether `encoded_len` base64 characters could decode to at most the cap. Checked before
/// decoding, so an enormous parameter is never decoded at all.
fn encoded_fits(encoded_len: usize, limit: StreamMessageLimit) -> bool {
    let Ok(encoded_len) = u64::try_from(encoded_len) else {
        return false;
    };
    let max_encoded = u64::from(limit.octets())
        .saturating_mul(4)
        .saturating_add(2)
        .checked_div(3)
        .unwrap_or(0);
    encoded_len <= max_encoded
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
