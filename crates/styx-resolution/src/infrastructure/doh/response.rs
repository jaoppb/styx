//! The HTTP side of a DoH answer: a wire-format message with its freshness, or an empty
//! error status.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{HeaderValue, ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Response, StatusCode};
use styx_proto::Ttl;

use crate::domain::error::DohError;
use crate::infrastructure::doh::request::DNS_MESSAGE_MEDIA_TYPE;

/// What a DoH stream is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohResponse {
    /// A DNS message, always 200: RFC 8484 §4.2.1 carries the DNS outcome in the message.
    Answer {
        /// The encoded message.
        wire: Vec<u8>,
        /// `Cache-Control: max-age`, the smallest TTL the message carries.
        max_age: Option<Ttl>,
    },
    /// An HTTP error with no DNS body.
    Error(DohError),
}

impl DohResponse {
    /// Wraps an encoded answer with `max_age` (RFC 8484 §5.1): the smallest TTL in the
    /// answer section, or in the authority section for a negative answer.
    #[must_use]
    pub fn answer(wire: Vec<u8>, max_age: Option<Ttl>) -> Self {
        Self::Answer { wire, max_age }
    }

    /// Builds the HTTP response.
    #[must_use]
    pub fn into_http(self) -> Response<Full<Bytes>> {
        match self {
            Self::Answer { wire, max_age } => answer_response(wire, max_age),
            Self::Error(error) => error_response(&error),
        }
    }
}

fn answer_response(wire: Vec<u8>, max_age: Option<Ttl>) -> Response<Full<Bytes>> {
    let length = HeaderValue::from(wire.len());
    let mut response = Response::new(Full::new(Bytes::from(wire)));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(DNS_MESSAGE_MEDIA_TYPE),
    );
    headers.insert(CONTENT_LENGTH, length);
    if let Some(ttl) = max_age {
        let seconds = ttl.seconds();
        if let Ok(value) = HeaderValue::from_str(&format!("max-age={seconds}")) {
            headers.insert(CACHE_CONTROL, value);
        }
    }
    response
}

fn error_response(error: &DohError) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status(error);
    let headers = response.headers_mut();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    if *error == DohError::MethodNotAllowed {
        // RFC 9110 §15.5.6: a 405 names the methods the resource does accept.
        headers.insert(ALLOW, HeaderValue::from_static("GET, POST"));
    }
    response
}

/// The HTTP status an error is answered with. A total match: a new variant does not
/// compile until its status is chosen.
const fn status(error: &DohError) -> StatusCode {
    match error {
        DohError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        DohError::PathNotFound => StatusCode::NOT_FOUND,
        DohError::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        DohError::MissingDnsParameter
        | DohError::MalformedBase64Url
        | DohError::EmptyBody
        | DohError::MalformedBody
        | DohError::Unanswerable => StatusCode::BAD_REQUEST,
        DohError::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        DohError::BodyReadTimeout => StatusCode::REQUEST_TIMEOUT,
        DohError::StreamBudgetExceeded | DohError::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_maps_to_its_documented_status() {
        let statuses = [
            (DohError::MethodNotAllowed, 405),
            (DohError::PathNotFound, 404),
            (DohError::UnsupportedMediaType, 415),
            (DohError::MissingDnsParameter, 400),
            (DohError::MalformedBase64Url, 400),
            (DohError::BodyTooLarge, 413),
            (DohError::BodyReadTimeout, 408),
            (DohError::EmptyBody, 400),
            (DohError::MalformedBody, 400),
            (DohError::Unanswerable, 400),
            (DohError::StreamBudgetExceeded, 503),
            (DohError::ShuttingDown, 503),
        ];
        for (error, expected) in statuses {
            let response = DohResponse::Error(error.clone()).into_http();
            assert_eq!(response.status().as_u16(), expected, "{error}");
        }
    }

    #[test]
    fn only_a_405_names_the_allowed_methods() {
        let refused = DohResponse::Error(DohError::MethodNotAllowed).into_http();
        assert_eq!(refused.headers()[ALLOW], "GET, POST");

        let not_found = DohResponse::Error(DohError::PathNotFound).into_http();
        assert!(!not_found.headers().contains_key(ALLOW));
    }

    #[test]
    fn answer_writes_cache_control_from_ttl_and_omits_when_absent() {
        let with_ttl = DohResponse::answer(vec![1, 2], Some(Ttl::from_secs(300))).into_http();
        assert_eq!(with_ttl.headers()[CACHE_CONTROL], "max-age=300");

        let without_ttl = DohResponse::answer(vec![1, 2], None).into_http();
        assert!(!without_ttl.headers().contains_key(CACHE_CONTROL));
    }
}
