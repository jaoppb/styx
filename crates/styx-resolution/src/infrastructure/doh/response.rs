//! The HTTP side of a DoH answer: a wire-format message with its freshness, or an empty
//! error status.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{HeaderValue, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Response, StatusCode};
use styx_proto::application::Decoder;

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
        max_age: Option<u32>,
    },
    /// An HTTP error with no DNS body.
    Error(DohError),
}

impl DohResponse {
    /// Wraps an encoded answer, taking its freshness from the message itself (RFC 8484
    /// §5.1): the smallest TTL in the answer section, or in the authority section for a
    /// negative answer. A forged answer therefore lives only as long as its own short TTL.
    #[must_use]
    pub fn answer(wire: Vec<u8>) -> Self {
        let max_age = min_ttl(&wire);
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

fn min_ttl(wire: &[u8]) -> Option<u32> {
    let message = Decoder::new(wire).decode_message().ok()?;
    let section = if message.answers.is_empty() {
        &message.authorities
    } else {
        &message.answers
    };
    section.iter().map(|record| record.ttl.seconds()).min()
}

fn answer_response(wire: Vec<u8>, max_age: Option<u32>) -> Response<Full<Bytes>> {
    let length = HeaderValue::from(wire.len());
    let mut response = Response::new(Full::new(Bytes::from(wire)));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(DNS_MESSAGE_MEDIA_TYPE),
    );
    headers.insert(CONTENT_LENGTH, length);
    if let Some(seconds) = max_age {
        if let Ok(value) = HeaderValue::from_str(&format!("max-age={seconds}")) {
            headers.insert(CACHE_CONTROL, value);
        }
    }
    response
}

fn error_response(error: &DohError) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() =
        StatusCode::from_u16(error.status()).unwrap_or(StatusCode::BAD_REQUEST);
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}
