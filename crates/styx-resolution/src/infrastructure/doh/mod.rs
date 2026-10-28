//! DNS over HTTPS (RFC 8484) over HTTP/2: one resource, a wire-format DNS message in and
//! out, served by the same query path as every other transport.
//!
//! The endpoint is a DNS listener, not part of the admin UI: it owns its own HTTP serving,
//! builds without the `web` feature, and never shares a port or TLS configuration with
//! the UI.

mod connection;
pub mod listener;
pub mod request;
pub mod response;

pub use listener::DohListener;
pub use request::{accept_body, extract_head, DohHead, DohRequestForm, DNS_MESSAGE_MEDIA_TYPE};
pub use response::DohResponse;
