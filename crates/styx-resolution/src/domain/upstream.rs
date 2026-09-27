//! Upstream resolution port and core domain types.
//!
//! Provides the single resolution contract satisfied by forwarders, recursors,
//! and test doubles.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_proto::{Message, Question};

use crate::domain::error::UpstreamError;

/// Opaque, cheap-to-clone identifier for an upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UpstreamId(Arc<str>);

impl UpstreamId {
    /// Creates a new `UpstreamId` from a string or string slice.
    #[must_use]
    pub fn new(id: impl Into<Arc<str>>) -> Self {
        Self(id.into())
    }

    /// Returns the string representation of this ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UpstreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for UpstreamId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The architectural kind of upstream provider.
///
/// Used for per-kind config defaults (e.g. canaries) and provenance
/// attribution on [`UpstreamResponse`]. Never used for dispatch routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamKind {
    /// Classic recursive/forwarding DNS resolver (Do53, DoT, DoH).
    Forwarder,
    /// Full iterative root-descending recursor.
    Recursor,
}

impl fmt::Display for UpstreamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forwarder => f.write_str("forwarder"),
            Self::Recursor => f.write_str("recursor"),
        }
    }
}

/// The unified outcome of an upstream query resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamResponse {
    /// Decoded DNS response datagram.
    pub message: Message,
    /// Identifier of the specific upstream member that produced this answer.
    pub answered_by: UpstreamId,
    /// The architectural kind of upstream provider that answered.
    pub kind: UpstreamKind,
    /// Total wall-clock resolution duration.
    pub elapsed: Duration,
    /// Whether the response was obtained over TCP (e.g. after UDP TC=1 fallback).
    pub via_tcp: bool,
    /// Number of concurrent candidates raced if `Race` strategy was used.
    pub raced_count: u8,
}

/// Unified resolution port implemented by all forwarders and recursors.
///
/// # Invariants
/// - Exactly three methods: identity, kind, and resolution.
/// - No recursion-specific diagnostics, descent hooks, or chain-material channels.
/// - `deadline` is an absolute [`Instant`] provided by the caller's clock.
pub trait Upstream: Send + Sync {
    /// Returns the unique, process-stable identifier for this upstream.
    fn id(&self) -> UpstreamId;

    /// Returns the architectural kind of this upstream.
    fn kind(&self) -> UpstreamKind;

    /// Resolves the given query against the upstream before the specified deadline.
    ///
    /// # Errors
    /// Returns [`UpstreamError`] if resolution fails, times out, or produces
    /// a protocol-level fault.
    fn resolve(
        &self,
        query: &Question,
        deadline: Instant,
    ) -> impl Future<Output = Result<UpstreamResponse, UpstreamError>> + Send;
}

impl<T: Upstream + ?Sized> Upstream for Arc<T> {
    fn id(&self) -> UpstreamId {
        (**self).id()
    }

    fn kind(&self) -> UpstreamKind {
        (**self).kind()
    }

    fn resolve(
        &self,
        query: &Question,
        deadline: Instant,
    ) -> impl Future<Output = Result<UpstreamResponse, UpstreamError>> + Send {
        (**self).resolve(query, deadline)
    }
}
