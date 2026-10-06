//! Ports: the traits this crate's domain declares and others implement.
//!
//! The descent state machine stays I/O-free because the socket, the
//! infrastructure cache and the two publication paths all live behind these.

use std::future::Future;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use styx_proto::{Message, Name, Question};

use crate::domain::chain_material::ChainMaterial;
use crate::domain::diagnostics::RecursionDiagnostics;
use crate::domain::metrics::{EdnsCapability, MetricEvent, NameserverMetrics};
use crate::domain::root_hints::RootHints;
use crate::domain::topology::{Delegation, NameserverAddr, ZoneCut};

/// What the transport learned about a server's EDNS support on one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdnsObservation {
    /// The server answered with an OPT record advertising this payload size.
    Supported(u16),
    /// The server rejected the EDNS query; the answer came from a plain retry.
    Intolerant,
    /// No conclusion: the query carried no EDNS, or the reply carried no OPT.
    Inconclusive,
}

/// A response from one nameserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportReply {
    /// The decoded response, matched to the question sent.
    pub message: Message,
    /// Whether it came over TCP after a truncated UDP response.
    pub via_tcp: bool,
    /// What the exchange showed about the server's EDNS support.
    pub edns: EdnsObservation,
    /// Packets-worth of exchanges the query cost: one per UDP or TCP attempt, so a
    /// truncated reply or an EDNS retry makes it more than one.
    pub wire_exchanges: u8,
}

/// Why no usable response came back from a nameserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// No matching response before the deadline.
    Timeout,
    /// The send or receive failed at the socket.
    Unreachable(ErrorKind),
    /// The response did not decode, or did not match the question.
    Malformed,
    /// The response stayed truncated over TCP.
    Truncated,
}

/// A failed query and what it cost on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportFailure {
    /// Why no usable response came back.
    pub error: TransportError,
    /// Exchanges spent before giving up. A failure whose TCP leg is not visible to
    /// the transport counts as one more than it can prove, never fewer than one.
    pub wire_exchanges: u8,
}

/// Sends one question to one nameserver. Implemented by the Do53 adapter, and by
/// recording fakes in tests.
pub trait Transport: Send + Sync {
    /// Sends `question` to `server` with DO=1 and EDNS shaped by `edns`.
    fn query(
        &self,
        server: NameserverAddr,
        question: &Question,
        edns: EdnsCapability,
        deadline: Instant,
    ) -> impl Future<Output = Result<TransportReply, TransportFailure>> + Send;
}

/// The infrastructure cache: delegations by zone, metrics by nameserver address.
///
/// Private to this crate and structurally separate from the global answer cache:
/// it stores no answers, and the answer cache stores no topology. Every method is
/// synchronous and in memory, so no caller can hold one of its locks across an
/// `.await`.
pub trait InfraCache: Send + Sync {
    /// The unexpired delegation for exactly `zone`.
    fn get_delegation(&self, zone: &Name, now: Instant) -> Option<Delegation>;

    /// Stores a delegation. A delegation of the root replaces the root NS set.
    fn put_delegation(&self, delegation: Delegation);

    /// The deepest unexpired cut at or above `name`, falling back to the root.
    fn closest_enclosing_cut(&self, name: &Name, now: Instant) -> ZoneCut;

    /// What is known about `server`, as of `now`.
    fn metrics(&self, server: NameserverAddr, now: Instant) -> NameserverMetrics;

    /// Folds one observation about `server` into its metrics.
    fn update_metrics(&self, server: NameserverAddr, event: MetricEvent, now: Instant);

    /// Records addresses looked up separately for `nameserver` in the cached
    /// delegation of `zone`, so later descents skip the lookup. The delegation's
    /// own expiry still bounds them, and `lifetime` can only shorten it.
    fn provide_addresses(
        &self,
        zone: &Name,
        nameserver: &Name,
        addresses: &[IpAddr],
        lifetime: Duration,
        now: Instant,
    );

    /// Seeds the root NS set from root hints, unless a primed set is already held.
    fn prime_from(&self, hints: &RootHints, now: Instant);

    /// Drops every delegation and metric past its expiry.
    fn evict_expired(&self, now: Instant);
}

/// Where root/TLD reachability snapshots are published for the admin/web layer.
/// Never routed through the pool.
pub trait DiagnosticsSink: Send + Sync {
    /// Replaces the published snapshot wholesale.
    fn publish(&self, snapshot: RecursionDiagnostics);
}

/// The push half of the DNSSEC validator's chain source. A no-op until the
/// validator exists; the port exists now so that phase does not reshape the
/// descent.
pub trait ChainMaterialSink: Send + Sync {
    /// Hands over the DS material one descent collected.
    fn push(&self, material: ChainMaterial);
}
