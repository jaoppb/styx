//! Request context, client identity, transport, and response size bounding.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use styx_proto::Message;

use crate::domain::answer::ResolutionOutcome;

/// Identity of a DNS client making a query.
///
/// In Phase 2, this is derived strictly from the socket peer IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId {
    /// IP address of the query source.
    pub addr: IpAddr,
}

impl ClientId {
    /// Creates a new `ClientId` from a peer socket address.
    #[must_use]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self { addr: addr.ip() }
    }

    /// Creates a new `ClientId` from an IP address.
    #[must_use]
    pub fn from_ip(addr: IpAddr) -> Self {
        Self { addr }
    }
}

/// Underlying transport layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// User Datagram Protocol (UDP). Subject to truncation limits.
    Udp,
    /// Transmission Control Protocol (TCP). Framed stream.
    Tcp,
}

/// Bounded response size ceiling for wire transmission.
///
/// Wraps a `u16` byte limit and centralizes size arithmetic to prevent
/// bare comparison scattering and unchecked arithmetic across listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MaxResponseSize {
    bytes: u16,
}

impl MaxResponseSize {
    /// Classic RFC 1035 pre-EDNS UDP payload size limit (512 octets).
    pub const CLASSIC_LIMIT: u16 = 512;

    /// Creates a `MaxResponseSize` configured with the classic 512-byte limit.
    #[must_use]
    pub const fn classic() -> Self {
        Self {
            bytes: Self::CLASSIC_LIMIT,
        }
    }

    /// Creates a `MaxResponseSize` from an EDNS(0) advertised UDP payload size.
    ///
    /// Accepts the advertised value verbatim, including values below 512.
    #[must_use]
    pub const fn from_edns_advertised(advertised: u16) -> Self {
        Self { bytes: advertised }
    }

    /// Creates a `MaxResponseSize` representing the maximum 16-bit TCP frame payload (`u16::MAX`).
    #[must_use]
    pub const fn tcp_ceiling() -> Self {
        Self { bytes: u16::MAX }
    }

    /// Returns the raw size limit in bytes.
    #[must_use]
    pub const fn as_u16(&self) -> u16 {
        self.bytes
    }

    /// Checks if a buffer length in bytes fits within this response size ceiling.
    #[must_use]
    pub fn fits(&self, len: usize) -> bool {
        let limit = usize::from(self.bytes);
        len <= limit
    }
}

/// Encapsulates the entire context of an inbound DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// Decoded DNS query message.
    pub query: Message,
    /// Identifier of the requesting client.
    pub client: ClientId,
    /// Transport protocol on which the query was received.
    pub transport: Transport,
    /// Monotonic timestamp when the query was received.
    pub received_at: Instant,
    /// Computed response size ceiling for truncation decisions.
    pub max_response_size: MaxResponseSize,
    /// Whether an EDNS(0) OPT pseudo-record was present in the query.
    pub edns_present: bool,
    /// Final resolution outcome audit record, populated on response path.
    pub outcome: Option<ResolutionOutcome>,
}

impl RequestContext {
    /// Creates a new `RequestContext`.
    #[must_use]
    pub fn new(
        query: Message,
        client: ClientId,
        transport: Transport,
        max_response_size: MaxResponseSize,
    ) -> Self {
        let edns_present = query.opt.is_some();
        Self {
            query,
            client,
            transport,
            received_at: Instant::now(),
            max_response_size,
            edns_present,
            outcome: None,
        }
    }

    /// Sets the received monotonic instant.
    #[must_use]
    pub fn with_received_at(mut self, instant: Instant) -> Self {
        self.received_at = instant;
        self
    }

    /// Automatically derives the appropriate `MaxResponseSize` for the given transport and query.
    #[must_use]
    pub fn derive_max_response_size(transport: Transport, query: &Message) -> MaxResponseSize {
        match transport {
            Transport::Tcp => MaxResponseSize::tcp_ceiling(),
            Transport::Udp => {
                if let Some(opt) = &query.opt {
                    MaxResponseSize::from_edns_advertised(opt.udp_payload_size())
                } else {
                    MaxResponseSize::classic()
                }
            }
        }
    }
}
