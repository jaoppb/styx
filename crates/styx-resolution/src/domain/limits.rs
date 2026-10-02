//! Concurrency limits bounding the listeners' admitted work.

use std::num::NonZeroUsize;
use std::time::Duration;

/// Default process-wide ceiling on concurrently processed queries.
///
/// Absorbs roughly five seconds of a few hundred queries per second against a dead
/// upstream — longer than the query deadline — before backpressure engages.
pub const DEFAULT_MAX_IN_FLIGHT_QUERIES: NonZeroUsize = NonZeroUsize::MIN.saturating_add(1023);

/// Default process-wide ceiling on open TCP connections.
///
/// Far below any file-descriptor limit, so the cap trips before `EMFILE` does.
pub const DEFAULT_MAX_TCP_CONNECTIONS: NonZeroUsize = NonZeroUsize::MIN.saturating_add(255);

/// Outstanding queries one TCP connection may hold before its reader stops reading.
pub const MAX_IN_FLIGHT_PER_CONNECTION: NonZeroUsize = NonZeroUsize::MIN.saturating_add(31);

/// Time one framed TCP response may take to write before the connection is closed.
pub const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Validated caps on concurrent listener work.
///
/// Every cap is non-zero by construction: a zero cap is a server that answers nothing,
/// and is rejected when configuration is parsed rather than discovered at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcurrencyLimits {
    max_in_flight_queries: NonZeroUsize,
    max_tcp_connections: NonZeroUsize,
    max_in_flight_per_connection: NonZeroUsize,
    udp_sockets_per_addr: NonZeroUsize,
    tcp_write_timeout: Duration,
}

impl ConcurrencyLimits {
    /// Creates limits from already-validated values.
    #[must_use]
    pub const fn new(
        max_in_flight_queries: NonZeroUsize,
        max_tcp_connections: NonZeroUsize,
        max_in_flight_per_connection: NonZeroUsize,
        udp_sockets_per_addr: NonZeroUsize,
        tcp_write_timeout: Duration,
    ) -> Self {
        Self {
            max_in_flight_queries,
            max_tcp_connections,
            max_in_flight_per_connection,
            udp_sockets_per_addr,
            tcp_write_timeout,
        }
    }

    /// Returns the default limits with a single UDP socket per address.
    ///
    /// The socket count is host-dependent, so it is filled in by infrastructure through
    /// [`Self::with_udp_sockets_per_addr`]; a single socket is the safe default.
    #[must_use]
    pub const fn default_limits() -> Self {
        Self::new(
            DEFAULT_MAX_IN_FLIGHT_QUERIES,
            DEFAULT_MAX_TCP_CONNECTIONS,
            MAX_IN_FLIGHT_PER_CONNECTION,
            NonZeroUsize::MIN,
            TCP_WRITE_TIMEOUT,
        )
    }

    /// Returns these limits with a different UDP socket count per address.
    #[must_use]
    pub const fn with_udp_sockets_per_addr(self, udp_sockets_per_addr: NonZeroUsize) -> Self {
        Self {
            udp_sockets_per_addr,
            ..self
        }
    }

    /// Process-wide ceiling on concurrently processed queries.
    #[must_use]
    pub const fn max_in_flight_queries(&self) -> NonZeroUsize {
        self.max_in_flight_queries
    }

    /// Process-wide ceiling on open TCP connections.
    #[must_use]
    pub const fn max_tcp_connections(&self) -> NonZeroUsize {
        self.max_tcp_connections
    }

    /// Outstanding queries allowed on one TCP connection.
    #[must_use]
    pub const fn max_in_flight_per_connection(&self) -> NonZeroUsize {
        self.max_in_flight_per_connection
    }

    /// UDP sockets bound per listen address.
    #[must_use]
    pub const fn udp_sockets_per_addr(&self) -> NonZeroUsize {
        self.udp_sockets_per_addr
    }

    /// Time allowed for writing one framed TCP response.
    #[must_use]
    pub const fn tcp_write_timeout(&self) -> Duration {
        self.tcp_write_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_values() {
        let limits = ConcurrencyLimits::default_limits();
        assert_eq!(limits.max_in_flight_queries().get(), 1024);
        assert_eq!(limits.max_tcp_connections().get(), 256);
        assert_eq!(limits.max_in_flight_per_connection().get(), 32);
        assert_eq!(limits.udp_sockets_per_addr().get(), 1);
        assert_eq!(limits.tcp_write_timeout(), Duration::from_secs(5));
    }

    #[test]
    fn socket_count_override_keeps_every_other_limit() {
        let four = NonZeroUsize::new(4).unwrap();
        let limits = ConcurrencyLimits::default_limits().with_udp_sockets_per_addr(four);
        assert_eq!(limits.udp_sockets_per_addr(), four);
        assert_eq!(limits.max_in_flight_queries().get(), 1024);
    }
}
