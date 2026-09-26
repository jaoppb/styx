//! Ephemeral server test fixture.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use styx_resolution::{
    AllowAllFilter, DiscardObserver, FilterPolicy, LocalRecords, MaxResponseSize, NoLocalRecords,
    Pipeline, QueryObserver, Server, ServerConfig, TerminalHandler,
};

use super::clock::TestClock;
use super::error::HarnessError;

/// Test fixture booting a real server instance on ephemeral ports (port 0).
pub struct TestServer {
    server: Server,
    clock: Arc<TestClock>,
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
}

impl TestServer {
    /// Boots a `Server` on ephemeral loopback ports with default no-op ports.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding or startup fails.
    pub async fn boot_ephemeral() -> Result<Self, HarnessError> {
        Self::boot_with_collaborators(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            None,
        )
        .await
    }

    /// Boots an ephemeral server with custom hot-path collaborators.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails.
    pub async fn boot_with_collaborators(
        local_records: Arc<dyn LocalRecords>,
        filter: Arc<dyn FilterPolicy>,
        observer: Arc<dyn QueryObserver>,
        terminal: Option<Arc<dyn TerminalHandler>>,
    ) -> Result<Self, HarnessError> {
        let clock = Arc::new(TestClock::new());
        let mut pipeline = Pipeline::new(local_records, filter, observer, clock.clone());

        if let Some(term) = terminal {
            pipeline = pipeline.with_terminal(term);
        }

        let config = ServerConfig {
            listen_addrs: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
            udp_payload_size_default: MaxResponseSize::classic(),
            tcp_idle_timeout: Duration::from_secs(5),
            query_timeout: Duration::from_secs(2),
        };

        let server = Server::bind(config, Arc::new(pipeline), clock.clone()).await?;
        let addrs = server.local_addrs();
        let udp_addr = *addrs
            .first()
            .ok_or_else(|| HarnessError::Protocol("missing bound UDP address".into()))?;
        let tcp_addr = *addrs
            .get(1)
            .ok_or_else(|| HarnessError::Protocol("missing bound TCP address".into()))?;

        Ok(Self {
            server,
            clock,
            udp_addr,
            tcp_addr,
        })
    }

    /// Returns the OS-assigned bound UDP address.
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    /// Returns the OS-assigned bound TCP address.
    #[must_use]
    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    /// Returns a reference to the injected [`TestClock`].
    #[must_use]
    pub fn clock(&self) -> Arc<TestClock> {
        Arc::clone(&self.clock)
    }

    /// Gracefully shuts down the server listeners.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if listener termination fails.
    pub async fn shutdown(&mut self) -> Result<(), HarnessError> {
        self.server.shutdown().await?;
        Ok(())
    }
}
