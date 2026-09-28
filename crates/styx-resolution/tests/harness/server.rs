//! Ephemeral server test fixture.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use styx_resolution::{
    AllowAllFilter, DiscardObserver, FilterPolicy, LocalRecords, MaxResponseSize, NoLocalRecords,
    Pipeline, QueryObserver, RefusedTerminal, Server, ServerConfig, TerminalHandler,
};

use super::clock::TestClock;
use super::error::HarnessError;

/// Test fixture booting a real server instance on ephemeral ports (port 0).
pub struct TestServer<
    L = NoLocalRecords,
    F = AllowAllFilter,
    O = DiscardObserver,
    C = TestClock,
    T = RefusedTerminal,
> {
    server: Server<L, F, O, C, T>,
    clock: Arc<TestClock>,
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
}

impl TestServer<NoLocalRecords, AllowAllFilter, DiscardObserver, TestClock, RefusedTerminal> {
    /// Boots a `Server` on ephemeral loopback ports with default no-op ports.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding or startup fails.
    pub async fn boot_ephemeral() -> Result<Self, HarnessError> {
        Self::boot_with_collaborators(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
        )
        .await
    }
}

impl<L, F, O> TestServer<L, F, O, TestClock, RefusedTerminal>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
{
    /// Boots an ephemeral server with custom hot-path collaborators and default terminal.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails.
    pub async fn boot_with_collaborators(
        local_records: Arc<L>,
        filter: Arc<F>,
        observer: Arc<O>,
    ) -> Result<Self, HarnessError> {
        let clock = Arc::new(TestClock::new());
        let pipeline = Pipeline::new(local_records, filter, observer, clock.clone());

        Self::boot_from_pipeline(pipeline, clock).await
    }

    /// Boots an ephemeral server with custom hot-path collaborators and a custom terminal.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails.
    pub async fn boot_with_terminal<T: TerminalHandler + Send + Sync + 'static>(
        local_records: Arc<L>,
        filter: Arc<F>,
        observer: Arc<O>,
        terminal: Arc<T>,
    ) -> Result<TestServer<L, F, O, TestClock, T>, HarnessError> {
        Self::boot_with_terminal_and_clock(
            local_records,
            filter,
            observer,
            terminal,
            Arc::new(TestClock::new()),
        )
        .await
    }

    /// Boots an ephemeral server with custom collaborators, a custom terminal, and a shared clock.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails.
    pub async fn boot_with_terminal_and_clock<T: TerminalHandler + Send + Sync + 'static>(
        local_records: Arc<L>,
        filter: Arc<F>,
        observer: Arc<O>,
        terminal: Arc<T>,
        clock: Arc<TestClock>,
    ) -> Result<TestServer<L, F, O, TestClock, T>, HarnessError> {
        let pipeline =
            Pipeline::new(local_records, filter, observer, clock.clone()).with_terminal(terminal);

        TestServer::boot_from_pipeline(pipeline, clock).await
    }
}

impl<L, F, O, T> TestServer<L, F, O, TestClock, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    async fn boot_from_pipeline(
        pipeline: Pipeline<L, F, O, TestClock, T>,
        clock: Arc<TestClock>,
    ) -> Result<Self, HarnessError> {
        let config = ServerConfig {
            listen_addrs: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
            udp_payload_size_default: MaxResponseSize::classic(),
            tcp_idle_timeout: Duration::from_secs(5),
            query_timeout: Duration::from_secs(2),
        };

        let server = Server::bind(config, Arc::new(pipeline), Arc::clone(&clock)).await?;
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
}

impl<L, F, O, C, T> TestServer<L, F, O, C, T> {
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
