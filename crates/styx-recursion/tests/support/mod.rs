//! A fake internet on loopback for socket-level recursion tests.
//!
//! Each fake nameserver listens on its own loopback address (127.0.0.N) and every
//! one shares a single port, because a referral carries only an IP and the
//! recursor's transport supplies the port. Fakes encode with `hickory-proto`, never
//! with `styx-proto`, so the resolver and its oracle do not share a codec.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use styx_core::{Clock, UpstreamId};
use styx_net::Do53Client;
use styx_proto::{Name, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl};
use styx_recursion::application::recursor::{Recursor, RecursorPorts, RecursorSettings};
use styx_recursion::domain::budget::DescentLimits;
use styx_recursion::domain::chain_material::ChainMaterial;
use styx_recursion::domain::error::ConfigError;
use styx_recursion::domain::ports::ChainMaterialSink;
use styx_recursion::domain::root_hints::RootHints;
use styx_recursion::infrastructure::do53_transport::Do53Transport;
use styx_recursion::infrastructure::infra_cache::MemoryInfraCache;
use styx_recursion::infrastructure::sinks::DiagnosticsStore;
use styx_testkit::{FakeNameServer, FakeRole, HarnessError, TestClock, ZoneScript};
use tokio::net::UdpSocket;

/// The root server's loopback address in every scenario.
pub const ROOT: u8 = 2;

/// Records every chain-material push.
#[derive(Debug, Default)]
pub struct RecordingChainMaterial(pub Mutex<Vec<ChainMaterial>>);

impl ChainMaterialSink for RecordingChainMaterial {
    fn push(&self, material: ChainMaterial) {
        match self.0.lock() {
            Ok(mut guard) => guard.push(material),
            Err(poisoned) => poisoned.into_inner().push(material),
        }
    }
}

pub type TestRecursor = Recursor<
    TestClock,
    Do53Transport<TestClock>,
    DiagnosticsStore,
    RecordingChainMaterial,
    MemoryInfraCache,
>;

/// The fakes, and the recursor wired to them.
pub struct Network {
    pub port: u16,
    pub servers: Vec<(u8, FakeNameServer)>,
    pub clock: Arc<TestClock>,
    pub infra: Arc<MemoryInfraCache>,
    pub diagnostics: Arc<DiagnosticsStore>,
    pub chain_material: Arc<RecordingChainMaterial>,
}

pub fn loopback(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
}

pub fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

pub fn a(owner: &str, last: u8) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(Ipv4Addr::new(127, 0, 0, last)),
    )
}

pub fn cname(owner: &str, target: &str) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        RecordType::CNAME,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Cname(name(target)),
    )
}

/// A root script that answers priming with itself as the only root server.
pub fn root_script() -> ZoneScript {
    let ns = ResourceRecord::new(
        Name::root(),
        RecordType::NS,
        RecordClass::In,
        Ttl::from_secs(518_400),
        RData::Ns(name("ns.root.")),
    );
    ZoneScript::new()
        .answer(".", RecordType::NS, vec![ns])
        .extra_glue("ns.root.", Ipv4Addr::new(127, 0, 0, ROOT))
}

impl Network {
    /// Picks a port free on 127.0.0.1; the other loopback addresses are unused by
    /// anything else, so the same port is free on them too.
    pub async fn new() -> std::io::Result<Self> {
        let probe = UdpSocket::bind("127.0.0.1:0").await?;
        let port = probe.local_addr()?.port();
        drop(probe);
        Ok(Self {
            port,
            servers: Vec::new(),
            clock: Arc::new(TestClock::new()),
            infra: Arc::new(MemoryInfraCache::default()),
            diagnostics: Arc::new(DiagnosticsStore::new()),
            chain_material: Arc::new(RecordingChainMaterial::default()),
        })
    }

    /// Starts a fake on 127.0.0.`last`.
    pub async fn serve(&mut self, last: u8, script: ZoneScript) -> Result<(), HarnessError> {
        let address = SocketAddr::new(loopback(last), self.port);
        let server = FakeNameServer::start_on(address, FakeRole::Authoritative, script).await?;
        self.servers.push((last, server));
        Ok(())
    }

    /// The fake on 127.0.0.`last`.
    pub fn server(&self, last: u8) -> Option<&FakeNameServer> {
        self.servers
            .iter()
            .find(|(address, _)| *address == last)
            .map(|(_, server)| server)
    }

    /// The questions 127.0.0.`last` received, as `"name TYPE"` strings, excluding
    /// priming queries for the root NS set.
    pub fn asked(&self, last: u8) -> Vec<String> {
        self.server(last)
            .map(FakeNameServer::received_queries)
            .unwrap_or_default()
            .into_iter()
            .filter(|question| !(question.qname.is_root() && question.qtype == RecordType::NS))
            .map(|question| format!("{} {}", question.qname, question.qtype))
            .collect()
    }

    /// A recursor whose root hints name the fake root at 127.0.0.2.
    pub fn recursor(&self, limits: DescentLimits) -> Result<TestRecursor, ConfigError> {
        let hints = RootHints::parse(&format!(
            ". 518400 NS ns.root.\nns.root. 518400 A 127.0.0.{ROOT}\n"
        ))?;
        let client = Do53Client::new(
            Duration::from_millis(300),
            Duration::from_millis(600),
            Arc::clone(&self.clock),
        );
        Ok(Recursor::new(
            UpstreamId::new("recursor"),
            RecursorSettings {
                limits,
                use_ipv6: false,
            },
            &hints,
            RecursorPorts {
                clock: Arc::clone(&self.clock),
                transport: Arc::new(Do53Transport::new(client, self.port)),
                diagnostics: Arc::clone(&self.diagnostics),
                chain_material: Arc::clone(&self.chain_material),
                infra: Arc::clone(&self.infra),
            },
        ))
    }

    /// A deadline comfortably far away on the test clock.
    pub fn deadline(&self) -> Instant {
        let now = self.clock.now_monotonic();
        now.checked_add(Duration::from_secs(30)).unwrap_or(now)
    }
}

pub fn question(qname: &str, qtype: RecordType) -> Question {
    Question::new(name(qname), qtype, RecordClass::In)
}

/// The owners of the answer section, as strings.
pub fn owners(records: &[ResourceRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| record.owner.to_string())
        .collect()
}
