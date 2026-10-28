//! A server with DoT and DoH bound on port 0 next to UDP and TCP, and real TLS clients
//! for it. No in-memory transport stands in: the handshake, ALPN, framing and HTTP/2
//! behaviour are what the encrypted tests exist to exercise.

#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, RootCertStore};
use styx_resolution::domain::tls::{
    DohResourcePath, EncryptedLimits, OperatorCertificateLoader, TlsConfig, TlsConfigParts,
};
use styx_resolution::infrastructure::cert_fs::FilesystemCertificateReader;
use styx_resolution::{
    AllowAllFilter, ConcurrencyLimits, DiscardObserver, EncryptedListeners, MaxResponseSize,
    NoLocalRecords, Pipeline, Server, ServerConfig, SupervisorBackoffPolicy, TerminalHandler,
    TlsServerSetup,
};
use styx_testkit::{TestClock, TestSleeper};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::certificates::{fixture_now, Scratch, TestCertificate};

/// The client's clock: the fixtures' "now", so certificate validity never depends on the
/// date the suite happens to run.
#[derive(Debug)]
struct FixtureTime;

impl TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(
            fixture_now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .ok()?,
        ))
    }
}

/// Which encrypted listeners to bind, and with what bounds.
#[derive(Debug, Clone, Copy)]
pub struct EncryptedOptions {
    pub limits: EncryptedLimits,
    pub dot: bool,
    pub doh: bool,
    pub allow_http1: bool,
}

impl Default for EncryptedOptions {
    fn default() -> Self {
        Self {
            limits: EncryptedLimits::default(),
            dot: true,
            doh: true,
            allow_http1: false,
        }
    }
}

type Booted<T> = Server<NoLocalRecords, AllowAllFilter, DiscardObserver, TestClock, T>;

/// A booted server and the certificate it serves.
pub struct EncryptedTestServer<T> {
    pub server: Booted<T>,
    pub udp_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    pub dot_addr: Option<SocketAddr>,
    pub doh_addr: Option<SocketAddr>,
    pub certificate: TestCertificate,
    pub scratch: Scratch,
}

impl<T: TerminalHandler + Send + Sync + 'static> EncryptedTestServer<T> {
    /// Boots with `terminal` answering every query, serving an operator certificate read
    /// through the production loader.
    pub async fn boot(terminal: Arc<T>, options: EncryptedOptions) -> Self {
        let certificate = TestCertificate::valid();
        let scratch = Scratch::new();
        let (cert_path, key_path) = scratch
            .write_pair(&certificate.cert_pem, &certificate.key_pem)
            .await;
        let identity = FilesystemCertificateReader::new()
            .load(&cert_path, &key_path)
            .await
            .unwrap();
        let config = tls_config(options, cert_path, key_path);
        let setup = TlsServerSetup::build(&identity, options.allow_http1).unwrap();

        let clock = Arc::new(TestClock::new());
        let pipeline = Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            Arc::clone(&clock),
        )
        .with_terminal(terminal);
        let server = Server::bind_with_encrypted(
            server_config(),
            Some(EncryptedListeners::new(config, setup)),
            Arc::new(pipeline),
            Arc::clone(&clock),
            Arc::new(TestSleeper::new(clock)),
        )
        .await
        .unwrap();
        let addrs = server.local_addrs();
        Self {
            udp_addr: addrs.first().copied().unwrap(),
            tcp_addr: addrs.get(1).copied().unwrap(),
            dot_addr: server.dot_addrs().first().copied(),
            doh_addr: None,
            server,
            certificate,
            scratch,
        }
    }

    pub fn dot(&self) -> SocketAddr {
        self.dot_addr.unwrap()
    }

    pub fn doh(&self) -> SocketAddr {
        self.doh_addr.unwrap()
    }

    pub async fn shutdown(&mut self) {
        self.server.shutdown().await.unwrap();
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn server_config() -> ServerConfig {
    ServerConfig {
        listen_addrs: vec![loopback()],
        udp_payload_size_default: MaxResponseSize::from_edns_advertised(1232),
        tcp_idle_timeout: Duration::from_secs(5),
        query_timeout: Duration::from_secs(2),
        limits: ConcurrencyLimits::default_limits(),
        supervisor: SupervisorBackoffPolicy::default(),
        upstream: None,
    }
}

fn tls_config(options: EncryptedOptions, cert_path: PathBuf, key_path: PathBuf) -> TlsConfig {
    let addrs = |on: bool| if on { vec![loopback()] } else { Vec::new() };
    TlsConfig::new(TlsConfigParts {
        dot_listen_addrs: addrs(options.dot),
        doh_listen_addrs: addrs(options.doh),
        cert_path: Some(cert_path),
        key_path: Some(key_path),
        self_signed_dir: PathBuf::from("unused"),
        self_signed_names: vec!["localhost".into()],
        doh_path: DohResourcePath::new(DohResourcePath::DEFAULT.into()).unwrap(),
        allow_http1: options.allow_http1,
        limits: options.limits,
    })
    .unwrap()
}

/// A TLS client that trusts only `certificate` and offers `alpn`.
pub fn connector(certificate: &TestCertificate, alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.cert_der()))
        .unwrap();
    let mut config =
        ClientConfig::builder_with_details(Arc::new(default_provider()), Arc::new(FixtureTime))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

/// Opens a TLS connection to `addr` for `localhost`.
pub async fn tls_connect(
    addr: SocketAddr,
    certificate: &TestCertificate,
    alpn: &[&[u8]],
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    connector(certificate, alpn)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
}

/// Writes one length-prefixed message.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(stream: &mut W, body: &[u8]) {
    let len = u16::try_from(body.len()).unwrap().to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(body).await.unwrap();
}

/// Reads one length-prefixed message; `None` on a clean close.
pub async fn read_frame<R: AsyncReadExt + Unpin>(stream: &mut R) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut body).await.ok()?;
    Some(body)
}

/// One DoT exchange on a fresh connection offering `dot`.
pub async fn dot_exchange(
    server: SocketAddr,
    certificate: &TestCertificate,
    query: &[u8],
) -> Vec<u8> {
    let mut stream = tls_connect(server, certificate, &[b"dot"]).await.unwrap();
    write_frame(&mut stream, query).await;
    read_frame(&mut stream).await.unwrap()
}

/// Answers every A question with one address, and a `large.` question with enough TXT
/// records to overflow any UDP payload. A `signed.` question is marked authentic, so the
/// AD bit is visible to the cross-transport comparison.
pub struct AnsweringTerminal;

impl TerminalHandler for AnsweringTerminal {
    async fn handle_terminal(
        &self,
        ctx: &styx_resolution::RequestContext,
    ) -> Result<styx_resolution::ResolutionResponse, styx_resolution::PipelineError> {
        use styx_proto::domain::rdata::basic::TxtRdata;
        use styx_proto::domain::rdata::CharacterString;
        use styx_proto::{
            Message, RData, RecordClass, RecordType, ResourceRecord, ResponseCode, Ttl,
        };
        use styx_resolution::{ResolutionOutcome, ResolvedSource};

        let question = ctx
            .query
            .questions
            .first()
            .cloned()
            .ok_or(styx_resolution::PipelineError::MalformedQuery)?;
        let name = question.qname.to_string();
        let mut response = Message::response_to(ctx.query.header.id, question.clone());
        let ttl = Ttl::from_secs(300);
        if name.starts_with("large.") {
            for i in 0..300 {
                let txt = CharacterString::new(format!("large payload record {i:04}").into_bytes());
                response.answers.push(ResourceRecord::new(
                    question.qname.clone(),
                    RecordType::TXT,
                    RecordClass::In,
                    ttl,
                    RData::Txt(TxtRdata::new(vec![txt])),
                ));
            }
        } else {
            response.answers.push(ResourceRecord::new(
                question.qname.clone(),
                RecordType::A,
                RecordClass::In,
                ttl,
                RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            ));
        }
        response.header.authentic_data = name.starts_with("signed.");
        let outcome = ResolutionOutcome::Resolved {
            source: ResolvedSource::Upstream,
            rcode: ResponseCode::NOERROR,
            cacheable: false,
            authentic_data: name.starts_with("signed."),
        };
        Ok(styx_resolution::ResolutionResponse::new(response, outcome))
    }
}
