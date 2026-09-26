//! In-process fake DNS authoritative and delegation name servers.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{
    Message as HMessage, MessageType as HMessageType, OpCode as HOpCode,
    ResponseCode as HResponseCode,
};
use hickory_proto::rr::rdata::{A as HA, NS as HNs};
use hickory_proto::rr::{
    DNSClass as HDnsClass, Name as HName, RData as HRData, Record as HRecord,
    RecordType as HRecordType,
};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use styx_proto::{Question, RecordType, ResourceRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::error::HarnessError;

/// Role played by an in-process fake DNS name server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeRole {
    /// Root DNS server (delegates TLDs via referrals).
    Root,
    /// Top-Level Domain (TLD) server (delegates zones via referrals).
    Tld,
    /// Authoritative server for a specific zone.
    Authoritative,
}

/// Scripted referral delegation directive.
#[derive(Debug, Clone)]
pub struct ScriptedReferral {
    /// Zone name being delegated.
    pub zone: String,
    /// Target nameserver FQDN.
    pub ns_target: String,
    /// Target glue IP address.
    pub glue_ip: Ipv4Addr,
}

/// Scripted answer record directive.
#[derive(Debug, Clone)]
pub struct ScriptedAnswer {
    /// Name being queried.
    pub name: String,
    /// Record type.
    pub rtype: RecordType,
    /// Records returned in the answer section.
    pub records: Vec<ResourceRecord>,
}

/// Scripted zone response configuration.
#[derive(Debug, Clone, Default)]
pub struct ZoneScript {
    /// Scripted answers for authoritative queries.
    pub answers: Vec<ScriptedAnswer>,
    /// Scripted referrals for root and TLD servers.
    pub referrals: Vec<ScriptedReferral>,
}

impl ZoneScript {
    /// Creates a new empty `ZoneScript`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an answer record to the zone script.
    #[must_use]
    pub fn answer(mut self, name: &str, rtype: RecordType, records: Vec<ResourceRecord>) -> Self {
        self.answers.push(ScriptedAnswer {
            name: name.to_string(),
            rtype,
            records,
        });
        self
    }

    /// Adds a referral delegation to the zone script.
    #[must_use]
    pub fn refer(mut self, zone: &str, ns_target: &str, glue_ip: Ipv4Addr) -> Self {
        self.referrals.push(ScriptedReferral {
            zone: zone.to_string(),
            ns_target: ns_target.to_string(),
            glue_ip,
        });
        self
    }
}

/// In-process fake DNS server encoding responses through `hickory-proto`.
pub struct FakeNameServer {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    received_queries: Arc<Mutex<Vec<Question>>>,
    cancel: CancellationToken,
}

impl FakeNameServer {
    /// Starts an in-process fake DNS server on ephemeral UDP and TCP ports.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails.
    pub async fn start(role: FakeRole, script: ZoneScript) -> Result<Self, HarnessError> {
        let cancel = CancellationToken::new();
        let received_queries = Arc::new(Mutex::new(Vec::new()));

        let udp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let udp_addr = udp_socket.local_addr()?;

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp_listener.local_addr()?;

        Self::spawn_udp_loop(
            Arc::clone(&udp_socket),
            role,
            script.clone(),
            Arc::clone(&received_queries),
            cancel.clone(),
        );

        Self::spawn_tcp_loop(
            tcp_listener,
            role,
            script,
            Arc::clone(&received_queries),
            cancel.clone(),
        );

        Ok(Self {
            udp_addr,
            tcp_addr,
            received_queries,
            cancel,
        })
    }

    /// Returns the OS-assigned UDP listening address.
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    /// Returns the OS-assigned TCP listening address.
    #[must_use]
    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    /// Returns the list of DNS questions received by this server.
    #[must_use]
    pub fn received_queries(&self) -> Vec<Question> {
        match self.received_queries.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Shuts down the fake server.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    fn spawn_udp_loop(
        socket: Arc<UdpSocket>,
        role: FakeRole,
        script: ZoneScript,
        queries: Arc<Mutex<Vec<Question>>>,
        cancel: CancellationToken,
    ) {
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    recv_res = socket.recv_from(&mut buf) => {
                        let Ok((len, peer)) = recv_res else { continue };
                        let Some(wire) = buf.get(..len) else { continue };
                        let resp_wire = Self::handle_query_bytes(wire, role, &script, &queries);
                        if let Some(bytes) = resp_wire {
                            let _ = socket.send_to(&bytes, peer).await;
                        }
                    }
                }
            }
        });
    }

    fn spawn_tcp_loop(
        listener: TcpListener,
        role: FakeRole,
        script: ZoneScript,
        queries: Arc<Mutex<Vec<Question>>>,
        cancel: CancellationToken,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    accept_res = listener.accept() => {
                        let Ok((stream, _)) = accept_res else { continue };
                        tokio::spawn(handle_tcp_connection(
                            stream,
                            role,
                            script.clone(),
                            Arc::clone(&queries),
                            cancel.clone(),
                        ));
                    }
                }
            }
        });
    }

    fn handle_query_bytes(
        bytes: &[u8],
        role: FakeRole,
        script: &ZoneScript,
        queries: &Arc<Mutex<Vec<Question>>>,
    ) -> Option<Vec<u8>> {
        let decoded = styx_proto::Message::decode(bytes).ok()?;
        let question = decoded.questions.first()?.clone();
        if let Ok(mut q) = queries.lock() {
            q.push(question.clone());
        }

        let mut hmsg = HMessage::new(decoded.header.id, HMessageType::Response, HOpCode::Query);
        hmsg.metadata.authoritative = true;
        hmsg.metadata.recursion_available = false;

        let qname_str = question.qname.to_string();
        let h_qname = HName::from_str(&qname_str).ok()?;
        let mut query = hickory_proto::op::Query::new();
        query.set_name(h_qname.clone());
        query.set_query_type(HRecordType::A);
        query.set_query_class(HDnsClass::IN);
        hmsg.add_query(query);

        match role {
            FakeRole::Root | FakeRole::Tld => {
                apply_referrals(&mut hmsg, &script.referrals);
            }
            FakeRole::Authoritative => {
                apply_answers(&mut hmsg, &script.answers, &qname_str, &h_qname);
            }
        }

        let mut out = Vec::new();
        let mut encoder = BinEncoder::new(&mut out);
        hmsg.emit(&mut encoder).ok()?;
        Some(out)
    }
}

fn apply_referrals(hmsg: &mut HMessage, referrals: &[ScriptedReferral]) {
    for r in referrals {
        let (Ok(zone_name), Ok(ns_name)) =
            (HName::from_str(&r.zone), HName::from_str(&r.ns_target))
        else {
            continue;
        };
        let ns_rec = HRecord::from_rdata(zone_name, 3600, HRData::NS(HNs(ns_name.clone())));
        hmsg.add_authority(ns_rec);
        let a_rec = HRecord::from_rdata(ns_name, 3600, HRData::A(HA(r.glue_ip)));
        hmsg.add_additional(a_rec);
    }
}

fn apply_answers(
    hmsg: &mut HMessage,
    answers: &[ScriptedAnswer],
    qname_str: &str,
    h_qname: &HName,
) {
    let mut found = false;
    for a in answers {
        let is_match = a.name == qname_str || format!("{}.", a.name) == qname_str;
        if is_match {
            found = true;
            let rec = HRecord::from_rdata(
                h_qname.clone(),
                3600,
                HRData::A(HA(Ipv4Addr::new(93, 184, 216, 34))),
            );
            hmsg.add_answer(rec);
        }
    }
    if !found {
        hmsg.metadata.response_code = HResponseCode::NXDomain;
    }
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    role: FakeRole,
    script: ZoneScript,
    queries: Arc<Mutex<Vec<Question>>>,
    cancel: CancellationToken,
) {
    let mut len_buf = [0u8; 2];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            res = stream.read_exact(&mut len_buf) => {
                if res.is_err() {
                    break;
                }
                let frame_len = usize::from(u16::from_be_bytes(len_buf));
                let mut payload = vec![0u8; frame_len];
                if stream.read_exact(&mut payload).await.is_err() {
                    break;
                }
                if let Some(resp) = FakeNameServer::handle_query_bytes(&payload, role, &script, &queries) {
                    if let Ok(framed) = styx_proto::frame_tcp(&resp) {
                        if stream.write_all(&framed).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}
