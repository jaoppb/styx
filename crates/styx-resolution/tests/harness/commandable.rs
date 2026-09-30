//! Commandable in-process upstream server for socket-level tests.
//!
//! Encodes DNS responses via `hickory-proto` to avoid circular bug-sharing with
//! `styx-proto`, tracks query counts, and supports dynamic behavior scripting
//! (delay, timeout, truncation, SERVFAIL/REFUSED, ID mismatch, drop).

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hickory_proto::op::{
    Message as HMessage, MessageType as HMessageType, OpCode as HOpCode,
    ResponseCode as HResponseCode,
};
use hickory_proto::rr::rdata::{A as HA, SOA as HSoa};
use hickory_proto::rr::{
    DNSClass as HDnsClass, Name as HName, RData as HRData, Record as HRecord,
    RecordType as HRecordType,
};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::error::HarnessError;

/// Scripted response behavior for a [`CommandableUpstream`].
#[derive(Debug, Clone)]
pub enum UpstreamBehavior {
    /// Responds normally with an A record.
    Normal,
    /// Delays by the given duration before answering normally.
    Delay(Duration),
    /// Never responds (induces client timeout).
    Timeout,
    /// Sets TC=1 on UDP to force TCP fallback, then answers normally on TCP.
    TruncateUdp,
    /// Sets TC=1 on TCP to simulate truncation persisting across TCP fallback.
    TruncateTcp,
    /// Responds with RCODE=SERVFAIL.
    Servfail,
    /// Responds with RCODE=REFUSED.
    Refused,
    /// Responds with a mismatched transaction ID.
    MismatchedId,
    /// Responds with a mismatched question name.
    MismatchedQuestion,
    /// Sends a stray mismatched ID datagram followed by a normal response.
    MismatchedIdThenNormal,
    /// Sends a stray mismatched question datagram followed by a normal response.
    MismatchedQuestionThenNormal,
    /// Silently drops all queries.
    DropAll,
    /// Responds with NXDOMAIN and an SOA record in Authority.
    NxdomainWithSoa {
        /// Zone name for SOA owner.
        zone: String,
        /// TTL on SOA record.
        ttl: u32,
        /// Minimum TTL in SOA rdata.
        minimum: u32,
    },
    /// Responds with NOERROR, 0 answers, and an SOA record in Authority.
    NodataWithSoa {
        /// Zone name for SOA owner.
        zone: String,
        /// TTL on SOA record.
        ttl: u32,
        /// Minimum TTL in SOA rdata.
        minimum: u32,
    },
    /// Responds with NXDOMAIN and NO SOA record.
    NxdomainWithoutSoa,
    /// Responds with Answer for queried name plus poisoned record in Additional.
    PoisonedAdditional {
        /// A record IP for queried name.
        answer_ip: Ipv4Addr,
        /// Out of bailiwick name.
        poisoned_name: String,
        /// Out of bailiwick IP.
        poisoned_ip: Ipv4Addr,
    },
}

/// In-process commandable fake upstream that counts queries and supports scripted behavior.
pub struct CommandableUpstream {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    query_count: Arc<AtomicUsize>,
    behavior: Arc<RwLock<UpstreamBehavior>>,
    cancel: CancellationToken,
}

impl CommandableUpstream {
    /// Starts a commandable upstream on ephemeral UDP and TCP ports.
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails.
    pub async fn start() -> Result<Self, HarnessError> {
        let cancel = CancellationToken::new();
        let query_count = Arc::new(AtomicUsize::new(0));
        let behavior = Arc::new(RwLock::new(UpstreamBehavior::Normal));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
        let shared_addr = tcp_listener.local_addr()?;
        let udp_socket = Arc::new(UdpSocket::bind(shared_addr).await?);
        let udp_addr = shared_addr;
        let tcp_addr = shared_addr;

        Self::spawn_udp_loop(
            Arc::clone(&udp_socket),
            Arc::clone(&query_count),
            Arc::clone(&behavior),
            cancel.clone(),
        );

        Self::spawn_tcp_loop(
            tcp_listener,
            Arc::clone(&query_count),
            Arc::clone(&behavior),
            cancel.clone(),
        );

        Ok(Self {
            udp_addr,
            tcp_addr,
            query_count,
            behavior,
            cancel,
        })
    }

    /// Starts a commandable upstream listening only on UDP (no TCP listener bound).
    ///
    /// # Errors
    /// Returns [`HarnessError`] if binding fails.
    pub async fn start_udp_only() -> Result<Self, HarnessError> {
        let cancel = CancellationToken::new();
        let query_count = Arc::new(AtomicUsize::new(0));
        let behavior = Arc::new(RwLock::new(UpstreamBehavior::Normal));

        let udp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let udp_addr = udp_socket.local_addr()?;
        let tcp_addr = udp_addr;

        Self::spawn_udp_loop(
            Arc::clone(&udp_socket),
            Arc::clone(&query_count),
            Arc::clone(&behavior),
            cancel.clone(),
        );

        Ok(Self {
            udp_addr,
            tcp_addr,
            query_count,
            behavior,
            cancel,
        })
    }

    /// Sets the dynamic response behavior.
    pub fn set_behavior(&self, behavior: UpstreamBehavior) {
        if let Ok(mut lock) = self.behavior.write() {
            *lock = behavior;
        }
    }

    /// Returns the total number of queries received by this upstream.
    #[must_use]
    pub fn query_count(&self) -> usize {
        self.query_count.load(Ordering::SeqCst)
    }

    /// Resets the received query count back to zero.
    pub fn reset_count(&self) {
        self.query_count.store(0, Ordering::SeqCst);
    }

    /// Returns the OS-assigned UDP listening address.
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    /// Shuts down the fake server listeners.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    fn spawn_udp_loop(
        socket: Arc<UdpSocket>,
        query_count: Arc<AtomicUsize>,
        behavior: Arc<RwLock<UpstreamBehavior>>,
        cancel: CancellationToken,
    ) {
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    recv_res = socket.recv_from(&mut buf) => {
                        let Ok((len, peer)) = recv_res else { continue };
                        query_count.fetch_add(1, Ordering::SeqCst);

                        let b = match behavior.read() {
                            Ok(guard) => guard.clone(),
                            Err(p) => p.into_inner().clone(),
                        };

                        if let UpstreamBehavior::Delay(d) = b {
                            tokio::time::sleep(d).await;
                        }
                        if matches!(b, UpstreamBehavior::Timeout | UpstreamBehavior::DropAll) {
                            continue;
                        }

                        let Some(slice) = buf.get(..len) else {
                            continue;
                        };
                        if matches!(b, UpstreamBehavior::MismatchedIdThenNormal) {
                            if let Some(m) = Self::build_response(slice, &UpstreamBehavior::MismatchedId, false) {
                                let _ = socket.send_to(&m, peer).await;
                            }
                            if let Some(n) = Self::build_response(slice, &UpstreamBehavior::Normal, false) {
                                let _ = socket.send_to(&n, peer).await;
                            }
                            continue;
                        }
                        if matches!(b, UpstreamBehavior::MismatchedQuestionThenNormal) {
                            if let Some(m) = Self::build_response(slice, &UpstreamBehavior::MismatchedQuestion, false) {
                                let _ = socket.send_to(&m, peer).await;
                            }
                            if let Some(n) = Self::build_response(slice, &UpstreamBehavior::Normal, false) {
                                let _ = socket.send_to(&n, peer).await;
                            }
                            continue;
                        }
                        if let Some(resp_bytes) = Self::build_response(slice, &b, false) {
                            let _ = socket.send_to(&resp_bytes, peer).await;
                        }
                    }
                }
            }
        });
    }

    fn spawn_tcp_loop(
        listener: TcpListener,
        query_count: Arc<AtomicUsize>,
        behavior: Arc<RwLock<UpstreamBehavior>>,
        cancel: CancellationToken,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    accept_res = listener.accept() => {
                        let Ok((mut stream, _)) = accept_res else { continue };
                        let q_count = Arc::clone(&query_count);
                        let beh = Arc::clone(&behavior);
                        let c = cancel.clone();

                        tokio::spawn(async move {
                            let mut len_buf = [0u8; 2];
                            loop {
                                tokio::select! {
                                    _ = c.cancelled() => break,
                                    res = stream.read_exact(&mut len_buf) => {
                                        if res.is_err() { break; }
                                        let frame_len = usize::from(u16::from_be_bytes(len_buf));
                                        let mut payload = vec![0u8; frame_len];
                                        if stream.read_exact(&mut payload).await.is_err() { break; }
                                        q_count.fetch_add(1, Ordering::SeqCst);

                                        let b = match beh.read() {
                                            Ok(guard) => guard.clone(),
                                            Err(p) => p.into_inner().clone(),
                                        };

                                        if let UpstreamBehavior::Delay(d) = b {
                                            tokio::time::sleep(d).await;
                                        }
                                        if matches!(b, UpstreamBehavior::Timeout | UpstreamBehavior::DropAll) {
                                            break;
                                        }

                                        if let Some(resp_bytes) = Self::build_response(&payload, &b, true) {
                                            if let Ok(framed) = styx_proto::frame_tcp(&resp_bytes) {
                                                let _ = stream.write_all(&framed).await;
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        });
    }

    fn build_response(raw: &[u8], behavior: &UpstreamBehavior, is_tcp: bool) -> Option<Vec<u8>> {
        let decoded = styx_proto::Message::decode(raw).ok()?;
        let question = decoded.questions.first()?.clone();

        let tx_id = match behavior {
            UpstreamBehavior::MismatchedId => decoded.header.id.wrapping_add(999),
            _ => decoded.header.id,
        };

        let mut hmsg = HMessage::new(tx_id, HMessageType::Response, HOpCode::Query);
        hmsg.metadata.authoritative = true;
        hmsg.metadata.recursion_available = true;

        if (!is_tcp && matches!(behavior, UpstreamBehavior::TruncateUdp))
            || matches!(behavior, UpstreamBehavior::TruncateTcp)
        {
            hmsg.metadata.truncation = true;
        }

        match behavior {
            UpstreamBehavior::Servfail => hmsg.metadata.response_code = HResponseCode::ServFail,
            UpstreamBehavior::Refused => hmsg.metadata.response_code = HResponseCode::Refused,
            UpstreamBehavior::NxdomainWithSoa { .. } | UpstreamBehavior::NxdomainWithoutSoa => {
                hmsg.metadata.response_code = HResponseCode::NXDomain;
            }
            _ => hmsg.metadata.response_code = HResponseCode::NoError,
        }

        let qname_str = match behavior {
            UpstreamBehavior::MismatchedQuestion => "mismatched.invalid.".to_string(),
            _ => question.qname.to_string(),
        };
        let h_qname = HName::from_str(&qname_str).ok()?;
        let mut query = hickory_proto::op::Query::new();
        query.set_name(h_qname.clone());
        query.set_query_type(HRecordType::A);
        query.set_query_class(HDnsClass::IN);
        hmsg.add_query(query);

        let is_truncated = hmsg.metadata.truncation;
        Self::apply_behavior_records(&mut hmsg, &h_qname, behavior, is_truncated)?;

        let mut out = Vec::new();
        let mut encoder = BinEncoder::new(&mut out);
        hmsg.emit(&mut encoder).ok()?;
        Some(out)
    }

    fn apply_behavior_records(
        hmsg: &mut HMessage,
        h_qname: &HName,
        behavior: &UpstreamBehavior,
        is_truncated: bool,
    ) -> Option<()> {
        match behavior {
            UpstreamBehavior::NxdomainWithSoa { zone, ttl, minimum }
            | UpstreamBehavior::NodataWithSoa { zone, ttl, minimum } => {
                let mname = HName::from_str(&format!("ns1.{zone}")).ok()?;
                let rname = HName::from_str(&format!("hostmaster.{zone}")).ok()?;
                let soa_rdata =
                    HRData::SOA(HSoa::new(mname, rname, 1, 7200, 3600, 1209600, *minimum));
                let soa_name = HName::from_str(zone).ok()?;
                let soa_rec = HRecord::from_rdata(soa_name, *ttl, soa_rdata);
                hmsg.add_authority(soa_rec);
            }
            UpstreamBehavior::PoisonedAdditional {
                answer_ip,
                poisoned_name,
                poisoned_ip,
            } => {
                let rec = HRecord::from_rdata(h_qname.clone(), 3600, HRData::A(HA(*answer_ip)));
                hmsg.add_answer(rec);
                let poison_name = HName::from_str(poisoned_name).ok()?;
                let poison_rec =
                    HRecord::from_rdata(poison_name, 3600, HRData::A(HA(*poisoned_ip)));
                hmsg.add_additional(poison_rec);
            }
            _ => {
                if !is_truncated
                    && matches!(
                        behavior,
                        UpstreamBehavior::Normal
                            | UpstreamBehavior::Delay(_)
                            | UpstreamBehavior::TruncateUdp
                            | UpstreamBehavior::MismatchedId
                            | UpstreamBehavior::MismatchedQuestion
                    )
                {
                    let rec = HRecord::from_rdata(
                        h_qname.clone(),
                        3600,
                        HRData::A(HA(Ipv4Addr::new(192, 0, 2, 1))),
                    );
                    hmsg.add_answer(rec);
                }
            }
        }
        Some(())
    }
}
