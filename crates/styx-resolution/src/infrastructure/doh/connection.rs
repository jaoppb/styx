//! One DoH connection: the TLS handshake, then HTTP/2 with the stream ceiling applied at the
//! protocol level, and one handler per stream that answers through the shared query path.
//!
//! Three limits, because they are three exhaustion paths: the connection ceiling (in the
//! listener), the stream ceiling (here, in HTTP/2 SETTINGS), and the body cap (per
//! request). The query ceiling counts streams, not connections, or multiplexing would make
//! it decorative.

use std::convert::Infallible;
use std::fmt::Display;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::rt::Executor;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use styx_core::{Clock, Sleeper};

use crate::application::terminal::TerminalHandler;
use crate::domain::error::DohError;
use crate::domain::limits::TCP_WRITE_TIMEOUT;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::Transport;
use crate::domain::tls::{DohResourcePath, EncryptedLimits, StreamMessageLimit};
use crate::infrastructure::admission::ListenerShared;
use crate::infrastructure::connection_bounds::{
    ConnectionLimiter, InFlightSlot, QueryCeiling, QueryLimit, Spend,
};
use crate::infrastructure::doh::request::{accept_body, extract_head, DohHead, DohRequestForm};
use crate::infrastructure::doh::response::DohResponse;
use crate::infrastructure::malformed_warning::MalformedWarning;
use crate::infrastructure::stream_query::{EncodedAnswer, QueryTask};
use crate::infrastructure::tls::accept_tls;

/// Cap on the decoded request header block per stream.
const MAX_HEADER_LIST_BYTES: u32 = 16 * 1024;

/// Listener-wide DoH request settings shared across accepted connections.
#[derive(Debug, Clone)]
pub struct DohSettings {
    resource: DohResourcePath,
    allow_http1: bool,
}

impl DohSettings {
    /// Builds settings for a DoH endpoint serving `resource`.
    #[must_use]
    pub fn new(resource: DohResourcePath, allow_http1: bool) -> Self {
        Self {
            resource,
            allow_http1,
        }
    }
}

/// Runs hyper's per-stream tasks on the server's task tracker, so shutdown drains and
/// aborts them like every other task.
#[derive(Clone)]
struct TrackedExecutor {
    tasks: TaskTracker,
    abort: CancellationToken,
}

impl<Fut> Executor<Fut> for TrackedExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        let abort = self.abort.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                () = abort.cancelled() => {}
                _ = fut => {}
            }
        });
    }
}

/// Listener-wide DoH endpoint state shared across connections.
pub(crate) struct DohEndpoint<L, F, O, C, T, S> {
    shared: ListenerShared<L, F, O, C, T, S>,
    malformed_warning: Arc<MalformedWarning<C, S>>,
    limits: EncryptedLimits,
    settings: DohSettings,
}

impl<L, F, O, C, T, S> DohEndpoint<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    pub(crate) fn new(
        shared: ListenerShared<L, F, O, C, T, S>,
        malformed_warning: Arc<MalformedWarning<C, S>>,
        limits: EncryptedLimits,
        settings: DohSettings,
    ) -> Self {
        Self {
            shared,
            malformed_warning,
            limits,
            settings,
        }
    }

    pub(crate) fn connection(
        self: &Arc<Self>,
        peer: SocketAddr,
    ) -> Arc<DohConnection<L, F, O, C, T, S>> {
        let streams = self.limits.max_streams_per_connection.as_usize();
        let ceiling =
            QueryCeiling::new(QueryLimit::limited(self.limits.max_queries_per_connection));
        let limiter =
            ConnectionLimiter::new(streams, ceiling, self.limits.idle_timeout.as_duration());
        Arc::new(DohConnection {
            endpoint: Arc::clone(self),
            peer,
            limiter,
            send_stalled: CancellationToken::new(),
        })
    }

    fn http_builder(&self) -> Builder<TrackedExecutor> {
        let executor = TrackedExecutor {
            tasks: self.shared.tasks.clone(),
            abort: self.shared.abort.clone(),
        };
        let mut builder = Builder::new(executor);
        if !self.settings.allow_http1 {
            builder = builder.http2_only();
        }
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(self.limits.idle_timeout.as_duration());
        let stream_window = u32::from(self.limits.max_request_body.octets());
        let connection_window = stream_window.saturating_mul(4);
        // No HTTP/2 keep-alive pings: the idle timer already closes a connection with no
        // stream outstanding, and a stalled body is bounded by its own read deadline.
        builder
            .http2()
            .timer(TokioTimer::new())
            .initial_stream_window_size(stream_window)
            .initial_connection_window_size(connection_window)
            .max_send_buf_size(usize::from(StreamMessageLimit::protocol_max().octets()))
            .max_concurrent_streams(self.limits.max_streams_per_connection.as_u32())
            .max_header_list_size(MAX_HEADER_LIST_BYTES);
        builder
    }

    /// How long a closing connection may take to finish the streams it already accepted.
    fn drain_bound(&self) -> Duration {
        self.shared
            .query_timeout
            .saturating_add(self.limits.handshake_timeout.as_duration())
    }

    async fn dispatch(&self, wire: &[u8], peer: SocketAddr) -> Result<EncodedAnswer, DohError> {
        let Some(_permit) = self.shared.budget.acquire().await else {
            return Err(DohError::ShuttingDown);
        };
        let received_at = self.shared.clock.now_monotonic();
        let task = QueryTask::new(
            self.shared.clone(),
            Arc::clone(&self.malformed_warning),
            peer,
            Transport::Doh,
            received_at,
        );
        task.respond(wire).await.ok_or(DohError::Unanswerable)
    }
}

/// Per-connection DoH state owning the connection's stream/query bounds.
pub(crate) struct DohConnection<L, F, O, C, T, S> {
    endpoint: Arc<DohEndpoint<L, F, O, C, T, S>>,
    peer: SocketAddr,
    limiter: ConnectionLimiter,
    send_stalled: CancellationToken,
}

struct SlottedAnswer {
    answer: EncodedAnswer,
    slot: InFlightSlot,
}

/// Response body that holds the stream's [`InFlightSlot`] and arms a per-stream send
/// deadline until hyper finishes queueing the response (or resets the stream).
struct SlottedBody {
    inner: Full<Bytes>,
    _slot: Option<InFlightSlot>,
    _cancel_timer: Option<oneshot::Sender<()>>,
}

impl Body for SlottedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<L, F, O, C, T, S> DohConnection<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    /// Completes the handshake under its deadline, then serves HTTP until the connection
    /// ends, idles out, spends its query ceiling, stalls sending, or the server shuts down.
    pub(crate) async fn serve(
        self: Arc<Self>,
        acceptor: TlsAcceptor,
        stream: TcpStream,
        closing: CancellationToken,
    ) {
        let timeout = self.endpoint.limits.handshake_timeout.as_duration();
        let Some(tls) =
            accept_tls(&acceptor, stream, timeout, self.peer, Transport::Doh.name()).await
        else {
            return;
        };
        let builder = self.endpoint.http_builder();
        let conn = Arc::clone(&self);
        let service = service_fn(move |request| {
            let conn = Arc::clone(&conn);
            async move { Ok::<_, Infallible>(conn.handle(request).await) }
        });
        let connection = builder.serve_connection(TokioIo::new(tls), service);
        tokio::pin!(connection);
        tokio::select! {
            served = connection.as_mut() => return log_end(self.peer, served),
            () = self.send_stalled.cancelled() => return,
            () = closing.cancelled() => {}
            () = self.limiter.idle_expired() => tracing::debug!(peer = %self.peer, "DoH connection idle; closing"),
            () = self.limiter.budget_spent() => tracing::debug!(peer = %self.peer, "DoH query ceiling reached; closing"),
        }
        connection.as_mut().graceful_shutdown();
        let drained = tokio::time::timeout(self.endpoint.drain_bound(), connection).await;
        if let Ok(served) = drained {
            log_end(self.peer, served);
        }
    }

    /// Answers one stream. Every failure is an HTTP status, never a panic.
    async fn handle(&self, request: Request<Incoming>) -> Response<SlottedBody> {
        match self.answer(request).await {
            Ok(slotted) => {
                let response =
                    DohResponse::answer(slotted.answer.wire, slotted.answer.min_ttl).into_http();
                self.wrap_slotted(response, slotted.slot)
            }
            Err(error) => {
                tracing::debug!(peer = %self.peer, transport = Transport::Doh.name(), %error, "DoH request refused");
                DohResponse::Error(error)
                    .into_http()
                    .map(|inner| SlottedBody {
                        inner,
                        _slot: None,
                        _cancel_timer: None,
                    })
            }
        }
    }

    fn wrap_slotted(
        &self,
        response: Response<Full<Bytes>>,
        slot: InFlightSlot,
    ) -> Response<SlottedBody> {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let abort = self.endpoint.shared.abort.clone();
        let stalled = self.send_stalled.clone();
        let peer = self.peer;
        self.endpoint.shared.tasks.spawn(async move {
            tokio::select! {
                () = abort.cancelled() => {}
                _ = cancel_rx => {}
                () = tokio::time::sleep(TCP_WRITE_TIMEOUT) => {
                    tracing::debug!(%peer, transport = Transport::Doh.name(), "DoH response send timed out; closing");
                    stalled.cancel();
                }
            }
        });
        response.map(|inner| SlottedBody {
            inner,
            _slot: Some(slot),
            _cancel_timer: Some(cancel_tx),
        })
    }

    async fn answer(&self, request: Request<Incoming>) -> Result<SlottedAnswer, DohError> {
        if self.limiter.spend() == Spend::Over {
            return Err(DohError::StreamBudgetExceeded);
        }
        let Some(slot) = self.limiter.track().await else {
            return Err(DohError::ShuttingDown);
        };
        let limits = self.endpoint.limits;
        let wire = read_wire(
            request,
            &self.endpoint.settings.resource,
            limits.max_request_body,
            limits.idle_timeout.as_duration(),
        )
        .await?;
        let answer = self.endpoint.dispatch(&wire, self.peer).await?;
        Ok(SlottedAnswer { answer, slot })
    }
}

async fn read_wire(
    request: Request<Incoming>,
    resource: &DohResourcePath,
    limit: StreamMessageLimit,
    body_timeout: Duration,
) -> Result<Bytes, DohError> {
    let (parts, body) = request.into_parts();
    let header = |name| parts.headers.get(name).and_then(|v| v.to_str().ok());
    let head = DohHead {
        method: parts.method.as_str(),
        path: parts.uri.path(),
        query: parts.uri.query(),
        content_type: header(CONTENT_TYPE),
        content_length: header(CONTENT_LENGTH),
    };
    match extract_head(&head, resource, limit)? {
        DohRequestForm::GetQueryParameter(wire) => Ok(Bytes::from(wire)),
        DohRequestForm::PostBody => read_body(body, limit, body_timeout).await,
    }
}

/// Reads a `POST` body under the cap. `Limited` stops a body the moment it passes the cap,
/// so no more than the cap is ever buffered; what was read is then judged by
/// [`accept_body`], the same rule the `GET` parameter goes through.
async fn read_body(
    body: Incoming,
    limit: StreamMessageLimit,
    timeout: Duration,
) -> Result<Bytes, DohError> {
    let limited = Limited::new(body, usize::from(limit.octets()));
    let collected = tokio::time::timeout(timeout, limited.collect())
        .await
        .map_err(|_| DohError::BodyReadTimeout)?
        .map_err(|error| {
            if error.is::<LengthLimitError>() {
                DohError::BodyTooLarge
            } else {
                DohError::MalformedBody
            }
        })?;
    let bytes = collected.to_bytes();
    accept_body(&bytes, limit)?;
    Ok(bytes)
}

fn log_end(peer: SocketAddr, served: Result<(), impl Display>) {
    if let Err(error) = served {
        tracing::debug!(%peer, %error, "DoH connection ended with an error");
    }
}
