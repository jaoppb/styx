//! One DoH connection: the TLS handshake, then HTTP/2 with the stream ceiling applied at the
//! protocol level, and one handler per stream that answers through the shared query path.
//!
//! Three limits, because they are three exhaustion paths: the connection ceiling (in the
//! listener), the stream ceiling (here, in HTTP/2 SETTINGS), and the body cap (per
//! request). The query ceiling counts streams, not connections, or multiplexing would make
//! it decorative.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::rt::Executor;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use styx_core::{Clock, Sleeper};

use crate::application::terminal::TerminalHandler;
use crate::domain::error::DohError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::Transport;
use crate::domain::tls::{DohResourcePath, EncryptedLimits};
use crate::infrastructure::admission::ListenerShared;
use crate::infrastructure::connection_bounds::{ConnectionLimiter, QueryLimit, Spend};
use crate::infrastructure::doh::request::{accept_body, extract_head, DohHead, DohRequestForm};
use crate::infrastructure::doh::response::DohResponse;
use crate::infrastructure::malformed_warning::MalformedWarning;
use crate::infrastructure::tcp_connection::QueryTask;
use crate::infrastructure::tls::accept_tls;

/// Cap on the decoded request header block per stream.
const MAX_HEADER_LIST_BYTES: u32 = 16 * 1024;

/// Settings fixed for every connection of one listener.
#[derive(Debug, Clone)]
pub(crate) struct DohSettings {
    pub(crate) resource: DohResourcePath,
    pub(crate) limits: EncryptedLimits,
    pub(crate) allow_http1: bool,
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

/// Everything one stream needs to answer, shared by the streams of one connection.
pub(crate) struct StreamHandler<L, F, O, C, T, S> {
    shared: ListenerShared<L, F, O, C, T, S>,
    malformed_warning: Arc<MalformedWarning<C, S>>,
    settings: DohSettings,
    peer: SocketAddr,
    limiter: ConnectionLimiter,
}

impl<L, F, O, C, T, S> StreamHandler<L, F, O, C, T, S>
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
        settings: DohSettings,
        peer: SocketAddr,
    ) -> Self {
        let streams = settings.limits.max_streams_per_connection.as_usize();
        let ceiling = QueryLimit::limited(settings.limits.max_queries_per_connection).ceiling();
        let limiter = ConnectionLimiter::new(streams, ceiling, settings.limits.idle_timeout);
        Self {
            shared,
            malformed_warning,
            settings,
            peer,
            limiter,
        }
    }

    /// Answers one stream. Every failure is an HTTP status, never a panic.
    async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let received_at = self.shared.clock.now_monotonic();
        let response = match self.answer(request, received_at).await {
            Ok(wire) => DohResponse::answer(wire),
            Err(error) => {
                tracing::debug!(peer = %self.peer, transport = Transport::Doh.name(), %error, "DoH request refused");
                DohResponse::Error(error)
            }
        };
        response.into_http()
    }

    async fn answer(
        &self,
        request: Request<Incoming>,
        received_at: std::time::Instant,
    ) -> Result<Vec<u8>, DohError> {
        if self.limiter.spend() == Spend::Over {
            return Err(DohError::StreamBudgetExceeded);
        }
        let _slot = self.limiter.track().await;
        let (parts, body) = request.into_parts();
        let header = |name| parts.headers.get(name).and_then(|v| v.to_str().ok());
        let head = DohHead {
            method: parts.method.as_str(),
            path: parts.uri.path(),
            query: parts.uri.query(),
            content_type: header(CONTENT_TYPE),
            content_length: header(CONTENT_LENGTH),
        };
        let limit = self.settings.limits.max_request_body;
        let wire = match extract_head(&head, &self.settings.resource, limit)? {
            DohRequestForm::GetQueryParameter(wire) => wire,
            DohRequestForm::PostBody => read_body(body, limit).await?,
        };
        let Some(_permit) = self.shared.budget.acquire().await else {
            return Err(DohError::StreamBudgetExceeded);
        };
        let task = QueryTask::new(
            self.shared.clone(),
            Arc::clone(&self.malformed_warning),
            self.peer,
            Transport::Doh,
            received_at,
        );
        task.respond(&wire).await.ok_or(DohError::Unanswerable)
    }
}

async fn read_body(
    body: Incoming,
    limit: crate::domain::tls::StreamMessageLimit,
) -> Result<Vec<u8>, DohError> {
    let collected = Limited::new(body, usize::from(limit.octets()))
        .collect()
        .await
        .map_err(|_| DohError::BodyTooLarge)?;
    let bytes = collected.to_bytes().to_vec();
    accept_body(&bytes, limit)?;
    Ok(bytes)
}

/// Completes the handshake under its deadline, then serves HTTP until the connection
/// ends, idles out, spends its query ceiling, or the server shuts down.
pub(crate) async fn serve<L, F, O, C, T, S>(
    handler: Arc<StreamHandler<L, F, O, C, T, S>>,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    closing: CancellationToken,
) where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    let peer = handler.peer;
    let handshake_timeout = handler.settings.limits.handshake_timeout;
    let Some(tls) = accept_tls(&acceptor, stream, handshake_timeout, peer, "DoH").await else {
        return;
    };
    let builder = http_builder(&handler);
    let service = {
        let handler = Arc::clone(&handler);
        service_fn(move |request| {
            let handler = Arc::clone(&handler);
            async move { Ok::<_, Infallible>(handler.handle(request).await) }
        })
    };
    let connection = builder.serve_connection(TokioIo::new(tls), service);
    tokio::pin!(connection);
    tokio::select! {
        served = connection.as_mut() => return log_end(peer, served.err()),
        () = closing.cancelled() => {}
        () = handler.limiter.idle_expired() => tracing::debug!(%peer, "DoH connection idle; closing"),
        () = handler.limiter.budget_spent() => tracing::debug!(%peer, "DoH query ceiling reached; closing"),
    }
    connection.as_mut().graceful_shutdown();
    let drained = tokio::time::timeout(drain_bound(&handler), connection).await;
    if let Ok(served) = drained {
        log_end(peer, served.err());
    }
}

fn http_builder<L, F, O, C, T, S>(
    handler: &StreamHandler<L, F, O, C, T, S>,
) -> Builder<TrackedExecutor> {
    let executor = TrackedExecutor {
        tasks: handler.shared.tasks.clone(),
        abort: handler.shared.abort.clone(),
    };
    let mut builder = Builder::new(executor);
    if !handler.settings.allow_http1 {
        builder = builder.http2_only();
    }
    builder
        .http2()
        .max_concurrent_streams(handler.settings.limits.max_streams_per_connection.as_u32())
        .max_header_list_size(MAX_HEADER_LIST_BYTES);
    builder
}

/// How long a closing connection may take to finish the streams it already accepted.
fn drain_bound<L, F, O, C, T, S>(handler: &StreamHandler<L, F, O, C, T, S>) -> Duration {
    handler
        .shared
        .query_timeout
        .saturating_add(handler.settings.limits.handshake_timeout)
}

fn log_end(peer: SocketAddr, error: Option<Box<dyn std::error::Error + Send + Sync>>) {
    if let Some(error) = error {
        tracing::debug!(%peer, %error, "DoH connection ended with an error");
    }
}
