//! Cache pipeline stage handling lookup, upstream resolution on miss, and admission.

use std::sync::Arc;
use std::time::Duration;

use styx_core::{Clock, Upstream, UpstreamKind};

use crate::application::cache_config::CacheConfig;
use crate::application::pool::UpstreamPool;
use crate::application::terminal::TerminalHandler;
use crate::application::validation::NoValidation;
use crate::domain::answer::{ResolutionOutcome, ResolutionResponse, ResolvedSource};
use crate::domain::cache::admission::Admission;
use crate::domain::cache::admission_request::AdmissionRequest;
use crate::domain::cache::dnssec::SecurityStatus;
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;
use crate::domain::cache::port::{AnswerCache, Lookup};
use crate::domain::cache::ttl::TtlPolicy;
use crate::domain::conditional::ConditionalRoutes;
use crate::domain::error::PipelineError;
use crate::domain::ports::validation::{ResponseValidator, Validation};
use crate::domain::request::RequestContext;
use crate::domain::selection::SelectionStrategy;
use crate::domain::signature_lifetime::{cap_ttls, remaining_signature_life};

/// Resolution terminal stage integrating the answer cache with the upstream pool.
///
/// Every upstream answer passes the validator `V` before it is admitted or served. Forged
/// answers never get here: the pipeline answers them before this stage (ADR 0010).
pub struct CacheStage<A, S, U, C, V = NoValidation> {
    cache: Arc<A>,
    pool: Arc<UpstreamPool<S, U, C>>,
    conditional: ConditionalRoutes<Arc<UpstreamPool<S, U, C>>>,
    admission: Admission,
    validator: Arc<V>,
    clock: Arc<C>,
    query_timeout: Duration,
}

impl<A, S, U, C> CacheStage<A, S, U, C>
where
    A: AnswerCache,
    S: SelectionStrategy,
    U: Upstream + Clone + 'static,
    C: Clock,
{
    /// Creates a new `CacheStage` with default admission TTL policies.
    #[must_use]
    pub fn new(
        cache: Arc<A>,
        pool: Arc<UpstreamPool<S, U, C>>,
        clock: Arc<C>,
        query_timeout: Duration,
    ) -> Self {
        Self {
            cache,
            pool,
            conditional: ConditionalRoutes::default(),
            admission: Admission::new(TtlPolicy::default()),
            validator: Arc::new(NoValidation),
            clock,
            query_timeout,
        }
    }

    /// Creates the `CacheStage` the `[cache]` section describes: admission clamps every
    /// answer to `config.ttl`. `cache` must already be sized from the same `config`.
    #[must_use]
    pub fn from_config(
        cache: Arc<A>,
        pool: Arc<UpstreamPool<S, U, C>>,
        config: &CacheConfig,
        clock: Arc<C>,
        query_timeout: Duration,
    ) -> Self {
        Self::with_admission(
            cache,
            pool,
            Admission::new(config.ttl),
            clock,
            query_timeout,
        )
    }

    /// Creates a new `CacheStage` with custom admission policy.
    #[must_use]
    pub fn with_admission(
        cache: Arc<A>,
        pool: Arc<UpstreamPool<S, U, C>>,
        admission: Admission,
        clock: Arc<C>,
        query_timeout: Duration,
    ) -> Self {
        Self {
            cache,
            pool,
            conditional: ConditionalRoutes::default(),
            admission,
            validator: Arc::new(NoValidation),
            clock,
            query_timeout,
        }
    }

    /// Validates every upstream answer with `validator` instead of leaving it unvalidated.
    #[must_use]
    pub fn with_validator<V2: ResponseValidator>(
        self,
        validator: Arc<V2>,
    ) -> CacheStage<A, S, U, C, V2> {
        CacheStage {
            cache: self.cache,
            pool: self.pool,
            conditional: self.conditional,
            admission: self.admission,
            validator,
            clock: self.clock,
            query_timeout: self.query_timeout,
        }
    }
}

impl<A, S, U, C, V> CacheStage<A, S, U, C, V>
where
    A: AnswerCache,
    S: SelectionStrategy,
    U: Upstream + Clone + 'static,
    C: Clock,
    V: ResponseValidator,
{
    /// Sends a question under a conditional domain to that route's pool instead of the main
    /// one. The answer is cached and admitted like any other.
    #[must_use]
    pub fn with_conditional(
        mut self,
        routes: ConditionalRoutes<Arc<UpstreamPool<S, U, C>>>,
    ) -> Self {
        self.conditional = routes;
        self
    }

    /// Returns a reference to the inner answer cache.
    #[must_use]
    pub fn cache(&self) -> &Arc<A> {
        &self.cache
    }

    /// Returns a reference to the upstream pool.
    #[must_use]
    pub fn pool(&self) -> &Arc<UpstreamPool<S, U, C>> {
        &self.pool
    }

    fn handle_cache_hit(&self, entry: &CacheEntry) -> Result<ResolutionResponse, PipelineError> {
        let now = self.clock.now_monotonic();
        let message = entry
            .to_response(now)
            .map_err(|e| PipelineError::Internal(e.to_string()))?;

        let outcome = ResolutionOutcome::Resolved {
            source: ResolvedSource::CacheHit,
            rcode: message.header.rcode,
            cacheable: true,
            authentic_data: message.header.authentic_data,
        };

        Ok(ResolutionResponse::new(message, outcome))
    }

    async fn resolve_uncacheable(
        &self,
        ctx: &RequestContext,
        question: &styx_proto::Question,
        deadline: std::time::Instant,
    ) -> Result<ResolutionResponse, PipelineError> {
        let validated = self.resolve_validated(ctx, question, deadline).await?;
        Ok(validated.into_response(false))
    }

    async fn resolve_and_admit(
        &self,
        ctx: &RequestContext,
        question: &styx_proto::Question,
        deadline: std::time::Instant,
    ) -> Result<ResolutionResponse, PipelineError> {
        let validated = self.resolve_validated(ctx, question, deadline).await?;
        if validated.cacheable {
            let now = self.clock.now_monotonic();
            let request =
                AdmissionRequest::new(question, &validated.message, validated.source.into(), now)
                    .map_err(|e| PipelineError::Internal(e.to_string()))?;
            let _ = self.cache.admit(self.admission.evaluate(request));
        }
        Ok(validated.into_response(true))
    }

    /// Resolves `question` upstream and judges the answer: AD reflects only styx's own
    /// verdict (RFC 4035 §4.6 has a resolver disregard the upstream's), a verdict the
    /// failure mode refuses is SERVFAIL unless the client set CD (RFC 4035 §3.2.2), and a
    /// Secure answer's TTLs are capped by its signatures (see [`signature_lifetime`]).
    ///
    /// An answer from a conditional route is not validated: such domains are local ones an
    /// operator sends to a LAN server, and building their chain would ask the main pool —
    /// the public upstreams — about the very names the route keeps off them. They are
    /// served as unvalidated, without AD and never refused, the way a validating resolver's
    /// `domain-insecure` list treats them.
    ///
    /// [`signature_lifetime`]: crate::domain::signature_lifetime
    async fn resolve_validated(
        &self,
        ctx: &RequestContext,
        question: &styx_proto::Question,
        deadline: std::time::Instant,
    ) -> Result<Validated, PipelineError> {
        let route = self.conditional.route(&question.qname);
        let pool = route.unwrap_or(&self.pool);
        let upstream_resp = pool.resolve(question, deadline).await?;
        let source = match upstream_resp.kind {
            UpstreamKind::Forwarder => ResolvedSource::Upstream,
            UpstreamKind::Recursor => ResolvedSource::Recursion,
        };
        let mut message = upstream_resp.message;
        let validation = match route {
            Some(_) => Validation::UNVALIDATED,
            None => self.validator.validate(question, &message).await,
        };
        if validation.rejected && !ctx.query.header.checking_disabled {
            return Err(PipelineError::ValidationFailed(validation.status));
        }
        let secure = validation.status == SecurityStatus::Secure;
        message.header.authentic_data = secure;
        let mut cacheable = !validation.rejected;
        if secure {
            if let Some(life) = remaining_signature_life(&message, self.clock.now_utc()) {
                cap_ttls(&mut message, life);
                cacheable &= life >= self.admission.ttl().floor();
            }
        }
        Ok(Validated {
            message,
            source,
            cacheable,
        })
    }
}

/// An upstream answer after validation, ready for the client.
struct Validated {
    message: styx_proto::Message,
    source: ResolvedSource,
    /// Whether the answer may enter the cache: not a refused verdict served to a CD=1
    /// client, and not signed for less time than the cache's TTL floor would keep it.
    cacheable: bool,
}

impl Validated {
    fn into_response(self, cacheable: bool) -> ResolutionResponse {
        let outcome = ResolutionOutcome::Resolved {
            source: self.source,
            rcode: self.message.header.rcode,
            cacheable: cacheable && self.cacheable,
            authentic_data: self.message.header.authentic_data,
        };
        ResolutionResponse::new(self.message, outcome)
    }
}

impl<A, S, U, C, V> TerminalHandler for CacheStage<A, S, U, C, V>
where
    A: AnswerCache + 'static,
    S: SelectionStrategy + 'static,
    U: Upstream + Clone + 'static,
    C: Clock + 'static,
    V: ResponseValidator,
{
    async fn handle_terminal(
        &self,
        ctx: &RequestContext,
    ) -> Result<ResolutionResponse, PipelineError> {
        let question = ctx
            .query
            .questions
            .first()
            .ok_or(PipelineError::MalformedQuery)?;

        let deadline = ctx
            .received_at
            .checked_add(self.query_timeout)
            .unwrap_or(ctx.received_at);

        let key = match CacheKey::from_question(question) {
            Ok(k) => k,
            Err(CacheError::UncacheableQuestion(_)) => {
                return self.resolve_uncacheable(ctx, question, deadline).await;
            }
            Err(other) => return Err(PipelineError::Internal(other.to_string())),
        };

        match self.cache.lookup(&key) {
            Lookup::Hit(entry) => self.handle_cache_hit(&entry),
            Lookup::Miss | Lookup::Expired => self.resolve_and_admit(ctx, question, deadline).await,
        }
    }
}
