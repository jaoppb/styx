//! What admission is asked to judge: a response, the client question it answers, and the
//! provenance it arrived with.

use std::time::Instant;

use styx_proto::{Message, Question};

use crate::domain::answer::AnswerSource;
use crate::domain::cache::bailiwick::Bailiwick;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;

/// A response offered to [`Admission::evaluate`](crate::domain::cache::Admission::evaluate)
/// for the client question it should answer.
///
/// The cache key and the bailiwick are derived from the client's question here, once,
/// so admission judges the response against the question that was asked and the key it
/// will be stored under cannot disagree with it.
#[derive(Debug, Clone)]
pub struct AdmissionRequest<'a> {
    key: CacheKey,
    bailiwick: Bailiwick,
    message: &'a Message,
    source: AnswerSource,
    now: Instant,
}

impl<'a> AdmissionRequest<'a> {
    /// Builds the request for `message`, the response to the client's `question`.
    ///
    /// # Errors
    /// Returns [`CacheError::UncacheableQuestion`] if the question asks for a meta-type
    /// (`ANY`, `AXFR`, `IXFR`, or `OPT`), which is never admitted.
    pub fn new(
        question: &Question,
        message: &'a Message,
        source: AnswerSource,
        now: Instant,
    ) -> Result<Self, CacheError> {
        Ok(Self {
            key: CacheKey::from_question(question)?,
            bailiwick: Bailiwick::of_response(question, message),
            message,
            source,
            now,
        })
    }

    /// The key the response is admitted under, derived from the client's question.
    #[must_use]
    pub const fn key(&self) -> &CacheKey {
        &self.key
    }

    /// The bailiwick of the responding authority, judged from the client's question.
    #[must_use]
    pub const fn bailiwick(&self) -> &Bailiwick {
        &self.bailiwick
    }

    /// The response under judgement.
    #[must_use]
    pub const fn message(&self) -> &'a Message {
        self.message
    }

    /// Where the response came from.
    #[must_use]
    pub const fn source(&self) -> AnswerSource {
        self.source
    }

    /// The instant TTL deadlines are computed from.
    #[must_use]
    pub const fn now(&self) -> Instant {
        self.now
    }
}
