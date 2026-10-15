//! Why a response was refused as a whole answer, with what it carried to be refused for.

use std::sync::Arc;

use styx_proto::{Message, Question, ResponseCode};

use crate::domain::cache::admission_outcome::RejectReason;

/// A response refused whole: the reason, and the questions it echoed when that is the
/// reason it was refused for.
///
/// The reason and its evidence are built together, so one cannot be stale against the
/// other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    reason: RejectReason,
    echoed: Arc<[Question]>,
}

impl Refusal {
    /// A refusal that points at no echoed question.
    pub(crate) fn of(reason: RejectReason) -> Self {
        Self {
            reason,
            echoed: Arc::from([]),
        }
    }

    /// A refusal for a question reason, keeping what `message` echoed.
    fn for_questions(reason: RejectReason, message: &Message) -> Self {
        Self {
            reason,
            echoed: Arc::from(message.questions.as_slice()),
        }
    }

    /// Why the response was refused.
    #[must_use]
    pub const fn reason(&self) -> RejectReason {
        self.reason
    }

    /// The questions the response echoed; empty unless it was refused for them.
    #[must_use]
    pub fn echoed(&self) -> &[Question] {
        &self.echoed
    }
}

/// Why `message` cannot be shown to answer the client's `question`, if it cannot.
///
/// Only NOERROR and NXDOMAIN speak for the question; any other rcode (SERVFAIL, REFUSED,
/// FORMERR, ...) may omit it legitimately and is never judged here. A judged response must
/// echo exactly one question, the client's up to letter case in the name.
#[must_use]
pub fn check_question(question: &Question, message: &Message) -> Option<Refusal> {
    if !speaks_for_question(message) {
        return None;
    }
    match message.questions.as_slice() {
        [echoed] if asks_the_same(question, echoed) => None,
        [] | [_] => Some(Refusal::for_questions(
            RejectReason::QuestionMismatch,
            message,
        )),
        _ => Some(Refusal::for_questions(
            RejectReason::MultipleQuestions,
            message,
        )),
    }
}

/// Whether `message` carries an rcode that answers the question it was asked, so that
/// what it echoes matters.
pub(crate) const fn speaks_for_question(message: &Message) -> bool {
    matches!(
        message.header.rcode,
        ResponseCode::NOERROR | ResponseCode::NXDOMAIN
    )
}

fn asks_the_same(asked: &Question, echoed: &Question) -> bool {
    asked.qname.eq_ignore_case(&echoed.qname)
        && asked.qtype == echoed.qtype
        && asked.qclass == echoed.qclass
}
