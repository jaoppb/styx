//! The pool's verdict on a reply: does it answer the question that was asked?
//!
//! One function judges, so real traffic, a raced fanout and a canary probe cannot disagree
//! about what a member may be credited for.

use styx_core::{UpstreamError, UpstreamId, UpstreamResponse};
use styx_proto::Question;

use crate::domain::cache::refusal::check_question;
use crate::domain::health::Outcome;

/// Passes `result` through, turning a reply that does not answer `query` into
/// [`UpstreamError::UntrustedReply`].
///
/// Only a refusal for the echoed question counts here; record-level rejections stay with
/// cache admission. An error from the upstream is returned untouched.
pub(crate) fn judge_reply(
    member: &UpstreamId,
    query: &Question,
    result: Result<UpstreamResponse, UpstreamError>,
) -> Result<UpstreamResponse, UpstreamError> {
    let response = result?;
    let Some(refusal) = check_question(query, &response.message) else {
        return Ok(response);
    };
    let Some(fault) = refusal.reason().reply_fault() else {
        return Ok(response);
    };
    tracing::debug!(
        upstream = %member,
        expected = ?query,
        echoed = ?refusal.echoed(),
        "refused a reply that does not answer the question"
    );
    Err(UpstreamError::UntrustedReply(fault))
}

/// The health observation for a failed attempt on a member.
pub(crate) fn outcome_of_error(error: &UpstreamError, was_probe: bool) -> Outcome {
    match error {
        UpstreamError::UntrustedReply(reason) => Outcome::Refused {
            reason: *reason,
            was_probe,
        },
        other => Outcome::Failure {
            class: other.classify(),
            was_probe,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use styx_core::{FailureClass, ReplyFault, UpstreamKind};
    use styx_proto::{Message, Name, RData, RecordClass, RecordType, ResourceRecord, Ttl};

    use super::*;

    fn ask(text: &str) -> Question {
        let name = Name::from_ascii(text).unwrap_or_else(|_| Name::root());
        Question::new(name, RecordType::A, RecordClass::In)
    }

    fn reply_echoing(asked: &Question, echoed: Vec<Question>) -> UpstreamResponse {
        let mut message = Message::response_to(1, asked.clone());
        message.questions = echoed;
        message.answers.push(ResourceRecord::new(
            asked.qname.clone(),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(60),
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        UpstreamResponse {
            message,
            answered_by: UpstreamId::new("up"),
            kind: UpstreamKind::Forwarder,
            elapsed: Duration::ZERO,
            via_tcp: false,
            raced_count: 1,
        }
    }

    fn judged(echoed: Vec<Question>) -> Result<UpstreamResponse, UpstreamError> {
        let asked = ask("www.example.com.");
        let reply = reply_echoing(&asked, echoed);
        judge_reply(&UpstreamId::new("up"), &asked, Ok(reply))
    }

    #[test]
    fn test_a_reply_echoing_the_question_passes() {
        assert!(judged(vec![ask("WWW.example.com.")]).is_ok());
    }

    #[test]
    fn test_a_reply_echoing_another_question_is_refused() {
        let error = judged(vec![ask("evil.example.net.")]).err();
        assert_eq!(
            error,
            Some(UpstreamError::UntrustedReply(ReplyFault::QuestionMismatch))
        );
    }

    #[test]
    fn test_a_reply_echoing_no_question_is_refused() {
        let error = judged(Vec::new()).err();
        assert_eq!(
            error,
            Some(UpstreamError::UntrustedReply(ReplyFault::QuestionMismatch))
        );
    }

    #[test]
    fn test_a_reply_echoing_two_questions_is_refused() {
        let error = judged(vec![ask("www.example.com."), ask("extra.example.com.")]).err();
        assert_eq!(
            error,
            Some(UpstreamError::UntrustedReply(ReplyFault::MultipleQuestions))
        );
    }

    #[test]
    fn test_an_upstream_error_is_returned_untouched() {
        let asked = ask("www.example.com.");
        let result = judge_reply(&UpstreamId::new("up"), &asked, Err(UpstreamError::Timeout));
        assert_eq!(result.err(), Some(UpstreamError::Timeout));
    }

    #[test]
    fn test_a_refused_reply_is_observed_as_refused_and_other_errors_as_failures() {
        assert_eq!(
            outcome_of_error(
                &UpstreamError::UntrustedReply(ReplyFault::MultipleQuestions),
                true
            ),
            Outcome::Refused {
                reason: ReplyFault::MultipleQuestions,
                was_probe: true,
            }
        );
        assert_eq!(
            outcome_of_error(&UpstreamError::Timeout, false),
            Outcome::Failure {
                class: FailureClass::UpstreamFault,
                was_probe: false,
            }
        );
    }
}
