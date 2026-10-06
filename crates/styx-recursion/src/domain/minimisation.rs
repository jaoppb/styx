//! Relaxed QNAME minimisation (RFC 9156): what actually goes on the wire.
//!
//! There is no code path that composes an outbound question without this type.
//! A naive recursor tells the root the whole of `secret-project.internal.example.com`
//! when it only needs `com`; this state machine sends one label more than the
//! current zone cut, as an NS query, until the descent reaches the zone that holds
//! the name, and only then asks the client's own question.
//!
//! Relaxed, not strict: a server that mishandles a minimised query gets the full
//! qname, because a resolver that cannot resolve is not private, it is broken. The
//! classification below decides when that fallback is warranted. It is the part of
//! this crate a future reader is most likely to "simplify" into a bug, so each
//! verdict says why.

use styx_proto::{Name, Question, RecordClass, RecordType};

use crate::domain::metrics::MinimisationVerdict;
use crate::domain::names::ancestor_with_labels;

/// Whether this descent still minimises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinimisationMode {
    /// Send one label below the zone cut.
    Relaxed,
    /// A server mishandled a minimised query: send the full qname for the rest of
    /// this zone cut. Crossing into a new cut or following an alias minimises again,
    /// because the servers there have not mishandled anything.
    FellBackFullQname,
}

/// What to do about a bad response to the last question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackDecision {
    /// Ask the same server the full qname.
    RetryFullQnameSameServer,
    /// Leave this server and try another of the zone's servers.
    TryNextServer,
    /// The response is a genuine answer: use it.
    AcceptAsGenuine,
}

/// The kinds of bad response [`MinimisationState::on_bad_response`] classifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadResponse {
    /// FORMERR, NOTIMP or REFUSED.
    Refused,
    /// SERVFAIL, or a FORMERR/NOTIMP/REFUSED to a question that was not minimised.
    ServerFailure,
    /// NXDOMAIN.
    NameError,
}

/// The question-composition state of one descent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimisationState {
    target: Name,
    qtype: RecordType,
    prefix_labels: usize,
    mode: MinimisationMode,
    minimised_steps: u8,
    awaiting_full_retry: bool,
}

impl MinimisationState {
    /// Starts minimising toward `target`/`qtype` from a cut at `cut_zone`.
    #[must_use]
    pub fn new(target: Name, qtype: RecordType, cut_zone: &Name) -> Self {
        let prefix_labels = cut_zone.label_count().saturating_add(1);
        Self {
            target,
            qtype,
            prefix_labels,
            mode: MinimisationMode::Relaxed,
            minimised_steps: 0,
            awaiting_full_retry: false,
        }
    }

    /// The question to send to a server of the cut at `cut_zone` whose verdict is
    /// `verdict`.
    ///
    /// Minimised: the target cut down to one label below the zone (or below the last
    /// empty non-terminal), asked as NS. Full: the target with the client's qtype —
    /// once the prefix has reached the target, after a fallback, or for a server
    /// proven to mishandle minimised queries.
    pub fn next_question(&mut self, cut_zone: &Name, verdict: MinimisationVerdict) -> Question {
        let labels = self
            .prefix_labels
            .max(cut_zone.label_count().saturating_add(1));
        let full = self.mode == MinimisationMode::FellBackFullQname
            || matches!(verdict, MinimisationVerdict::MishandlesMinimised(_))
            || labels >= self.target.label_count();
        if full {
            return Question::new(self.target.clone(), self.qtype, RecordClass::In);
        }
        self.minimised_steps = self.minimised_steps.saturating_add(1);
        Question::new(
            ancestor_with_labels(&self.target, labels),
            RecordType::NS,
            RecordClass::In,
        )
    }

    /// Whether `sent` was a minimised intermediate question rather than the client's.
    #[must_use]
    pub fn is_intermediate(&self, sent: &Question) -> bool {
        !(sent.qname == self.target && sent.qtype == self.qtype)
    }

    /// Classifies a bad response to `sent`.
    ///
    /// - **Refused** (FORMERR, NOTIMP, REFUSED) to a minimised question: the
    ///   server may simply not understand minimised queries, so retry the full
    ///   qname at the same server and fall back for the rest of this zone cut. That
    ///   retry is also the experiment that proves (or not) that the server
    ///   mishandles minimisation — see [`Self::fallback_proved_mishandling`].
    /// - **Refused** after falling back, or **ServerFailure**: a health problem,
    ///   not evidence about minimisation. Try another server; never write a
    ///   verdict, or one lost packet would downgrade privacy for a whole zone.
    /// - **NameError** at an intermediate label: trusted (RFC 8020). NXDOMAIN
    ///   means nothing exists below that name, and retrying in full would send
    ///   every typo and random tracker subdomain in full to the parent zone — the
    ///   leak minimisation exists to stop. The cost, a false NXDOMAIN from a
    ///   never-seen server with broken empty-non-terminal handling, is accepted.
    ///   A server already known to mishandle minimisation was asked in full, so
    ///   its NXDOMAIN is final too.
    pub fn on_bad_response(&mut self, kind: BadResponse, sent: &Question) -> FallbackDecision {
        match kind {
            BadResponse::Refused if self.is_intermediate(sent) => {
                self.fall_back_to_full_qname();
                self.awaiting_full_retry = true;
                FallbackDecision::RetryFullQnameSameServer
            }
            BadResponse::Refused | BadResponse::ServerFailure => {
                self.awaiting_full_retry = false;
                FallbackDecision::TryNextServer
            }
            BadResponse::NameError => FallbackDecision::AcceptAsGenuine,
        }
    }

    /// Whether the full-qname retry that followed a refusal succeeded, which is the
    /// only evidence that writes a `MishandlesMinimised` verdict. `answered` is
    /// whether the retry produced a referral, an answer or an alias.
    pub fn fallback_proved_mishandling(&mut self, answered: bool) -> bool {
        let proved = self.awaiting_full_retry && answered;
        self.awaiting_full_retry = false;
        proved
    }

    /// An empty NOERROR to a minimised question: the name is an empty non-terminal
    /// (it has descendants but no records), not an answer to the client. Descend
    /// one more label within the same zone instead of concluding NODATA.
    pub fn advance_past_empty_non_terminal(&mut self) {
        self.prefix_labels = self.prefix_labels.saturating_add(1);
    }

    /// The server being asked is authoritative for the zone holding the target —
    /// a DNAME above it says so — so the next question to it is the client's own.
    pub fn advance_to_target(&mut self) {
        self.prefix_labels = self.target.label_count();
    }

    /// The descent crossed into a new zone cut: minimise again from just below it.
    pub fn enter_cut(&mut self, cut_zone: &Name) {
        self.mode = MinimisationMode::Relaxed;
        self.prefix_labels = cut_zone.label_count().saturating_add(1);
    }

    /// An alias redirected the descent to `target`, now asked from `cut_zone`.
    pub fn retarget(&mut self, target: Name, cut_zone: &Name) {
        self.target = target;
        self.enter_cut(cut_zone);
    }

    /// Sends the full qname for the remainder of this zone cut.
    pub fn fall_back_to_full_qname(&mut self) {
        self.mode = MinimisationMode::FellBackFullQname;
    }

    /// The current mode.
    #[must_use]
    pub const fn mode(&self) -> MinimisationMode {
        self.mode
    }

    /// The name being resolved now (the client's qname, or an alias target).
    #[must_use]
    pub const fn target(&self) -> &Name {
        &self.target
    }

    /// How many minimised questions have been composed.
    #[must_use]
    pub const fn minimised_steps(&self) -> u8 {
        self.minimised_steps
    }
}

#[cfg(test)]
#[path = "minimisation_tests.rs"]
mod tests;
