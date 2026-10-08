//! What styx has observed about individual nameservers.
//!
//! These are learned facts with their own expiry, not DNS records: round-trip
//! time, EDNS capability, whether the server mishandles minimised queries, and
//! which zones it is lame for. They live in the infrastructure cache, keyed by
//! address, and shape server selection and question composition.

use std::time::{Duration, Instant};

use styx_proto::Name;

/// An RTT sample larger than this is clamped before it enters the average, so one
/// pathological or hostile sample cannot drag a good server's SRTT out of reach.
pub const MAX_RTT_SAMPLE: Duration = Duration::from_secs(5);

/// SRTT charged for each failure, so a failing server sorts behind working ones.
pub const FAILURE_PENALTY: Duration = Duration::from_millis(800);

/// Consecutive failures after which a server is in backoff and skipped while an
/// alternative exists.
pub const BACKOFF_AFTER_FAILURES: u16 = 3;

/// How long a server in backoff is skipped before it is tried again.
pub const BACKOFF_WINDOW: Duration = Duration::from_secs(60);

/// How long a server stays marked EDNS-intolerant before the next query tries EDNS
/// again. One FORMERR can come from a middlebox or a transient fault, so the mark
/// must not outlive the evidence (unbound's `infra-host-ttl` is the same 900 s).
pub const EDNS_INTOLERANCE_TTL: Duration = Duration::from_secs(900);

/// Most lame-zone marks kept per nameserver. A shared host can be lame for
/// thousands of customer zones; the oldest-expiring marks are dropped first.
pub const MAX_LAME_MARKS: usize = 64;

/// A smoothed round-trip time: the RFC 6298 style EWMA, `srtt = 7/8 srtt + 1/8
/// sample`, computed with checked, saturating arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Srtt {
    smoothed: Duration,
}

impl Srtt {
    /// An SRTT seeded from a first sample.
    #[must_use]
    pub fn initial(sample: Duration) -> Self {
        Self {
            smoothed: sample.min(MAX_RTT_SAMPLE),
        }
    }

    /// The SRTT of a server never measured: zero, so unmeasured servers are tried
    /// before measured ones and every server of a set gets explored.
    #[must_use]
    pub const fn unmeasured() -> Self {
        Self {
            smoothed: Duration::ZERO,
        }
    }

    /// Folds in one sample, clamped to [`MAX_RTT_SAMPLE`]. Returns a new value.
    #[must_use]
    pub fn update(self, sample: Duration) -> Self {
        let sample = sample.min(MAX_RTT_SAMPLE);
        let kept = self
            .smoothed
            .checked_mul(7)
            .and_then(|scaled| scaled.checked_div(8))
            .unwrap_or(MAX_RTT_SAMPLE);
        let added = sample.checked_div(8).unwrap_or_default();
        Self {
            smoothed: kept.saturating_add(added).min(MAX_RTT_SAMPLE),
        }
    }

    /// The smoothed value.
    #[must_use]
    pub const fn smoothed(self) -> Duration {
        self.smoothed
    }
}

/// Whether a server speaks EDNS(0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdnsCapability {
    /// Not yet observed: queries carry EDNS.
    Unknown,
    /// Answered an EDNS query, advertising this payload size.
    Supported(u16),
    /// Rejected EDNS until the instant given: queries are sent without an OPT
    /// record until then.
    Intolerant(Instant),
}

/// Whether a server copes with minimised queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinimisationVerdict {
    /// No evidence either way: minimise.
    Unknown,
    /// Answered minimised queries correctly.
    HandlesMinimised,
    /// Proven, by differential evidence, to mishandle minimised queries; send it
    /// the full qname until the verdict expires.
    MishandlesMinimised(Instant),
}

/// One observation to fold into a server's metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricEvent {
    /// The server answered, taking this long.
    Success(Duration),
    /// The server timed out, failed at the transport, or answered SERVFAIL.
    Failure,
    /// The server answered an EDNS query, advertising this payload size.
    EdnsSupported(u16),
    /// The server rejected EDNS.
    EdnsIntolerant,
    /// The server answered a minimised query correctly.
    HandlesMinimised,
    /// Differential evidence: the server refused a minimised query, then answered
    /// the same question in full. The verdict lasts until the instant given.
    MishandlesMinimised(Instant),
    /// The server answered without authority for a zone it was delegated, until
    /// the instant given.
    LameFor(Name, Instant),
}

/// What is known about one nameserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameserverMetrics {
    srtt: Srtt,
    consecutive_failures: u16,
    edns: EdnsCapability,
    minimisation: MinimisationVerdict,
    lame_for: Vec<LameMark>,
    last_failure: Option<Instant>,
    last_seen: Instant,
}

/// A zone a server is lame for, and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LameMark {
    zone: Name,
    until: Instant,
}

impl NameserverMetrics {
    /// Metrics for a server first seen at `now`.
    #[must_use]
    pub const fn new(now: Instant) -> Self {
        Self {
            srtt: Srtt::unmeasured(),
            consecutive_failures: 0,
            edns: EdnsCapability::Unknown,
            minimisation: MinimisationVerdict::Unknown,
            lame_for: Vec::new(),
            last_failure: None,
            last_seen: now,
        }
    }

    /// Folds in one observation made at `now`.
    pub fn apply(&mut self, event: MetricEvent, now: Instant) {
        self.last_seen = now;
        match event {
            MetricEvent::Success(rtt) => self.record_success(rtt),
            MetricEvent::Failure => self.record_failure(now),
            MetricEvent::EdnsSupported(size) => self.edns = EdnsCapability::Supported(size),
            MetricEvent::EdnsIntolerant => {
                let until = now.checked_add(EDNS_INTOLERANCE_TTL).unwrap_or(now);
                self.edns = EdnsCapability::Intolerant(until);
            }
            MetricEvent::HandlesMinimised => {
                if !matches!(
                    self.minimisation,
                    MinimisationVerdict::MishandlesMinimised(_)
                ) {
                    self.minimisation = MinimisationVerdict::HandlesMinimised;
                }
            }
            MetricEvent::MishandlesMinimised(until) => {
                self.minimisation = MinimisationVerdict::MishandlesMinimised(until);
            }
            MetricEvent::LameFor(zone, until) => self.mark_lame(zone, until, now),
        }
    }

    /// Marks the server lame for `zone` until `until`, dropping expired marks and,
    /// past [`MAX_LAME_MARKS`], the mark that expires soonest.
    fn mark_lame(&mut self, zone: Name, until: Instant, now: Instant) {
        self.lame_for
            .retain(|mark| mark.until > now && !mark.zone.eq_ignore_case(&zone));
        self.lame_for.push(LameMark { zone, until });
        if self.lame_for.len() <= MAX_LAME_MARKS {
            return;
        }
        let soonest = self
            .lame_for
            .iter()
            .enumerate()
            .min_by_key(|(_, mark)| mark.until)
            .map(|(index, _)| index);
        if let Some(index) = soonest {
            self.lame_for.swap_remove(index);
        }
    }

    /// Advances the SRTT with a successful sample and clears the failure streak.
    pub fn record_success(&mut self, rtt: Duration) {
        self.srtt = if self.srtt == Srtt::unmeasured() {
            Srtt::initial(rtt)
        } else {
            self.srtt.update(rtt)
        };
        self.consecutive_failures = 0;
    }

    /// Penalises the SRTT and extends the failure streak.
    pub fn record_failure(&mut self, now: Instant) {
        self.srtt = self.srtt.update(FAILURE_PENALTY.saturating_mul(8));
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure = Some(now);
    }

    /// The smoothed RTT.
    #[must_use]
    pub const fn srtt(&self) -> Srtt {
        self.srtt
    }

    /// The EDNS capability as of `now`: an expired intolerance reads as unknown, so
    /// the next query sends EDNS again.
    #[must_use]
    pub fn edns(&self, now: Instant) -> EdnsCapability {
        match self.edns {
            EdnsCapability::Intolerant(until) if until <= now => EdnsCapability::Unknown,
            capability => capability,
        }
    }

    /// How many lame-zone marks are held.
    #[must_use]
    pub fn lame_mark_count(&self) -> usize {
        self.lame_for.len()
    }

    /// The minimisation verdict as of `now`: an expired verdict reads as unknown.
    #[must_use]
    pub fn minimisation(&self, now: Instant) -> MinimisationVerdict {
        match self.minimisation {
            MinimisationVerdict::MishandlesMinimised(until) if until <= now => {
                MinimisationVerdict::Unknown
            }
            verdict => verdict,
        }
    }

    /// Whether the server is marked lame for `zone` as of `now`.
    #[must_use]
    pub fn is_lame_for(&self, zone: &Name, now: Instant) -> bool {
        self.lame_for
            .iter()
            .any(|mark| mark.zone.eq_ignore_case(zone) && mark.until > now)
    }

    /// Whether the server is in failure backoff as of `now`.
    #[must_use]
    pub fn in_backoff(&self, now: Instant) -> bool {
        self.consecutive_failures >= BACKOFF_AFTER_FAILURES
            && self
                .last_failure
                .is_some_and(|failed| now.saturating_duration_since(failed) < BACKOFF_WINDOW)
    }

    /// Consecutive failures.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u16 {
        self.consecutive_failures
    }

    /// When the server was last observed.
    #[must_use]
    pub const fn last_seen(&self) -> Instant {
        self.last_seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srtt_moves_an_eighth_of_the_way_toward_each_sample() {
        let srtt = Srtt::initial(Duration::from_millis(80)).update(Duration::from_millis(160));
        assert_eq!(srtt.smoothed(), Duration::from_millis(90));
    }

    #[test]
    fn one_hostile_sample_cannot_corrupt_the_average() {
        let srtt = Srtt::initial(Duration::from_millis(20)).update(Duration::MAX);
        assert!(srtt.smoothed() <= MAX_RTT_SAMPLE);
        assert!(srtt.smoothed() < Duration::from_secs(1));
    }

    #[test]
    fn a_verdict_expires() {
        let now = Instant::now();
        let mut metrics = NameserverMetrics::new(now);
        let until = now + Duration::from_secs(10);
        metrics.apply(MetricEvent::MishandlesMinimised(until), now);
        assert_eq!(
            metrics.minimisation(now),
            MinimisationVerdict::MishandlesMinimised(until)
        );
        assert_eq!(metrics.minimisation(until), MinimisationVerdict::Unknown);
    }

    #[test]
    fn three_failures_put_a_server_in_backoff_and_a_success_clears_it() {
        let now = Instant::now();
        let mut metrics = NameserverMetrics::new(now);
        for _ in 0..BACKOFF_AFTER_FAILURES {
            metrics.apply(MetricEvent::Failure, now);
        }
        assert!(metrics.in_backoff(now));
        assert!(!metrics.in_backoff(now + BACKOFF_WINDOW));
        metrics.apply(MetricEvent::Success(Duration::from_millis(5)), now);
        assert!(!metrics.in_backoff(now));
    }

    #[test]
    fn edns_intolerance_expires_so_the_next_query_probes_again() {
        let now = Instant::now();
        let mut metrics = NameserverMetrics::new(now);
        metrics.apply(MetricEvent::EdnsIntolerant, now);
        assert!(matches!(metrics.edns(now), EdnsCapability::Intolerant(_)));
        let later = now + EDNS_INTOLERANCE_TTL;
        assert_eq!(metrics.edns(later), EdnsCapability::Unknown);
    }

    #[test]
    fn lame_marks_are_bounded_and_expired_ones_are_dropped() {
        let now = Instant::now();
        let mut metrics = NameserverMetrics::new(now);
        for index in 0..(MAX_LAME_MARKS + 20) {
            let zone = Name::from_ascii(&format!("zone{index}.example.")).unwrap();
            let until = now + Duration::from_secs(60 + index as u64);
            metrics.apply(MetricEvent::LameFor(zone, until), now);
        }
        assert_eq!(metrics.lame_mark_count(), MAX_LAME_MARKS);
        let latest = Name::from_ascii("zone83.example.").unwrap();
        assert!(metrics.is_lame_for(&latest, now));

        let expired_at = now + Duration::from_secs(10_000);
        let fresh = Name::from_ascii("fresh.example.").unwrap();
        metrics.apply(
            MetricEvent::LameFor(fresh, expired_at + Duration::from_secs(60)),
            expired_at,
        );
        assert_eq!(metrics.lame_mark_count(), 1);
    }
}
