//! `RecursionDiagnostics`: is the internet's delegation infrastructure reachable
//! from this box?
//!
//! Deliberately a different type, with a different name, from the pool's
//! `HealthState`, which answers "should the pool send the next query here?".
//! Conflating the two makes an outage undiagnosable. Every field is derived from
//! real descent and priming traffic — the recursor runs no probe loop of its own —
//! so each status carries the time it was last observed, and a stale entry looks
//! stale.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use styx_proto::Name;

/// The outcome of the most recent contact with a server or zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactOutcome {
    /// Not contacted since startup.
    NeverContacted,
    /// The last query was answered.
    Answered,
    /// The last query timed out or failed.
    Failed,
}

/// One root server's reachability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootServerStatus {
    /// The root server's name.
    pub name: Name,
    /// The address queried.
    pub address: IpAddr,
    /// The outcome of the last contact.
    pub last_outcome: ContactOutcome,
    /// The round-trip time of the last answered query.
    pub last_rtt: Option<Duration>,
    /// When it was last contacted.
    pub last_contact: Option<Instant>,
}

/// One top-level domain's reachability, judged by its servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TldStatus {
    /// The TLD.
    pub tld: Name,
    /// The outcome of the last contact with any of its servers.
    pub last_outcome: ContactOutcome,
    /// When it was last contacted.
    pub last_contact: Option<Instant>,
}

/// A snapshot of the recursor's view of delegation infrastructure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursionDiagnostics {
    /// Root servers, from the current root NS set.
    pub roots: Vec<RootServerStatus>,
    /// TLDs the recursor has contacted.
    pub tlds: Vec<TldStatus>,
    /// When the root NS set was last refreshed from a live priming query.
    pub last_successful_priming: Option<Instant>,
    /// Client questions resolved by descent since startup.
    pub descents_total: u64,
    /// Of those, how many failed.
    pub descents_failed: u64,
    /// Descents that fell back to the full qname — the visible measure of how much
    /// minimisation leaked.
    pub minimisation_fallbacks: u64,
    /// When this snapshot was taken.
    pub observed_at: Instant,
}
