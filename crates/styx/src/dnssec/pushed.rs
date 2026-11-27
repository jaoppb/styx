//! The push half of the validator's chain source (Phase 06, 6d.2): the DS RRsets the
//! recursor's DO=1 descent already received in its referrals (RFC 4035 §3.1.4), kept so the
//! pull half need not ask for them again.
//!
//! Pushed material is a shortcut around a fetch, not around provenance: a referral is kept
//! only for a child strictly below the zone that gave it, and only the DS records owned by
//! that child and the RRSIGs over them signed by that parent zone. The validator still
//! authenticates every record against the parent's keys before relying on it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use styx_core::Clock;
use styx_dnssec::SignedRrset;
use styx_proto::{Name, RData, RecordType, ResourceRecord};
use styx_recursion::domain::chain_material::{ChainMaterial, SignedReferral};
use styx_recursion::domain::ports::ChainMaterialSink;

/// How many zones' DS RRsets are kept at once. Each is a few hundred bytes, and a referral
/// stream an attacker steers cannot grow the store past this.
const MAX_ZONES: usize = 4096;

/// DS RRsets pushed by recursor descents, keyed by the delegated zone.
#[derive(Debug)]
pub struct PushedReferrals<C> {
    clock: Arc<C>,
    zones: Mutex<HashMap<Name, PushedDs>>,
}

#[derive(Debug, Clone)]
struct PushedDs {
    ds: SignedRrset,
    expires_at: Instant,
}

impl<C: Clock> PushedReferrals<C> {
    /// An empty store reading time from `clock`.
    #[must_use]
    pub fn new(clock: Arc<C>) -> Self {
        Self {
            clock,
            zones: Mutex::new(HashMap::new()),
        }
    }

    /// The signed DS RRset last pushed for `zone`, while its TTL lasts.
    #[must_use]
    pub fn ds_for(&self, zone: &Name) -> Option<SignedRrset> {
        let now = self.clock.now_monotonic();
        self.with_zones(|zones| {
            zones
                .get(&zone.to_canonical())
                .filter(|pushed| pushed.expires_at > now)
                .map(|pushed| pushed.ds.clone())
        })
    }

    fn keep(&self, zone: Name, pushed: PushedDs, now: Instant) {
        self.with_zones(|zones| {
            if zones.len() >= MAX_ZONES && !zones.contains_key(&zone) {
                zones.retain(|_, kept| kept.expires_at > now);
            }
            if zones.len() < MAX_ZONES || zones.contains_key(&zone) {
                zones.insert(zone, pushed);
            }
        });
    }

    fn with_zones<R>(&self, operation: impl FnOnce(&mut HashMap<Name, PushedDs>) -> R) -> R {
        let mut guard = match self.zones.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        operation(&mut guard)
    }
}

impl<C: Clock> ChainMaterialSink for PushedReferrals<C> {
    fn push(&self, material: ChainMaterial) {
        let now = self.clock.now_monotonic();
        for referral in material.referrals() {
            if let Some(pushed) = in_bailiwick(referral, now) {
                self.keep(referral.child_zone.to_canonical(), pushed, now);
            }
        }
    }
}

/// The referral's DS RRset, when it is the parent zone's to give: a child strictly below
/// the parent, DS records owned by the child, and at least one RRSIG over them by the parent.
fn in_bailiwick(referral: &SignedReferral, now: Instant) -> Option<PushedDs> {
    let SignedReferral {
        parent_zone,
        child_zone,
        ds_records,
    } = referral;
    if !child_zone.is_subdomain_of(parent_zone) || child_zone.eq_ignore_case(parent_zone) {
        return None;
    }
    let owned = |record: &&ResourceRecord| record.owner.eq_ignore_case(child_zone);
    let records: Vec<ResourceRecord> = ds_records
        .iter()
        .filter(owned)
        .filter(|record| matches!(record.rdata, RData::Ds(_)))
        .cloned()
        .collect();
    let signatures: Vec<ResourceRecord> = ds_records
        .iter()
        .filter(owned)
        .filter(|record| match &record.rdata {
            RData::Rrsig(signature) => {
                signature.type_covered() == RecordType::DS
                    && signature.signer_name().eq_ignore_case(parent_zone)
            }
            _ => false,
        })
        .cloned()
        .collect();
    if records.is_empty() || signatures.is_empty() {
        return None;
    }
    let ttl = records
        .iter()
        .chain(&signatures)
        .map(|record| record.ttl.seconds())
        .min()?;
    let expires_at = now.checked_add(Duration::from_secs(u64::from(ttl)))?;
    Some(PushedDs {
        ds: SignedRrset::new(records, signatures),
        expires_at,
    })
}

#[cfg(test)]
#[path = "pushed_tests.rs"]
mod tests;
