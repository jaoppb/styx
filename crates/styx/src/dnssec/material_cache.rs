//! Chain material fetched for one validation, kept for the next ones.
//!
//! Without it every validated cache miss would ask the pool for the DS and DNSKEY RRsets of
//! every zone cut from the root down, a handful of round trips before the answer leaves. An
//! entry lives as long as the shortest TTL among the records it holds, at most
//! [`MAX_LIFETIME`]; the validator still checks every signature's validity window against
//! its own clock on every use, so a kept entry never outlives a signature unnoticed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use styx_core::Clock;
use styx_dnssec::{Delegation, SignedRrset, ZoneCutMaterial};
use styx_proto::{Name, ResourceRecord};

/// How many zones' material is kept at once.
const MAX_ZONES: usize = 4096;

/// The longest any material is kept, whatever its TTLs say.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// How long a "not a zone cut" answer is kept. It carries no records of its own to take a
/// TTL from, and a new delegation should be noticed within minutes.
const NOT_A_CUT_LIFETIME: Duration = Duration::from_secs(60);

/// Material per zone, each entry with its own expiry.
#[derive(Debug)]
pub struct MaterialCache<C> {
    clock: Arc<C>,
    zones: Mutex<HashMap<Name, Kept>>,
}

#[derive(Debug, Clone)]
struct Kept {
    material: ZoneCutMaterial,
    expires_at: Instant,
}

impl<C: Clock> MaterialCache<C> {
    /// An empty cache reading time from `clock`.
    #[must_use]
    pub fn new(clock: Arc<C>) -> Self {
        Self {
            clock,
            zones: Mutex::new(HashMap::new()),
        }
    }

    /// The material kept for `zone`, unless it has expired.
    #[must_use]
    pub fn get(&self, zone: &Name) -> Option<ZoneCutMaterial> {
        let now = self.clock.now_monotonic();
        self.with_zones(|zones| {
            zones
                .get(&zone.to_canonical())
                .filter(|kept| kept.expires_at > now)
                .map(|kept| kept.material.clone())
        })
    }

    /// Keeps `material` for as long as its records allow.
    pub fn keep(&self, material: &ZoneCutMaterial) {
        let now = self.clock.now_monotonic();
        let Some(expires_at) = now.checked_add(lifetime(&material.delegation)) else {
            return;
        };
        let zone = material.zone.to_canonical();
        let kept = Kept {
            material: material.clone(),
            expires_at,
        };
        self.with_zones(|zones| {
            if zones.len() >= MAX_ZONES && !zones.contains_key(&zone) {
                zones.retain(|_, entry| entry.expires_at > now);
            }
            if zones.len() < MAX_ZONES || zones.contains_key(&zone) {
                zones.insert(zone, kept);
            }
        });
    }

    fn with_zones<R>(&self, operation: impl FnOnce(&mut HashMap<Name, Kept>) -> R) -> R {
        let mut guard = match self.zones.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        operation(&mut guard)
    }
}

fn lifetime(delegation: &Delegation) -> Duration {
    let records: Vec<&ResourceRecord> = match delegation {
        Delegation::NotACut => return NOT_A_CUT_LIFETIME,
        Delegation::Apex { dnskey } => rrset_records(dnskey).collect(),
        Delegation::Signed { ds, dnskey } => {
            rrset_records(ds).chain(rrset_records(dnskey)).collect()
        }
        Delegation::Unsigned {
            ds_denial,
            signatures,
        } => ds_denial.records().iter().chain(signatures).collect(),
    };
    records
        .iter()
        .map(|record| Duration::from_secs(u64::from(record.ttl.seconds())))
        .min()
        .map_or(Duration::ZERO, |shortest| shortest.min(MAX_LIFETIME))
}

fn rrset_records(rrset: &SignedRrset) -> impl Iterator<Item = &ResourceRecord> {
    rrset.records.iter().chain(&rrset.signatures)
}
