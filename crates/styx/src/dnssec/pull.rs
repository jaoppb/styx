//! The validator's chain source (Phase 06, 6d.2 and 6d.3): DS and DNSKEY RRsets asked of the
//! upstream pool on demand, the DS taken from a recursor's referral when one was pushed.
//!
//! Every query goes through the pool with DO=1 and CD=1 (the forwarder always sets both), so
//! a forwarder and a recursor are asked alike. An answer that comes back without the
//! RRSIGs or denial records DNSSEC requires — a forwarder that strips them, an upstream that
//! ignores DO — is a [`ChainSourceError`], which the validator turns into
//! `Indeterminate/ChainMaterialUnavailable`. It is never taken for an unsigned zone: that
//! conflation is the downgrade this split exists to prevent.

use std::sync::Arc;
use std::time::Duration;

use styx_core::{Clock, Upstream};
use styx_dnssec::{
    ChainSource, ChainSourceError, Delegation, DenialProof, Nsec3IterationsCap, SignedRrset,
    TrustAnchors, ZoneCutMaterial,
};
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType, ResourceRecord};
use styx_resolution::{SelectionStrategy, UpstreamPool};

use crate::dnssec::material_cache::MaterialCache;
use crate::dnssec::pushed::PushedReferrals;

/// Fetches chain material through `pool`, preferring DS RRsets `pushed` by recursors.
pub struct PoolChainSource<S, U, C> {
    pool: Arc<UpstreamPool<S, U, C>>,
    pushed: Arc<PushedReferrals<C>>,
    cache: MaterialCache<C>,
    clock: Arc<C>,
    query_timeout: Duration,
    anchored: Vec<Name>,
    nsec3_cap: Nsec3IterationsCap,
}

impl<S, U, C> PoolChainSource<S, U, C>
where
    S: SelectionStrategy,
    U: Upstream + Clone + 'static,
    C: Clock,
{
    /// A source asking `pool`, giving each query `query_timeout`. The zones `anchors` vouch
    /// for are apexes whose DNSKEY RRset the anchors authenticate directly.
    #[must_use]
    pub fn new(
        pool: Arc<UpstreamPool<S, U, C>>,
        pushed: Arc<PushedReferrals<C>>,
        clock: Arc<C>,
        query_timeout: Duration,
        anchors: &TrustAnchors,
        nsec3_cap: Nsec3IterationsCap,
    ) -> Self {
        Self {
            pool,
            pushed,
            cache: MaterialCache::new(Arc::clone(&clock)),
            clock,
            query_timeout,
            anchored: anchors
                .as_slice()
                .iter()
                .map(|anchor| anchor.owner().clone())
                .collect(),
            nsec3_cap,
        }
    }

    async fn fetch(&self, zone: &Name) -> Result<ZoneCutMaterial, ChainSourceError> {
        if self
            .anchored
            .iter()
            .any(|anchor| anchor.eq_ignore_case(zone))
        {
            let dnskey = self.dnskey(zone).await?;
            return Ok(ZoneCutMaterial::new(
                zone.clone(),
                Delegation::Apex { dnskey },
            ));
        }
        let delegation = match self.pushed.ds_for(zone) {
            Some(ds) => {
                tracing::debug!(%zone, origin = "pushed", "DS taken from a recursor referral");
                Delegation::Signed {
                    ds,
                    dnskey: self.dnskey(zone).await?,
                }
            }
            None => self.pulled_delegation(zone).await?,
        };
        Ok(ZoneCutMaterial::new(zone.clone(), delegation))
    }

    /// Asks for the DS RRset at `zone`: a signed one makes a secure delegation, and its
    /// absence is classified from the parent's denial records.
    async fn pulled_delegation(&self, zone: &Name) -> Result<Delegation, ChainSourceError> {
        let reply = self.ask(zone, RecordType::DS).await?;
        let ds = signed_rrset(&reply.answers, zone, RecordType::DS);
        if ds.records.is_empty() {
            return self.classify_absence(zone, &reply);
        }
        if ds.signatures.is_empty() {
            return Err(stripped(zone, RecordType::DS));
        }
        Ok(Delegation::Signed {
            ds,
            dnskey: self.dnskey(zone).await?,
        })
    }

    /// No DS at `zone`: an unsigned delegation when the parent's signed NSEC or NSEC3
    /// records say so, otherwise not a zone cut at all. A reply without signed denial
    /// records proves neither, so it is an error rather than a guess.
    ///
    /// The classification only decides which material to hand over; the validator
    /// authenticates the proof against the parent's keys and checks it again.
    fn classify_absence(
        &self,
        zone: &Name,
        reply: &Message,
    ) -> Result<Delegation, ChainSourceError> {
        let proof_records: Vec<&ResourceRecord> = reply
            .authorities
            .iter()
            .filter(|record| matches!(record.rtype, RecordType::NSEC | RecordType::NSEC3))
            .collect();
        let signatures: Vec<ResourceRecord> = reply
            .authorities
            .iter()
            .filter(|record| covers_denial(record))
            .cloned()
            .collect();
        let signer = signatures.iter().find_map(|record| match &record.rdata {
            RData::Rrsig(signature) => Some(signature.signer_name().clone()),
            _ => None,
        });
        let (Some(signer), false) = (signer, proof_records.is_empty()) else {
            return Err(stripped(zone, RecordType::NSEC));
        };
        let ds_denial = DenialProof::from_records(&proof_records)
            .map_err(|_| stripped(zone, RecordType::NSEC))?;
        if ds_denial
            .prove_ds_absence(&signer, zone, self.nsec3_cap)
            .is_ok()
        {
            return Ok(Delegation::Unsigned {
                ds_denial,
                signatures,
            });
        }
        Ok(Delegation::NotACut)
    }

    async fn dnskey(&self, zone: &Name) -> Result<SignedRrset, ChainSourceError> {
        let reply = self.ask(zone, RecordType::DNSKEY).await?;
        let dnskey = signed_rrset(&reply.answers, zone, RecordType::DNSKEY);
        if dnskey.records.is_empty() || dnskey.signatures.is_empty() {
            return Err(stripped(zone, RecordType::DNSKEY));
        }
        Ok(dnskey)
    }

    async fn ask(&self, zone: &Name, rtype: RecordType) -> Result<Message, ChainSourceError> {
        let question = Question::new(zone.clone(), rtype, RecordClass::In);
        let now = self.clock.now_monotonic();
        let Some(deadline) = now.checked_add(self.query_timeout) else {
            return Err(ChainSourceError::Unavailable(zone.clone()));
        };
        match self.pool.resolve(&question, deadline).await {
            Ok(response) => Ok(response.message),
            Err(error) => {
                tracing::debug!(%zone, ?rtype, %error, "chain material query failed");
                Err(ChainSourceError::Unavailable(zone.clone()))
            }
        }
    }
}

impl<S, U, C> ChainSource for PoolChainSource<S, U, C>
where
    S: SelectionStrategy,
    U: Upstream + Clone + 'static,
    C: Clock,
{
    async fn material_for(&self, zone: &Name) -> Result<ZoneCutMaterial, ChainSourceError> {
        if let Some(material) = self.cache.get(zone) {
            return Ok(material);
        }
        let material = self.fetch(zone).await?;
        self.cache.keep(&material);
        Ok(material)
    }
}

/// The records of `rtype` owned by `owner`, and the RRSIGs over them.
fn signed_rrset(records: &[ResourceRecord], owner: &Name, rtype: RecordType) -> SignedRrset {
    let owned = || {
        records
            .iter()
            .filter(|record| record.owner.eq_ignore_case(owner))
    };
    SignedRrset::new(
        owned()
            .filter(|record| record.rtype == rtype)
            .cloned()
            .collect(),
        owned()
            .filter(|record| {
                matches!(&record.rdata, RData::Rrsig(signature) if signature.type_covered() == rtype)
            })
            .cloned()
            .collect(),
    )
}

fn covers_denial(record: &ResourceRecord) -> bool {
    matches!(
        &record.rdata,
        RData::Rrsig(signature)
            if matches!(signature.type_covered(), RecordType::NSEC | RecordType::NSEC3)
    )
}

fn stripped(zone: &Name, rtype: RecordType) -> ChainSourceError {
    tracing::warn!(
        %zone,
        ?rtype,
        "upstream reply lacks the signed records DNSSEC requires; it may strip DNSSEC"
    );
    ChainSourceError::Unavailable(zone.clone())
}

#[cfg(test)]
#[path = "pull_tests.rs"]
mod tests;
