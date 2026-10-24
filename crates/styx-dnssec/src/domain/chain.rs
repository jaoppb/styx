//! Chain material collected or queried across zone cuts.

use styx_proto::{Name, ResourceRecord};

use crate::domain::denial::DenialProof;

/// Origin of chain material, used for diagnostics and tracing.
///
/// Must not influence validation logic or verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterialOrigin {
    /// Pushed from recursive descent queries (e.g. DS RRsets in referrals).
    PushedFromDescent,
    /// Explicitly pulled on demand (e.g. forwarder path).
    PulledOnDemand,
}

/// Authentication and denial material for a single zone cut delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneCutMaterial {
    /// Delegated child zone name.
    pub zone: Name,
    /// DS records authenticated by the parent zone.
    pub ds: Option<Vec<ResourceRecord>>,
    /// Denial-of-existence proof if DS records do not exist at the delegation.
    pub ds_denial: Option<DenialProof>,
    /// DNSKEY records published by the child zone.
    pub dnskey: Option<Vec<ResourceRecord>>,
    /// Signatures over the child zone's DNSKEY RRset.
    pub dnskey_signatures: Vec<ResourceRecord>,
    /// Provenance origin of this material.
    pub origin: MaterialOrigin,
}

impl ZoneCutMaterial {
    /// Constructs a new [`ZoneCutMaterial`].
    #[must_use]
    pub fn new(
        zone: Name,
        ds: Option<Vec<ResourceRecord>>,
        ds_denial: Option<DenialProof>,
        dnskey: Option<Vec<ResourceRecord>>,
        dnskey_signatures: Vec<ResourceRecord>,
        origin: MaterialOrigin,
    ) -> Self {
        Self {
            zone,
            ds,
            ds_denial,
            dnskey,
            dnskey_signatures,
            origin,
        }
    }
}

/// Collection of zone cuts forming the chain from trust anchor to answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainMaterial {
    cuts: Vec<ZoneCutMaterial>,
}

impl ChainMaterial {
    /// Creates an empty [`ChainMaterial`].
    #[must_use]
    pub fn new() -> Self {
        Self { cuts: Vec::new() }
    }

    /// Creates a [`ChainMaterial`] containing the specified `cuts`.
    #[must_use]
    pub fn with_cuts(cuts: Vec<ZoneCutMaterial>) -> Self {
        Self { cuts }
    }

    /// Adds a cut to the collected material.
    pub fn add_cut(&mut self, cut: ZoneCutMaterial) {
        self.cuts.push(cut);
    }

    /// Returns a slice over all collected cuts.
    #[must_use]
    pub fn cuts(&self) -> &[ZoneCutMaterial] {
        &self.cuts
    }

    /// Finds material for the specified zone name.
    #[must_use]
    pub fn cut_for(&self, zone: &Name) -> Option<&ZoneCutMaterial> {
        self.cuts.iter().find(|cut| &cut.zone == zone)
    }
}
