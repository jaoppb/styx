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

/// An RRset together with the RRSIG records that cover it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRrset {
    /// The records of the RRset.
    pub records: Vec<ResourceRecord>,
    /// The RRSIG records covering `records`.
    pub signatures: Vec<ResourceRecord>,
}

impl SignedRrset {
    /// Constructs a new [`SignedRrset`].
    #[must_use]
    pub fn new(records: Vec<ResourceRecord>, signatures: Vec<ResourceRecord>) -> Self {
        Self {
            records,
            signatures,
        }
    }
}

/// What the chain source knows about one name on the way down to the answer.
///
/// None of this material is trusted as delivered: the validator authenticates every
/// RRset against keys it has already authenticated before relying on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delegation {
    /// The name is not a zone cut; the enclosing zone stays authoritative for it.
    NotACut,
    /// A zone apex with no parent-side material, as at the root: only a trust anchor
    /// can vouch for its DNSKEY RRset.
    Apex {
        /// The zone's DNSKEY RRset and its self-signatures.
        dnskey: SignedRrset,
    },
    /// A secure delegation.
    Signed {
        /// The DS RRset at the delegation, signed by the parent zone.
        ds: SignedRrset,
        /// The child zone's DNSKEY RRset and its self-signatures.
        dnskey: SignedRrset,
    },
    /// An unsigned delegation.
    Unsigned {
        /// The parent zone's proof that no DS RRset exists at the delegation.
        ds_denial: DenialProof,
        /// The RRSIG records covering the proof's NSEC or NSEC3 records.
        signatures: Vec<ResourceRecord>,
    },
}

impl Delegation {
    /// The zone's own signed DNSKEY RRset, when this material carries one.
    #[must_use]
    pub fn dnskey(&self) -> Option<&SignedRrset> {
        match self {
            Self::Apex { dnskey } | Self::Signed { dnskey, .. } => Some(dnskey),
            Self::NotACut | Self::Unsigned { .. } => None,
        }
    }
}

/// Chain material for a single name: whether it is a zone cut, and the proof material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneCutMaterial {
    /// The name this material describes.
    pub zone: Name,
    /// The delegation material for `zone`.
    pub delegation: Delegation,
    /// Provenance origin of this material.
    pub origin: MaterialOrigin,
}

impl ZoneCutMaterial {
    /// Constructs a new [`ZoneCutMaterial`].
    #[must_use]
    pub fn new(zone: Name, delegation: Delegation, origin: MaterialOrigin) -> Self {
        Self {
            zone,
            delegation,
            origin,
        }
    }
}
