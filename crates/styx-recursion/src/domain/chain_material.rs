//! DNSSEC chain material collected en route, for the validator to be fed from.
//!
//! With DO=1 set on descent queries, a signed parent includes the child's DS RRset
//! and its RRSIG in every referral (RFC 4035 §3.1.4). It arrives unasked, so
//! keeping it costs nothing on the wire, while re-querying for it later would
//! double descent traffic and might reach a server with a different view.

use styx_proto::{Name, ResourceRecord};

/// A DS RRset, with its signatures, as one parent's referral delivered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReferral {
    /// The zone whose server gave the referral and signed the DS RRset.
    pub parent_zone: Name,
    /// The delegated zone the DS RRset is for.
    pub child_zone: Name,
    /// The DS records and the RRSIGs covering them.
    pub ds_records: Vec<ResourceRecord>,
}

/// Everything collected during one client question's descent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainMaterial {
    referrals: Vec<SignedReferral>,
}

impl ChainMaterial {
    /// Keeps one referral's DS material. A referral without DS records — an
    /// unsigned delegation — has nothing to keep.
    pub fn push_referral(&mut self, referral: SignedReferral) {
        if !referral.ds_records.is_empty() {
            self.referrals.push(referral);
        }
    }

    /// Adds everything `other` collected — a glue sub-descent's material, say.
    pub fn extend(&mut self, other: Self) {
        self.referrals.extend(other.referrals);
    }

    /// The DS RRsets collected, one per signed referral.
    #[must_use]
    pub fn referrals(&self) -> &[SignedReferral] {
        &self.referrals
    }

    /// Whether nothing was collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.referrals.is_empty()
    }
}
