//! NSEC-based proofs of non-existence (RFC 4035 §3.1.3, §5.4).

use styx_proto::domain::rdata::NsecRdata;
use styx_proto::{Name, RData, RecordType, ResourceRecord};

use crate::domain::denial::{longest_common_ancestor, nsec_covers_name, ClosestEncloserProof};
use crate::domain::error::DenialError;
use crate::domain::node_types::OwnerTypes;

/// NSEC records that together prove a name or a type absent within one zone.
///
/// Built only through [`DenialProof`](crate::domain::denial::DenialProof), which is the
/// one public verifier: each leg here proves part of a denial, never a whole one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsecProof {
    records: Vec<ResourceRecord>,
}

impl NsecProof {
    pub(crate) fn new(records: Vec<ResourceRecord>) -> Self {
        Self { records }
    }

    pub(crate) fn records(&self) -> &[ResourceRecord] {
        &self.records
    }

    fn nsecs(&self) -> impl Iterator<Item = (&Name, &NsecRdata)> {
        self.records.iter().filter_map(|record| match record.rdata {
            RData::Nsec(ref nsec) => Some((&record.owner, nsec)),
            _ => None,
        })
    }

    fn check_zone(&self, signer_zone: &Name, qname: &Name) -> Result<(), DenialError> {
        let all_in_zone = !self.records.is_empty()
            && self
                .records
                .iter()
                .all(|record| record.owner.is_subdomain_of(signer_zone));
        if all_in_zone && qname.is_subdomain_of(signer_zone) {
            Ok(())
        } else {
            Err(DenialError::NotCovered)
        }
    }

    /// The NSEC owned by `name`, if the proof carries one.
    fn matching(&self, name: &Name) -> Option<&NsecRdata> {
        self.nsecs()
            .find(|(owner, _)| owner.eq_ignore_case(name))
            .map(|(_, nsec)| nsec)
    }

    fn covers(&self, name: &Name) -> bool {
        self.nsecs()
            .any(|(owner, nsec)| nsec_covers_name(owner, nsec.next_domain(), name))
    }

    /// The closest encloser of `qname` within `signer_zone` that a covering NSEC implies,
    /// provided the zone is still authoritative there.
    fn closest_encloser(&self, signer_zone: &Name, qname: &Name) -> Result<Name, DenialError> {
        self.nsecs()
            .filter(|(owner, nsec)| nsec_covers_name(owner, nsec.next_domain(), qname))
            .map(|(owner, nsec)| {
                let left = longest_common_ancestor(qname, owner);
                let right = longest_common_ancestor(qname, nsec.next_domain());
                if left.label_count() >= right.label_count() {
                    left
                } else {
                    right
                }
            })
            .find(|encloser| {
                encloser.is_subdomain_of(signer_zone) && !self.ends_authority(encloser)
            })
            .ok_or(DenialError::NotCovered)
    }

    fn ends_authority(&self, name: &Name) -> bool {
        self.matching(name)
            .is_some_and(|nsec| OwnerTypes::new(name, nsec.types()).ends_authority())
    }

    /// NXDOMAIN: an NSEC covers `qname`, and another covers the wildcard at its closest
    /// encloser (RFC 4035 §5.4).
    pub(crate) fn prove_nxdomain(
        &self,
        signer_zone: &Name,
        qname: &Name,
    ) -> Result<(), DenialError> {
        self.check_zone(signer_zone, qname)?;
        let encloser = self.closest_encloser(signer_zone, qname)?;
        let legs = ClosestEncloserProof::new(qname, encloser)?;
        if self.covers(legs.wildcard()) {
            Ok(())
        } else {
            Err(DenialError::DenialProofIncomplete)
        }
    }

    /// NODATA, in the three shapes RFC 4035 §3.1.3 allows: an NSEC owned by `qname`
    /// without `qtype`; an empty non-terminal, whose covering NSEC's next name lies below
    /// `qname`; or a wildcard at the closest encloser that lacks `qtype`.
    pub(crate) fn prove_nodata(
        &self,
        signer_zone: &Name,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(), DenialError> {
        self.check_zone(signer_zone, qname)?;
        if let Some(nsec) = self.matching(qname) {
            return if OwnerTypes::new(qname, nsec.types()).denies(qtype) {
                Ok(())
            } else {
                Err(DenialError::NotCovered)
            };
        }
        if qtype != RecordType::DS && self.proves_empty_non_terminal(qname) {
            return Ok(());
        }
        let encloser = self.closest_encloser(signer_zone, qname)?;
        let legs = ClosestEncloserProof::new(qname, encloser)?;
        match self.matching(legs.wildcard()) {
            Some(nsec) if OwnerTypes::new(legs.wildcard(), nsec.types()).denies(qtype) => Ok(()),
            _ => Err(DenialError::NotCovered),
        }
    }

    fn proves_empty_non_terminal(&self, qname: &Name) -> bool {
        self.nsecs().any(|(owner, nsec)| {
            let next = nsec.next_domain();
            nsec_covers_name(owner, next, qname)
                && next.is_subdomain_of(qname)
                && !next.eq_ignore_case(qname)
        })
    }

    /// No name closer than the wildcard's closest encloser exists for a wildcard
    /// expansion of `owner` (RFC 4035 §5.3.4).
    pub(crate) fn prove_wildcard_expansion(
        &self,
        signer_zone: &Name,
        owner: &Name,
        signature_labels: u8,
    ) -> Result<(), DenialError> {
        self.check_zone(signer_zone, owner)?;
        let max_encloser_labels = usize::from(signature_labels);
        match self.closest_encloser(signer_zone, owner) {
            Ok(encloser) if encloser.label_count() <= max_encloser_labels => Ok(()),
            _ => Err(DenialError::DenialProofIncomplete),
        }
    }

    /// No DS at the delegation `zone`: the parent's NSEC owned by `zone` lists NS, and
    /// neither DS nor SOA.
    pub(crate) fn prove_ds_absence(
        &self,
        signer_zone: &Name,
        zone: &Name,
    ) -> Result<(), DenialError> {
        self.check_zone(signer_zone, zone)?;
        match self.matching(zone) {
            Some(nsec) if OwnerTypes::new(zone, nsec.types()).is_unsigned_delegation() => Ok(()),
            _ => Err(DenialError::NotCovered),
        }
    }
}
