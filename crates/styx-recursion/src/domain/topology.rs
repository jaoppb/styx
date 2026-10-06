//! What a descent learns from referrals: zone cuts, delegations, nameservers.

use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use styx_proto::{Message, Name, RData, RecordType, ResourceRecord, Ttl};

use crate::domain::bailiwick::{check_referral, is_in_bailiwick};
use crate::domain::error::RecursionError;

/// The address of an authoritative nameserver. The port is the transport's
/// concern, so a nameserver is identified by its IP alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NameserverAddr(IpAddr);

impl NameserverAddr {
    /// Wraps an address.
    #[must_use]
    pub const fn new(ip: IpAddr) -> Self {
        Self(ip)
    }

    /// The IP address.
    #[must_use]
    pub const fn ip(self) -> IpAddr {
        self.0
    }
}

impl fmt::Display for NameserverAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Where a nameserver's addresses came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlueOrigin {
    /// Glue the referring server was entitled to vouch for.
    InBailiwickGlue,
    /// Looked up by a separate sub-descent, or seeded from root hints.
    ResolvedSeparately,
    /// Glue was offered for a name the referring server may not speak for, and was
    /// thrown away: out-of-bailiwick glue is a cache-poisoning vector, not a hint.
    OutOfBailiwickDiscarded,
}

/// One nameserver of an NS set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nameserver {
    /// The nameserver's name, from the NS record.
    pub name: Name,
    /// Its known addresses; empty until glue or a sub-descent supplies them.
    pub addresses: Vec<IpAddr>,
    /// Where those addresses came from.
    pub glue_origin: GlueOrigin,
}

/// The nameservers of one zone, with the per-descent record of which addresses have
/// been tried and which names have had their addresses looked up.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NsSet {
    members: Vec<Nameserver>,
    tried: Vec<NameserverAddr>,
    lookups_attempted: Vec<Name>,
}

impl NsSet {
    /// Creates an NS set with nothing tried yet.
    #[must_use]
    pub const fn new(members: Vec<Nameserver>) -> Self {
        Self {
            members,
            tried: Vec::new(),
            lookups_attempted: Vec::new(),
        }
    }

    /// The nameservers.
    #[must_use]
    pub fn members(&self) -> &[Nameserver] {
        &self.members
    }

    /// Addresses not yet tried in this descent, in NS-set order.
    #[must_use]
    pub fn untried(&self) -> Vec<NameserverAddr> {
        self.members
            .iter()
            .flat_map(|member| member.addresses.iter().copied().map(NameserverAddr::new))
            .filter(|address| !self.tried.contains(address))
            .collect()
    }

    /// Records that `address` has been tried and should not be chosen again.
    pub fn mark_tried(&mut self, address: NameserverAddr) {
        if !self.tried.contains(&address) {
            self.tried.push(address);
        }
    }

    /// The next nameserver name with no usable address whose lookup has not been
    /// attempted. An address is usable unless it is IPv6 and `use_ipv6` is off, so a
    /// nameserver with only AAAA glue still gets an A lookup on an IPv4-only host.
    #[must_use]
    pub fn next_unresolved(&self, use_ipv6: bool) -> Option<Name> {
        self.members
            .iter()
            .filter(|member| {
                member
                    .addresses
                    .iter()
                    .all(|address| address.is_ipv6() && !use_ipv6)
            })
            .map(|member| member.name.clone())
            .find(|name| {
                !self
                    .lookups_attempted
                    .iter()
                    .any(|done| done.eq_ignore_case(name))
            })
    }

    /// Records that a lookup of `name`'s addresses was attempted.
    pub fn mark_lookup_attempted(&mut self, name: &Name) {
        self.lookups_attempted.push(name.clone());
    }

    /// Supplies addresses for `name`, looked up separately.
    pub fn provide_addresses(&mut self, name: &Name, addresses: &[IpAddr]) {
        for member in self
            .members
            .iter_mut()
            .filter(|member| member.name.eq_ignore_case(name))
        {
            member.addresses.extend_from_slice(addresses);
            member.glue_origin = GlueOrigin::ResolvedSeparately;
        }
    }
}

/// The zone a descent is currently asking, and its servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneCut {
    /// The zone apex.
    pub zone: Name,
    /// The zone's nameservers.
    pub nameservers: NsSet,
    /// Whether this is the root zone.
    pub is_root: bool,
}

impl ZoneCut {
    /// A cut at `zone` served by `nameservers`.
    #[must_use]
    pub fn new(zone: Name, nameservers: NsSet) -> Self {
        let is_root = zone.is_root();
        Self {
            zone,
            nameservers,
            is_root,
        }
    }
}

/// A delegation learned from a referral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    parent_zone: Name,
    child_zone: Name,
    nameservers: Vec<Nameserver>,
    ttl: Ttl,
    ds_records: Vec<ResourceRecord>,
    learned_at: Instant,
}

impl Delegation {
    /// Builds a delegation directly, as root hints and priming do.
    #[must_use]
    pub const fn new(
        parent_zone: Name,
        child_zone: Name,
        nameservers: Vec<Nameserver>,
        ttl: Ttl,
        learned_at: Instant,
    ) -> Self {
        Self {
            parent_zone,
            child_zone,
            nameservers,
            ttl,
            ds_records: Vec::new(),
            learned_at,
        }
    }

    /// Extracts the delegation a server for `parent_zone` gave while the descent
    /// was resolving `asked`: the NS RRset from the authority section, glue the
    /// parent may vouch for, and any DS RRset (with its signatures) for the child.
    ///
    /// # Errors
    ///
    /// Returns [`RecursionError::Malformed`] if the authority section carries no NS
    /// RRset, and the errors of [`check_referral`] for a referral that does not
    /// descend toward `asked`.
    pub fn from_referral(
        parent_zone: &Name,
        message: &Message,
        asked: &Name,
        learned_at: Instant,
    ) -> Result<Self, RecursionError> {
        let ns_records: Vec<&ResourceRecord> = message
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NS)
            .collect();
        let child_zone = ns_records
            .first()
            .map(|record| record.owner.clone())
            .ok_or(RecursionError::Malformed)?;
        check_referral(parent_zone, &child_zone, asked)?;

        let records_for_child = || {
            ns_records
                .iter()
                .copied()
                .filter(|record| record.owner.eq_ignore_case(&child_zone))
        };
        let ttl = records_for_child()
            .map(|record| record.ttl)
            .min()
            .unwrap_or(Ttl::ZERO);
        let nameservers = records_for_child()
            .filter_map(|record| match &record.rdata {
                RData::Ns(target) => Some(glue_for(parent_zone, target, &message.additionals)),
                _ => None,
            })
            .collect();
        let ds_records = message
            .authorities
            .iter()
            .filter(|record| record.owner.eq_ignore_case(&child_zone))
            .filter(|record| covers_ds(record))
            .cloned()
            .collect();

        Ok(Self {
            parent_zone: parent_zone.clone(),
            child_zone,
            nameservers,
            ttl,
            ds_records,
            learned_at,
        })
    }

    /// The zone whose server gave the referral.
    #[must_use]
    pub const fn parent_zone(&self) -> &Name {
        &self.parent_zone
    }

    /// The delegated zone.
    #[must_use]
    pub const fn child_zone(&self) -> &Name {
        &self.child_zone
    }

    /// The delegated zone's nameservers.
    #[must_use]
    pub fn nameservers(&self) -> &[Nameserver] {
        &self.nameservers
    }

    /// The NS RRset's TTL.
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// The DS RRset for the child, with its RRSIGs, as it arrived unasked (DO=1).
    #[must_use]
    pub fn ds_records(&self) -> &[ResourceRecord] {
        &self.ds_records
    }

    /// When the delegation was learned, on the injected clock.
    #[must_use]
    pub const fn learned_at(&self) -> Instant {
        self.learned_at
    }

    /// The zone cut this delegation leads to.
    #[must_use]
    pub fn to_cut(&self) -> ZoneCut {
        ZoneCut::new(
            self.child_zone.clone(),
            NsSet::new(self.nameservers.clone()),
        )
    }
}

/// Builds the [`Nameserver`] for `target`, taking addresses only from glue the
/// parent zone's server is entitled to vouch for.
fn glue_for(parent_zone: &Name, target: &Name, additionals: &[ResourceRecord]) -> Nameserver {
    if !is_in_bailiwick(parent_zone, target) {
        let offered = additionals
            .iter()
            .any(|record| record.owner.eq_ignore_case(target));
        return Nameserver {
            name: target.clone(),
            addresses: Vec::new(),
            glue_origin: if offered {
                GlueOrigin::OutOfBailiwickDiscarded
            } else {
                GlueOrigin::ResolvedSeparately
            },
        };
    }
    let addresses = additionals
        .iter()
        .filter(|record| record.owner.eq_ignore_case(target))
        .filter_map(|record| match record.rdata {
            RData::A(address) => Some(IpAddr::V4(address)),
            RData::Aaaa(address) => Some(IpAddr::V6(address)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let glue_origin = if addresses.is_empty() {
        GlueOrigin::ResolvedSeparately
    } else {
        GlueOrigin::InBailiwickGlue
    };
    Nameserver {
        name: target.clone(),
        addresses,
        glue_origin,
    }
}

fn covers_ds(record: &ResourceRecord) -> bool {
    match &record.rdata {
        RData::Ds(_) => true,
        RData::Rrsig(signature) => signature.type_covered() == RecordType::DS,
        _ => false,
    }
}
