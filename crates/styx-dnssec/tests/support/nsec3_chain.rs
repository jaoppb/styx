//! A zone's NSEC3 hash chain built from the names that exist in it.

use styx_dnssec::domain::denial::Nsec3Params;
use styx_dnssec::domain::nsec3::hash_nsec3_name;
use styx_dnssec::{Nsec3HashAlgorithm, Nsec3IterationsCap};
use styx_proto::domain::rdata::{Nsec3Rdata, TypeBitmap};
use styx_proto::{Name, RData, RecordType, ResourceRecord};

use super::{base32hex_encode, bitmap, name, record};

pub const SALT: [u8; 2] = [0xAB, 0xCD];
pub const CAP: Nsec3IterationsCap = Nsec3IterationsCap::DEFAULT;
pub const APEX_TYPES: &[RecordType] = &[
    RecordType::NS,
    RecordType::SOA,
    RecordType::RRSIG,
    RecordType::DNSKEY,
    RecordType::NSEC3PARAM,
];

pub fn hash(owner: &Name) -> Vec<u8> {
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, SALT.to_vec());
    hash_nsec3_name(owner, &params, CAP).expect("SHA-1 under the cap")
}

/// One existing name of the zone: its types, and whether the NSEC3 at it has Opt-Out.
pub struct Node {
    pub owner: Name,
    pub types: &'static [RecordType],
    pub opt_out: bool,
}

pub fn node(owner: &str, types: &'static [RecordType]) -> Node {
    Node {
        owner: name(owner),
        types,
        opt_out: false,
    }
}

/// The zone's NSEC3 chain in hash order, each record pointing at the next and the last
/// wrapping to the first.
pub fn chain(zone: &Name, nodes: &[Node]) -> Vec<ResourceRecord> {
    let mut hashed: Vec<(Vec<u8>, &Node)> =
        nodes.iter().map(|node| (hash(&node.owner), node)).collect();
    hashed.sort_by(|left, right| left.0.cmp(&right.0));
    let nexts = hashed.iter().cycle().skip(1).map(|(next, _)| next.clone());
    hashed
        .iter()
        .zip(nexts)
        .map(|((owner_hash, node), next)| {
            let owner = name(&format!("{}.{zone}", base32hex_encode(owner_hash)));
            let types = if node.types.is_empty() {
                TypeBitmap::new(Vec::new())
            } else {
                bitmap(node.types)
            };
            let flags = u8::from(node.opt_out);
            let rdata = Nsec3Rdata::new(1, flags, 1, SALT.to_vec(), next, types);
            record(&owner, RecordType::NSEC3, RData::Nsec3(rdata))
        })
        .collect()
}

pub fn opt_out(mut nodes: Vec<Node>) -> Vec<Node> {
    for node in &mut nodes {
        node.opt_out = true;
    }
    nodes
}
