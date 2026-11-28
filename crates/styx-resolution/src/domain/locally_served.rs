//! Names styx answers itself, without asking an upstream: the empty zones of RFC 6303 §4,
//! `localhost.` and `invalid.` (RFC 6761 §6.3–6.4), and Firefox's DoH canary.

use std::net::{Ipv4Addr, Ipv6Addr};

use styx_proto::{
    Name, Question, RData, RecordClass, RecordType, ResourceRecord, ResponseCode, SoaRdata, Ttl,
};

/// TTL of every locally served record, the SOA's negative TTL included: RFC 6303 §3 asks
/// that the two match, and a short one lets a conditional entry added later take over soon.
pub const LOCALLY_SERVED_TTL: Ttl = Ttl::from_secs(60);

/// The Firefox canary: a non-NOERROR answer tells Firefox to keep its default DoH off.
const DOH_CANARY: &str = "use-application-dns.net.";

/// `nobody.invalid.`, the empty zones' SOA RNAME (RFC 6303 §3), in wire form.
const EMPTY_ZONE_RNAME: &[u8] = b"\x06nobody\x07invalid\x00";

/// SOA timers of an empty zone. RFC 6303 §3 lets them be arbitrary, as nothing transfers
/// the zone; these are its example's.
const EMPTY_ZONE_SERIAL: u32 = 1;
const EMPTY_ZONE_REFRESH: u32 = 3600;
const EMPTY_ZONE_RETRY: u32 = 1200;
const EMPTY_ZONE_EXPIRE: u32 = 604_800;

/// The zones of RFC 6303 §4.1–4.6, answered as empty zones.
const EMPTY_ZONES: [&str; 33] = [
    "10.in-addr.arpa.",
    "16.172.in-addr.arpa.",
    "17.172.in-addr.arpa.",
    "18.172.in-addr.arpa.",
    "19.172.in-addr.arpa.",
    "20.172.in-addr.arpa.",
    "21.172.in-addr.arpa.",
    "22.172.in-addr.arpa.",
    "23.172.in-addr.arpa.",
    "24.172.in-addr.arpa.",
    "25.172.in-addr.arpa.",
    "26.172.in-addr.arpa.",
    "27.172.in-addr.arpa.",
    "28.172.in-addr.arpa.",
    "29.172.in-addr.arpa.",
    "30.172.in-addr.arpa.",
    "31.172.in-addr.arpa.",
    "168.192.in-addr.arpa.",
    "0.in-addr.arpa.",
    "127.in-addr.arpa.",
    "254.169.in-addr.arpa.",
    "2.0.192.in-addr.arpa.",
    "100.51.198.in-addr.arpa.",
    "113.0.203.in-addr.arpa.",
    "255.255.255.255.in-addr.arpa.",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
    "d.f.ip6.arpa.",
    "8.e.f.ip6.arpa.",
    "9.e.f.ip6.arpa.",
    "a.e.f.ip6.arpa.",
    "b.e.f.ip6.arpa.",
    "8.b.d.0.1.0.0.2.ip6.arpa.",
];

/// The sections of a locally served reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocallyServedReply {
    /// NOERROR or NXDOMAIN.
    pub rcode: ResponseCode,
    /// The answer section.
    pub answers: Vec<ResourceRecord>,
    /// The authority section: an empty zone's SOA on a negative reply, else nothing.
    pub authority: Vec<ResourceRecord>,
}

/// How a special-use name is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecialUse {
    /// Address questions get the loopback address, the others NODATA (RFC 6761 §6.3).
    Loopback,
    /// Every question gets NXDOMAIN (RFC 6761 §6.4, and the DoH canary).
    Nonexistent,
}

/// The table of locally served names, each matching itself and every name below it.
#[derive(Debug, Clone)]
pub struct LocallyServed {
    special: Vec<(Name, SpecialUse)>,
    empty_zones: Vec<Name>,
    deferred: Vec<Name>,
}

impl Default for LocallyServed {
    /// Every locally served name, the DoH canary included, with no zone deferred.
    fn default() -> Self {
        Self::new(Vec::new(), true)
    }
}

impl LocallyServed {
    /// Builds the table. A name under one of `deferred` is left out of the empty zones, so
    /// the conditional entry that covers it is asked instead; the special-use names are never
    /// deferred. `doh_canary` answers the DoH canary NXDOMAIN.
    #[must_use]
    pub fn new(deferred: Vec<Name>, doh_canary: bool) -> Self {
        let mut special = vec![
            ("localhost.", SpecialUse::Loopback),
            ("invalid.", SpecialUse::Nonexistent),
        ];
        if doh_canary {
            special.push((DOH_CANARY, SpecialUse::Nonexistent));
        }
        Self {
            special: special
                .into_iter()
                .filter_map(|(text, kind)| Some((Name::from_ascii(text).ok()?, kind)))
                .collect(),
            empty_zones: EMPTY_ZONES
                .iter()
                .filter_map(|text| Name::from_ascii(text).ok())
                .collect(),
            deferred,
        }
    }

    /// The reply styx gives `question` itself, or `None` when the name is not locally served.
    #[must_use]
    pub fn answer(&self, question: &Question) -> Option<LocallyServedReply> {
        let qname = &question.qname;
        if let Some((_, kind)) = self
            .special
            .iter()
            .find(|(name, _)| qname.is_subdomain_of(name))
        {
            return Some(special_use_reply(*kind, question));
        }
        let zone = self.empty_zone_of(qname)?;
        Some(empty_zone_reply(zone, question))
    }

    fn empty_zone_of(&self, qname: &Name) -> Option<&Name> {
        if self
            .deferred
            .iter()
            .any(|domain| qname.is_subdomain_of(domain))
        {
            return None;
        }
        self.empty_zones
            .iter()
            .find(|zone| qname.is_subdomain_of(zone))
    }
}

fn special_use_reply(kind: SpecialUse, question: &Question) -> LocallyServedReply {
    match kind {
        SpecialUse::Loopback => reply(ResponseCode::NOERROR, loopback(question), Vec::new()),
        SpecialUse::Nonexistent => reply(ResponseCode::NXDOMAIN, Vec::new(), Vec::new()),
    }
}

fn loopback(question: &Question) -> Vec<ResourceRecord> {
    let rdata = match question.qtype {
        RecordType::A => RData::A(Ipv4Addr::LOCALHOST),
        RecordType::AAAA => RData::Aaaa(Ipv6Addr::LOCALHOST),
        _ => return Vec::new(),
    };
    vec![record(question.qname.clone(), rdata)]
}

/// An empty zone holds only its SOA and NS at the apex (RFC 6303 §3): a name below the apex
/// does not exist, and the apex has no other type.
fn empty_zone_reply(zone: &Name, question: &Question) -> LocallyServedReply {
    if !question.qname.eq_ignore_case(zone) {
        return reply(ResponseCode::NXDOMAIN, Vec::new(), vec![soa(zone)]);
    }
    match question.qtype {
        RecordType::SOA => reply(ResponseCode::NOERROR, vec![soa(zone)], Vec::new()),
        RecordType::NS => reply(
            ResponseCode::NOERROR,
            vec![record(zone.clone(), RData::Ns(zone.clone()))],
            Vec::new(),
        ),
        _ => reply(ResponseCode::NOERROR, Vec::new(), vec![soa(zone)]),
    }
}

/// The SOA RFC 6303 §3 recommends: MNAME is the zone, the target of its only NS record.
fn soa(zone: &Name) -> ResourceRecord {
    record(
        zone.clone(),
        RData::Soa(SoaRdata::new(
            zone.clone(),
            Name::from_wire(Box::from(EMPTY_ZONE_RNAME)),
            EMPTY_ZONE_SERIAL,
            EMPTY_ZONE_REFRESH,
            EMPTY_ZONE_RETRY,
            EMPTY_ZONE_EXPIRE,
            LOCALLY_SERVED_TTL.seconds(),
        )),
    )
}

fn record(owner: Name, rdata: RData) -> ResourceRecord {
    ResourceRecord::new(
        owner,
        rdata.rtype(),
        RecordClass::In,
        LOCALLY_SERVED_TTL,
        rdata,
    )
}

const fn reply(
    rcode: ResponseCode,
    answers: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
) -> LocallyServedReply {
    LocallyServedReply {
        rcode,
        answers,
        authority,
    }
}

#[cfg(test)]
#[path = "locally_served_tests.rs"]
mod tests;
