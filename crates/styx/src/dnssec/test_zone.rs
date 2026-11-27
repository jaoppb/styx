//! Signed-zone fixtures for the binary's DNSSEC wiring tests, after
//! `styx-dnssec/tests/support`: one fresh Ed25519 key per zone, every signature over one
//! fixed validity window, so a test sets the injected clock rather than the calendar.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use ring::signature::{Ed25519KeyPair, KeyPair};
use styx_core::test_util::TestClock;
use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::domain::signature::compute_dnskey_digest;
use styx_dnssec::{DigestType, TrustAnchor, TrustAnchors};
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata, NsecRdata, RrsigRdata, TypeBitmap};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord, Ttl};

pub const INCEPTION: u32 = 1_700_000_000;
pub const EXPIRATION: u32 = 1_700_003_600;
pub const NOW: u64 = 1_700_000_100;
const ED25519: u8 = 15;
const ZONE_KEY_FLAGS: u16 = 257;

/// Parses a fixture name.
pub fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("fixture name")
}

/// A test clock whose wall time is [`NOW`], inside every fixture signature's window.
pub fn clock() -> TestClock {
    let clock = TestClock::new();
    clock.set_utc(
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(NOW))
            .expect("fixture time"),
    );
    clock
}

/// A record of `rdata`'s type at `owner`, with a 300 s TTL.
pub fn record(owner: &Name, rdata: RData) -> ResourceRecord {
    ResourceRecord::new(
        owner.clone(),
        rdata.rtype(),
        RecordClass::In,
        Ttl::from_secs(300),
        rdata,
    )
}

/// An A record at `owner`.
pub fn a_record(owner: &Name) -> ResourceRecord {
    record(owner, RData::A(Ipv4Addr::new(192, 0, 2, 7)))
}

/// An NSEC record at `owner` pointing at `next`, listing `types` (all below 256).
pub fn nsec(owner: &Name, next: &Name, types: &[RecordType]) -> ResourceRecord {
    let mut octets = [0u8; 32];
    for rtype in types {
        let value = usize::from(rtype.value());
        let slot = octets.get_mut(value >> 3).expect("window-0 type");
        *slot |= 0x80 >> (value & 7);
    }
    let last = octets
        .iter()
        .rposition(|&octet| octet != 0)
        .expect("a type");
    let used = octets.get(..=last).expect("in range");
    let mut windows = vec![0, u8::try_from(used.len()).expect("at most 32")];
    windows.extend_from_slice(used);
    let rdata = NsecRdata::new(next.clone(), TypeBitmap::new(windows));
    record(owner, RData::Nsec(rdata))
}

/// One zone's key, acting as both KSK and ZSK.
pub struct ZoneKey {
    zone: Name,
    pair: Ed25519KeyPair,
    dnskey: DnskeyRdata,
}

impl ZoneKey {
    /// A fresh key for `zone`.
    pub fn generate(zone: &str) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let public_key = pair.public_key().as_ref().to_vec();
        Self {
            zone: name(zone),
            pair,
            dnskey: DnskeyRdata::new(ZONE_KEY_FLAGS, 3, ED25519, public_key),
        }
    }

    /// The zone this key signs for.
    pub fn zone(&self) -> &Name {
        &self.zone
    }

    /// The RRSIG this key makes over `rrset`, all of one owner and type.
    pub fn sign(&self, rrset: &[ResourceRecord]) -> ResourceRecord {
        let first = rrset.first().expect("non-empty rrset");
        let labels = u8::try_from(first.owner.label_count()).expect("label count");
        let rrsig = |signature: Vec<u8>| {
            RrsigRdata::new(
                first.rtype,
                ED25519,
                labels,
                300,
                EXPIRATION,
                INCEPTION,
                self.dnskey.key_tag(),
                self.zone.clone(),
                signature,
            )
        };
        let rrset: Vec<&ResourceRecord> = rrset.iter().collect();
        let signed_data =
            build_canonical_signed_data(&rrsig(Vec::new()), &rrset).expect("canonical form");
        let signature = self.pair.sign(&signed_data).as_ref().to_vec();
        record(&first.owner, RData::Rrsig(rrsig(signature)))
    }

    /// `rrset` followed by this key's signature over it.
    pub fn signed(&self, rrset: Vec<ResourceRecord>) -> Vec<ResourceRecord> {
        let signature = self.sign(&rrset);
        rrset.into_iter().chain([signature]).collect()
    }

    /// The zone's DNSKEY RRset with its self-signature.
    pub fn dnskey_rrset(&self) -> Vec<ResourceRecord> {
        self.signed(vec![record(&self.zone, RData::Dnskey(self.dnskey.clone()))])
    }

    fn ds_rdata(&self) -> DsRdata {
        let digest =
            compute_dnskey_digest(&self.zone, &self.dnskey, DigestType::SHA256).expect("digest");
        DsRdata::new(
            self.dnskey.key_tag(),
            ED25519,
            DigestType::SHA256.value(),
            digest,
        )
    }

    /// The DS record for this zone, as its parent publishes it.
    pub fn ds_record(&self) -> ResourceRecord {
        record(&self.zone, RData::Ds(self.ds_rdata()))
    }

    /// A trust anchor at this zone vouching for its key.
    pub fn anchors(&self) -> TrustAnchors {
        TrustAnchors::new(TrustAnchor::new(self.zone.clone(), self.ds_rdata()))
    }
}
