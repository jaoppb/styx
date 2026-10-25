//! Signed-zone fixtures shared by the validator's integration tests.
//!
//! Every key is a fresh Ed25519 key, and every signature uses one fixed validity
//! window, so a test moves the injected clock rather than waiting on the calendar.

#![allow(dead_code)]
#![allow(clippy::expect_used)]

use std::time::{Duration, SystemTime};

use ring::signature::{Ed25519KeyPair, KeyPair};
use styx_core::test_util::TestClock;
use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::domain::signature::compute_dnskey_digest;
use styx_dnssec::{
    Delegation, MaterialOrigin, SignedRrset, TrustAnchor, TrustAnchorError, TrustAnchorSource,
    ZoneCutMaterial,
};
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata, RrsigRdata};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl,
};

pub const INCEPTION: u32 = 1_700_000_000;
pub const EXPIRATION: u32 = 1_700_000_200;
pub const NOW: u64 = 1_700_000_100;

pub const ED25519: u8 = 15;
pub const DIGEST_SHA1: u8 = 1;
pub const DIGEST_SHA256: u8 = 2;

pub fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("fixture name")
}

pub fn clock_at(seconds: u64) -> TestClock {
    let clock = TestClock::new();
    let now = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds));
    clock.set_utc(now.expect("fixture time"));
    clock
}

pub fn clock() -> TestClock {
    clock_at(NOW)
}

pub fn record(owner: &Name, rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord::new(
        owner.clone(),
        rtype,
        RecordClass::In,
        Ttl::from_secs(300),
        rdata,
    )
}

pub fn a_record(owner: &Name, last_octet: u8) -> ResourceRecord {
    let address = std::net::Ipv4Addr::new(192, 0, 2, last_octet);
    record(owner, RecordType::A, RData::A(address))
}

pub fn query(qname: &Name, qtype: RecordType) -> Message {
    let mut message = Message::new(Header::new_query(1, Opcode::Query, false));
    message.questions.push(Question {
        qname: qname.clone(),
        qtype,
        qclass: RecordClass::In,
    });
    message
}

/// A zone's signing key: one Ed25519 key acting as both KSK and ZSK.
pub struct ZoneKey {
    pub zone: Name,
    pub pair: Ed25519KeyPair,
    pub dnskey: DnskeyRdata,
}

impl ZoneKey {
    pub fn generate(zone: &Name) -> Self {
        Self::generate_with_flags(zone, 257)
    }

    pub fn generate_with_flags(zone: &Name, flags: u16) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let dnskey = DnskeyRdata::new(flags, 3, ED25519, pair.public_key().as_ref().to_vec());
        Self {
            zone: zone.clone(),
            pair,
            dnskey,
        }
    }

    pub fn key_tag(&self) -> u16 {
        self.dnskey.key_tag()
    }

    pub fn dnskey_record(&self) -> ResourceRecord {
        record(
            &self.zone,
            RecordType::DNSKEY,
            RData::Dnskey(self.dnskey.clone()),
        )
    }

    /// Signs `rrset` with this key over the fixed validity window.
    pub fn sign(&self, rrset: &[ResourceRecord]) -> ResourceRecord {
        self.sign_window(rrset, INCEPTION, EXPIRATION)
    }

    pub fn sign_window(
        &self,
        rrset: &[ResourceRecord],
        inception: u32,
        expiration: u32,
    ) -> ResourceRecord {
        let first = rrset.first().expect("non-empty rrset");
        let labels = u8::try_from(first.owner.label_count()).expect("label count");
        let unsigned = |signature: Vec<u8>| {
            RrsigRdata::new(
                first.rtype,
                ED25519,
                labels,
                300,
                expiration,
                inception,
                self.key_tag(),
                self.zone.clone(),
                signature,
            )
        };
        let signed_data =
            build_canonical_signed_data(&unsigned(Vec::new()), rrset).expect("canonical form");
        let signature = self.pair.sign(&signed_data).as_ref().to_vec();
        record(
            &first.owner,
            RecordType::RRSIG,
            RData::Rrsig(unsigned(signature)),
        )
    }

    /// This zone's DNSKEY RRset, self-signed.
    pub fn dnskey_rrset(&self) -> SignedRrset {
        let records = vec![self.dnskey_record()];
        let signatures = vec![self.sign(&records)];
        SignedRrset::new(records, signatures)
    }

    pub fn ds(&self, digest_type: u8) -> DsRdata {
        let digest =
            compute_dnskey_digest(&self.zone, &self.dnskey, digest_type).expect("digest type");
        DsRdata::new(self.key_tag(), ED25519, digest_type, digest)
    }

    pub fn ds_record(&self) -> ResourceRecord {
        record(
            &self.zone,
            RecordType::DS,
            RData::Ds(self.ds(DIGEST_SHA256)),
        )
    }

    pub fn anchor(&self) -> TrustAnchor {
        let ds = self.ds(DIGEST_SHA256);
        TrustAnchor::new(
            self.zone.clone(),
            ds.key_tag(),
            ds.algorithm(),
            ds.digest_type(),
            ds.digest().to_vec(),
        )
    }

    /// Material for this zone as a trust-anchored apex.
    pub fn apex_cut(&self) -> ZoneCutMaterial {
        ZoneCutMaterial::new(
            self.zone.clone(),
            Delegation::Apex {
                dnskey: self.dnskey_rrset(),
            },
            MaterialOrigin::PulledOnDemand,
        )
    }

    /// Material for a secure delegation to this zone, its DS RRset signed by `signer`.
    pub fn signed_cut(&self, signer: &ZoneKey) -> ZoneCutMaterial {
        let ds = vec![self.ds_record()];
        let ds_signatures = vec![signer.sign(&ds)];
        ZoneCutMaterial::new(
            self.zone.clone(),
            Delegation::Signed {
                ds: SignedRrset::new(ds, ds_signatures),
                dnskey: self.dnskey_rrset(),
            },
            MaterialOrigin::PulledOnDemand,
        )
    }
}

pub struct StaticAnchorSource {
    pub anchors: Vec<TrustAnchor>,
}

impl StaticAnchorSource {
    pub fn new(anchors: Vec<TrustAnchor>) -> Self {
        Self { anchors }
    }
}

impl TrustAnchorSource for StaticAnchorSource {
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustAnchorError> {
        Ok(self.anchors.clone())
    }
}
