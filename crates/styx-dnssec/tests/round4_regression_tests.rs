//! Regression tests for PR #131 round-4 review findings.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, RsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING, RSA_PKCS1_SHA512,
};
use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::domain::denial::{DenialProof, Nsec3Params};
use styx_dnssec::domain::nsec3::hash_nsec3_name;
use styx_dnssec::domain::signature::{compute_dnskey_digest, verify_rrsig_record};
use styx_dnssec::{
    ChainSource, ChainSourceError, Delegation, DigestType, DnssecAlgorithm, InMemoryChainSource,
    Nsec3HashAlgorithm, Nsec3IterationsCap, SignedRrset, TrustAnchor, TrustAnchors,
    ValidationPolicy, ValidationVerdict, Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata, Nsec3Rdata, RrsigRdata};
use styx_proto::{Name, RData, RecordType, ResourceRecord, ResponseCode};
use support::{
    a_record, base32hex_encode, bitmap, clock, mark_non_cuts, name, nsec, query, record, ZoneKey,
    EXPIRATION, INCEPTION,
};

const RSA_2048_PKCS8_HEX: &str = "\
308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100ac668501ac2f0ff001f6\
d2b6d9abeed4707b9749d683c5635ab33d7cee9d7904b17277a1788638def1a7a8f2640ab17d7d6fb06349eebec13e\
451d70c28f7332e0f9c0c705a03ebb5c7719482fe5d6182c50cb5ec7f1b6c65e1ea2b7419ab4400b46dd178241e930\
be58612aef5bae1a98ac7f75e2cdb125a57faf30eb27030ffb1be0ddfd6a587e91805ebffc3b074f29c821742963bb\
60f991ed95cb53b21b7a1c1a7cdeea6a31c911dbce50663ff3a64d70b1553751d903b4af6bb781057580eca1fcf348\
5d8eec1f5ac62025d3b04f8bc631a5e0201e50d2e0186fcafce033591d275a33d94a65d56b00401ec91009793a325a\
6c664f0a1755e0930ff6f102030100010282010019a0a8749e07659b9c7722a355753bacaf1c8d849ce8fc03da7245\
99823bbcc727fcfcefef0e28d06a0f8320fbcd23cda4980b44f488687e7fc6b4c07e88e62b8734fe900c9e8c64bc08\
8fa4b84b615ee38b8e726efa2d5ce1eb34edfff3183363046c38f7e9db591dc533e08c31f938c69447384622f9dfea\
465cf66d2660a11612c92f31d7f0032f901df76cbb924129f85b7772b322dc0c317e391ac207b7a9d98f828fc9d69b9\
21a040a4aab4faad43aee717302f84611cd6ecc48882ac85bc044c7515f8d865a658f7173c1e46d450fe3d45f80a83\
bef9755a33740c3c44b99df2d00b7238d1a69bdd77d6ff5a976f6b7d7c257072dd82158cbb994eb1f02818100e1d694\
8eb5c7e80adb482b5c77c2261efa79aa8f7896648a327659d0ba670790277fb0c831497fa165e5d26659866e9bf7c6\
b83f87ddda1dee42946fa20ad3a16fd3d74663dcfbbc7f4609e0c16edada36bf101effa9bcd7e212962b869cbd4ad3\
c93734c3e5e9d078739413e0507492d8a7e2a3a2408ca9343b64afa53cde5f02818100c36ce679ddbeeb4bd20e96e9\
ebf87f2bd7d51b946531f0ef2def5ab6df53952f2ca6cf31f2cfa86f4490b066837a6d03ffd1539a7226adcbb72735\
1b8e3e45ae2d976b0690027d4336fa55627d508ab1b74791fb866b94963a99c4c7c0c0d1ca406360784800a0f501fb\
c43e21218b40dceae5ca20cac5921c40696d2a288caf02818100a05c86506fb3eb8909fc4d0df3dbe0c5ce85e61eca\
39c05a814a98ac263052a681e5a1da056573435fdfb96f03d2f967b6a15ce37fce80bb101c26dabded8228f8072cad\
c6eb7bb5758a7e2922315d25e609f5a08d5a31c5f9b9c8f84f35ad141d1e9c1cd39dc65149b6884734d8ec6df979fce\
cc4a1a13fe4dee7b7f1552f710281800fe4c171d3d8fd25f375804c920669c155125de5d9bd100d43bd1db195c42473\
ebbbbd4a20a746d995c7f6b0bfacab4511ff223f835d25f15579f8d5bee1cda4f6cc43c60adc48f7b876ef8ecd0649e\
15e3891e4d4efd6ebc8e44c9eba4c744370ad246163e9b92d73f5d7e5fda7cebd7dba14ea35748850f3bf4153c183f\
ebd02818100da40b99675a0919a70447f27ea31029fa96c7ecde640d411b2cc249d1a6aaba5b44c8b3f54700abdd955\
70c8b0666e8e1143bb329cb414b389278d6cb455762b6b83da23d0a1224c589341abb6e8ffd3d63d75947911a72d58\
e485e157f8350dd597a9f01ef5ffc584d8f28ece3b8011c56bde94c7a27e1b55a52e48bc1f9bbc";

const RSA_2048_RFC3110_HEX: &str = "\
03010001ac668501ac2f0ff001f6d2b6d9abeed4707b9749d683c5635ab33d7cee9d7904b17277a1788638def1a7a8\
f2640ab17d7d6fb06349eebec13e451d70c28f7332e0f9c0c705a03ebb5c7719482fe5d6182c50cb5ec7f1b6c65e1e\
a2b7419ab4400b46dd178241e930be58612aef5bae1a98ac7f75e2cdb125a57faf30eb27030ffb1be0ddfd6a587e91\
805ebffc3b074f29c821742963bb60f991ed95cb53b21b7a1c1a7cdeea6a31c911dbce50663ff3a64d70b1553751d9\
03b4af6bb781057580eca1fcf3485d8eec1f5ac62025d3b04f8bc631a5e0201e50d2e0186fcafce033591d275a33d9\
4a65d56b00401ec91009793a325a6c664f0a1755e0930ff6f1";

fn decode_hex(hex: &str) -> Vec<u8> {
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.as_bytes())
        .unwrap()
}

#[tokio::test]
async fn test_ip6_arpa_34_label_ptr_lookup_succeeds() {
    let root = ZoneKey::generate(&Name::root());
    let arpa = ZoneKey::generate(&name("ip6.arpa."));
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    source.record_not_a_cut(name("arpa."));
    source.insert_cut(arpa.signed_cut(&root));

    let ptr_name =
        name("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.");
    assert_eq!(ptr_name.label_count(), 34);
    mark_non_cuts(&source, &ptr_name, &name("ip6.arpa."));

    let ptr = record(
        &ptr_name,
        RecordType::PTR,
        RData::Ptr(name("host.example.")),
    );
    let mut message = query(&ptr_name, RecordType::PTR);
    message.answers.push(arpa.sign(std::slice::from_ref(&ptr)));
    message.answers.push(ptr);

    let outcome = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    )
    .validate(&message, &source)
    .await;
    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
}

#[tokio::test]
async fn test_signed_delegation_nsec_verified_against_parent_keys() {
    let root = ZoneKey::generate(&Name::root());
    let example = ZoneKey::generate(&name("example."));
    let sub = ZoneKey::generate(&name("sub.example."));
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    source.insert_cut(example.signed_cut(&root));
    source.insert_cut(sub.signed_cut(&example));
    source.record_not_a_cut(name("subz.example."));

    let subz = name("subz.example.");
    let mut nxdomain_message = query(&subz, RecordType::A);
    nxdomain_message.header.rcode = ResponseCode::NXDOMAIN;
    let delegation_nsec = nsec(
        &name("sub.example."),
        &name("tz.example."),
        &[
            RecordType::NS,
            RecordType::DS,
            RecordType::RRSIG,
            RecordType::NSEC,
        ],
    );
    let wildcard_nsec = nsec(
        &name("example."),
        &name("sub.example."),
        &[
            RecordType::SOA,
            RecordType::NS,
            RecordType::RRSIG,
            RecordType::NSEC,
        ],
    );
    nxdomain_message
        .authorities
        .push(example.sign(std::slice::from_ref(&delegation_nsec)));
    nxdomain_message.authorities.push(delegation_nsec);
    nxdomain_message
        .authorities
        .push(example.sign(std::slice::from_ref(&wildcard_nsec)));
    nxdomain_message.authorities.push(wildcard_nsec);

    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );
    assert_eq!(
        validator.validate(&nxdomain_message, &source).await.verdict,
        ValidationVerdict::Secure
    );
}

#[tokio::test]
async fn test_unsigned_delegation_ds_nodata_stays_secure() {
    let root = ZoneKey::generate(&Name::root());
    let example = ZoneKey::generate(&name("example."));
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    source.insert_cut(example.signed_cut(&root));

    let unsigned = name("unsigned.example.");
    let ds_absence_nsec = nsec(
        &unsigned,
        &name("z.example."),
        &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
    );
    let ds_proof = DenialProof::from_records(&[&ds_absence_nsec]).unwrap();
    source.insert_cut(ZoneCutMaterial::new(
        unsigned.clone(),
        Delegation::Unsigned {
            ds_denial: ds_proof,
            signatures: vec![example.sign(std::slice::from_ref(&ds_absence_nsec))],
        },
    ));
    let mut ds_message = query(&unsigned, RecordType::DS);
    ds_message
        .authorities
        .push(example.sign(std::slice::from_ref(&ds_absence_nsec)));
    ds_message.authorities.push(ds_absence_nsec);

    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );
    assert_eq!(
        validator.validate(&ds_message, &source).await.verdict,
        ValidationVerdict::Secure
    );
}

#[tokio::test]
async fn test_nsec3_authorities_verify_without_probing_hash_owner() {
    let root = ZoneKey::generate(&Name::root());
    let example = ZoneKey::generate(&name("example."));
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    source.insert_cut(example.signed_cut(&root));
    source.record_not_a_cut(name("subz.example."));

    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 0, Vec::new());
    let example_hash =
        hash_nsec3_name(&name("example."), &params, Nsec3IterationsCap::DEFAULT).unwrap();
    let hash_owner = name(&format!(
        "{}.example.",
        base32hex_encode(&example_hash).to_ascii_lowercase()
    ));
    let nsec3_record = record(
        &hash_owner,
        RecordType::NSEC3,
        RData::Nsec3(Nsec3Rdata::new(
            1,
            0,
            0,
            Vec::new(),
            example_hash,
            bitmap(&[
                RecordType::SOA,
                RecordType::NS,
                RecordType::RRSIG,
                RecordType::NSEC3,
            ]),
        )),
    );
    let mut nsec3_message = query(&name("subz.example."), RecordType::A);
    nsec3_message.header.rcode = ResponseCode::NXDOMAIN;
    nsec3_message
        .authorities
        .push(example.sign(std::slice::from_ref(&nsec3_record)));
    nsec3_message.authorities.push(nsec3_record);

    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );
    assert_eq!(
        validator.validate(&nsec3_message, &source).await.verdict,
        ValidationVerdict::Secure
    );
}

#[tokio::test]
async fn test_failure_budget_allows_n_failures_and_rejects_n_plus_one() {
    let root = ZoneKey::generate(&Name::root());
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    let host = name("host.");
    source.record_not_a_cut(host.clone());
    let answer = a_record(&host, 1);

    let good_sig = root.sign(std::slice::from_ref(&answer));
    let mut bad_sig = good_sig.clone();
    if let RData::Rrsig(ref rrsig) = bad_sig.rdata {
        bad_sig.rdata = RData::Rrsig(RrsigRdata::new(
            rrsig.type_covered(),
            rrsig.algorithm(),
            rrsig.labels(),
            rrsig.original_ttl(),
            rrsig.signature_expiration(),
            rrsig.signature_inception(),
            rrsig.key_tag(),
            rrsig.signer_name().clone(),
            vec![0xFF; 64],
        ));
    }

    let policy = ValidationPolicy {
        max_signature_failures: 1,
        ..ValidationPolicy::default()
    };
    let validator = Validator::new(clock(), policy, TrustAnchors::new(root.anchor()));

    let mut one_stale = query(&host, RecordType::A);
    one_stale.answers.push(bad_sig.clone());
    one_stale.answers.push(good_sig);
    one_stale.answers.push(answer.clone());
    assert_eq!(
        validator.validate(&one_stale, &source).await.verdict,
        ValidationVerdict::Secure
    );

    let mut two_bad = query(&host, RecordType::A);
    two_bad.answers.push(bad_sig.clone());
    two_bad.answers.push(bad_sig);
    two_bad.answers.push(answer);
    let outcome = validator.validate(&two_bad, &source).await;
    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::SignatureBudgetExceeded);
}

#[test]
fn test_rsasha512_positive_and_flipped_signature() {
    let root = Name::root();
    let host = name("host.");
    let rsa_pair = RsaKeyPair::from_pkcs8(&decode_hex(RSA_2048_PKCS8_HEX)).unwrap();
    let rsa_dnskey = DnskeyRdata::new(
        257,
        3,
        DnssecAlgorithm::RSASHA512.value(),
        decode_hex(RSA_2048_RFC3110_HEX),
    );
    let rsa_rr = a_record(&host, 10);
    let template = |sig: Vec<u8>| {
        RrsigRdata::new(
            RecordType::A,
            DnssecAlgorithm::RSASHA512.value(),
            1,
            300,
            EXPIRATION,
            INCEPTION,
            rsa_dnskey.key_tag(),
            root.clone(),
            sig,
        )
    };
    let data = build_canonical_signed_data(&template(Vec::new()), &[&rsa_rr]).unwrap();
    let mut rsa_sig = vec![0u8; rsa_pair.public().modulus_len()];
    rsa_pair
        .sign(&RSA_PKCS1_SHA512, &SystemRandom::new(), &data, &mut rsa_sig)
        .unwrap();
    assert_eq!(
        verify_rrsig_record(
            &template(rsa_sig.clone()),
            &[&rsa_rr],
            &rsa_dnskey,
            &root,
            &clock(),
        ),
        Ok(())
    );
    if let Some(byte) = rsa_sig.first_mut() {
        *byte ^= 0x01;
    }
    assert!(
        verify_rrsig_record(&template(rsa_sig), &[&rsa_rr], &rsa_dnskey, &root, &clock(),).is_err()
    );
}

fn sign_p384(
    pair: &EcdsaKeyPair,
    rng: &SystemRandom,
    zone: &Name,
    key_tag: u16,
    rrset: &[ResourceRecord],
) -> ResourceRecord {
    let first = rrset.first().unwrap();
    let template = |sig: Vec<u8>| {
        RrsigRdata::new(
            first.rtype,
            DnssecAlgorithm::ECDSAP384SHA384.value(),
            u8::try_from(first.owner.label_count()).unwrap(),
            300,
            EXPIRATION,
            INCEPTION,
            key_tag,
            zone.clone(),
            sig,
        )
    };
    let refs: Vec<&ResourceRecord> = rrset.iter().collect();
    let data = build_canonical_signed_data(&template(Vec::new()), &refs).unwrap();
    let sig = pair.sign(rng, &data).unwrap().as_ref().to_vec();
    record(&first.owner, RecordType::RRSIG, RData::Rrsig(template(sig)))
}

#[tokio::test]
async fn test_ecdsa_p384_chain_validation() {
    let root = Name::root();
    let host = name("host.");
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let raw_xy = pair.public_key().as_ref().get(1..).unwrap().to_vec();
    let dnskey = DnskeyRdata::new(257, 3, DnssecAlgorithm::ECDSAP384SHA384.value(), raw_xy);
    let dnskey_rr = record(&root, RecordType::DNSKEY, RData::Dnskey(dnskey.clone()));

    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        root.clone(),
        Delegation::Apex {
            dnskey: SignedRrset::new(
                vec![dnskey_rr.clone()],
                vec![sign_p384(
                    &pair,
                    &rng,
                    &root,
                    dnskey.key_tag(),
                    std::slice::from_ref(&dnskey_rr),
                )],
            ),
        },
    ));
    source.record_not_a_cut(host.clone());
    let a_rr = a_record(&host, 14);
    let mut msg = query(&host, RecordType::A);
    msg.answers.push(sign_p384(
        &pair,
        &rng,
        &root,
        dnskey.key_tag(),
        std::slice::from_ref(&a_rr),
    ));
    msg.answers.push(a_rr);

    let digest = compute_dnskey_digest(&root, &dnskey, DigestType::SHA384).unwrap();
    let anchor = TrustAnchor::new(
        root,
        DsRdata::new(
            dnskey.key_tag(),
            DnssecAlgorithm::ECDSAP384SHA384.value(),
            DigestType::SHA384.value(),
            digest,
        ),
    );
    let outcome = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(anchor),
    )
    .validate(&msg, &source)
    .await;
    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
}

struct MisdirectedRootSource {
    decoy: ZoneCutMaterial,
}

impl ChainSource for MisdirectedRootSource {
    async fn material_for(&self, _zone: &Name) -> Result<ZoneCutMaterial, ChainSourceError> {
        Ok(self.decoy.clone())
    }
}

#[tokio::test]
async fn test_anchored_zone_rejects_misdirected_material_as_indeterminate() {
    let root = ZoneKey::generate(&Name::root());
    let decoy = ZoneKey::generate(&name("decoy."));
    let source = MisdirectedRootSource {
        decoy: decoy.apex_cut(),
    };
    let host = name("host.");
    let mut msg = query(&host, RecordType::A);
    let answer = a_record(&host, 1);
    msg.answers.push(root.sign(std::slice::from_ref(&answer)));
    msg.answers.push(answer);

    let outcome = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    )
    .validate(&msg, &source)
    .await;
    assert_eq!(outcome.verdict, ValidationVerdict::Indeterminate);
    assert_eq!(outcome.reason, VerdictReason::ChainMaterialUnavailable);
}
