//! Fixed cryptographic and RFC test vectors for RSA/SHA-256, ECDSA P-256, NSEC3, DS,
//! and RFC 4034 canonical encoding.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use data_encoding::BASE64;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::domain::denial::Nsec3Params;
use styx_dnssec::domain::nsec3::hash_nsec3_name;
use styx_dnssec::domain::signature::{compute_dnskey_digest, verify_rrsig_record};
use styx_dnssec::{
    Delegation, DigestType, DnssecAlgorithm, InMemoryChainSource, Nsec3HashAlgorithm,
    Nsec3IterationsCap, SignedRrset, TrustAnchor, TrustAnchors, ValidationPolicy,
    ValidationVerdict, Validator, ZoneCutMaterial,
};
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata, RrsigRdata};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord, Ttl};
use support::{
    a_record, base32hex_encode, clock, clock_at, name, query, record, EXPIRATION, INCEPTION,
};

const RSA_1024_SIG_HEX: &str = "\
3aa832912f48c3ca8dea227991d6894724e2cc4d45739eb3a3d6350c0ff3081570f1997ac9e1cce26bf0efe5a5e23ef\
173959c8dfb05af8ee9935de7b6872956696876175bb65a06c9e34540dacdc0745ece8cb75e1db8f8c929a486e4f5b9\
bd90f605469652c332b8be2870f0cc2ff999f2da55ea0cb0c4f82b965ca832c675";

const RSA_1024_RFC3110_HEX: &str = "\
03010001dee859e245653ca0244a2f9df22ed5544be68e64319804b6799344b0ad9ac87a53957bf3aa2dda13e89456\
af599ed3a4ac5a67d42805d996da52afcc5528cef0b0cc9b9476f602b7a0db272e69c5eb719515c1c03d20f4ca914f\
abf4736330b3047f57e1b3f221cf401a2547051bf04bcbe1897f6f62607af9723d92aba516b1";

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
        .expect("valid hex")
}

fn rsa_sign(
    zone: &Name,
    pair: &RsaKeyPair,
    dnskey: &DnskeyRdata,
    rrset: &[ResourceRecord],
) -> ResourceRecord {
    let first = rrset.first().expect("non-empty");
    let template = |sig: Vec<u8>| {
        RrsigRdata::new(
            first.rtype,
            DnssecAlgorithm::RSASHA256.value(),
            u8::try_from(first.owner.label_count()).expect("labels"),
            300,
            EXPIRATION,
            INCEPTION,
            dnskey.key_tag(),
            zone.clone(),
            sig,
        )
    };
    let refs: Vec<&ResourceRecord> = rrset.iter().collect();
    let signed_data = build_canonical_signed_data(&template(Vec::new()), &refs).unwrap();
    let mut signature = vec![0u8; pair.public().modulus_len()];
    pair.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        &signed_data,
        &mut signature,
    )
    .unwrap();
    record(
        &first.owner,
        RecordType::RRSIG,
        RData::Rrsig(template(signature)),
    )
}

fn flip_first_signature_byte(sig_record: &mut ResourceRecord) {
    if let RData::Rrsig(ref rrsig) = sig_record.rdata {
        let mut flipped = rrsig.signature().to_vec();
        if let Some(first) = flipped.first_mut() {
            *first ^= 0x01;
        }
        sig_record.rdata = RData::Rrsig(RrsigRdata::new(
            rrsig.type_covered(),
            rrsig.algorithm(),
            rrsig.labels(),
            rrsig.original_ttl(),
            rrsig.signature_expiration(),
            rrsig.signature_inception(),
            rrsig.key_tag(),
            rrsig.signer_name().clone(),
            flipped,
        ));
    }
}

async fn run_rsa_chain_check(pkcs8_hex: &str, rfc3110_hex: &str) {
    let root = Name::root();
    let pair = RsaKeyPair::from_pkcs8(&decode_hex(pkcs8_hex)).unwrap();
    let dnskey = DnskeyRdata::new(
        257,
        3,
        DnssecAlgorithm::RSASHA256.value(),
        decode_hex(rfc3110_hex),
    );
    let dnskey_rr = record(&root, RecordType::DNSKEY, RData::Dnskey(dnskey.clone()));
    let dnskey_sig = rsa_sign(&root, &pair, &dnskey, std::slice::from_ref(&dnskey_rr));

    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        root.clone(),
        Delegation::Apex {
            dnskey: SignedRrset::new(vec![dnskey_rr], vec![dnskey_sig]),
        },
    ));
    let host = name("host.");
    source.record_not_a_cut(host.clone());
    let answer = a_record(&host, 10);
    let mut answer_sig = rsa_sign(&root, &pair, &dnskey, std::slice::from_ref(&answer));

    let mut message = query(&host, RecordType::A);
    message.answers.push(answer_sig.clone());
    message.answers.push(answer);

    let digest = compute_dnskey_digest(&root, &dnskey, DigestType::SHA256).unwrap();
    let anchor = TrustAnchor::new(
        root,
        DsRdata::new(
            dnskey.key_tag(),
            DnssecAlgorithm::RSASHA256.value(),
            DigestType::SHA256.value(),
            digest,
        ),
    );
    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(anchor),
    );
    assert_eq!(
        validator.validate(&message, &source).await.verdict,
        ValidationVerdict::Secure
    );

    flip_first_signature_byte(&mut answer_sig);
    if let Some(slot) = message.answers.get_mut(0) {
        *slot = answer_sig;
    }
    assert_eq!(
        validator.validate(&message, &source).await.verdict,
        ValidationVerdict::Bogus
    );
}

#[tokio::test]
async fn test_rsasha256_2048_and_1024_legacy_positive_and_flipped_signature() {
    run_rsa_chain_check(RSA_2048_PKCS8_HEX, RSA_2048_RFC3110_HEX).await;

    let zone = name("example.net.");
    let dnskey = DnskeyRdata::new(
        257,
        3,
        DnssecAlgorithm::RSASHA256.value(),
        decode_hex(RSA_1024_RFC3110_HEX),
    );
    assert_eq!(dnskey.key_tag(), 40831);
    let a_rr = a_record(&name("www.example.net."), 1);
    let sig_bytes = decode_hex(RSA_1024_SIG_HEX);
    let rrsig = RrsigRdata::new(
        RecordType::A,
        DnssecAlgorithm::RSASHA256.value(),
        3,
        300,
        EXPIRATION,
        INCEPTION,
        dnskey.key_tag(),
        zone.clone(),
        sig_bytes.clone(),
    );
    assert_eq!(
        verify_rrsig_record(&rrsig, &[&a_rr], &dnskey, &zone, &clock()),
        Ok(())
    );

    let mut flipped = sig_bytes;
    if let Some(first) = flipped.first_mut() {
        *first ^= 0x01;
    }
    let bad_rrsig = RrsigRdata::new(
        RecordType::A,
        DnssecAlgorithm::RSASHA256.value(),
        3,
        300,
        EXPIRATION,
        INCEPTION,
        dnskey.key_tag(),
        zone.clone(),
        flipped,
    );
    assert!(verify_rrsig_record(&bad_rrsig, &[&a_rr], &dnskey, &zone, &clock()).is_err());
}

#[test]
fn test_malformed_rsa_and_ecdsa_public_key_blobs_are_rejected() {
    let rr = a_record(&name("www.example.net."), 1);
    let sig = RrsigRdata::new(
        RecordType::A,
        DnssecAlgorithm::RSASHA256.value(),
        3,
        300,
        EXPIRATION,
        INCEPTION,
        1,
        name("example.net."),
        vec![0; 128],
    );
    for bad_rsa in [vec![], vec![0x00, 0x01], vec![0x03, 0x01, 0x00, 0x01]] {
        let key = DnskeyRdata::new(257, 3, DnssecAlgorithm::RSASHA256.value(), bad_rsa);
        let rrsig = RrsigRdata::new(
            sig.type_covered(),
            sig.algorithm(),
            sig.labels(),
            sig.original_ttl(),
            sig.signature_expiration(),
            sig.signature_inception(),
            key.key_tag(),
            sig.signer_name().clone(),
            vec![0; 128],
        );
        assert!(
            verify_rrsig_record(&rrsig, &[&rr], &key, &name("example.net."), &clock()).is_err()
        );
    }

    let bad_ecdsa = DnskeyRdata::new(
        257,
        3,
        DnssecAlgorithm::ECDSAP256SHA256.value(),
        vec![0; 63],
    );
    let rrsig = RrsigRdata::new(
        RecordType::A,
        DnssecAlgorithm::ECDSAP256SHA256.value(),
        3,
        300,
        EXPIRATION,
        INCEPTION,
        bad_ecdsa.key_tag(),
        name("example.net."),
        vec![0; 64],
    );
    assert!(
        verify_rrsig_record(&rrsig, &[&rr], &bad_ecdsa, &name("example.net."), &clock()).is_err()
    );
}

/// RFC 6605 §6.1: P-256 ECDSAP256SHA256 example vector (key, DS, A record, RRSIG).
#[test]
fn test_rfc6605_section_6_1_ecdsa_p256_vector() {
    let zone = name("example.net.");
    let www = name("www.example.net.");
    let pubkey = BASE64
        .decode(b"GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==")
        .unwrap();
    let dnskey = DnskeyRdata::new(257, 3, DnssecAlgorithm::ECDSAP256SHA256.value(), pubkey);
    assert_eq!(dnskey.key_tag(), 55648);

    let ds_digest = compute_dnskey_digest(&zone, &dnskey, DigestType::SHA256).unwrap();
    assert_eq!(
        ds_digest,
        decode_hex("b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17")
    );

    let a_rr = ResourceRecord::new(
        www,
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(3600),
        RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    );
    let sig_bytes = BASE64
        .decode(b"qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==")
        .unwrap();
    let rrsig = RrsigRdata::new(
        RecordType::A,
        DnssecAlgorithm::ECDSAP256SHA256.value(),
        3,
        3600,
        1_284_026_679,
        1_281_607_479,
        55648,
        zone.clone(),
        sig_bytes.clone(),
    );
    let mid_window = clock_at(1_282_000_000);
    assert_eq!(
        verify_rrsig_record(&rrsig, &[&a_rr], &dnskey, &zone, &mid_window),
        Ok(())
    );

    let mut flipped = sig_bytes;
    if let Some(byte) = flipped.first_mut() {
        *byte ^= 0x01;
    }
    let bad_rrsig = RrsigRdata::new(
        RecordType::A,
        DnssecAlgorithm::ECDSAP256SHA256.value(),
        3,
        3600,
        1_284_026_679,
        1_281_607_479,
        55648,
        zone.clone(),
        flipped,
    );
    assert!(verify_rrsig_record(&bad_rrsig, &[&a_rr], &dnskey, &zone, &mid_window).is_err());
}

/// RFC 5155 Appendix A: NSEC3 SHA-1 hash vectors (salt `aabbccdd`, 12 iterations).
#[test]
fn test_rfc5155_appendix_a_nsec3_hash_vectors() {
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 12, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    let cap = Nsec3IterationsCap::DEFAULT;
    let vectors = [
        ("example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
        ("a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
        ("ns1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
        ("*.w.example.", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
    ];
    for (domain, expected_base32hex) in vectors {
        let digest = hash_nsec3_name(&name(domain), &params, cap).unwrap();
        assert_eq!(base32hex_encode(&digest), expected_base32hex, "{domain}");
    }
}

/// RFC 4509 §2.3 / RFC 4034 §5.4: SHA-256 DS digest vector for `dskey.example.com.`.
#[test]
fn test_rfc4509_ds_sha256_digest_vector() {
    let pubkey = BASE64
        .decode(
            b"AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/\
              2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvx\
              egXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc\
              nOf+EPbtG9DMBmADjFDc2w/rljwvFw==",
        )
        .unwrap();
    let dnskey = DnskeyRdata::new(256, 3, 5, pubkey);
    assert_eq!(dnskey.key_tag(), 60485);
    let digest =
        compute_dnskey_digest(&name("dskey.example.com."), &dnskey, DigestType::SHA256).unwrap();
    assert_eq!(
        digest,
        decode_hex("D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A")
    );
}

/// RFC 4034 §3.1.8.1 / §6.2: canonical signed data lowercases owner, signer, and RDATA names.
#[test]
fn test_rfc4034_canonical_signed_data_mixed_case_owner_and_embedded_name() {
    let owner = name("WwW.ExAmPlE.");
    let target = name("TaRgEt.ExAmPlE.");
    let signer = name("ExAmPlE.");
    let cname_rr = ResourceRecord::new(
        owner,
        RecordType::CNAME,
        RecordClass::In,
        Ttl::from_secs(600),
        RData::Cname(target),
    );
    let rrsig = RrsigRdata::new(
        RecordType::CNAME,
        DnssecAlgorithm::ED25519.value(),
        2,
        300,
        0x0000_0200,
        0x0000_0100,
        0x1234,
        signer,
        Vec::new(),
    );
    let bytes = build_canonical_signed_data(&rrsig, &[&cname_rr]).unwrap();
    let expected = concat!(
        "0005",                             // type covered = CNAME (5)
        "0f",                               // algorithm = 15 (Ed25519)
        "02",                               // labels = 2
        "0000012c",                         // original TTL = 300
        "00000200",                         // expiration
        "00000100",                         // inception
        "1234",                             // key tag
        "076578616d706c6500",               // signer_name = example.
        "03777777076578616d706c6500",       // canonical owner = www.example.
        "0005",                             // type = CNAME
        "0001",                             // class = IN
        "0000012c",                         // original TTL = 300
        "0010",                             // rdlength = 16
        "06746172676574076578616d706c6500", // canonical target = target.example.
    );
    assert_eq!(bytes, decode_hex(expected));
}
