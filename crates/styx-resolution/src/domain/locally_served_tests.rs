use super::*;

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("valid test name")
}

fn question(qname: &str, qtype: RecordType) -> Question {
    Question::new(name(qname), qtype, RecordClass::In)
}

fn answer(table: &LocallyServed, qname: &str, qtype: RecordType) -> Option<LocallyServedReply> {
    table.answer(&question(qname, qtype))
}

fn soa_owner(records: &[ResourceRecord]) -> Option<&Name> {
    match records {
        [record] if record.rtype == RecordType::SOA => Some(&record.owner),
        _ => None,
    }
}

#[test]
fn every_rfc_6303_zone_parses() {
    assert_eq!(
        LocallyServed::default().empty_zones.len(),
        EMPTY_ZONES.len()
    );
}

#[test]
fn every_special_use_name_parses() {
    assert_eq!(LocallyServed::new(Vec::new(), true).special.len(), 3);
    assert_eq!(LocallyServed::new(Vec::new(), false).special.len(), 2);
}

#[test]
fn the_soa_rname_is_nobody_invalid() {
    assert_eq!(
        Name::from_wire(Box::from(EMPTY_ZONE_RNAME)),
        name("nobody.invalid.")
    );
}

#[test]
fn a_name_below_a_private_reverse_zone_is_nxdomain_with_the_zone_soa() {
    let reply = answer(
        &LocallyServed::default(),
        "10.1.168.192.in-addr.arpa.",
        RecordType::PTR,
    )
    .expect("locally served");

    assert_eq!(reply.rcode, ResponseCode::NXDOMAIN);
    assert!(reply.answers.is_empty());
    assert_eq!(
        soa_owner(&reply.authority),
        Some(&name("168.192.in-addr.arpa."))
    );
}

#[test]
fn the_soa_negative_ttl_matches_its_own_ttl() {
    let reply = answer(
        &LocallyServed::default(),
        "1.0.0.10.in-addr.arpa.",
        RecordType::PTR,
    )
    .expect("locally served");
    let soa = reply.authority.first().expect("an SOA");

    assert_eq!(soa.ttl, LOCALLY_SERVED_TTL);
    let RData::Soa(rdata) = &soa.rdata else {
        panic!("an SOA record carries SOA data");
    };
    assert_eq!(rdata.minimum(), LOCALLY_SERVED_TTL.seconds());
    assert_eq!(rdata.mname(), &name("10.in-addr.arpa."));
}

#[test]
fn the_zone_apex_answers_its_soa_and_ns_and_nodata_otherwise() {
    let table = LocallyServed::default();
    let apex = "d.f.ip6.arpa.";

    let soa = answer(&table, apex, RecordType::SOA).expect("locally served");
    assert_eq!(soa.rcode, ResponseCode::NOERROR);
    assert_eq!(soa_owner(&soa.answers), Some(&name(apex)));

    let ns = answer(&table, apex, RecordType::NS).expect("locally served");
    assert_eq!(ns.rcode, ResponseCode::NOERROR);
    assert_eq!(
        ns.answers.first().map(|record| &record.rdata),
        Some(&RData::Ns(name(apex)))
    );

    let nodata = answer(&table, apex, RecordType::A).expect("locally served");
    assert_eq!(nodata.rcode, ResponseCode::NOERROR);
    assert!(nodata.answers.is_empty());
    assert_eq!(soa_owner(&nodata.authority), Some(&name(apex)));
}

#[test]
fn a_public_reverse_name_is_not_locally_served() {
    let table = LocallyServed::default();
    assert_eq!(
        answer(&table, "8.8.8.8.in-addr.arpa.", RecordType::PTR),
        None
    );
    assert_eq!(
        answer(&table, "10.15.172.in-addr.arpa.", RecordType::PTR),
        None
    );
    assert_eq!(answer(&table, "in-addr.arpa.", RecordType::SOA), None);
}

#[test]
fn the_ranges_split_across_several_zones_are_served_up_to_their_edges() {
    let table = LocallyServed::default();
    let served = [
        "1.16.172.in-addr.arpa.",
        "1.31.172.in-addr.arpa.",
        "1.254.169.in-addr.arpa.",
        "1.8.e.f.ip6.arpa.",
        "1.b.e.f.ip6.arpa.",
    ];
    for qname in served {
        let reply = answer(&table, qname, RecordType::PTR).expect(qname);
        assert_eq!(reply.rcode, ResponseCode::NXDOMAIN, "{qname}");
    }
    let forwarded = [
        "1.15.172.in-addr.arpa.",
        "1.32.172.in-addr.arpa.",
        "1.253.169.in-addr.arpa.",
        "1.7.e.f.ip6.arpa.",
        "1.c.e.f.ip6.arpa.",
    ];
    for qname in forwarded {
        assert_eq!(answer(&table, qname, RecordType::PTR), None, "{qname}");
    }
}

#[test]
fn an_upper_case_apex_is_answered_as_the_apex() {
    let table = LocallyServed::default();

    let soa = answer(&table, "D.F.IP6.ARPA.", RecordType::SOA).expect("locally served");
    assert_eq!(soa.rcode, ResponseCode::NOERROR);
    assert_eq!(
        soa.answers.first().map(|record| record.rtype),
        Some(RecordType::SOA)
    );

    let nodata = answer(&table, "168.192.IN-ADDR.ARPA.", RecordType::PTR).expect("locally served");
    assert_eq!(nodata.rcode, ResponseCode::NOERROR, "NODATA, not NXDOMAIN");
    assert!(nodata.answers.is_empty());
}

#[test]
fn a_deferred_domain_leaves_only_its_own_names_to_the_upstream() {
    let table = LocallyServed::new(vec![name("1.168.192.in-addr.arpa.")], true);

    assert_eq!(
        answer(&table, "10.1.168.192.in-addr.arpa.", RecordType::PTR),
        None
    );
    let outside = answer(&table, "10.2.168.192.in-addr.arpa.", RecordType::PTR)
        .expect("still locally served");
    assert_eq!(outside.rcode, ResponseCode::NXDOMAIN);
}

#[test]
fn a_deferred_domain_above_a_zone_defers_the_whole_zone() {
    let table = LocallyServed::new(vec![name("in-addr.arpa.")], true);
    assert_eq!(
        answer(&table, "10.1.168.192.in-addr.arpa.", RecordType::PTR),
        None
    );
}

#[test]
fn a_deferred_domain_equal_to_a_zone_defers_its_apex_and_everything_below() {
    let table = LocallyServed::new(vec![name("168.192.in-addr.arpa.")], true);
    assert_eq!(
        answer(&table, "168.192.in-addr.arpa.", RecordType::SOA),
        None
    );
    assert_eq!(
        answer(&table, "10.1.168.192.in-addr.arpa.", RecordType::PTR),
        None
    );
    assert!(answer(&table, "1.0.0.10.in-addr.arpa.", RecordType::PTR).is_some());
}

#[test]
fn a_deferred_domain_matches_whatever_the_case_of_either_name() {
    let table = LocallyServed::new(vec![name("1.168.192.IN-ADDR.ARPA.")], true);
    assert_eq!(
        answer(&table, "10.1.168.192.in-addr.arpa.", RecordType::PTR),
        None
    );
    assert_eq!(
        answer(&table, "10.1.168.192.In-Addr.Arpa.", RecordType::PTR),
        None
    );
    assert!(answer(&table, "10.2.168.192.IN-ADDR.ARPA.", RecordType::PTR).is_some());
}

#[test]
fn a_deferred_domain_never_defers_a_special_use_name() {
    let table = LocallyServed::new(vec![name("localhost."), name("net.")], true);

    let localhost = answer(&table, "localhost.", RecordType::A).expect("locally served");
    assert_eq!(localhost.rcode, ResponseCode::NOERROR);
    let canary = answer(&table, DOH_CANARY, RecordType::A).expect("locally served");
    assert_eq!(canary.rcode, ResponseCode::NXDOMAIN);
}

#[test]
fn localhost_and_names_below_it_answer_the_loopback_address() {
    let table = LocallyServed::default();
    let ipv4 = answer(&table, "localhost.", RecordType::A).expect("locally served");
    let ipv6 = answer(&table, "app.LOCALHOST.", RecordType::AAAA).expect("locally served");

    assert_eq!(ipv4.rcode, ResponseCode::NOERROR);
    assert_eq!(
        ipv4.answers.first().map(|record| &record.rdata),
        Some(&RData::A(Ipv4Addr::LOCALHOST))
    );
    assert_eq!(
        ipv6.answers
            .first()
            .map(|record| (&record.owner, &record.rdata)),
        Some((&name("app.LOCALHOST."), &RData::Aaaa(Ipv6Addr::LOCALHOST)))
    );
}

#[test]
fn localhost_answers_other_types_nodata() {
    let reply =
        answer(&LocallyServed::default(), "localhost.", RecordType::MX).expect("locally served");
    assert_eq!(reply.rcode, ResponseCode::NOERROR);
    assert!(reply.answers.is_empty());
    assert!(reply.authority.is_empty());
}

#[test]
fn invalid_and_names_below_it_are_nxdomain() {
    let table = LocallyServed::default();
    for qname in ["invalid.", "foo.invalid."] {
        let reply = answer(&table, qname, RecordType::A).expect("locally served");
        assert_eq!(reply.rcode, ResponseCode::NXDOMAIN, "{qname}");
        assert!(reply.answers.is_empty());
    }
}

#[test]
fn the_doh_canary_is_nxdomain_only_while_its_switch_is_on() {
    let on = answer(
        &LocallyServed::new(Vec::new(), true),
        DOH_CANARY,
        RecordType::AAAA,
    )
    .expect("locally served");
    assert_eq!(on.rcode, ResponseCode::NXDOMAIN);

    assert_eq!(
        answer(
            &LocallyServed::new(Vec::new(), false),
            DOH_CANARY,
            RecordType::A
        ),
        None
    );
}

#[test]
fn a_label_that_only_ends_with_a_special_name_is_not_served() {
    let table = LocallyServed::default();
    assert_eq!(answer(&table, "notlocalhost.", RecordType::A), None);
    assert_eq!(answer(&table, "application-dns.net.", RecordType::A), None);
    assert_eq!(answer(&table, "example.com.", RecordType::A), None);
}
