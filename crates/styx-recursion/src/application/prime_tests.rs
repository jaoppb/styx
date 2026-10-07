use std::net::Ipv4Addr;

use styx_proto::{Header, MessageKind, Opcode};

use super::*;

const HINTS: &str = "
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     199.9.14.201
";

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn root_ns_answer(authoritative: bool, truncated: bool, servers: &[(&str, [u8; 4])]) -> Message {
    let mut header = Header::new_query(1, Opcode::Query, false);
    header.kind = MessageKind::Response;
    header.authoritative = authoritative;
    header.truncated = truncated;
    let mut message = Message::new(header);
    for (server, octets) in servers {
        let record = |owner: Name, rdata: RData| {
            styx_proto::ResourceRecord::new(
                owner,
                rdata.rtype(),
                RecordClass::In,
                Ttl::from_secs(518_400),
                rdata,
            )
        };
        message
            .answers
            .push(record(Name::root(), RData::Ns(name(server))));
        message
            .additionals
            .push(record(name(server), RData::A(Ipv4Addr::from(*octets))));
    }
    message
}

#[test]
fn only_an_authoritative_complete_answer_can_replace_the_root_set() {
    let servers = [("evil.example.", [6, 6, 6, 6])];
    let now = Instant::now();
    assert!(root_ns_set(&root_ns_answer(false, false, &servers), now).is_none());
    assert!(root_ns_set(&root_ns_answer(true, true, &servers), now).is_none());
    assert!(root_ns_set(&root_ns_answer(true, false, &servers), now).is_some());
}

#[test]
fn a_short_live_answer_never_removes_a_hint_server() {
    let now = Instant::now();
    let hints = RootHints::parse(HINTS).unwrap().to_delegation(now);
    let live = root_ns_set(
        &root_ns_answer(true, false, &[("a.root-servers.net.", [198, 41, 0, 4])]),
        now,
    )
    .unwrap();
    let merged = union_with_hints(live, &hints);
    let names: Vec<String> = merged
        .nameservers()
        .iter()
        .map(|server| server.name.to_string().to_ascii_lowercase())
        .collect();
    assert_eq!(names, ["a.root-servers.net.", "b.root-servers.net."]);
}

#[test]
fn a_live_server_keeps_its_own_address_and_gains_the_hinted_one() {
    let now = Instant::now();
    let hints = RootHints::parse(HINTS).unwrap().to_delegation(now);
    let live = root_ns_set(
        &root_ns_answer(true, false, &[("a.root-servers.net.", [192, 0, 2, 53])]),
        now,
    )
    .unwrap();
    let merged = union_with_hints(live, &hints);
    let first = merged.nameservers().first().unwrap();
    assert_eq!(first.addresses.len(), 2);
    assert_eq!(
        first.addresses.first(),
        Some(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)))
    );
}
