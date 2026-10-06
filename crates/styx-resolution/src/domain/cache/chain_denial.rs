//! A denial that ends an alias chain: `www.example.com CNAME www.bank.com`, then
//! NXDOMAIN or NODATA for `www.bank.com`, with the SOA of `bank.com`.
//!
//! The SOA belongs to another zone than the one that answered, so the bailiwick rule
//! would refuse it, and the chain could not be cached with its ending. It is
//! admitted here, but only as part of the qname's own composite entry, never as a
//! negative entry for the target name: the answering zone may vouch for what its own
//! name resolves to, and nothing more, so it cannot deny `www.bank.com` to anyone
//! who asks for it directly (ADR 0020).

use styx_proto::{Message, RData, RecordType, ResponseCode};

use crate::domain::cache::answer_scope::AnswerScope;
use crate::domain::cache::key::CanonicalName;

/// Whether `message` ends its alias chain in a denial rather than in data: NXDOMAIN
/// (RFC 6604: the code speaks for the name the chain ends at), or NOERROR with
/// nothing but aliases owned by that name.
pub(crate) fn ends_in_denial(message: &Message, scope: &AnswerScope) -> bool {
    match message.header.rcode {
        ResponseCode::NXDOMAIN => true,
        ResponseCode::NOERROR => !message
            .answers
            .iter()
            .any(|record| holds_data_at(record.owner.clone(), &record.rdata, scope)),
        _ => false,
    }
}

fn holds_data_at(owner: styx_proto::Name, rdata: &RData, scope: &AnswerScope) -> bool {
    let is_alias = matches!(rdata, RData::Cname(_)) || rdata.rtype() == RecordType::DNAME;
    !is_alias && CanonicalName::canonicalize(&owner) == *scope.chain_end()
}

/// Whether an SOA owned by `soa_owner` may close the chain `scope` describes: its
/// zone must enclose the exact name the chain ends at.
pub(crate) fn soa_closes_chain(scope: &AnswerScope, soa_owner: &CanonicalName) -> bool {
    scope.chain_end().is_subdomain_of(soa_owner)
}
