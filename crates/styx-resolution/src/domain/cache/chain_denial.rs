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

use crate::domain::cache::admission::{RejectReason, RejectedRecord};
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

/// Whether a positive answer ends its alias chain in what was asked for: a record of
/// `qtype` owned by the chain's last name, or a denial closed by an SOA that
/// encloses it. Anything else is a chain that leads nowhere, and served from cache
/// it would hand a stub a CNAME with no address to follow. A question about the
/// alias itself (CNAME, DNAME) or about every type (ANY) is complete as answered. A
/// chain that loops back on itself has no last name, so it is never complete.
pub(crate) fn chain_is_complete(message: &Message, scope: &AnswerScope, qtype: RecordType) -> bool {
    if matches!(
        qtype,
        RecordType::CNAME | RecordType::DNAME | RecordType::ANY
    ) {
        return true;
    }
    if scope.is_cyclic() {
        return false;
    }
    let has_wanted_data = message.answers.iter().any(|record| {
        record.rtype == qtype && CanonicalName::canonicalize(&record.owner) == *scope.chain_end()
    });
    has_wanted_data || (ends_in_denial(message, scope) && has_closing_soa(message, scope))
}

fn has_closing_soa(message: &Message, scope: &AnswerScope) -> bool {
    message.authorities.iter().any(|record| {
        record.rtype == RecordType::SOA
            && soa_closes_chain(scope, &CanonicalName::canonicalize(&record.owner))
    })
}

/// Every record of a refused answer, each with the reason it is refused for: a record
/// the answer had no standing to carry (a foreign SOA beside an alias chain, say) is
/// out of bailiwick, as it would be in any other answer, so the forgery stays visible;
/// the rest are refused only because the chain they belong to leads nowhere.
pub(crate) fn refused_records(message: &Message, scope: &AnswerScope) -> Vec<RejectedRecord> {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .map(|record| {
            let owner = CanonicalName::canonicalize(&record.owner);
            let reason = if scope.permits(&owner, record.rtype) {
                RejectReason::IncompleteChain
            } else {
                RejectReason::OutOfBailiwick
            };
            RejectedRecord {
                owner,
                rtype: record.rtype,
                reason,
            }
        })
        .collect()
}
