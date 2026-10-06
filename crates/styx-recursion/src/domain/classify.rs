//! What a response means for the descent.

use std::time::Instant;

use styx_proto::{
    Message, Name, Question, RData, RecordClass, RecordType, ResourceRecord, ResponseCode,
};

use crate::domain::bailiwick::is_in_bailiwick;
use crate::domain::error::RecursionError;
use crate::domain::names::{parse_uncompressed_name, substitute_suffix};
use crate::domain::topology::Delegation;

/// The DNAME record type (RFC 6672), which `styx-proto` carries as unknown RDATA.
pub const DNAME: RecordType = RecordType::from_u16(39);

/// Which alias produced a redirection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasKind {
    /// A CNAME at the asked name.
    Cname,
    /// A DNAME above the asked name, with its synthesized CNAME.
    Dname,
}

/// One redirection: the records that justify it and the name it leads to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasLink {
    /// The name that was asked.
    pub owner: Name,
    /// The name it redirects to.
    pub target: Name,
    /// Which alias produced it.
    pub kind: AliasKind,
    /// The alias records to carry into the final answer: the CNAME, or the DNAME
    /// followed by its synthesized CNAME.
    pub records: Vec<ResourceRecord>,
}

/// The classification of one response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseKind {
    /// A delegation to a zone below the server's.
    Referral(Delegation),
    /// Records for the question asked, or an authoritative NODATA for the client's
    /// own question.
    AuthoritativeAnswer,
    /// The asked name is an alias.
    Alias(AliasLink),
    /// An authoritative empty answer to a minimised question: the name has no
    /// records of its own but may have descendants.
    NoDataAtEmptyNonTerminal,
    /// NXDOMAIN.
    NameError,
    /// SERVFAIL, or another failure RCODE not attributable to minimisation.
    ServerFailure,
    /// The server answered without authority for a zone it was delegated, or
    /// referred the descent sideways or upward.
    Lame,
    /// FORMERR, NOTIMP or REFUSED to a minimised question.
    MinimisationRefused,
    /// Still truncated after the TCP retry.
    Truncated,
    /// Structurally unusable.
    Malformed,
}

/// Classifies `message`, the response from a server for `server_zone` to `sent`.
/// `intermediate` says whether `sent` was a minimised question.
#[must_use]
pub fn classify(
    server_zone: &Name,
    sent: &Question,
    intermediate: bool,
    message: &Message,
    learned_at: Instant,
) -> ResponseKind {
    if message.header.truncated {
        return ResponseKind::Truncated;
    }
    match message.header.rcode {
        ResponseCode::NOERROR => {}
        ResponseCode::NXDOMAIN => {
            return alias_at(server_zone, sent, message).unwrap_or(ResponseKind::NameError);
        }
        ResponseCode::FORMERR | ResponseCode::NOTIMP | ResponseCode::REFUSED if intermediate => {
            return ResponseKind::MinimisationRefused;
        }
        _ => return ResponseKind::ServerFailure,
    }
    if let Some(alias) = alias_at(server_zone, sent, message) {
        return alias;
    }
    if has_records_for(message, sent) {
        if intermediate && sent.qtype == RecordType::NS {
            return referral_from_answer(server_zone, sent, message, learned_at);
        }
        return if message.header.authoritative {
            ResponseKind::AuthoritativeAnswer
        } else {
            ResponseKind::Lame
        };
    }
    if let Some(referral) = referral(server_zone, sent, message, learned_at) {
        return referral;
    }
    if !message.header.authoritative {
        return ResponseKind::Lame;
    }
    if intermediate {
        ResponseKind::NoDataAtEmptyNonTerminal
    } else {
        ResponseKind::AuthoritativeAnswer
    }
}

fn has_records_for(message: &Message, sent: &Question) -> bool {
    message
        .answers
        .iter()
        .any(|record| record.owner == sent.qname && record.rtype == sent.qtype)
}

/// A referral in the authority section: NS records for a zone strictly below the
/// server's. NS records for the server's own zone are just authority data.
fn referral(
    server_zone: &Name,
    sent: &Question,
    message: &Message,
    learned_at: Instant,
) -> Option<ResponseKind> {
    let delegated = message
        .authorities
        .iter()
        .find(|record| record.rtype == RecordType::NS)?;
    if delegated.owner == *server_zone && message.header.authoritative {
        return None;
    }
    Some(
        match Delegation::from_referral(server_zone, message, &sent.qname, learned_at) {
            Ok(delegation) => ResponseKind::Referral(delegation),
            Err(RecursionError::Malformed) => ResponseKind::Malformed,
            Err(_) => ResponseKind::Lame,
        },
    )
}

/// A minimised NS question answered from the zone's own apex: the server is
/// authoritative for both sides of the cut, and the answer section's NS RRset is
/// the delegation.
fn referral_from_answer(
    server_zone: &Name,
    sent: &Question,
    message: &Message,
    learned_at: Instant,
) -> ResponseKind {
    if sent.qname == *server_zone {
        return ResponseKind::AuthoritativeAnswer;
    }
    let mut as_referral = Message::new(message.header.clone());
    as_referral.authorities = message
        .answers
        .iter()
        .filter(|record| record.rtype == RecordType::NS || record.rtype == RecordType::DS)
        .cloned()
        .collect();
    as_referral.additionals = message.additionals.clone();
    match Delegation::from_referral(server_zone, &as_referral, &sent.qname, learned_at) {
        Ok(delegation) => ResponseKind::Referral(delegation),
        Err(_) => ResponseKind::Lame,
    }
}

/// A DNAME above the asked name, or else a CNAME at it, within the server's
/// bailiwick.
///
/// The DNAME is checked first: when one is present, the CNAME beside it is only
/// the server's synthesis, and must be verified against the DNAME rather than
/// trusted on its own — otherwise a forged "synthesized" CNAME would redirect the
/// descent anywhere.
fn alias_at(server_zone: &Name, sent: &Question, message: &Message) -> Option<ResponseKind> {
    if sent.qtype != DNAME {
        let dname = message.answers.iter().find(|record| {
            record.rtype == DNAME
                && sent.qname != record.owner
                && sent.qname.is_subdomain_of(&record.owner)
        });
        if let Some(record) = dname {
            return Some(dname_link(server_zone, sent, record, message));
        }
    }
    if sent.qtype == RecordType::CNAME {
        return None;
    }
    let cname = message
        .answers
        .iter()
        .find(|record| record.owner == sent.qname && record.rtype == RecordType::CNAME)?;
    Some(cname_link(server_zone, sent, cname))
}

fn cname_link(server_zone: &Name, sent: &Question, record: &ResourceRecord) -> ResponseKind {
    let RData::Cname(target) = &record.rdata else {
        return ResponseKind::Malformed;
    };
    if !is_in_bailiwick(server_zone, &record.owner) {
        return ResponseKind::Lame;
    }
    ResponseKind::Alias(AliasLink {
        owner: sent.qname.clone(),
        target: target.clone(),
        kind: AliasKind::Cname,
        records: vec![record.clone()],
    })
}

/// Follows a DNAME: the owner must be within the server's bailiwick, the target
/// is computed here rather than trusted, and the server's synthesized CNAME is
/// accepted only if it says the same thing (otherwise one is synthesized).
fn dname_link(
    server_zone: &Name,
    sent: &Question,
    dname: &ResourceRecord,
    message: &Message,
) -> ResponseKind {
    if !is_in_bailiwick(server_zone, &dname.owner) {
        return ResponseKind::Lame;
    }
    let RData::Unknown(rdata) = &dname.rdata else {
        return ResponseKind::Malformed;
    };
    let Some(dname_target) = parse_uncompressed_name(rdata.octets()) else {
        return ResponseKind::Malformed;
    };
    let Some(target) = substitute_suffix(&sent.qname, &dname.owner, &dname_target) else {
        return ResponseKind::Malformed;
    };
    let synthesized = message
        .answers
        .iter()
        .find(|record| {
            record.owner == sent.qname
                && matches!(&record.rdata, RData::Cname(cname) if *cname == target)
        })
        .cloned()
        .unwrap_or_else(|| {
            ResourceRecord::new(
                sent.qname.clone(),
                RecordType::CNAME,
                RecordClass::In,
                dname.ttl,
                RData::Cname(target.clone()),
            )
        });
    ResponseKind::Alias(AliasLink {
        owner: sent.qname.clone(),
        target,
        kind: AliasKind::Dname,
        records: vec![dname.clone(), synthesized],
    })
}

#[cfg(test)]
#[path = "classify_tests.rs"]
mod tests;
