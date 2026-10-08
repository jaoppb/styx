//! Builds a fake server's response to one query from its [`ZoneScript`].
//!
//! The decision order, first match wins:
//!
//! 1. EDNS intolerance: a query carrying OPT gets FORMERR and no OPT.
//! 2. A scripted RCODE for this question.
//! 3. Lameness: AA=0 and nothing in any section.
//! 4. An exact scripted answer for the question's name and type.
//! 5. A referral, when the name is at or below a delegated zone.
//! 6. The authoritative answer: records, then CNAME and DNAME chasing within the
//!    script, then NODATA for a name that exists (an empty non-terminal included)
//!    or NXDOMAIN for one that does not.
//!
//! Scripted extra glue is then appended to the additional section of a referral or
//! an answer alike. Truncation is applied last, over UDP only. A silent server
//! records the query and sends nothing.

use hickory_proto::op::{
    Edns, Message as HMessage, MessageType as HMessageType, OpCode as HOpCode, Query as HQuery,
    ResponseCode as HResponseCode,
};
use hickory_proto::rr::rdata::{A, CNAME, NS, SOA};
use hickory_proto::rr::{DNSClass as HDnsClass, RData as HRData, Record as HRecord};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use styx_proto::{Message, Question, ResponseCode};

use crate::convert::{dname_record, hickory_name, hickory_record, hickory_type};
use crate::error::HarnessError;
use crate::script::{is_at_or_below, normalise, ZoneScript};

/// TTL on records the fake synthesizes itself (referral NS and glue, SOA, DNAME).
const SYNTHESIZED_TTL: u32 = 3600;

/// How many CNAME or DNAME links one answer follows inside the script.
const MAX_CHASE: usize = 8;

/// Payload size the fake advertises when it answers with EDNS.
const ADVERTISED_PAYLOAD: u16 = 1232;

/// What the fake recorded about one query it received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedQuery {
    /// The question exactly as it arrived on the wire, case included.
    pub question: Question,
    /// Whether it arrived over TCP.
    pub via_tcp: bool,
    /// Whether it carried an OPT record with the DO bit set.
    pub dnssec_ok: bool,
}

/// A decoded query and the encoded reply to it; no reply from a silent server.
pub(crate) struct Exchange {
    pub(crate) received: ReceivedQuery,
    pub(crate) reply: Option<Vec<u8>>,
}

/// Answers one raw query, or returns `None` for bytes that are not a usable query.
pub(crate) fn respond(bytes: &[u8], script: &ZoneScript, via_tcp: bool) -> Option<Exchange> {
    let query = Message::decode(bytes).ok()?;
    let question = query.questions.first()?.clone();
    let dnssec_ok = query.opt.as_ref().is_some_and(styx_proto::Opt::dnssec_ok);
    let received = ReceivedQuery {
        question: question.clone(),
        via_tcp,
        dnssec_ok,
    };
    if script.silent {
        return Some(Exchange {
            received,
            reply: None,
        });
    }
    let mut reply = empty_reply(&query, &question).ok()?;

    if script.edns_intolerant && query.opt.is_some() {
        reply.metadata.response_code = HResponseCode::FormErr;
    } else {
        reply.edns = query.opt.as_ref().map(|opt| {
            let mut edns = Edns::new();
            edns.set_max_payload(ADVERTISED_PAYLOAD)
                .set_dnssec_ok(opt.dnssec_ok());
            edns
        });
        fill(&mut reply, &question, script).ok()?;
    }

    if script.truncate_udp && !via_tcp {
        reply.metadata.truncation = true;
        reply.answers.clear();
        reply.authorities.clear();
        reply.additionals.clear();
    }

    let mut out = Vec::new();
    reply.emit(&mut BinEncoder::new(&mut out)).ok()?;
    Some(Exchange {
        received,
        reply: Some(out),
    })
}

fn empty_reply(query: &Message, question: &Question) -> Result<HMessage, HarnessError> {
    let mut reply = HMessage::new(query.header.id, HMessageType::Response, HOpCode::Query);
    reply.metadata.recursion_desired = query.header.recursion_desired;
    let mut echoed = HQuery::new();
    echoed.set_name(hickory_name(&question.qname.to_string())?);
    echoed.set_query_type(hickory_type(question.qtype));
    echoed.set_query_class(HDnsClass::IN);
    reply.add_query(echoed);
    Ok(reply)
}

fn fill(
    reply: &mut HMessage,
    question: &Question,
    script: &ZoneScript,
) -> Result<(), HarnessError> {
    let name = normalise(&question.qname.to_string());
    if let Some(scripted) = script.rcodes.iter().find(|scripted| {
        normalise(&scripted.name) == name && scripted.rtype.is_none_or(|t| t == question.qtype)
    }) {
        reply.metadata.response_code = hickory_rcode(scripted.rcode);
        return Ok(());
    }
    if script.lame {
        return Ok(());
    }
    let has_exact_answer = script
        .answers
        .iter()
        .any(|answer| normalise(&answer.name) == name && answer.rtype == question.qtype);
    let referred = !has_exact_answer && refer(reply, &name, script)?;
    if !referred {
        reply.metadata.authoritative = true;
        answer(reply, &name, question, script)?;
    }
    for glue in &script.extra_glue {
        reply.add_additional(HRecord::from_rdata(
            hickory_name(&glue.name)?,
            SYNTHESIZED_TTL,
            HRData::A(A(glue.ip)),
        ));
    }
    Ok(())
}

/// Writes the referral for the deepest delegated zone at or above `name`, if any.
fn refer(reply: &mut HMessage, name: &str, script: &ZoneScript) -> Result<bool, HarnessError> {
    let Some(zone) = script
        .referrals
        .iter()
        .map(|referral| normalise(&referral.zone))
        .filter(|zone| is_at_or_below(name, zone))
        .max_by_key(String::len)
    else {
        return Ok(false);
    };
    for referral in script
        .referrals
        .iter()
        .filter(|referral| normalise(&referral.zone) == zone)
    {
        let target = hickory_name(&referral.ns_target)?;
        reply.add_authority(HRecord::from_rdata(
            hickory_name(&zone)?,
            SYNTHESIZED_TTL,
            HRData::NS(NS(target.clone())),
        ));
        if let Some(ip) = referral.glue_ip {
            reply.add_additional(HRecord::from_rdata(
                target,
                SYNTHESIZED_TTL,
                HRData::A(A(ip)),
            ));
        }
    }
    Ok(true)
}

fn answer(
    reply: &mut HMessage,
    name: &str,
    question: &Question,
    script: &ZoneScript,
) -> Result<(), HarnessError> {
    let mut current = name.to_string();
    for _ in 0..MAX_CHASE {
        let Some(next) = answer_one(reply, &current, question, script)? else {
            break;
        };
        current = next;
    }
    if reply.answers.is_empty() {
        deny(reply, name, script)?;
    }
    Ok(())
}

/// Answers for one name of a chain. Returns the next name to follow, if the
/// answer was an alias.
fn answer_one(
    reply: &mut HMessage,
    name: &str,
    question: &Question,
    script: &ZoneScript,
) -> Result<Option<String>, HarnessError> {
    let at_name = |rtype| {
        script
            .answers
            .iter()
            .filter(move |answer| normalise(&answer.name) == name && answer.rtype == rtype)
    };
    let direct: Vec<_> = at_name(question.qtype).collect();
    if !direct.is_empty() {
        for record in direct.iter().flat_map(|answer| &answer.records) {
            reply.add_answer(hickory_record(record)?);
        }
        return Ok(None);
    }
    if let Some(alias) = at_name(styx_proto::RecordType::CNAME).next() {
        let mut target = None;
        for record in &alias.records {
            if let styx_proto::RData::Cname(next) = &record.rdata {
                target = Some(normalise(&next.to_string()));
            }
            reply.add_answer(hickory_record(record)?);
        }
        return Ok(target);
    }
    let Some(dname) = script.dnames.iter().find(|dname| {
        let owner = normalise(&dname.owner);
        owner != name && is_at_or_below(name, &owner)
    }) else {
        return Ok(None);
    };
    let owner = normalise(&dname.owner);
    let prefix = name.strip_suffix(&owner).unwrap_or(name);
    let synthesized = normalise(&format!("{prefix}{}", normalise(&dname.target)));
    reply.add_answer(dname_record(&owner, &dname.target, SYNTHESIZED_TTL)?);
    reply.add_answer(HRecord::from_rdata(
        hickory_name(name)?,
        SYNTHESIZED_TTL,
        HRData::CNAME(CNAME(hickory_name(&synthesized)?)),
    ));
    Ok(Some(synthesized))
}

/// Writes a negative answer: NODATA when `name` exists in the script — itself, as a
/// DNAME owner, or as an empty non-terminal above scripted names — and NXDOMAIN
/// otherwise.
fn deny(reply: &mut HMessage, name: &str, script: &ZoneScript) -> Result<(), HarnessError> {
    let exists = script
        .answers
        .iter()
        .map(|answer| &answer.name)
        .chain(script.dnames.iter().map(|dname| &dname.owner))
        .any(|owner| is_at_or_below(&normalise(owner), name));
    if !exists {
        reply.metadata.response_code = HResponseCode::NXDomain;
    }
    let Some(origin) = &script.origin else {
        return Ok(());
    };
    let zone = hickory_name(&normalise(&origin.zone))?;
    let soa = SOA::new(
        zone.prepend_label("ns")?,
        zone.prepend_label("hostmaster")?,
        1,
        3600,
        600,
        86400,
        origin.negative_ttl,
    );
    reply.add_authority(HRecord::from_rdata(zone, SYNTHESIZED_TTL, HRData::SOA(soa)));
    Ok(())
}

fn hickory_rcode(rcode: ResponseCode) -> HResponseCode {
    <HResponseCode as From<u16>>::from(rcode.value())
}
