//! An answer section read as the chain that leads from the question to its data.

use styx_proto::{Name, Question, RData, RecordType, ResourceRecord};

/// The most CNAME hops followed before an answer is refused as a loop or an attack.
const MAX_CNAME_HOPS: usize = 8;

/// One owner name along the chain and the records the answer carries for it: a CNAME
/// pointing further, or the data the question asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink<'a> {
    owner: Name,
    records: Vec<&'a ResourceRecord>,
}

impl<'a> ChainLink<'a> {
    /// The owner name of this link's records.
    #[must_use]
    pub fn owner(&self) -> &Name {
        &self.owner
    }

    /// The records at this link.
    #[must_use]
    pub fn records(&self) -> &[&'a ResourceRecord] {
        &self.records
    }
}

/// How the chain ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEnd {
    /// The last link holds the data the question asked for.
    Terminal,
    /// No data at this name: the response must prove its absence (RFC 4035 §5.3,
    /// RFC 6840 §4.3). A response with no answer at all dangles at the qname itself.
    Dangling(Name),
}

/// The answer section as a chain from the question name, through CNAMEs, to the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerChain<'a> {
    links: Vec<ChainLink<'a>>,
    end: ChainEnd,
}

impl<'a> AnswerChain<'a> {
    /// Follows `answers` from `question`. `None` when the section is not one chain bound
    /// to the question: a record off the chain, a fork, a loop, or too many hops.
    #[must_use]
    pub fn follow(question: &Question, answers: &'a [ResourceRecord]) -> Option<Self> {
        if answers
            .iter()
            .any(|record| record.rclass != question.qclass)
        {
            return None;
        }
        let data: Vec<&ResourceRecord> = answers
            .iter()
            .filter(|record| !matches!(record.rdata, RData::Rrsig(_)))
            .collect();
        let mut state = ChainWalk {
            links: Vec::new(),
            visited: Vec::new(),
            synthesized_cnames: 0,
            current: question.qname.to_canonical(),
        };
        for _ in 0..=MAX_CNAME_HOPS {
            match state.advance(question.qtype, &data)? {
                StepOutcome::Continue => {}
                StepOutcome::Finish(end) => return state.complete(end, data.len()),
            }
        }
        None
    }

    /// The links in order from the question name.
    #[must_use]
    pub fn links(&self) -> &[ChainLink<'a>] {
        &self.links
    }

    /// How the chain ends.
    #[must_use]
    pub fn end(&self) -> &ChainEnd {
        &self.end
    }
}

enum StepOutcome {
    Continue,
    Finish(ChainEnd),
}

/// What a DNAME above the current name does to the chain.
enum DnameStep {
    /// No DNAME redirects the current name.
    NotApplicable,
    /// A DNAME redirected the current name, and the chain goes on as `StepOutcome` says.
    Applied(StepOutcome),
    /// The DNAMEs or their synthesized CNAME do not form one redirection.
    Malformed,
}

struct ChainWalk<'a> {
    links: Vec<ChainLink<'a>>,
    visited: Vec<Name>,
    synthesized_cnames: usize,
    current: Name,
}

impl<'a> ChainWalk<'a> {
    fn advance(&mut self, qtype: RecordType, data: &[&'a ResourceRecord]) -> Option<StepOutcome> {
        if self.visited.contains(&self.current) {
            return None;
        }
        self.visited.push(self.current.clone());
        let at_owner: Vec<&ResourceRecord> = data
            .iter()
            .copied()
            .filter(|record| record.owner.eq_ignore_case(&self.current))
            .collect();
        match self.try_dname_step(qtype, data, &at_owner) {
            DnameStep::NotApplicable => {}
            DnameStep::Applied(outcome) => return Some(outcome),
            DnameStep::Malformed => return None,
        }
        let terminal: Vec<&ResourceRecord> = at_owner
            .iter()
            .copied()
            .filter(|record| qtype == RecordType::ANY || record.rtype == qtype)
            .collect();
        if !terminal.is_empty() {
            self.links.push(ChainLink {
                owner: self.current.clone(),
                records: terminal,
            });
            return Some(StepOutcome::Finish(ChainEnd::Terminal));
        }
        let [cname] = at_owner.as_slice() else {
            return at_owner
                .is_empty()
                .then(|| StepOutcome::Finish(ChainEnd::Dangling(self.current.clone())));
        };
        let RData::Cname(ref target) = cname.rdata else {
            return None;
        };
        self.links.push(ChainLink {
            owner: self.current.clone(),
            records: vec![*cname],
        });
        self.current = target.to_canonical();
        Some(StepOutcome::Continue)
    }

    fn try_dname_step(
        &mut self,
        qtype: RecordType,
        data: &[&'a ResourceRecord],
        at_owner: &[&ResourceRecord],
    ) -> DnameStep {
        let (dname, next) = match find_dname_redirection(&self.current, data) {
            DnameLookup::None => return DnameStep::NotApplicable,
            DnameLookup::Malformed => return DnameStep::Malformed,
            DnameLookup::Match(dname, next) => (dname, next),
        };
        let Some(consumed) = matching_synthesized_cname(at_owner, &next) else {
            return DnameStep::Malformed;
        };
        self.synthesized_cnames = self.synthesized_cnames.saturating_add(consumed);
        self.links.push(ChainLink {
            owner: dname.owner.to_canonical(),
            records: vec![dname],
        });
        if qtype == RecordType::CNAME && consumed == 1 {
            return DnameStep::Applied(StepOutcome::Finish(ChainEnd::Terminal));
        }
        self.current = next;
        DnameStep::Applied(StepOutcome::Continue)
    }

    fn complete(self, end: ChainEnd, data_records: usize) -> Option<AnswerChain<'a>> {
        let in_chain: usize = self.links.iter().map(|link| link.records.len()).sum();
        (in_chain.checked_add(self.synthesized_cnames) == Some(data_records)).then_some(
            AnswerChain {
                links: self.links,
                end,
            },
        )
    }
}

enum DnameLookup<'a> {
    None,
    Match(&'a ResourceRecord, Name),
    Malformed,
}

fn find_dname_redirection<'a>(current: &Name, data: &[&'a ResourceRecord]) -> DnameLookup<'a> {
    let matching: Vec<&ResourceRecord> = data
        .iter()
        .copied()
        .filter(|record| {
            record.rtype == RecordType::DNAME
                && !record.owner.eq_ignore_case(current)
                && current.is_subdomain_of(&record.owner)
        })
        .collect();
    let Some(best) = matching
        .iter()
        .copied()
        .max_by_key(|record| record.owner.label_count())
    else {
        return DnameLookup::None;
    };
    let same_owner_count = matching
        .iter()
        .filter(|record| record.owner.eq_ignore_case(&best.owner))
        .count();
    if same_owner_count != 1 {
        return DnameLookup::Malformed;
    }
    let RData::Unknown(ref rdata) = best.rdata else {
        return DnameLookup::Malformed;
    };
    let Some(dname_target) = Name::from_uncompressed_wire(rdata.octets()) else {
        return DnameLookup::Malformed;
    };
    let Some(next) = current.substitute_suffix(&best.owner, &dname_target) else {
        return DnameLookup::Malformed;
    };
    DnameLookup::Match(best, next.to_canonical())
}

fn matching_synthesized_cname(
    at_owner: &[&ResourceRecord],
    expected_target: &Name,
) -> Option<usize> {
    match at_owner {
        [] => Some(0),
        [record]
            if matches!(
                &record.rdata,
                RData::Cname(target) if target.eq_ignore_case(expected_target)
            ) =>
        {
            Some(1)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use styx_proto::domain::rdata::UnknownRdata;
    use styx_proto::{RecordClass, Ttl};

    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn record(owner: &str, rtype: RecordType, rdata: RData) -> ResourceRecord {
        ResourceRecord::new(
            name(owner),
            rtype,
            RecordClass::In,
            Ttl::from_secs(300),
            rdata,
        )
    }

    fn cname(owner: &str, target: &str) -> ResourceRecord {
        record(owner, RecordType::CNAME, RData::Cname(name(target)))
    }

    fn dname(owner: &str, target: &str) -> ResourceRecord {
        let octets = name(target).as_wire_bytes().to_vec();
        let rdata = RData::Unknown(UnknownRdata::new(RecordType::DNAME, octets));
        record(owner, RecordType::DNAME, rdata)
    }

    fn a(owner: &str) -> ResourceRecord {
        record(
            owner,
            RecordType::A,
            RData::A(std::net::Ipv4Addr::LOCALHOST),
        )
    }

    fn question(qname: &str) -> Question {
        Question {
            qname: name(qname),
            qtype: RecordType::A,
            qclass: RecordClass::In,
        }
    }

    /// `hop0.example.` through `hop<hops>.example.`, one CNAME each, then the data.
    fn cname_chain(hops: usize) -> Vec<ResourceRecord> {
        let mut answers: Vec<ResourceRecord> = (0..hops)
            .map(|hop| {
                let next = hop.saturating_add(1);
                cname(
                    &format!("hop{hop}.example."),
                    &format!("hop{next}.example."),
                )
            })
            .collect();
        answers.push(a(&format!("hop{hops}.example.")));
        answers
    }

    #[test]
    fn eight_cname_hops_are_followed_and_nine_are_refused() {
        let at_cap = cname_chain(MAX_CNAME_HOPS);
        let chain = AnswerChain::follow(&question("hop0.example."), &at_cap).unwrap();
        assert_eq!(chain.links().len(), MAX_CNAME_HOPS.saturating_add(1));
        assert_eq!(chain.end(), &ChainEnd::Terminal);

        let over_cap = cname_chain(MAX_CNAME_HOPS.saturating_add(1));
        assert_eq!(
            AnswerChain::follow(&question("hop0.example."), &over_cap),
            None
        );
    }

    /// A DNAME may arrive without the CNAME a server synthesizes from it (RFC 6672 §3.4).
    #[test]
    fn a_bare_dname_redirects_to_its_target() {
        let answers = vec![dname("old.example.", "new.example."), a("www.new.example.")];

        let chain = AnswerChain::follow(&question("www.old.example."), &answers).unwrap();

        let owners: Vec<&Name> = chain.links().iter().map(ChainLink::owner).collect();
        assert_eq!(owners, [&name("old.example."), &name("www.new.example.")]);
        assert_eq!(chain.end(), &ChainEnd::Terminal);
    }

    #[test]
    fn two_dnames_at_one_owner_are_refused() {
        let answers = vec![
            dname("old.example.", "new.example."),
            dname("old.example.", "other.example."),
            a("www.new.example."),
        ];

        assert_eq!(
            AnswerChain::follow(&question("www.old.example."), &answers),
            None
        );
    }
}
