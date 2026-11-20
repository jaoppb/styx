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
        let data: Vec<&ResourceRecord> = answers
            .iter()
            .filter(|record| {
                !matches!(record.rdata, RData::Rrsig(_)) && record.rclass == question.qclass
            })
            .collect();
        let mut links = Vec::new();
        let mut current = question.qname.to_canonical();
        for _ in 0..=MAX_CNAME_HOPS {
            if links
                .iter()
                .any(|link: &ChainLink<'_>| link.owner == current)
            {
                return None;
            }
            let at_owner: Vec<&ResourceRecord> = data
                .iter()
                .copied()
                .filter(|record| record.owner.eq_ignore_case(&current))
                .collect();
            let terminal: Vec<&ResourceRecord> = at_owner
                .iter()
                .copied()
                .filter(|record| {
                    question.qtype == RecordType::ANY || record.rtype == question.qtype
                })
                .collect();
            if !terminal.is_empty() {
                links.push(ChainLink {
                    owner: current,
                    records: terminal,
                });
                return Self::complete(links, ChainEnd::Terminal, data.len());
            }
            let [cname] = at_owner.as_slice() else {
                return at_owner
                    .is_empty()
                    .then(|| Self::complete(links, ChainEnd::Dangling(current), data.len()))
                    .flatten();
            };
            let RData::Cname(ref target) = cname.rdata else {
                return None;
            };
            let next = target.to_canonical();
            links.push(ChainLink {
                owner: current,
                records: vec![*cname],
            });
            current = next;
        }
        None
    }

    /// The chain, provided it accounts for every data record in the section.
    fn complete(links: Vec<ChainLink<'a>>, end: ChainEnd, data_records: usize) -> Option<Self> {
        let in_chain: usize = links.iter().map(|link| link.records.len()).sum();
        (in_chain == data_records).then_some(Self { links, end })
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
