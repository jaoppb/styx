//! Which owner names an answer section may carry, given the question asked.
//!
//! ADR 0017: an answer record is admissible when its owner is within the
//! bailiwick zone, *or* is reached from the query name through a chain of CNAMEs.
//! The chain is walked from the qname only: a CNAME that merely happens to sit
//! inside the zone, but is not a link of that chain, extends nothing, so an in-zone
//! name cannot be used to smuggle an out-of-zone owner into the cache.

use std::collections::{HashMap, HashSet};

use styx_proto::{Name, RData, RecordType, ResourceRecord};

use crate::domain::cache::key::CanonicalName;

/// One DNAME record of an answer: the subtree it redirects and where to.
#[derive(Debug)]
struct DnameRecord {
    owner: CanonicalName,
    target: Name,
}

/// The owner names an answer section may carry: the bailiwick zone's subtree, each
/// exact target reached from the qname through CNAME links, and each DNAME whose
/// synthesized CNAME is one of those links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnswerScope {
    zone: CanonicalName,
    chain_end: CanonicalName,
    alias_targets: HashSet<CanonicalName>,
    dname_owners: HashSet<CanonicalName>,
    cyclic: bool,
}

impl AnswerScope {
    /// Walks the alias chain that starts at `qname`.
    ///
    /// Every CNAME is canonicalized once into an owner-to-target map, and each link
    /// is followed at most once, so the walk is linear in the records and a cyclic
    /// chain ends at the first repeated target without a separate loop detector.
    pub(crate) fn from_chain(
        zone: CanonicalName,
        qname: &CanonicalName,
        answers: &[ResourceRecord],
    ) -> Self {
        let cnames = cname_links(answers);
        let dnames = dname_records(answers);
        let mut scope = Self {
            zone,
            chain_end: qname.clone(),
            alias_targets: HashSet::new(),
            dname_owners: HashSet::new(),
            cyclic: false,
        };
        let mut link = qname.clone();
        while let Some(target) = cnames.get(&link) {
            if !scope.alias_targets.insert(target.clone()) {
                scope.cyclic = true;
                break;
            }
            scope.admit_matching_dnames(&link, target, &dnames);
            link = target.clone();
        }
        scope.chain_end = link;
        scope
    }

    /// The name the alias chain ends at: the qname when it has no alias. For a cyclic
    /// chain this is an arbitrary link of the loop, so it names no ending at all.
    pub(crate) const fn chain_end(&self) -> &CanonicalName {
        &self.chain_end
    }

    /// Whether the chain loops back on a name it already passed through, and so
    /// leads nowhere however many records the answer carries.
    pub(crate) const fn is_cyclic(&self) -> bool {
        self.cyclic
    }

    /// Admits each DNAME that explains the CNAME `link -> target`: RFC 6672 §3.1
    /// has the server synthesize that CNAME from the DNAME, so a DNAME is
    /// admissible exactly when substituting its owner for its target in `link`
    /// gives `target`. A DNAME without its synthesized CNAME proves nothing.
    fn admit_matching_dnames(
        &mut self,
        link: &CanonicalName,
        target: &CanonicalName,
        dnames: &[DnameRecord],
    ) {
        for dname in dnames {
            let synthesized = link
                .inner()
                .substitute_suffix(dname.owner.inner(), &dname.target);
            let matches =
                synthesized.is_some_and(|name| CanonicalName::canonicalize(&name) == *target);
            if matches {
                self.dname_owners.insert(dname.owner.clone());
            }
        }
    }

    /// Returns `true` if an answer RRset of type `rtype` owned by `owner` is
    /// admissible.
    pub(crate) fn permits(&self, owner: &CanonicalName, rtype: RecordType) -> bool {
        if owner.is_subdomain_of(&self.zone) || self.alias_targets.contains(owner) {
            return true;
        }
        rtype == RecordType::DNAME && self.dname_owners.contains(owner)
    }
}

/// Each CNAME's owner mapped to its target; the first CNAME of an owner wins, since
/// an owner with several CNAMEs is malformed and only one can be followed.
fn cname_links(answers: &[ResourceRecord]) -> HashMap<CanonicalName, CanonicalName> {
    let mut links = HashMap::new();
    for record in answers {
        let RData::Cname(target) = &record.rdata else {
            continue;
        };
        links
            .entry(CanonicalName::canonicalize(&record.owner))
            .or_insert_with(|| CanonicalName::canonicalize(target));
    }
    links
}

fn dname_records(answers: &[ResourceRecord]) -> Vec<DnameRecord> {
    answers
        .iter()
        .filter(|record| record.rtype == RecordType::DNAME)
        .filter_map(|record| {
            let RData::Unknown(rdata) = &record.rdata else {
                return None;
            };
            Some(DnameRecord {
                owner: CanonicalName::canonicalize(&record.owner),
                target: Name::from_uncompressed_wire(rdata.octets())?,
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "answer_scope_tests.rs"]
mod tests;
