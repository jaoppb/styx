//! Bailiwick zone scoping and cache-poisoning prevention.
//!
//! A responding server only holds authority over names within its assigned bailiwick zone.
//! Permitting arbitrary records into the answer cache without bailiwick verification
//! creates a classic cache-poisoning vulnerability.

use styx_proto::{Message, Question, RData, RecordType, ResourceRecord};

use crate::domain::cache::key::CanonicalName;

/// The authoritative zone scope defining cache admission boundaries for a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bailiwick {
    zone: CanonicalName,
}

impl Bailiwick {
    /// Creates a new `Bailiwick` enclosing the given zone.
    #[must_use]
    pub const fn new(zone: CanonicalName) -> Self {
        Self { zone }
    }

    /// Derives the bailiwick zone of authority from a query question and its response message.
    ///
    /// Determination order:
    /// 1. SOA record in the authority section (its owner is the authoritative zone).
    /// 2. Deepest NS record in the authority section whose owner is at or above the qname.
    /// 3. The query name itself as fallback.
    #[must_use]
    pub fn of_response(question: &Question, message: &Message) -> Self {
        let qname_canon = CanonicalName::canonicalize(&question.qname);

        if let Some(zone) = Self::find_soa_zone(&qname_canon, message) {
            return Self { zone };
        }

        if let Some(zone) = Self::find_deepest_ns_zone(&qname_canon, message) {
            return Self { zone };
        }

        Self { zone: qname_canon }
    }

    fn find_soa_zone(qname: &CanonicalName, message: &Message) -> Option<CanonicalName> {
        for rr in &message.authorities {
            if rr.rtype != RecordType::SOA {
                continue;
            }
            let zone = CanonicalName::canonicalize(&rr.owner);
            if qname.is_subdomain_of(&zone) {
                return Some(zone);
            }
        }
        None
    }

    fn find_deepest_ns_zone(qname: &CanonicalName, message: &Message) -> Option<CanonicalName> {
        let mut deepest: Option<CanonicalName> = None;
        for rr in &message.authorities {
            if rr.rtype != RecordType::NS {
                continue;
            }
            let candidate = CanonicalName::canonicalize(&rr.owner);
            if !qname.is_subdomain_of(&candidate) {
                continue;
            }
            let is_deeper = deepest
                .as_ref()
                .is_none_or(|cur| candidate.label_count() > cur.label_count());
            if is_deeper {
                deepest = Some(candidate);
            }
        }
        deepest
    }

    /// Returns `true` if `owner` falls within this bailiwick zone.
    ///
    /// An owner name is permitted if it is equal to or a subdomain of the bailiwick zone.
    #[must_use]
    pub fn permits(&self, owner: &CanonicalName) -> bool {
        owner.is_subdomain_of(&self.zone)
    }

    /// Returns the enclosing zone of authority.
    #[must_use]
    pub const fn zone(&self) -> &CanonicalName {
        &self.zone
    }

    /// Returns the owner names an answer section may carry under this bailiwick.
    ///
    /// ADR 0017: an answer record is admissible when its owner is within the zone,
    /// *or* is reached through a CNAME chain whose every link is itself admissible.
    /// Each such CNAME permits its target — that exact name, never its subtree — so a
    /// cross-zone chain (`www.example.com CNAME x.cdn.net`, `x.cdn.net A …`) is
    /// admitted whole instead of leaving a dangling CNAME in the cache.
    ///
    /// A DNAME needs no rule of its own: RFC 6672 §3.1 requires the server to send
    /// the CNAME it synthesizes alongside it, and that CNAME's owner sits beneath
    /// the DNAME's, so the CNAME rule carries the chain across.
    pub(crate) fn answer_scope(&self, answers: &[ResourceRecord]) -> AnswerScope {
        let mut scope = AnswerScope {
            zone: self.zone.clone(),
            alias_targets: Vec::new(),
        };
        // A pass only ever adds targets, and a chain of n links needs at most n
        // passes, so bounding the passes by the record count ends a cyclic or
        // adversarial chain without a separate loop detector.
        for _ in 0..answers.len() {
            if !scope.extend_through_aliases(answers) {
                break;
            }
        }
        scope
    }
}

/// The owner names an answer section may carry: the bailiwick zone's subtree, plus
/// each exact target reached from it through admissible CNAME links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnswerScope {
    zone: CanonicalName,
    alias_targets: Vec<CanonicalName>,
}

impl AnswerScope {
    /// Returns `true` if an answer record owned by `owner` is admissible.
    pub(crate) fn permits(&self, owner: &CanonicalName) -> bool {
        owner.is_subdomain_of(&self.zone) || self.alias_targets.contains(owner)
    }

    /// Adds the target of every CNAME whose owner is already permitted. Returns
    /// whether anything was added, so the caller knows when the chain is closed.
    fn extend_through_aliases(&mut self, answers: &[ResourceRecord]) -> bool {
        let mut extended = false;
        for record in answers {
            let RData::Cname(target) = &record.rdata else {
                continue;
            };
            let target = CanonicalName::canonicalize(target);
            if self.permits(&target) || !self.permits(&CanonicalName::canonicalize(&record.owner)) {
                continue;
            }
            self.alias_targets.push(target);
            extended = true;
        }
        extended
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use styx_proto::{Name, RecordClass, Ttl};

    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("name")
    }

    fn canonical(text: &str) -> CanonicalName {
        CanonicalName::canonicalize(&name(text))
    }

    fn cname(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord::new(
            name(owner),
            RecordType::CNAME,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::Cname(name(target)),
        )
    }

    fn address(owner: &str) -> ResourceRecord {
        ResourceRecord::new(
            name(owner),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
    }

    fn bailiwick(zone: &str) -> Bailiwick {
        Bailiwick::new(canonical(zone))
    }

    #[test]
    fn a_cross_zone_chain_permits_each_target() {
        let answers = [
            cname("www.example.com.", "edge.cdn.net."),
            cname("edge.cdn.net.", "pop1.cdn.org."),
            address("pop1.cdn.org."),
        ];
        let scope = bailiwick("www.example.com.").answer_scope(&answers);

        assert!(scope.permits(&canonical("www.example.com.")));
        assert!(scope.permits(&canonical("edge.cdn.net.")));
        assert!(scope.permits(&canonical("pop1.cdn.org.")));
    }

    #[test]
    fn a_chain_listed_out_of_order_is_still_followed() {
        let answers = [
            address("pop1.cdn.org."),
            cname("edge.cdn.net.", "pop1.cdn.org."),
            cname("www.example.com.", "edge.cdn.net."),
        ];
        let scope = bailiwick("www.example.com.").answer_scope(&answers);

        assert!(scope.permits(&canonical("pop1.cdn.org.")));
    }

    #[test]
    fn a_target_is_permitted_exactly_never_its_subtree() {
        let answers = [cname("www.example.com.", "edge.cdn.net.")];
        let scope = bailiwick("www.example.com.").answer_scope(&answers);

        assert!(!scope.permits(&canonical("evil.edge.cdn.net.")));
        assert!(!scope.permits(&canonical("cdn.net.")));
    }

    #[test]
    fn a_cname_owned_outside_the_scope_extends_nothing() {
        let answers = [
            cname("www.example.com.", "edge.cdn.net."),
            cname("unrelated.attacker.example.", "bank.example.org."),
        ];
        let scope = bailiwick("www.example.com.").answer_scope(&answers);

        assert!(!scope.permits(&canonical("unrelated.attacker.example.")));
        assert!(!scope.permits(&canonical("bank.example.org.")));
    }

    #[test]
    fn a_cyclic_chain_terminates() {
        let answers = [
            cname("www.example.com.", "a.loop.net."),
            cname("a.loop.net.", "b.loop.net."),
            cname("b.loop.net.", "a.loop.net."),
        ];
        let scope = bailiwick("www.example.com.").answer_scope(&answers);

        assert!(scope.permits(&canonical("a.loop.net.")));
        assert!(scope.permits(&canonical("b.loop.net.")));
    }

    #[test]
    fn without_aliases_the_scope_is_the_zone() {
        let answers = [address("www.example.com."), address("other.example.net.")];
        let scope = bailiwick("example.com.").answer_scope(&answers);

        assert!(scope.permits(&canonical("deep.www.example.com.")));
        assert!(!scope.permits(&canonical("other.example.net.")));
    }
}
