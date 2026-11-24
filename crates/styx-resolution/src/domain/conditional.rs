//! Conditional forwarding: which names leave the main pool for a pool of their own.

use styx_proto::Name;

/// One `[[upstream.conditional]]` entry: the zones it covers and where they go.
#[derive(Debug, Clone)]
pub struct ConditionalRoute<T> {
    /// Zones this route answers for, each matching itself and every name below it.
    pub domains: Vec<Name>,
    /// Where a matching question is sent.
    pub target: T,
}

/// The conditional routes, matched by the longest configured suffix of the question name.
#[derive(Debug, Clone)]
pub struct ConditionalRoutes<T> {
    routes: Vec<ConditionalRoute<T>>,
}

impl<T> Default for ConditionalRoutes<T> {
    fn default() -> Self {
        Self { routes: Vec::new() }
    }
}

impl<T> ConditionalRoutes<T> {
    /// Builds the table from routes whose domains are pairwise distinct.
    ///
    /// Distinct domains are what makes the longest match unique; `PoolConfig` rejects a
    /// file that repeats one.
    #[must_use]
    pub const fn new(routes: Vec<ConditionalRoute<T>>) -> Self {
        Self { routes }
    }

    /// The target of the route whose domain is the longest suffix of `qname`, or `None`
    /// when no route covers it and the main pool answers.
    #[must_use]
    pub fn route(&self, qname: &Name) -> Option<&T> {
        self.routes
            .iter()
            .flat_map(|route| route.domains.iter().map(move |domain| (domain, route)))
            .filter(|(domain, _)| qname.is_subdomain_of(domain))
            .max_by_key(|(domain, _)| domain.label_count())
            .map(|(_, route)| &route.target)
    }

    /// Every route target, in configuration order.
    pub fn targets(&self) -> impl Iterator<Item = &T> {
        self.routes.iter().map(|route| &route.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap_or_else(|_| Name::root())
    }

    fn routes() -> ConditionalRoutes<&'static str> {
        ConditionalRoutes::new(vec![
            ConditionalRoute {
                domains: vec![name("lan"), name("1.168.192.in-addr.arpa")],
                target: "router",
            },
            ConditionalRoute {
                domains: vec![name("iot.lan")],
                target: "hub",
            },
        ])
    }

    #[test]
    fn a_name_below_a_domain_takes_its_route() {
        assert_eq!(routes().route(&name("nas.lan.")), Some(&"router"));
        assert_eq!(
            routes().route(&name("10.1.168.192.in-addr.arpa.")),
            Some(&"router")
        );
    }

    #[test]
    fn the_domain_apex_itself_takes_its_route() {
        assert_eq!(routes().route(&name("lan.")), Some(&"router"));
    }

    #[test]
    fn the_longest_suffix_wins_whatever_the_order() {
        assert_eq!(routes().route(&name("bulb.iot.lan.")), Some(&"hub"));
        let reversed = ConditionalRoutes::new(routes().routes.into_iter().rev().collect());
        assert_eq!(reversed.route(&name("bulb.iot.lan.")), Some(&"hub"));
    }

    #[test]
    fn matching_ignores_case() {
        assert_eq!(routes().route(&name("NAS.LAN.")), Some(&"router"));
    }

    #[test]
    fn a_label_that_only_ends_with_the_domain_text_does_not_match() {
        assert_eq!(routes().route(&name("notlan.")), None);
        assert_eq!(routes().route(&name("example.com.")), None);
    }
}
