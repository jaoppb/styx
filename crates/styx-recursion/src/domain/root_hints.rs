//! Root hints: the seed list of root servers, before priming replaces it.

use std::net::IpAddr;
use std::time::Instant;

use styx_proto::{Name, Ttl};

use crate::domain::error::ConfigError;
use crate::domain::topology::{Delegation, GlueOrigin, Nameserver};

/// TTL given to the hints-derived root NS set: the conventional named.root value
/// (six days). Priming replaces it with the live set's own TTL.
pub const ROOT_HINTS_TTL: Ttl = Ttl::from_secs(518_400);

/// The root servers named by a `named.root`-style file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootHints {
    seed: Vec<Nameserver>,
}

impl RootHints {
    /// Parses `named.root` format: one record per line — owner, optional TTL,
    /// optional class `IN`, type and data — with `;` comments. Only root NS records
    /// and A/AAAA records for their targets are meaningful; any other record type
    /// is an error, so a wrong file is noticed rather than half-used.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::RootHintsInvalid`] for an unparseable line and
    /// [`ConfigError::RootHintsEmpty`] when no root server has an address.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut servers: Vec<Name> = Vec::new();
        let mut addresses: Vec<(Name, IpAddr)> = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split(';').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let invalid = |reason: &str| ConfigError::RootHintsInvalid {
                line: index.saturating_add(1),
                reason: reason.to_string(),
            };
            let tokens: Vec<&str> = line
                .split_whitespace()
                .filter(|token| token.parse::<u32>().is_err() && !token.eq_ignore_ascii_case("IN"))
                .collect();
            let [owner, rtype, data] = tokens.as_slice() else {
                return Err(invalid("expected owner, type and data"));
            };
            let owner = Name::from_ascii(owner).map_err(|_| invalid("bad owner name"))?;
            match rtype.to_ascii_uppercase().as_str() {
                "NS" if owner.is_root() => {
                    servers.push(Name::from_ascii(data).map_err(|_| invalid("bad NS target"))?);
                }
                "A" | "AAAA" => {
                    let address = data.parse().map_err(|_| invalid("bad address"))?;
                    addresses.push((owner, address));
                }
                _ => {
                    return Err(invalid(
                        "only root NS and A/AAAA records belong in root hints",
                    ))
                }
            }
        }
        let seed: Vec<Nameserver> = servers
            .into_iter()
            .map(|name| Nameserver {
                addresses: addresses
                    .iter()
                    .filter(|(owner, _)| *owner == name)
                    .map(|(_, address)| *address)
                    .collect(),
                name,
                glue_origin: GlueOrigin::ResolvedSeparately,
            })
            .filter(|server| !server.addresses.is_empty())
            .collect();
        if seed.is_empty() {
            return Err(ConfigError::RootHintsEmpty);
        }
        Ok(Self { seed })
    }

    /// The root servers and their addresses.
    #[must_use]
    pub fn seed(&self) -> &[Nameserver] {
        &self.seed
    }

    /// The root NS set as a delegation of the root to itself.
    #[must_use]
    pub fn to_delegation(&self, now: Instant) -> Delegation {
        Delegation::new(
            Name::root(),
            Name::root(),
            self.seed.clone(),
            ROOT_HINTS_TTL,
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HINTS: &str = "
; This file holds the information on root name servers
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
.                        3600000  IN  NS    B.ROOT-SERVERS.NET.
";

    #[test]
    fn root_servers_without_addresses_are_dropped() {
        let hints = RootHints::parse(HINTS).unwrap();
        assert_eq!(hints.seed().len(), 1);
        assert_eq!(hints.seed()[0].addresses.len(), 2);
    }

    #[test]
    fn a_foreign_record_type_is_an_error_with_its_line() {
        let error = RootHints::parse(". 1 MX 10 mail.example.").unwrap_err();
        assert!(matches!(
            error,
            ConfigError::RootHintsInvalid { line: 1, .. }
        ));
        assert_eq!(
            RootHints::parse("; empty"),
            Err(ConfigError::RootHintsEmpty)
        );
    }
}
