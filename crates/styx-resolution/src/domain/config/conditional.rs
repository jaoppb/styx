//! `[[upstream.conditional]]`: zones forwarded to their own small pool.

use serde::Deserialize;
use styx_proto::Name;

use super::{parse_member, RawUpstreamConfig, RawUpstreamKind, UpstreamConfig};
use crate::domain::error::ConfigError;

/// One conditional forwarding entry, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalConfig {
    /// Zones sent to `members` instead of the main pool.
    pub domains: Vec<Name>,
    /// The forwarders that answer for `domains`, tried in order.
    pub members: Vec<UpstreamConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawConditionalConfig {
    pub(super) domains: Vec<String>,
    #[serde(default)]
    pub(super) members: Vec<RawUpstreamConfig>,
}

pub(super) fn parse_conditionals(
    raw: Vec<RawConditionalConfig>,
) -> Result<Vec<ConditionalConfig>, ConfigError> {
    let mut parsed: Vec<ConditionalConfig> = Vec::with_capacity(raw.len());
    for entry in raw {
        let conditional = parse_conditional(entry)?;
        for domain in &conditional.domains {
            let repeated = parsed
                .iter()
                .chain(std::iter::once(&conditional))
                .flat_map(|other| other.domains.iter())
                .filter(|other| other.eq_ignore_case(domain))
                .count()
                > 1;
            if repeated {
                return Err(ConfigError::Invalid(format!(
                    "conditional domain `{domain}` is listed more than once"
                )));
            }
        }
        parsed.push(conditional);
    }
    Ok(parsed)
}

fn parse_conditional(raw: RawConditionalConfig) -> Result<ConditionalConfig, ConfigError> {
    if raw.domains.is_empty() {
        return Err(ConfigError::Invalid(
            "a conditional entry must list at least one domain".into(),
        ));
    }
    if raw.members.is_empty() {
        return Err(ConfigError::Invalid(
            "a conditional entry must have at least one member".into(),
        ));
    }
    let domains = raw
        .domains
        .iter()
        .map(|text| parse_domain(text))
        .collect::<Result<Vec<_>, _>>()?;
    let members = raw
        .members
        .into_iter()
        .map(parse_forwarder)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ConditionalConfig { domains, members })
}

/// The root would send every name to the conditional pool, which is what
/// `[upstream].members` is for. A domain matches by suffix, never as a pattern, so a `*`
/// label would match only a literal `*` and leave the names it seems to cover on the main
/// pool, leaking them.
fn parse_domain(text: &str) -> Result<Name, ConfigError> {
    let domain = Name::from_ascii(text)
        .map_err(|error| ConfigError::Invalid(format!("invalid conditional domain: {error}")))?;
    if domain.is_root() {
        return Err(ConfigError::Invalid(
            "a conditional domain cannot be the root; configure [upstream].members instead".into(),
        ));
    }
    if domain.labels().any(|label| label.as_bytes() == b"*") {
        return Err(ConfigError::Invalid(format!(
            "conditional domain `{text}` has a `*` label; list the domain itself, which \
             already covers every name below it"
        )));
    }
    Ok(domain)
}

/// A recursor walks down from the root, and the root has never heard of a home
/// network's private names, so only forwarders may answer for them. Members are tried in
/// order, so a `weight` would have no effect and is refused rather than ignored.
fn parse_forwarder(raw: RawUpstreamConfig) -> Result<UpstreamConfig, ConfigError> {
    if raw.weight.is_some() {
        return Err(ConfigError::Invalid(format!(
            "conditional member `{}` cannot set weight; members are tried in order",
            raw.name
        )));
    }
    if raw.kind != RawUpstreamKind::Forwarder {
        return Err(ConfigError::Invalid(format!(
            "conditional member `{}` must be a forwarder",
            raw.name
        )));
    }
    parse_member(raw)
}

#[cfg(test)]
mod tests {
    use crate::domain::config::PoolConfig;
    use crate::domain::error::ConfigError;

    fn pool_with(conditional: &str) -> Result<PoolConfig, ConfigError> {
        PoolConfig::from_toml_str(&format!(
            r#"
            strategy = "ordered_failover"
            [[members]]
            name = "public"
            kind = "forwarder"
            addr = "9.9.9.9:53"
            {conditional}
            "#
        ))
    }

    fn rejected(conditional: &str) -> bool {
        matches!(pool_with(conditional), Err(ConfigError::Invalid(_)))
    }

    #[test]
    fn an_entry_parses_its_domains_and_forwarders() {
        let pool = pool_with(
            r#"
            [[conditional]]
            domains = ["lan", "1.168.192.in-addr.arpa."]
            [[conditional.members]]
            name = "router"
            kind = "forwarder"
            addr = "192.168.1.1:53"
            "#,
        )
        .expect("valid conditional entry");
        let entry = pool.conditional.first().expect("one entry");
        assert_eq!(entry.domains.len(), 2);
        assert_eq!(
            entry.members.first().map(|m| m.name.as_str()),
            Some("router")
        );
    }

    #[test]
    fn a_file_without_entries_has_none() {
        assert!(pool_with("").expect("valid pool").conditional.is_empty());
    }

    #[test]
    fn a_wildcard_label_is_rejected() {
        assert!(rejected(
            r#"
            [[conditional]]
            domains = ["*.lan"]
            [[conditional.members]]
            name = "a"
            kind = "forwarder"
            addr = "192.168.1.1:53"
            "#
        ));
    }

    #[test]
    fn a_member_weight_is_rejected() {
        assert!(rejected(
            r#"
            [[conditional]]
            domains = ["lan"]
            [[conditional.members]]
            name = "a"
            kind = "forwarder"
            addr = "192.168.1.1:53"
            weight = 2
            "#
        ));
    }

    #[test]
    fn a_recursor_member_is_rejected() {
        assert!(rejected(
            r#"
            [[conditional]]
            domains = ["lan"]
            [[conditional.members]]
            name = "r"
            kind = "recursor"
            addr = "0.0.0.0:0"
            "#
        ));
    }

    #[test]
    fn a_recursor_member_is_rejected_as_a_recursor_before_its_canary_is_checked() {
        let error = pool_with(
            r#"
            [[conditional]]
            domains = ["lan"]
            [[conditional.members]]
            name = "r"
            kind = "recursor"
            addr = "0.0.0.0:0"
            [conditional.members.canary]
            qname = "."
            qtype = "NS"
            "#,
        );
        assert!(
            matches!(&error, Err(ConfigError::Invalid(text)) if text.contains("must be a forwarder")),
            "{error:?}"
        );
    }

    #[test]
    fn a_domain_repeated_across_entries_is_rejected_whatever_its_case() {
        assert!(rejected(
            r#"
            [[conditional]]
            domains = ["lan"]
            [[conditional.members]]
            name = "a"
            kind = "forwarder"
            addr = "192.168.1.1:53"
            [[conditional]]
            domains = ["LAN."]
            [[conditional.members]]
            name = "b"
            kind = "forwarder"
            addr = "192.168.1.2:53"
            "#
        ));
    }

    #[test]
    fn an_entry_without_domains_or_members_or_with_the_root_is_rejected() {
        assert!(rejected(
            r#"
            [[conditional]]
            domains = []
            [[conditional.members]]
            name = "a"
            kind = "forwarder"
            addr = "192.168.1.1:53"
            "#
        ));
        assert!(rejected(
            r#"
            [[conditional]]
            domains = ["lan"]
            "#
        ));
        assert!(rejected(
            r#"
            [[conditional]]
            domains = ["."]
            [[conditional.members]]
            name = "a"
            kind = "forwarder"
            addr = "192.168.1.1:53"
            "#
        ));
    }
}
