//! Which client networks may query the server at all.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IP network in CIDR notation whose host bits are all zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientNetwork {
    address: IpAddr,
    prefix: u8,
}

/// Why a CIDR string is not a [`ClientNetwork`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientNetworkError {
    /// The string has no `/prefix` part.
    #[error("`{0}` has no prefix length; write it as address/prefix")]
    MissingPrefix(String),
    /// The address part is not an IPv4 or IPv6 address.
    #[error("`{0}` is not an IP address")]
    InvalidAddress(String),
    /// The prefix part is not a number, or is longer than the address family allows.
    #[error("`{0}` has an invalid prefix length")]
    InvalidPrefix(String),
    /// The address has bits set past the prefix, so it names a host rather than a network.
    #[error("`{0}` has host bits set; did you mean the network address?")]
    HostBitsSet(String),
}

impl ClientNetwork {
    /// Creates a network from its address and prefix length.
    ///
    /// A network written in IPv4-mapped form (`::ffff:10.0.0.0/104`) becomes the IPv4
    /// network it denotes (`10.0.0.0/8`), because peers are matched in their canonical form.
    ///
    /// # Errors
    /// Returns [`ClientNetworkError::InvalidPrefix`] when `prefix` exceeds the family's
    /// width and [`ClientNetworkError::HostBitsSet`] when `address` has bits set past it.
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, ClientNetworkError> {
        let display = || format!("{address}/{prefix}");
        if prefix > family_width(address) {
            return Err(ClientNetworkError::InvalidPrefix(display()));
        }
        if masked(address, prefix) != address_bits(address) {
            return Err(ClientNetworkError::HostBitsSet(display()));
        }
        Ok(Self { address, prefix }.canonical())
    }

    fn canonical(self) -> Self {
        let IpAddr::V6(v6) = self.address else {
            return self;
        };
        match v6.to_ipv4_mapped() {
            Some(v4) if self.prefix >= MAPPED_PREFIX => Self {
                address: IpAddr::V4(v4),
                prefix: self.prefix.saturating_sub(MAPPED_PREFIX),
            },
            _ => self,
        }
    }

    /// Returns `true` when `peer` lies inside this network.
    ///
    /// An IPv4-mapped IPv6 peer (`::ffff:a.b.c.d`, what a dual-stack socket reports for an
    /// IPv4 client) is matched as the IPv4 address it carries.
    #[must_use]
    pub fn contains(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        peer.is_ipv4() == self.address.is_ipv4()
            && masked(peer, self.prefix) == address_bits(self.address)
    }

    /// Loopback, the RFC 1918 and RFC 4193 private ranges, and link-local: the networks a
    /// home resolver answers when `allow_networks` is not set.
    #[must_use]
    pub fn private_networks() -> Vec<Self> {
        PRIVATE_NETWORKS
            .iter()
            .map(|&(address, prefix)| Self { address, prefix })
            .collect()
    }
}

/// Length of the `::ffff:0:0/96` prefix that carries an IPv4 address inside IPv6.
const MAPPED_PREFIX: u8 = 96;

impl FromStr for ClientNetwork {
    type Err = ClientNetworkError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = text
            .split_once('/')
            .ok_or_else(|| ClientNetworkError::MissingPrefix(text.to_owned()))?;
        let address = IpAddr::from_str(address)
            .map_err(|_| ClientNetworkError::InvalidAddress(text.to_owned()))?;
        let prefix =
            u8::from_str(prefix).map_err(|_| ClientNetworkError::InvalidPrefix(text.to_owned()))?;
        Self::new(address, prefix)
    }
}

const fn family_width(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn address_bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// The address's bits with everything past `prefix` cleared; `prefix` never exceeds the
/// family's width.
fn masked(address: IpAddr, prefix: u8) -> u128 {
    let host_bits = u32::from(family_width(address).saturating_sub(prefix));
    let mask = u128::MAX.checked_shl(host_bits).unwrap_or(0);
    address_bits(address) & mask
}

/// Why an allow/deny pair is not a usable [`ClientAccess`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientAccessError {
    /// An empty allow-list would answer no client at all.
    #[error("allow_networks is empty, so no client could query; list at least one network")]
    NothingAllowed,
}

/// The allow-list and deny-list deciding which client addresses may query.
///
/// A peer is admitted when some allowed network contains it and no denied network does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAccess {
    allow: Vec<ClientNetwork>,
    deny: Vec<ClientNetwork>,
}

impl ClientAccess {
    /// Creates the policy from its two lists.
    ///
    /// # Errors
    /// Returns [`ClientAccessError::NothingAllowed`] when `allow` is empty.
    pub fn new(
        allow: Vec<ClientNetwork>,
        deny: Vec<ClientNetwork>,
    ) -> Result<Self, ClientAccessError> {
        if allow.is_empty() {
            return Err(ClientAccessError::NothingAllowed);
        }
        Ok(Self { allow, deny })
    }

    /// Returns `true` when `peer` may query the server.
    #[must_use]
    pub fn admits(&self, peer: IpAddr) -> bool {
        let inside = |networks: &[ClientNetwork]| networks.iter().any(|net| net.contains(peer));
        inside(&self.allow) && !inside(&self.deny)
    }

    /// Returns `true` when an address on the public internet would be admitted.
    ///
    /// Two well-known public resolvers stand in for "the internet", so an allow-list that
    /// covers it in pieces (`0.0.0.0/1` plus `128.0.0.0/1`) counts as well as a `/0`.
    #[must_use]
    pub fn admits_public_addresses(&self) -> bool {
        PUBLIC_PROBES.iter().any(|&probe| self.admits(probe))
    }
}

const PUBLIC_PROBES: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
];

/// Kept as raw pairs so the list can be a `const`; a test checks each one passes
/// [`ClientNetwork::new`].
const PRIVATE_NETWORKS: [(IpAddr, u8); 8] = [
    (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
];

impl Default for ClientAccess {
    fn default() -> Self {
        Self {
            allow: ClientNetwork::private_networks(),
            deny: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(text: &str) -> ClientNetwork {
        text.parse().expect(text)
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect(text)
    }

    #[test]
    fn default_networks_are_valid_cidrs() {
        for (address, prefix) in PRIVATE_NETWORKS {
            assert!(
                ClientNetwork::new(address, prefix).is_ok(),
                "{address}/{prefix}"
            );
        }
    }

    #[test]
    fn default_policy_refuses_public_sources() {
        let access = ClientAccess::default();
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "2001:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(!access.admits(ip(public)), "{public} must be refused");
        }
    }

    #[test]
    fn default_policy_admits_loopback_private_and_link_local() {
        let access = ClientAccess::default();
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.31.255.254",
            "192.168.1.10",
            "169.254.0.5",
            "::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:192.168.1.10",
        ] {
            assert!(access.admits(ip(private)), "{private} must be admitted");
        }
    }

    #[test]
    fn deny_wins_over_allow() {
        let access = ClientAccess::new(
            vec![network("192.168.0.0/16")],
            vec![network("192.168.1.0/24")],
        )
        .expect("valid");
        assert!(access.admits(ip("192.168.2.1")));
        assert!(!access.admits(ip("192.168.1.1")));
    }

    #[test]
    fn whole_family_networks_match_only_their_own_family() {
        let everything_v4 = network("0.0.0.0/0");
        assert!(everything_v4.contains(ip("203.0.113.9")));
        assert!(everything_v4.contains(ip("::ffff:203.0.113.9")));
        assert!(!everything_v4.contains(ip("2001:db8::1")));
        assert!(network("::/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn host_prefixes_match_exactly_one_address() {
        let host = network("127.0.0.1/32");
        assert!(host.contains(ip("127.0.0.1")));
        assert!(!host.contains(ip("127.0.0.2")));
    }

    #[test]
    fn malformed_cidrs_are_rejected() {
        let parse = |text: &str| text.parse::<ClientNetwork>();
        assert!(matches!(
            parse("10.0.0.0"),
            Err(ClientNetworkError::MissingPrefix(_))
        ));
        assert!(matches!(
            parse("10.0.0/8"),
            Err(ClientNetworkError::InvalidAddress(_))
        ));
        assert!(matches!(
            parse("10.0.0.0/33"),
            Err(ClientNetworkError::InvalidPrefix(_))
        ));
        assert!(matches!(
            parse("::/129"),
            Err(ClientNetworkError::InvalidPrefix(_))
        ));
        assert!(matches!(
            parse("10.0.0.0/x"),
            Err(ClientNetworkError::InvalidPrefix(_))
        ));
        assert!(matches!(
            parse("192.168.1.5/16"),
            Err(ClientNetworkError::HostBitsSet(_))
        ));
    }

    #[test]
    fn empty_allow_list_is_rejected() {
        assert_eq!(
            ClientAccess::new(Vec::new(), Vec::new()),
            Err(ClientAccessError::NothingAllowed)
        );
    }

    #[test]
    fn public_reach_is_reported_however_the_allow_list_spells_it() {
        assert!(!ClientAccess::default().admits_public_addresses());
        for allow in [
            vec![network("::/0")],
            vec![network("0.0.0.0/0")],
            vec![network("0.0.0.0/1"), network("128.0.0.0/1")],
        ] {
            let open = ClientAccess::new(allow.clone(), Vec::new()).expect("valid");
            assert!(open.admits_public_addresses(), "{allow:?}");
        }
    }

    #[test]
    fn ipv4_mapped_networks_match_as_ipv4() {
        assert_eq!(network("::ffff:10.0.0.0/104"), network("10.0.0.0/8"));
        assert_eq!(network("::ffff:0:0/96"), network("0.0.0.0/0"));
        let access = ClientAccess::new(
            vec![network("0.0.0.0/0")],
            vec![network("::ffff:10.0.0.0/104")],
        )
        .expect("valid");
        assert!(!access.admits(ip("10.1.1.1")));
        assert!(!access.admits(ip("::ffff:10.1.1.1")));
        assert!(access.admits(ip("11.1.1.1")));
    }
}
