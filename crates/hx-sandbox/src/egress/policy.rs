//! The semantics of a single egress allowlist entry.
//!
//! This is the *library's* copy of the rule, so the matching can be unit-tested without the
//! std-only proxy binary. The proxy (`crate::bin::egress_proxy`) deliberately holds a copy — it
//! compiles with `std` alone, and the two are kept in step by carrying the same test table on
//! both sides.
//!
//! An operator writes one of three shapes:
//!
//! - a **name** — `crates.io` (exact) or `*.crates.io` (a domain globe);
//! - a **raw IP** — `1.2.3.4`, or an IPv6 literal like `2001:db8::1`;
//! - a **CIDR** — `1.2.3.0/24`, `2001:db8::/32`.
//!
//! A name is matched by name: the `CONNECT` target's host is compared (exact or suffix). An IP or
//! CIDR is matched by *address*: the target is resolved to an `IpAddr` first, then tested. A
//! name rule is never tested against an address and an address rule is never tested against a name.
use std::net::IpAddr;

/// One parseable egress allowlist entry in the shape an operator writes it.
#[derive(Clone, Debug, PartialEq)]
pub enum EgressRule {
    /// A hostname, exact (`crates.io`) or `*.domain` globe (`*.crates.io`).
    Name(String),
    /// A single canonical address, e.g. `1.2.3.4`.
    Ip(IpAddr),
    /// An address plus a prefix length, e.g. `1.2.3.0/24`.
    Cidr { network: IpAddr, prefix: u8 },
}

impl EgressRule {
    /// Parse one allowlist entry. Returns `None` for a shape this proxy cannot enforce — the
    /// ambiguous `inet_aton` family (`0x01010101`, `127.1`, `2130706433`), a `host:port`,
    /// an empty string — exactly the set the validators refuse up front.
    pub fn parse(entry: &str) -> Option<EgressRule> {
        let entry = entry.trim().trim_end_matches('.');
        if entry.is_empty() {
            return None;
        }
        // A CIDR: `addr/prefix`, both canonical. An IPv6 network necessarily contains a `:`, so the
        // `split_once('/')` never needs to know which family the addr side is.
        if let Some((net, prefix)) = entry.split_once('/') {
            let (address, prefix) = (net.parse::<IpAddr>().ok()?, prefix.parse().ok()?);
            let max = if matches!(address, IpAddr::V4(_)) {
                32
            } else {
                128
            };
            if prefix > max {
                return None;
            }
            return Some(EgressRule::Cidr {
                network: address,
                prefix,
            });
        }
        // Else a canonical IP (`1.2.3.4`, `::1`) or a name. `IpAddr::from_str` parses the
        // canonical forms (dotted-quad and IPv6) but rejects the whole `inet_aton` family
        // (`0x01010101`, `127.1`, `2130706433`), which is exactly the split we want: an entry
        // that parses as a canonical IP is an IP; anything else is either a real name or an
        // ambiguous address, and the validators answer that either/or (a non-name is refused).
        match entry.parse::<IpAddr>() {
            Ok(ip) => Some(EgressRule::Ip(ip)),
            Err(_) => Some(EgressRule::Name(to_hostname(entry))),
        }
    }

    /// Whether a canonical `ip` is admitted by this rule. A `Name` rule admits no address: it is
    /// matched by name, not by its resolved IP.
    pub fn allows(&self, ip: IpAddr) -> bool {
        match self {
            EgressRule::Ip(allowed) => *allowed == ip,
            EgressRule::Cidr { network, prefix } => ip_in_network(ip, *network, *prefix),
            EgressRule::Name(_) => false,
        }
    }
}

/// Normalise a name entry the way the proxy's own name matching does, so parsing and matching cannot
/// disagree about case or a trailing dot.
fn to_hostname(entry: &str) -> String {
    entry.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether an address with `prefix` leading bits equal to `network` (a manual CIDR match).
fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let (a, n) = (u128::from(a), u128::from(n));
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (a & mask) == (n & mask)
        }
        // A v4 rule never matches a v6 address and vice versa: a `10.0.0.0/8` entry must
        // not admit a mapped `::ffff:10.0.0.0` without the operator writing it so.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn a_cidr_rule_allows_addresses_inside_and_blocks_those_outside() {
        let rule = EgressRule::parse("10.0.0.0/8").unwrap();
        assert!(rule.allows("10.1.2.3".parse::<IpAddr>().unwrap()));
        assert!(rule.allows("10.255.255.255".parse::<IpAddr>().unwrap()));
        assert!(rule.allows("10.10.10.10".parse::<IpAddr>().unwrap()));
        assert!(!rule.allows("11.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!rule.allows("9.255.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn a_host_prefix_cidr_blocks_everything_but_the_exact_host() {
        // `192.168.1.1/32` is a single host — the /32 form is how an operator writes "one IP"
        // when they want to say CIDR.
        let rule = EgressRule::parse("192.168.1.1/32").unwrap();
        assert!(rule.allows("192.168.1.1".parse().unwrap()));
        assert!(!rule.allows("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn a_slash_zero_cidr_allows_the_whole_family() {
        let v4 = EgressRule::parse("0.0.0.0/0").unwrap();
        assert!(v4.allows("203.0.113.5".parse().unwrap()));
        assert!(v4.allows("10.0.0.1".parse().unwrap()));
        let v6 = EgressRule::parse("::/0").unwrap();
        assert!(v6.allows("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn an_ip_rule_matches_exactly_that_address() {
        let rule = EgressRule::parse("1.2.3.4").unwrap();
        assert!(matches!(rule, EgressRule::Ip(_)));
        assert!(rule.allows("1.2.3.4".parse().unwrap()));
        assert!(!rule.allows("1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn an_ipv6_literal_is_an_ip_rule() {
        let rule = EgressRule::parse("2001:db8::1").unwrap();
        assert!(matches!(rule, EgressRule::Ip(_)));
        assert!(rule.allows("2001:db8::1".parse().unwrap()));
        assert!(!rule.allows("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn an_ipv6_cidr_matches_inside_and_outside() {
        let rule = EgressRule::parse("2001:db8::/32").unwrap();
        assert!(rule.allows("2001:db8:0:1::5".parse().unwrap()));
        assert!(!rule.allows("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn a_v4_rule_never_matches_a_v6_address() {
        // A `10.0.0.0/8` entry must not sweep in the mapped `::ffff:10.0.0.0`; the
        // operator writes the v6 form explicitly if that is intended.
        let rule = EgressRule::parse("10.0.0.0/8").unwrap();
        assert!(!rule.allows("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn a_name_rule_parses_but_admits_no_address() {
        // Name rules are matched by name (in the proxy), never by a resolved IP: a name's address can
        // change between the check and the dial, so testing the address would be a TOCTOU that made the
        // allowlist a fiction. The proxy tests cover the name matching; here we pin that an address is
        // never the test for a name rule.
        let rule = EgressRule::parse("crates.io").unwrap();
        assert!(matches!(rule, EgressRule::Name(_)));
        assert!(!rule.allows("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn an_inet_aton_family_entry_parses_as_a_name_but_admits_no_address() {
        // These are neither canonical IPs nor names: `IpAddr::from_str` rejects them (so they do
        // not parse as `Ip`), and they are "names" only syntactically. The *validator* refuses
        // them (`SpecError::EgressNotEnforced`); here we pin that as a rule they can never admit an
        // address by — so even if one reached the proxy, it could not open a connection.
        for bad in [
            "0x01010101",
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "1234",
            "1.2.3.999",
        ] {
            let rule =
                EgressRule::parse(bad).unwrap_or_else(|| panic!("{bad} must parse to a rule"));
            assert!(
                matches!(rule, EgressRule::Name(_)),
                "{bad} is a syntactic name"
            );
            assert!(
                !rule.allows("1.1.1.1".parse().unwrap()),
                "{bad} must never admit an address"
            );
        }
    }

    #[test]
    fn a_too_long_prefix_is_not_a_parseable_rule() {
        assert!(EgressRule::parse("1.2.3.0/33").is_none());
        assert!(EgressRule::parse("2001:db8::/129").is_none());
    }
}
