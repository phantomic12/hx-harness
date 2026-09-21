//! Hermetic tests for the egress allowlist policy: CIDR and raw-IP matching.
//!
//! These exercise the library's [`hx_sandbox::egress::policy`] rules — the canonical split that
//! the spec validator and the std-only proxy binary both build on. Everything here is pure parsing and
//! matching over `std::net::IpAddr`; there is no network and no DNS, so the suite runs anywhere.
//!
//! The proxy binary holds a deliberate copy of this matching (it compiles with `std` alone) and is
//! kept honest against it by the shared test table; see `hx-sandbox/src/bin/egress_proxy.rs`.
use hx_sandbox::egress::policy::EgressRule;

#[test]
fn a_slash_eight_cidr_allows_the_family_and_blocks_adjoining_ones() {
    let rule = EgressRule::parse("10.0.0.0/8").expect("canned CIDR");
    // same family, /8 catches everything in 10.x.y.z
    assert!(rule.allows("10.1.2.3".parse().unwrap()));
    assert!(rule.allows("10.255.255.255".parse().unwrap()));
    // outside the /8
    assert!(!rule.allows("11.0.0.1".parse().unwrap()));
    assert!(!rule.allows("9.0.0.1".parse().unwrap()));
}

#[test]
fn a_cidr_entry_parses_to_a_network() {
    let rule = EgressRule::parse("192.168.1.0/24").expect("a /24 parses");
    assert!(rule.allows("192.168.1.254".parse().unwrap()));
    assert!(!rule.allows("192.168.2.1".parse().unwrap()));
}

#[test]
fn a_host_shaped_cidr_entry_allows_only_that_host() {
    // `1.2.3.4/32` is how one writes "this exact address" as a CIDR.
    let rule = EgressRule::parse("1.2.3.4/32").expect("/32 parses");
    assert!(rule.allows("1.2.3.4".parse().unwrap()));
    assert!(!rule.allows("1.2.3.5".parse().unwrap()));
}

#[test]
fn an_invalid_cidr_prefix_is_refused() {
    // A prefix longer than the family's width is not a thing; it must not become a rule that would
    // have to mean "nothing" (a silent half-enforcement).
    assert!(EgressRule::parse("1.2.3.0/33").is_none());
    assert!(EgressRule::parse("::/129").is_none());
}

#[test]
fn a_canonical_ip_entry_allows_exactly_that_address() {
    let rule = EgressRule::parse("8.8.8.8").expect("a canonical IP parses");
    assert!(rule.allows("8.8.8.8".parse().unwrap()));
    assert!(!rule.allows("8.8.8.7".parse().unwrap()));
}
