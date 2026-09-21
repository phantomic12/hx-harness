//! The egress proxy that enforces a sandbox's allowlist.
//!
//! A sandbox on an [`crate::egress`] internal network cannot reach the internet directly — the
//! network has no default route. The *only* path out to the internet is this proxy, which sits on
//! both that internal network and the normal bridge, and which admits connections only to
//! destinations on the allowlist it was started with. (The far host's own bridge address remains
//! reachable on-link; see `crate::egress`'s module doc for the measurement and the ROADMAP item.)
//!
//! Why a separate binary rather than a thread in the daemon: the proxy must live *inside a
//! container* to hold a foot on both networks (internal for the sandbox, bridge for the
//! internet). The daemon runs on the host and is not on the internal network, so a host-side
//! thread could not be reached by the sandbox. This process is the thing [`crate::egress`]
//! starts as the sidecar's command.
//!
//! ## The allowlist
//!
//! `HX_EGRESS_ALLOW` is a comma-separated list of entries, each one a **hostname** or
//! `*.domain` globe (e.g. `crates.io,*.crates.io`), a **raw IP** (`1.2.3.4`), or a
//! **CIDR** (`1.2.3.0/24`). A name is matched by name: an entry with a leading `*.` matches
//! any host whose name ends with that domain; any other entry matches a host exactly. An IP or CIDR
//! is matched by *address*: the `CONNECT` target is resolved to an `IpAddr` first, then
//! tested against the entry. Only a target that matches a name entry *or* falls inside an IP/CIDR
//! entry is dialed.
//!
//! The ambiguous `inet_aton` family (`0x01010101`, `127.1`, `2130706433`) is refused everywhere:
//! it is neither a canonical IP nor a real name, and the resolver would dial it as an address the
//! operator never named.
//!
//! Only the HTTP `CONNECT` method is meaningful for egress (HTTPS is how package registries,
//! git hosts and APIs are reached). Plain HTTP proxy requests are refused: an allowlisted proxy that
//! also forwards cleartext HTTP is an allowlisted door to the same destinations, and there is no
//! reason to widen it. `CONNECT` to a port other than 443 is permitted — some ecosystems
//! (Docker's own registry API, some git-over-HTTPS setups) use non-standard TLS ports — so the
//! port is not part of the allowlist decision.
//!
//! A denied target answers `403 Forbidden` and closes. It does not time out and it does not
//! accidentally get forwarded, because the forward happens *only* after the allowlist check passes.
//!
//! ## The address it binds
//!
//! In production the listen address is `0.0.0.0:3128`, and it is fixed: it has to stay in step with
//! `hx_sandbox::egress::PROXY_PORT`, because that port is what the sandbox's `HTTP_PROXY` names, and
//! a mismatch leaves the sandbox pointing at nothing.
//!
//! `HX_EGRESS_LISTEN` can move it, and exists for exactly one caller: the live integration test
//! (`crates/hx-sandbox/tests/egress_live.rs`) starts *this* compiled binary as a child process and
//! needs it on a free loopback port rather than on a fixed one — the same reason no test here binds
//! a hard-coded port. It can also be given port `0`, in which case the line this process prints on
//! startup names the port the kernel actually handed out, so the test never has to guess one. The
//! daemon never sets the variable, so a sandbox's sidecar still binds 3128. A value that cannot be
//! parsed or bound is refused at startup rather than quietly falling back to the default: a proxy
//! listening somewhere other than where it was told to listen is one the sandbox cannot find.
//!
//! ## Defence in depth: the proxy will not dial an address either
//!
//! The validator (`SandboxSpec::validate`, in `crate::spec` of the library) refuses an allowlist
//! entry that is address-shaped in the `inet_aton` grammar (`0x01010101`, `127.1`, `2130706433`,
//! `0177.0.0.1`, …), but this file does not *rely* on that. It holds its own copy of the predicate —
//! the same grammar, the same test table on both sides — and refuses to dial a destination that is
//! address-shaped even when the entry matched the allowlist exactly.
//!
//! The copy is deliberate and was the decision of record: this binary depends on `std` alone, so a
//! bad entry that reaches it (an older validator, a hand-written `HX_EGRESS_ALLOW`, a future caller
//! that forgets to validate) cannot become a live connection. Measured before the guard existed: an
//! allowlist of `0x01010101` answered `200 Connection established` and dialed 1.1.1.1 — a
//! destination the operator never named. Two implementations with one shared test table is the
//! accepted cost of keeping this binary's dependency list empty.

use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::thread;

const LISTEN_ADDR: &str = "0.0.0.0:3128";
/// Overrides [`LISTEN_ADDR`] for the live test; the daemon never sets it (see the module doc).
const LISTEN_ENV: &str = "HX_EGRESS_LISTEN";

const USAGE: &str = "\
hx-egress-proxy — the allowlist-enforcing egress proxy for a sandbox.

Started by the daemon as the sidecar container's command; not normally run by
hand. It listens on the internal network and forwards only CONNECT requests to
destinations named in its allowlist.

Environment:
  HX_EGRESS_ALLOW   comma-separated entries, each a `host`, `*.domain`, a raw IP,
                    or a CIDR (e.g. `crates.io,*.crates.io,10.0.0.0/8`).
                    Absent or empty means nothing is allowed, which is the fail-closed default.
  HX_EGRESS_LISTEN  the address to bind (default `0.0.0.0:3128`). The daemon does
                    not set this; it exists so the live integration test can run
                    this binary on a free loopback port. Port `0` asks the kernel
                    for one, which the startup line then reports.

Options:
  -h, --help        print this and exit
  -V, --version     print the version and exit

It takes no other arguments: in production the listen address is
`0.0.0.0:3128`, because the network it must sit on is the whole reason it
exists (`HX_EGRESS_LISTEN` is the one exception, and nothing in production sets
it).
";

/// Run the proxy until killed. The caller (the sidecar's entrypoint) is the supervisor.
fn main() {
    // Checked *before* binding. A `--help` that opens port 3128 is worse than unhelpful: it
    // occupies the port the real proxy needs, so the next sandbox's sidecar cannot start, and the
    // failure surfaces as a sandbox with no egress rather than as a usage error. This was a real
    // bug — the binary ignored its arguments entirely.
    //
    // The first argument decides everything: this binary takes no options that affect its work, so
    // there is nothing to parse and no order to respect.
    if let Some(arg) = env::args().nth(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            "-V" | "--version" => {
                println!("hx-egress-proxy {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            // Refused rather than ignored, for the same reason as `--help`: a typo silently
            // producing a running proxy would make the operator think an option took effect.
            other => {
                eprintln!("hx-egress-proxy: unrecognised argument '{other}'");
                eprint!("{USAGE}");
                std::process::exit(2);
            }
        }
    }

    let allow = parse_allowlist(env::var("HX_EGRESS_ALLOW").unwrap_or_default());

    // The production address unless a caller (the live test) asked for another one. Refused, not
    // fallen back from: a proxy that binds somewhere other than where it was told is invisible to
    // the `HTTP_PROXY` that names it, which reads as a sandbox with no egress at all.
    let listen = env::var(LISTEN_ENV).unwrap_or_else(|_| LISTEN_ADDR.to_string());
    let listener = match TcpListener::bind(&listen) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("hx-egress-proxy: cannot bind {listen:?} from {LISTEN_ENV}: {e}");
            std::process::exit(3);
        }
    };
    // The *bound* address, not the requested one: with port `0` the kernel picks the port, and the
    // live test reads its port from this line rather than guessing one that might already be taken.
    let bound = listener
        .local_addr()
        .expect("a bound listener has a local address");
    eprintln!("egress proxy listening on {bound}");

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let allow = allow.clone();
        // A hostile sandbox is precisely the case this exists for, so each connection is handled on
        // its own thread and never lets a malicious peer block the others.
        thread::spawn(move || handle(stream, &allow));
    }
}

/// One allowlist entry the proxy can enforce: a name, a raw IP, or a CIDR.
///
/// **A deliberate copy of `hx_sandbox::egress::policy::EgressRule`.** This binary is compiled
/// with `std` alone and must stay that way (see the module doc); the two are kept in step by
/// carrying the *same test table* on both sides, which is the accepted answer here rather than
/// linking the library in. A CIDR is stored as its network plus a prefix and matched by address; an IP
/// is matched exactly; a name by hostname.
#[derive(Clone, Debug)]
enum ProxyRule {
    /// A hostname, exact (`crates.io`) or `*.domain` globe (`*.crates.io`).
    Name(String),
    /// A single canonical address.
    Ip(IpAddr),
    /// An address plus a prefix length.
    Cidr { network: IpAddr, prefix: u8 },
}

impl ProxyRule {
    /// Parse one entry. `None` for a shape this proxy cannot enforce — the ambiguous `inet_aton`
    /// family, a `host:port`, an empty string.
    fn parse(entry: &str) -> Option<ProxyRule> {
        let entry = entry.trim().trim_end_matches('.');
        if entry.is_empty() {
            return None;
        }
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
            return Some(ProxyRule::Cidr {
                network: address,
                prefix,
            });
        }
        match entry.parse::<IpAddr>() {
            Ok(ip) => Some(ProxyRule::Ip(ip)),
            Err(_) => Some(ProxyRule::Name(
                entry.trim_end_matches('.').to_ascii_lowercase(),
            )),
        }
    }

    /// Whether this rule admits `ip`. A `Name` rule never admits an address by IP.
    fn allows(&self, ip: IpAddr) -> bool {
        match self {
            ProxyRule::Ip(allowed) => *allowed == ip,
            ProxyRule::Cidr { network, prefix } => match (ip, *network) {
                (IpAddr::V4(a), IpAddr::V4(n)) => {
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    };
                    (u32::from(a) & mask) == (u32::from(n) & mask)
                }
                (IpAddr::V6(a), IpAddr::V6(n)) => {
                    let (a, n) = (u128::from(a), u128::from(n));
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    };
                    (a & mask) == (n & mask)
                }
                _ => false,
            },
            ProxyRule::Name(_) => false,
        }
    }
}

/// Parse `host,*.domain,1.2.3.4,1.2.3.0/24` into matchers. An unrecognised shape is
/// dropped rather than trusted: if it cannot be enforced, pretending it can is how the allowlist
/// becomes a fiction.
fn parse_allowlist(raw: String) -> Vec<ProxyRule> {
    raw.split(',').filter_map(ProxyRule::parse).collect()
}

/// A host name is allowed when it equals a `Name` entry, or when a `*.domain` entry matches its
/// suffix. IP/CIDR rules are *not* consulted here — they are address rules and are checked against
/// the resolved address instead ([`allowed_address`]).
fn allowed_name(host: &str, allow: &[ProxyRule]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allow.iter().any(|rule| match rule {
        ProxyRule::Name(entry) => {
            if let Some(domain) = entry.strip_prefix("*.") {
                // `*.example.com` matches `a.example.com` but not the bare apex `example.com` —
                // an entry that names the apex explicitly is the honest way to allow it.
                host != domain
                    && host.ends_with(domain)
                    && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
            } else {
                host == *entry
            }
        }
        _ => false,
    })
}

/// An address is allowed when it falls inside an `Ip` or `Cidr` rule. Name rules are *not*
/// consulted here (they are matched by name, not by a resolved IP, which can change between the check
/// and the dial).
fn allowed_address(ip: IpAddr, allow: &[ProxyRule]) -> bool {
    allow.iter().any(|rule| rule.allows(ip))
}

/// Resolve a hostname to all its addresses for allowlist matching.
///
/// `TcpStream::connect` will later pick among these same addresses (via `getaddrinfo`), so checking
/// the resolved set against the address rules matches what the dial can actually reach. An empty set means
/// the name does not resolve here; the dial below will fail with a `502`, so a name that cannot be
/// resolved is never a *bypass* — it is just denied at dial time.
fn resolve(host: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    (host, 0)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// Whether a `CONNECT` target is address-shaped in the `inet_aton` grammar rather than a name.
///
/// **A deliberate copy of `hx_sandbox::spec::is_address_shaped`.** This binary is compiled with
/// `std` alone and must stay that way (see the module doc); the two implementations are kept in step
/// by carrying the *same test table* on both sides, which is the accepted answer here rather than
/// linking the library in. The reason it exists at all: `getaddrinfo` — and therefore
/// `TcpStream::connect` — accepts `0x01010101`, `127.1`, `2130706433`, `0177.0.0.1` and the rest of
/// the `inet_aton` family, so a destination that merely *looks* like a name can be dialed as an
/// address. This proxy matches by name; it must not dial what is not one.
fn is_address_shaped(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }
    parts.iter().all(|p| is_inet_aton_number(p))
}

/// One dot-separated part of a host: decimal, octal (`0`-prefixed) or hex (`0x`-prefixed).
fn is_inet_aton_number(part: &str) -> bool {
    if part.is_empty() {
        return false;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
    } else if part.len() > 1 && part.starts_with('0') {
        part.chars().all(|c| ('0'..='7').contains(&c)) // octal
    } else {
        part.chars().all(|c| c.is_ascii_digit()) // decimal
    }
}

fn handle(mut client: TcpStream, allow: &[ProxyRule]) {
    let mut buf = [0u8; 4096];
    let read = match client.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let head = String::from_utf8_lossy(&buf[..read]);
    let mut lines = head.lines();
    let request = match lines.next() {
        Some(l) => l,
        None => return,
    };
    let mut parts = request.split_whitespace();
    let method = parts.next();
    let target = parts.next();

    // Only CONNECT is a valid egress request. Anything else (GET, a bare-URI request) is
    // refused outright: an egress proxy that also spoke plain HTTP would be an allowlisted door to
    // the same hosts, with no reason to exist.
    if method.map(|m| m.eq_ignore_ascii_case("CONNECT")) != Some(true) {
        let _ = write_status(&mut client, 405, "Method Not Allowed");
        return;
    }
    let Some(target) = target else {
        let _ = write_status(&mut client, 400, "Bad Request");
        return;
    };

    // `CONNECT host:port`; split the host from the port.
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(0)),
        None => (target, 443),
    };
    if host.is_empty() || port == 0 {
        let _ = write_status(&mut client, 400, "Bad Request");
        return;
    }

    // Decide whether this host may be dialed, and how the allowlist is consulted. The two match
    // dimensions correspond to the two rule kinds: a *canonical address* is tested against the `Ip`
    // and `Cidr` rules; a *name* is tested against the `Name` rules by name and, if that fails,
    // against the `Ip`/`Cidr` rules by its resolved addresses (an allowlist of `10.0.0.0/8`
    // must admit a `CONNECT` to a name that resolves into that block).
    if let Ok(ip) = host.parse::<IpAddr>() {
        // A canonical address (`1.2.3.4`, `::1`) — unambiguous, so safe to reason about by
        // address alone. Name rules never apply to an address.
        if !allowed_address(ip, allow) {
            eprintln!("egress DENIED {host}:{port}");
            let _ = write_status(&mut client, 403, "Forbidden");
            return;
        }
    } else {
        // A name — but only a *real* name. The `inet_aton` family (`0x01010101`, `127.1`,
        // `2130706433`) is neither a canonical IP (so it falls through the parse above) nor a name,
        // and the resolver would dial it as an address; refuse it. Measured before this guard existed:
        // the proxy answered `200 Connection established` and opened a real connection to 1.1.1.1.
        if is_address_shaped(host) {
            eprintln!(
                "egress DENIED {host}:{port} (address-shaped destination; not a name to dial)"
            );
            let _ = write_status(&mut client, 403, "Forbidden");
            return;
        }
        let allowed =
            allowed_name(host, allow) || resolve(host).iter().any(|&ip| allowed_address(ip, allow));
        if !allowed {
            eprintln!("egress DENIED {host}:{port}");
            // A clear, immediate refusal: the sandbox must observe the failure as a *denial*, not a
            // hang, or a tool will retry into a black hole and the operator will never see why.
            let _ = write_status(&mut client, 403, "Forbidden");
            return;
        }
    }

    eprintln!("egress ALLOWED {host}:{port}");
    // Dial the destination through the proxy's *other* interface (the bridge). This is the only
    // connection to the outside world the sandbox's traffic can ride.
    let upstream = match TcpStream::connect((host, port)) {
        Ok(u) => u,
        Err(e) => {
            let _ = write_status(&mut client, 502, "Bad Gateway");
            eprintln!("egress connect to {host}:{port} failed: {e}");
            return;
        }
    };

    if let Err(e) = write_status(&mut client, 200, "Connection established") {
        eprintln!("egress write 200 to {host}:{port} failed: {e}");
        return;
    }

    // Once the tunnel is established it is a pure byte pump in both directions; the proxy no longer
    // inspects anything, because there is nothing left to enforce — the destination was already checked.
    match tunnel(client, upstream) {
        Ok(()) => {}
        Err(e) => eprintln!("egress tunnel to {host}:{port}: {e}"),
    }
}

fn write_status(stream: &mut TcpStream, code: u16, text: &str) -> std::io::Result<()> {
    stream.write_all(
        format!("HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
}

/// Bidirectionally copy bytes between the client and the upstream until either side closes.
fn tunnel(mut a: TcpStream, mut b: TcpStream) -> std::io::Result<()> {
    let mut a2 = a.try_clone()?;
    let mut b2 = b.try_clone()?;
    let t1 = thread::spawn(move || copy_loop(&mut a2, &mut b2));
    let t2 = thread::spawn(move || copy_loop(&mut b, &mut a));
    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn copy_loop(src: &mut TcpStream, dst: &mut TcpStream) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_domain_globe_matches_subdomains_but_not_the_apex() {
        // `*.crates.io` must admit `static.crates.io` and refuse the bare `crates.io` itself —
        // that apex is a separate destination and needs its own entry to be allowed.
        let allow = parse_allowlist("*.crates.io,github.com".to_string());
        assert!(allowed_name("static.crates.io", &allow));
        assert!(allowed_name("index.crates.io", &allow));
        assert!(
            !allowed_name("crates.io", &allow),
            "apex must not be swept in by the globe"
        );
        assert!(
            !allowed_name("evilcrates.io", &allow),
            "suffix must not match a lookalike"
        );
        assert!(allowed_name("github.com", &allow));
        assert!(!allowed_name("gitlab.com", &allow));
    }

    #[test]
    fn an_exact_entry_matches_only_itself_case_insensitively() {
        let allow = parse_allowlist("github.com".to_string());
        assert!(allowed_name("github.com", &allow));
        assert!(allowed_name("GITHUB.COM", &allow));
        assert!(!allowed_name("api.github.com", &allow));
    }

    #[test]
    fn a_trailing_dot_is_ignored_when_matching() {
        let allow = parse_allowlist("example.com".to_string());
        assert!(allowed_name("example.com.", &allow));
        assert!(!allowed_name("other.com.", &allow));
    }

    #[test]
    fn a_cidr_entry_allows_by_address_inside_and_blocks_outside() {
        // A CIDR entry is enforced by address, so the Ip/Cidr rules are consulted against the
        // resolved address of the target. Here we pin the address-side matching directly.
        let allow = parse_allowlist("127.0.0.0/8,10.0.0.0/8,*.example.com".to_string());
        assert!(allowed_name("api.example.com", &allow)); // the name globe still works alongside CIDRs
        assert!(allowed_address("127.0.0.1".parse().unwrap(), &allow));
        assert!(allowed_address("10.1.2.3".parse().unwrap(), &allow));
        assert!(!allowed_address("11.0.0.1".parse().unwrap(), &allow));
    }

    #[test]
    fn a_raw_ip_entry_allows_exactly_that_address() {
        let allow = parse_allowlist("127.0.0.1".to_string());
        assert!(allowed_address("127.0.0.1".parse().unwrap(), &allow));
        assert!(!allowed_address("127.0.0.2".parse().unwrap(), &allow));
    }

    #[test]
    fn a_name_entry_is_not_an_address_rule() {
        // A name rule is matched by name, never by its resolved IP (which can change between the
        // check and the dial), so it must never admit an address directly.
        let allow = parse_allowlist("example.com".to_string());
        assert!(allowed_name("example.com", &allow));
        assert!(!allowed_address("93.184.216.34".parse().unwrap(), &allow));
    }

    #[test]
    fn the_inet_aton_family_parses_to_rules_that_admit_nothing_by_address() {
        // These are neither canonical IPs nor names, so if a hand-written HX_EGRESS_ALLOW feeds
        // them to this proxy they must never admit an address. They sit stored as `Name` rules that
        // equal themselves, but the `handle` path refuses an address-shaped *destination* (is_address_shaped)
        // before it is ever matched or dialed — the dial-guard test proves that end to end. Here we
        // pin the address side: none of them may admit any real address.
        let allow = parse_allowlist("0x01010101,127.1,2130706433,0177.0.0.1".to_string());
        assert!(!allowed_address("1.1.1.1".parse().unwrap(), &allow));
        assert!(!allowed_address("127.0.0.1".parse().unwrap(), &allow));
    }

    // ---- the dial guard: real loopback sockets, no copy of the predicate ----

    /// Run the proxy's own `handle` behind a real loopback listener and return its port.
    ///
    /// The tests below drive the proxy the way a sandbox does — a TCP connection carrying a
    /// `CONNECT` line — rather than calling `handle` with a hand-made buffer, so both the refusal
    /// and the dial are real. Nothing here needs the internet: the "upstream" is another loopback
    /// listener this test owns.
    fn proxy_on_a_loopback_port(allow: Vec<String>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the proxy's test port");
        let port = listener
            .local_addr()
            .expect("the test listener has an address")
            .port();
        thread::spawn(move || {
            let allow = parse_allowlist(allow.join(","));
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let allow = allow.clone();
                thread::spawn(move || handle(stream, &allow));
            }
        });
        port
    }

    /// Send `CONNECT <target>` to the proxy and return the status line it answers.
    fn connect_through(proxy_port: u16, target: &str) -> String {
        let mut client =
            TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to the test proxy");
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .expect("write the CONNECT line");
        let mut buf = [0u8; 256];
        let read = client.read(&mut buf).unwrap_or(0);
        String::from_utf8_lossy(&buf[..read]).to_string()
    }

    #[test]
    fn the_proxy_dials_a_name_entry_and_answers_200() {
        // The control for the refusal below, and the reason it is not a copy of the predicate: it
        // proves the proxy really *does* dial when the entry is a name, so a guard that refused
        // everything (or a proxy that never dialed at all) would fail here instead of passing as a
        // false "the hole is closed". `localhost` resolves to the loopback upstream this test bound.
        let upstream = TcpListener::bind("127.0.0.1:0").expect("bind a loopback upstream");
        let upstream_port = upstream.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream.accept() {
                let _ = stream.write_all(b"UPSTREAM\n");
            }
        });

        let proxy = proxy_on_a_loopback_port(vec!["localhost".to_string()]);
        let status = connect_through(proxy, &format!("localhost:{upstream_port}"));
        assert!(
            status.contains("200 Connection established"),
            "a name entry must be dialed and relayed: {status:?}"
        );
    }

    #[test]
    fn the_proxy_refuses_to_dial_an_address_shaped_destination() {
        // The end-to-end proof of the guard, against a real socket. Each of these entries matches
        // the allowlist *exactly* (`allowed` returns true — that is what makes this a dial guard and
        // not a second allowlist check), and each is address-shaped, so the resolver underneath
        // `TcpStream::connect` would read it as an address: `0x01010101` is 1.1.1.1, `127.1` is
        // 127.0.0.1. Before the guard existed the first of these answered
        // `200 Connection established` and opened a real connection to 1.1.1.1.
        for smuggled in [
            "0x01010101",
            "0x7f000001",
            "127.1",
            "2130706433",
            "0177.0.0.1",
        ] {
            let allow = parse_allowlist(smuggled.to_string());
            assert!(
                allowed_name(smuggled, &allow),
                "{smuggled} must match its own (name) allowlist entry, or this test proves nothing"
            );
            let proxy = proxy_on_a_loopback_port(vec![smuggled.to_string()]);
            let status = connect_through(proxy, &format!("{smuggled}:443"));
            assert!(
                status.contains("403"),
                "{smuggled} is an address, not a name to dial: {status:?}"
            );
            assert!(
                !status.contains("200"),
                "{smuggled} must never be tunneled: {status:?}"
            );
        }
    }

    #[test]
    fn the_proxy_dials_a_cidr_entry_that_contains_the_resolved_address() {
        // The end-to-end proof that a CIDR entry really tunnels: allow `127.0.0.0/8` and
        // CONNECT to `localhost` (which resolves to 127.0.0.1, inside the block). The proxy
        // must resolve the name, match it against the CIDR by address, and answer 200 — not refuse
        // it because there is no matching hostname, and not claim a false denial.
        let upstream = TcpListener::bind("127.0.0.1:0").expect("bind a loopback upstream");
        let upstream_port = upstream.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream.accept() {
                let _ = stream.write_all(b"UPSTREAM\n");
            }
        });

        let proxy = proxy_on_a_loopback_port(vec!["127.0.0.0/8".to_string()]);
        let status = connect_through(proxy, &format!("localhost:{upstream_port}"));
        assert!(
            status.contains("200 Connection established"),
            "a CIDR containing the resolved address must be dialed: {status:?}"
        );
    }

    #[test]
    fn the_proxy_refuses_to_dial_a_cidr_entry_that_does_not_contain_the_resolved_address() {
        // The negative half of the CIDR pair: allow a block that does *not* contain loopback, and
        // CONNECT to `localhost`. The name resolves to 127.0.0.1, which is outside `192.168.0.0/16`,
        // so the proxy must refuse — an address-side allowlist is meaningless if a name that resolves outside
        // it still gets through.
        let proxy = proxy_on_a_loopback_port(vec!["192.168.0.0/16".to_string()]);
        let status = connect_through(proxy, "localhost:443");
        assert!(
            status.contains("403"),
            "a CIDR that does not contain the resolved address must be refused: {status:?}"
        );
    }

    #[test]
    fn the_proxys_address_grammar_matches_the_librarys_on_the_same_table() {
        // The proxy keeps its own copy of the predicate rather than linking the library (see the
        // module doc), so the two are kept honest by carrying the *same* test table. This is that
        // table; `hx_sandbox::spec`'s `the_address_shape_predicate_matches_the_inet_aton_grammar_it_claims_to`
        // is its twin. A change to one grammar that is not made to the other fails here.
        for shaped in [
            "0",
            "0x0",
            "0X0",
            "00",
            "017",
            "1",
            "1.2",
            "1.2.3",
            "1.2.3.4",
            "0xffffffff",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "2130706433",
        ] {
            assert!(is_address_shaped(shaped), "{shaped} is address-shaped");
        }
        for not_shaped in [
            "",
            "example.com",
            "123.example.com",
            "localhost",
            "09",
            "1.2.3.4.5",
            "0x",
            "a.1",
        ] {
            assert!(!is_address_shaped(not_shaped), "{not_shaped} is not");
        }
    }
}
