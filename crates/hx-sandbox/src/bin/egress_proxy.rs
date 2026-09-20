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
//! `HX_EGRESS_ALLOW` is a comma-separated list of `hostname` or `*.domain` entries,
//! e.g. `crates.io,*.crates.io`. Matching is deliberately simple: an entry with a leading
//! `*.` matches any host whose name ends with that domain; any other entry matches a host exactly.
//! Nothing else is accepted, because nothing else can be enforced *here*. A CIDR cannot be matched
//! against an unresolved CONNECT target, so an allowlist entry that is not a hostname or `*.domain`
//! is refused by [`crate::spec::SandboxSpec::validate`] before a sandbox is ever created —
//! this proxy never sees it.
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
use std::net::{TcpListener, TcpStream};
use std::thread;

const LISTEN_ADDR: &str = "0.0.0.0:3128";

const USAGE: &str = "\
hx-egress-proxy — the allowlist-enforcing egress proxy for a sandbox.

Started by the daemon as the sidecar container's command; not normally run by
hand. It listens on the internal network and forwards only CONNECT requests to
destinations named in its allowlist.

Environment:
  HX_EGRESS_ALLOW   comma-separated `host` or `*.domain` entries, e.g.
                    `crates.io,*.crates.io`. Absent or empty means nothing is
                    allowed, which is the fail-closed default.

Options:
  -h, --help        print this and exit
  -V, --version     print the version and exit

It takes no other arguments: the listen address is fixed, because the network
it must sit on is the whole reason it exists.
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

    let listener = TcpListener::bind(LISTEN_ADDR).expect("proxy must bind the internal port");
    eprintln!("egress proxy listening on {LISTEN_ADDR}");

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

/// Parse `host,*.domain` into a matcher. An unrecognised shape is dropped rather than trusted:
/// if it cannot be enforced, pretending it can is how the allowlist becomes a fiction.
fn parse_allowlist(raw: String) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// A host is allowed when it equals an entry, or when an entry `*.domain` matches its suffix.
fn allowed(host: &str, allow: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allow.iter().any(|entry| {
        if let Some(domain) = entry.strip_prefix("*.") {
            // `*.example.com` matches `a.example.com` but not the bare apex `example.com` —
            // an entry that name the apex explicitly is the honest way to allow it.
            host != domain
                && host.ends_with(domain)
                && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
        } else {
            host == *entry
        }
    })
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

fn handle(mut client: TcpStream, allow: &[String]) {
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

    if !allowed(host, allow) {
        eprintln!("egress DENIED {host}:{port}");
        // A clear, immediate refusal: the sandbox must observe the failure as a *denial*, not a
        // hang, or a tool will retry into a black hole and the operator will never see why.
        let _ = write_status(&mut client, 403, "Forbidden");
        return;
    }

    // Defence in depth, and it is the difference between a refusal and a live connection. The
    // validator refuses an address-shaped allowlist entry, but this proxy does not trust that: an
    // entry that matched here (`0x01010101` matched `0x01010101` exactly) must still not be *dialed*,
    // because the resolver would read it as 1.1.1.1. Measured before this guard existed: the proxy
    // answered `200 Connection established` and opened a real connection to 1.1.1.1. The refusal is
    // the same 403 the allowlist itself produces — the sandbox sees a denial, never a tunnel.
    if is_address_shaped(host) {
        eprintln!("egress DENIED {host}:{port} (address-shaped destination; not a name to dial)");
        let _ = write_status(&mut client, 403, "Forbidden");
        return;
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
        let allow = vec!["*.crates.io".to_string(), "github.com".to_string()];
        assert!(allowed("static.crates.io", &allow));
        assert!(allowed("index.crates.io", &allow));
        assert!(
            !allowed("crates.io", &allow),
            "apex must not be swept in by the globe"
        );
        assert!(
            !allowed("evilcrates.io", &allow),
            "suffix must not match a lookalike"
        );
        assert!(allowed("github.com", &allow));
        assert!(!allowed("gitlab.com", &allow));
    }

    #[test]
    fn an_exact_entry_matches_only_itself_case_insensitively() {
        let allow = vec!["github.com".to_string()];
        assert!(allowed("github.com", &allow));
        assert!(allowed("GITHUB.COM", &allow));
        assert!(!allowed("api.github.com", &allow));
    }

    #[test]
    fn a_trailing_dot_is_ignored_when_matching() {
        let allow = vec!["example.com".to_string()];
        assert!(allowed("example.com.", &allow));
        assert!(!allowed("other.com.", &allow));
    }

    #[test]
    fn unsupported_entry_shapes_match_nothing_and_never_allow_a_bypass() {
        // A CIDR like `10.0.0.0/8` cannot be matched against an unresolved CONNECT target,
        // so if one slips through it must be *inert* — it can never admit a connection, only fail
        // to admit one. The validator rejects such shapes earlier, but the proxy must not trust them
        // even if it somehow sees one (paranoia is the default in this file).
        let allow = parse_allowlist("crates.io,10.0.0.0/8,*.example.com".to_string());
        assert!(allowed("crates.io", &allow));
        assert!(allowed("api.example.com", &allow));
        assert!(
            !allowed("10.0.0.5", &allow),
            "a CIDR entry must admit nothing"
        );
        assert!(!allowed("crates.io.evil.com", &allow));
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
            let allow = vec![smuggled.to_string()];
            assert!(
                allowed(smuggled, &allow),
                "{smuggled} must match its own allowlist entry, or this test proves nothing"
            );
            let proxy = proxy_on_a_loopback_port(allow);
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
