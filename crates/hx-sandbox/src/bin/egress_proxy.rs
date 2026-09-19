//! The egress proxy that enforces a sandbox's allowlist.
//!
//! A sandbox on an [`crate::egress`] internal network cannot reach the internet directly —
//! the network has no gateway. The *only* path out is this proxy, which sits on both that
//! internal network and the normal bridge, and which admits connections only to destinations on the
//! allowlist it was started with.
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
}
