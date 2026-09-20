//! Target admission: what this crate will fetch, and what it refuses to look at.
//!
//! ## The property this module holds
//!
//! **A remote page cannot make this crate read a local file or reach the local network.** The
//! fetcher runs inside the daemon's own process, on the operator's machine, so a URL is a request
//! the operator's own host will make — which is the definition of server-side request forgery. Two
//! shapes of it are refused here:
//!
//! - **a non-http scheme**, so `file:///home/me/.ssh/id_rsa`, `data:` and `gopher://` are not
//!   fetchable. A `file://` URL is not a page; it is this process opening a local file and handing
//!   the contents back to whoever asked;
//! - **an address on the local machine or the local network** — loopback, RFC 1918, link-local,
//!   unique-local, CGNAT, and the cloud metadata service (`169.254.169.254`, the hostname
//!   `metadata.google.internal`). The metadata endpoint is the one that turns an SSRF into a
//!   credential theft: it answers with the instance's IAM credentials to anyone who asks from
//!   inside the machine.
//!
//! Admission is **structural**: [`TargetUrl`] is the only thing a rung can be pointed at, and the
//! only way to build one is through [`TargetUrl::parse`]. A caller cannot forget to check, because
//! there is nothing to check *with* — the type is the check.
//!
//! ## Why the escape hatch is a named policy rather than a weakening
//!
//! The hermetic test suite drives real HTTP against a stub server on `127.0.0.1`, which is exactly
//! what the default refuses. Rather than widen the default, [`Admission::AllowLocal`] exists as a
//! *named* decision — the same shape as `hx-remote`'s `HostKeyPolicy`, where accepting anything is
//! an explicit choice rather than a default that happens because verification was absent. It lifts
//! only the address rule: a scheme is never fetchable just because someone allowed local hosts, and
//! that is asserted.
//!
//! ## What is deliberately NOT done
//!
//! - **No DNS resolution check.** `http://127.0.0.1.nip.io/` is a public hostname that resolves to
//!   loopback, and nothing here catches it: the check is on the *name*, and resolving it is a
//!   network call this module deliberately does not make (a resolver that runs during validation is
//!   itself an SSRF surface, and the answer can change between the check and the connect — DNS
//!   rebinding). Catching that class properly means resolving once and pinning the address on the
//!   connection, which belongs in the rung that owns the socket, and is not done here.
//! - **No robots.txt or rate policy.** This module decides *what may be reached*, not *how often*.
//! - **No path sanitisation.** A URL's path is the site's business. What this module does do is keep
//!   the path out of nothing and the *query* out of everything: see [`TargetUrl::redacted`].

use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// The longest redacted form kept in a report or an error, in bytes.
///
/// A URL is caller-supplied and can be arbitrarily long, so an error message built from one is a
/// log-flooding vector as well as a leak. Truncation happens in [`redact`], which every display path
/// goes through.
const MAX_DISPLAY_BYTES: usize = 200;

/// Whether a target may reach the machine hx runs on, and the network around it.
///
/// The default is [`Admission::PublicInternet`] and it is the default for a reason: the fetcher
/// makes requests from inside the daemon, so "local" is not a smaller request, it is a different
/// capability. Loosening it is a decision with a name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Admission {
    /// The public internet only. Loopback, private, link-local, CGNAT and metadata addresses are
    /// refused.
    #[default]
    PublicInternet,
    /// The address rule is lifted: loopback and private addresses are admitted.
    ///
    /// Two callers. The hermetic suite, whose stub server is on `127.0.0.1`. And an operator who has
    /// deliberately pointed hx at a service on their own machine. It does **not** lift the scheme
    /// rule — `file://` is refused under either policy.
    AllowLocal,
}

/// Why a target was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockReason {
    #[error("the scheme is {scheme:?}, and only http and https are fetchable")]
    Scheme { scheme: String },

    #[error("{host} is not on the public internet: {reason}")]
    PrivateHost { host: String, reason: &'static str },

    #[error("it is not a URL ({reason})")]
    Malformed { reason: String },

    #[error("it redirected to {host}, which is not on the public internet: {reason}")]
    Redirected { host: String, reason: &'static str },
}

/// A target admission refused, with the redacted form of what was refused.
///
/// The redacted form is carried rather than reconstructed because the caller needs to say *what*
/// was refused without repeating a query string that may hold a token.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{display} is not a fetchable target: {reason}")]
pub struct TargetRefusal {
    pub reason: BlockReason,
    /// Never contains userinfo, a query or a fragment. See [`redact`].
    pub display: String,
}

/// A URL that has passed admission.
///
/// The only way a rung is ever pointed at anything. Construction is the check, so a rung cannot be
/// handed an unchecked target even by a caller who forgot.
///
/// `Debug` is redacted and there is deliberately no `Display`: the one thing a caller must not do
/// with this type is paste it into a log line. [`TargetUrl::request_url`] exists for the rung that
/// needs the real thing to make a request, and says so.
#[derive(Clone, PartialEq, Eq)]
pub struct TargetUrl {
    url: Url,
}

impl TargetUrl {
    /// Admit a URL under the default policy: the public internet only.
    pub fn parse(raw: &str) -> Result<Self, TargetRefusal> {
        Self::parse_with(Admission::PublicInternet, raw)
    }

    /// Admit a URL under an explicit policy.
    pub fn parse_with(admission: Admission, raw: &str) -> Result<Self, TargetRefusal> {
        let trimmed = raw.trim();
        let refuse = |reason: BlockReason| TargetRefusal {
            reason,
            display: best_effort_display(trimmed),
        };

        let url = Url::parse(trimmed).map_err(|e| {
            // Only `url`'s own message is used. Echoing the input would put whatever the caller
            // passed — token and all — into an error the model reads.
            refuse(BlockReason::Malformed {
                reason: e.to_string(),
            })
        })?;

        match url.scheme() {
            "http" | "https" => {}
            other => {
                return Err(refuse(BlockReason::Scheme {
                    scheme: other.to_string(),
                }))
            }
        }

        let host = url.host_str().ok_or_else(|| {
            refuse(BlockReason::Malformed {
                reason: "it has no host".to_string(),
            })
        })?;

        // `url` lowercases the host, but it keeps the brackets on an IPv6 literal — so the string
        // form is *not* an address and `"::1".parse::<IpAddr>()` never sees one. Brackets come off
        // for the name rules below, and the address rules use `url.host()` instead of a string
        // parse, which is the only version of that check that cannot be fooled by spelling.
        //
        // A trailing dot is a fully-qualified spelling of the same name — `localhost.` is localhost,
        // and `metadata.google.internal.` is the metadata service — so it comes off before every
        // comparison. Leaving it on would be a one-character bypass of every name rule.
        let host = unbracket(host).trim_end_matches('.');
        if host.is_empty() {
            return Err(refuse(BlockReason::Malformed {
                reason: "it has an empty host".to_string(),
            }));
        }

        if admission == Admission::PublicInternet {
            let refusal = match url.host() {
                Some(Host::Ipv4(v4)) => why_not_public_v4(v4),
                Some(Host::Ipv6(v6)) => why_not_public_v6(v6),
                _ => local_name_reason(host),
            };
            if let Some(reason) = refusal {
                return Err(refuse(BlockReason::PrivateHost {
                    host: host.to_string(),
                    reason,
                }));
            }
        }

        Ok(Self { url })
    }

    /// The full URL, **for the request a rung makes** and nothing else.
    ///
    /// Named for its one legitimate use. It is not the display form; use [`TargetUrl::redacted`] for
    /// anything a human or a model will read.
    pub fn request_url(&self) -> &str {
        self.url.as_str()
    }

    /// The host, lowercased, with an IPv6 literal's brackets removed. Safe to display: it is the
    /// part that is never a secret.
    pub fn host(&self) -> &str {
        // A `TargetUrl` was built from a URL that had a host, so this cannot be `None`.
        unbracket(self.url.host_str().unwrap_or_default())
    }

    /// The URL with everything that can carry a credential removed: userinfo, query and fragment.
    ///
    /// **Every URL this crate puts in a report, an error or a log goes through here.** A signed
    /// download link, a password-reset link and a share link all carry their token in the query
    /// string, and a *failed* fetch is exactly the moment one would otherwise be written down for
    /// good. Truncated to [`MAX_DISPLAY_BYTES`].
    pub fn redacted(&self) -> String {
        redact(&self.url)
    }
}

impl std::fmt::Debug for TargetUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately not `f.debug_struct`, so a derived-looking `TargetUrl { url: ... }` can
        // never appear in a log with the real thing inside it.
        write!(f, "TargetUrl({})", self.redacted())
    }
}

/// The display form of a URL: scheme, host, port and path, and nothing that can carry a secret.
fn redact(url: &Url) -> String {
    let mut out = String::from(url.scheme());
    out.push_str("://");
    out.push_str(url.host_str().unwrap_or("<no host>"));
    if let Some(port) = url.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(url.path());
    truncate(out)
}

/// The best display form of a string that may not even parse.
fn best_effort_display(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(url) => redact(&url),
        // The input is not repeated. A string that failed to parse is a string whose shape is
        // unknown, and unknown is not a reason to write it into a log.
        Err(_) => "<unparseable URL>".to_string(),
    }
}

fn truncate(mut value: String) -> String {
    if value.len() <= MAX_DISPLAY_BYTES {
        return value;
    }
    // Truncate on a char boundary so a multi-byte host or path cannot panic here.
    let mut end = MAX_DISPLAY_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push('…');
    value
}

/// Strip the brackets `url` keeps on an IPv6 literal, so the string form is the address itself.
///
/// The reason this matters is not cosmetic: a check that string-parses a host to decide whether it
/// is an address silently fails for every IPv6 literal, and then falls through to the *name* rules,
/// where `[::1]` looks like a single-label hostname. It still refuses, for the wrong reason, which is
/// the kind of accident that becomes an acceptance the moment a name rule is relaxed.
fn unbracket(host: &str) -> &str {
    match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) => inner,
        None => host,
    }
}

/// `None` when the address is on the public internet, otherwise why it is not.
fn why_not_public_v4(v4: Ipv4Addr) -> Option<&'static str> {
    if v4.is_loopback() {
        Some("it is the loopback address")
    } else if v4.is_private() {
        Some("it is in a private range (RFC 1918)")
    } else if v4.is_link_local() {
        Some("it is a link-local address, which is where the cloud metadata service lives")
    } else if v4.is_unspecified() {
        Some("it is the unspecified address 0.0.0.0")
    } else if v4.is_broadcast() {
        Some("it is the broadcast address")
    } else if v4.is_multicast() {
        Some("it is a multicast address")
    } else if v4.is_documentation() {
        Some("it is in a documentation range, which never routes")
    } else if is_cgnat(v4) {
        Some("it is in the carrier-grade NAT range 100.64.0.0/10")
    } else {
        None
    }
}

fn why_not_public_v6(v6: Ipv6Addr) -> Option<&'static str> {
    if v6.is_loopback() {
        Some("it is the IPv6 loopback address")
    } else if v6.is_unspecified() {
        Some("it is the unspecified IPv6 address")
    } else if v6.is_multicast() {
        Some("it is an IPv6 multicast address")
    } else if v6.is_unique_local() {
        Some("it is an IPv6 unique-local address (fc00::/7)")
    } else if v6.is_unicast_link_local() {
        Some("it is an IPv6 link-local address (fe80::/10)")
    } else if let Some(mapped) = v6.to_ipv4_mapped() {
        // `::ffff:127.0.0.1` is loopback wearing a v6 coat, and `::ffff:169.254.169.254` is the
        // metadata service. Judged as the address it maps to, not as the way it is spelled.
        why_not_public_v4(mapped)
    } else {
        None
    }
}

/// `100.64.0.0/10` — carrier-grade NAT, which is somebody else's private network.
fn is_cgnat(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (octets[1] & 0xc0) == 64
}

/// `None` when the host is an ordinary public name, otherwise why it is not.
fn local_name_reason(host: &str) -> Option<&'static str> {
    if host == "localhost" {
        return Some("it is localhost");
    }
    // Named individually rather than left to the `.internal` suffix rule below, because this is the
    // hostname that answers with the instance's credentials and it deserves to be named.
    if matches!(
        host,
        "metadata.google.internal" | "instance-data" | "metadata"
    ) {
        return Some("it is a cloud metadata service name");
    }
    if !host.contains('.') {
        // A single-label name has no public DNS home: it resolves only through a search domain, i.e.
        // only on the local network.
        return Some("a single-label name can only resolve on the local network");
    }
    for (suffix, reason) in [
        (
            ".localhost",
            "the .localhost TLD is reserved for the loopback interface (RFC 6761)",
        ),
        (
            ".local",
            "the .local TLD is mDNS, which only resolves on the local network",
        ),
        (
            ".internal",
            "the .internal TLD is reserved for private networks",
        ),
        (
            ".home.arpa",
            "the .home.arpa TLD is reserved for home networks (RFC 8375)",
        ),
    ] {
        if host.ends_with(suffix) {
            return Some(reason);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(raw: &str) -> TargetRefusal {
        TargetUrl::parse(raw).expect_err(raw)
    }

    // ---------------------------------------------------------------------------------------
    // The schemes a page must not be able to turn into a local file read
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_file_url_is_refused_because_a_page_must_not_read_a_local_file() {
        let err = refused("file:///home/me/.ssh/id_rsa");
        assert!(
            matches!(err.reason, BlockReason::Scheme { ref scheme } if scheme == "file"),
            "{err:?}"
        );
        assert!(err.to_string().contains("file"), "{err}");
    }

    #[test]
    fn every_non_http_scheme_is_refused() {
        for raw in [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "gopher://example.com/",
            "data:text/html,<h1>hi</h1>",
            "chrome://settings",
            "ws://example.com/",
        ] {
            assert!(
                matches!(refused(raw).reason, BlockReason::Scheme { .. }),
                "{raw} must be refused for its scheme"
            );
        }
    }

    // ---------------------------------------------------------------------------------------
    // The addresses
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_link_local_address_is_refused_because_that_is_where_metadata_lives() {
        // The one that turns an SSRF into a credential theft.
        let err = refused("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
        assert!(
            matches!(err.reason, BlockReason::PrivateHost { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("link-local"), "{err}");
    }

    #[test]
    fn every_private_and_special_address_range_is_refused() {
        for raw in [
            "http://127.0.0.1:8080/",
            "http://127.1.2.3/",
            "http://10.0.0.5/",
            "http://172.16.4.4/",
            "http://192.168.1.1/",
            "http://0.0.0.0/",
            "http://100.64.0.1/",
            "http://224.0.0.1/",
            "http://192.0.2.1/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fc00::1]/",
            "http://[fd12:3456::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
        ] {
            assert!(
                matches!(refused(raw).reason, BlockReason::PrivateHost { .. }),
                "{raw} must be refused as a local address"
            );
        }
    }

    #[test]
    fn a_public_address_is_accepted() {
        // The control for the test above: the rule is a list of ranges, not "refuse IP literals".
        for raw in [
            "http://93.184.216.34/",
            "https://1.1.1.1/",
            "http://[2606:4700:4700::1111]/",
        ] {
            assert!(TargetUrl::parse(raw).is_ok(), "{raw} is a public address");
        }
    }

    #[test]
    fn localhost_and_its_spellings_are_refused() {
        for raw in [
            "http://localhost/",
            "http://LOCALHOST/admin",
            // The trailing dot is the fully-qualified spelling of the same name. Leaving it on
            // would be a one-character bypass of every rule below.
            "http://localhost./admin",
            "http://a.localhost/",
            "http://box.local/",
            "http://printer/",
            "http://nas.home.arpa/",
            "http://metadata.google.internal/",
            "http://metadata.google.internal./",
            "http://metadata/",
        ] {
            assert!(
                matches!(refused(raw).reason, BlockReason::PrivateHost { .. }),
                "{raw} must be refused as a local name"
            );
        }
    }

    #[test]
    fn a_public_hostname_is_accepted() {
        for raw in [
            "https://example.com/",
            "https://en.wikipedia.org/wiki/Rust",
            "https://docs.rs/hx-browser/latest/hx_browser/",
        ] {
            assert!(TargetUrl::parse(raw).is_ok(), "{raw} is a public host");
        }
    }

    #[test]
    fn the_allow_local_policy_does_not_lift_the_scheme_guard() {
        // `AllowLocal` is an address decision, not a licence. If it ever lifted the scheme rule,
        // the test suite's convenience would become a production `file://` read.
        assert!(matches!(
            refused("file:///etc/passwd").reason,
            BlockReason::Scheme { .. }
        ));

        assert!(TargetUrl::parse_with(Admission::AllowLocal, "http://127.0.0.1:9/").is_ok());
        assert!(TargetUrl::parse_with(Admission::AllowLocal, "http://localhost:9/").is_ok());
        assert!(TargetUrl::parse_with(Admission::AllowLocal, "http://169.254.169.254/").is_ok());
        assert!(TargetUrl::parse_with(Admission::AllowLocal, "file:///etc/passwd").is_err());
    }

    // ---------------------------------------------------------------------------------------
    // Never write down a token
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_token_in_the_query_never_renders_in_the_display_form_or_in_debug() {
        let url =
            TargetUrl::parse("https://example.test/reset?token=SECRETVALUE&x=1#frag").unwrap();

        assert!(
            !url.redacted().contains("SECRETVALUE"),
            "{}",
            url.redacted()
        );
        assert!(!url.redacted().contains("token"), "{}", url.redacted());
        assert!(!format!("{url:?}").contains("SECRETVALUE"), "{url:?}");
        // The path and host survive, because a report that says only "some URL" is useless.
        assert_eq!(url.redacted(), "https://example.test/reset");
        assert_eq!(url.host(), "example.test");
        // And the real URL is still available to the rung that has to make the request.
        assert!(url.request_url().contains("SECRETVALUE"));
    }

    #[test]
    fn userinfo_is_dropped_from_the_display_form() {
        let url = TargetUrl::parse("https://alice:hunter2@example.test/private").unwrap();
        assert!(!url.redacted().contains("hunter2"), "{}", url.redacted());
        assert!(!url.redacted().contains("alice"), "{}", url.redacted());
        assert_eq!(url.redacted(), "https://example.test/private");
    }

    #[test]
    fn a_refused_target_does_not_echo_a_token_in_its_message() {
        let err = refused("file:///etc/passwd?token=SECRETVALUE");
        assert!(!err.to_string().contains("SECRETVALUE"), "{err}");
        assert!(!format!("{err:?}").contains("SECRETVALUE"), "{err:?}");

        let err = refused("http://169.254.169.254/x?token=SECRETVALUE");
        assert!(!err.to_string().contains("SECRETVALUE"), "{err}");
    }

    #[test]
    fn a_url_that_does_not_parse_is_refused_without_echoing_it() {
        let err = refused("this is not a url?token=SECRETVALUE");
        assert!(
            matches!(err.reason, BlockReason::Malformed { .. }),
            "{err:?}"
        );
        assert!(!err.to_string().contains("SECRETVALUE"), "{err}");
        assert!(err.to_string().contains("unparseable"), "{err}");
    }

    #[test]
    fn an_enormous_url_is_truncated_in_its_display_form() {
        // A URL is caller-supplied and can be arbitrarily long, so an error built from one is a
        // log-flooding vector as well as a leak.
        let long = format!("file:///etc/passwd/{}", "a".repeat(5000));
        let err = refused(&long);
        assert!(
            err.display.len() <= MAX_DISPLAY_BYTES + 4,
            "{}",
            err.display.len()
        );
        assert!(err.display.ends_with('…'), "{}", err.display);
    }

    #[test]
    fn a_host_is_lowercased_and_its_brackets_are_gone() {
        // `url` lowercases the host and keeps the brackets on an IPv6 literal, and the rules above
        // depend on the brackets coming off — a check that string-parses `"[::1]"` as an address
        // never matches, and falls through to the *name* rules instead.
        let url = TargetUrl::parse("https://EXAMPLE.test/Path").unwrap();
        assert_eq!(url.host(), "example.test");

        let v6 = TargetUrl::parse("http://[2606:4700:4700::1111]/").unwrap();
        assert_eq!(v6.host(), "2606:4700:4700::1111");

        let refused = refused("http://[::1]/");
        match &refused.reason {
            // The address is reported without its brackets; the redacted URL keeps them, because
            // that is how an IPv6 literal is written in a URL.
            BlockReason::PrivateHost { host, .. } => assert_eq!(host, "::1"),
            other => panic!("expected a private host refusal, got {other:?}"),
        }
        assert!(refused.to_string().contains("loopback"), "{refused}");
    }
}
