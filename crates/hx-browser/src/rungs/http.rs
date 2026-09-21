//! The cheap rung: a real HTTP client, and the one thing it must not do.
//!
//! ## Why this rung exists
//!
//! Most of the web is readable without a browser. Spending a browser launch on a page that answers a
//! plain `GET` is the expensive half of the ladder being spent for nothing, so the climb starts here.
//!
//! ## The redirect is the interesting part
//!
//! Admission happens once, when a [`TargetUrl`] is built, and a rung is only ever pointed at one — so
//! it is tempting to think a rung cannot be aimed anywhere it should not go. **A redirect breaks that
//! reasoning.** The URL a rung connects to is not always the URL it was handed: a page on the public
//! internet can answer `302 Location: http://169.254.169.254/latest/meta-data/` and a client that
//! follows redirects itself will have opened that socket before any of this crate's code sees the
//! second URL. The fetch would succeed, the metadata service would answer, and the page body would be
//! a credential with a comment about sandboxing next to it.
//!
//! So the client is built with [`Policy::none()`] and this rung follows redirects itself, admitting
//! **every hop before anything connects to it**. The guard is not a check on the response; it is a
//! check that runs before the request that would use the redirect target exists.
//!
//! ## The hostname behind the URL is resolved once and pinned
//!
//! Admitting the URL is not enough: a public-looking hostname can resolve to loopback or
//! private space (`http://127.0.0.1.nip.io/`), and the answer can change between the check
//! and the connect (rebinding). So every hop is resolved once through a controlled
//! [`HostResolver`](crate::target::HostResolver) and judged — *any* non-public address
//! refuses the hop — and a hostname hop is then sent through a client with
//! `resolve_to_addrs` carrying exactly the approved addresses. The socket can only go where
//! admission looked. An IP literal goes over the shared client: the literal *is* the
//! address, judged by admission itself, with no name a rebinding could change.
//!
//! ## What it refuses
//!
//! - A wall — 403/429/503, or a 200 whose body carries a challenge marker — is a [`FetchError::Refused`],
//!   which is the one failure that escalates. Reporting it as a generic failure would silently cost the
//!   ladder its reason to climb.
//! - A transport failure is not a wall. Escalating spends a browser, and then a person, on a host that
//!   is down.
//! - A body over [`MAX_BODY_BYTES`] is [`FetchError::TooLarge`]. The timeout bounds how long a body
//!   takes, not how much of it arrives.
//!
//! ## What it does not do
//!
//! No JavaScript, no cookies beyond the session's own jar, no cache, no `304` handling (a rung with no
//! cache has nothing to revalidate). No `Accept-*` negotiation: the server's answer is what it is, and
//! sending a browser-shaped `Accept` from a non-browser would be a fingerprint this rung cannot live up
//! to. Escalation to the stealth rung is for the pages that need it.
//!
//! ## Credentials
//!
//! The session's cookies are a credential and go into a `Cookie` header and nowhere else — not into a
//! log, not into an error, not into `Debug`. [`transport_reason`] exists because `reqwest::Error`'s own
//! `Display` appends the URL, and a URL can carry a token in its query string: a failed fetch is exactly
//! the moment one would otherwise be written down.

use crate::error::{FetchError, RefusalReason};
use crate::rung::{FetchRequest, Fetcher, RungKind, UntrustedPage};
use crate::target::{Admission, BlockReason, HostResolver, PinnedTarget, SystemResolver};
use crate::target::{TargetRefusal, TargetUrl};
use async_trait::async_trait;
use reqwest::header::{HeaderValue, CONTENT_TYPE, COOKIE, LOCATION};
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;

/// The `User-Agent` this rung sends.
///
/// Explicit rather than `reqwest`'s default, so the request says what it is and so a test can assert it
/// on the wire. A rung that lies about being a browser is the stealth rung's job, and it does it by
/// being a browser.
pub const USER_AGENT: &str = concat!("hx-browser/", env!("CARGO_PKG_VERSION"));

/// How many redirects one fetch will follow before it gives up.
///
/// Five is the number browsers converged on and the number a redirect loop is usually caught by. It is
/// a bound on hops, not a promise about the destination: every hop is admitted.
pub const MAX_REDIRECTS: usize = 5;

/// How much of a body this rung will hold in memory.
///
/// A page worth reading is far smaller. A hostile one can be unbounded, and the per-attempt timeout
/// bounds how long that takes rather than how much arrives, so the cap is on bytes.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Strings that identify a challenge or interstitial served *with a 200*, where the status alone says
/// nothing.
///
/// Matched against the body, which is untrusted input — so the match is on a fixed list of markers and
/// what leaves this rung is the **marker**, never the page. See [`RefusalReason::Challenge`].
const CHALLENGE_MARKERS: &[&str] = &[
    "cf-challenge",
    "cf_chl_opt",
    "challenge-platform",
    "__cf_chl",
    "just a moment",
    "attention required",
    "checking your browser before accessing",
    "enable javascript and cookies to continue",
    "ddos protection by",
    "captcha-delivery",
];

/// The plain-HTTP rung.
#[derive(Debug)]
pub struct HttpRung {
    client: reqwest::Client,
    admission: Admission,
    resolver: Arc<dyn HostResolver>,
}

impl HttpRung {
    /// The rung as a caller normally gets it: public internet only.
    pub fn new() -> Result<Self, FetchError> {
        Self::with_admission(Admission::default())
    }

    /// The rung under an explicit admission policy.
    ///
    /// Two callers, matching [`Admission`]'s own docs: the hermetic suite, whose stub server is on
    /// `127.0.0.1`, and an operator who has deliberately pointed hx at a service on their own machine.
    pub fn with_admission(admission: Admission) -> Result<Self, FetchError> {
        let client = reqwest::Client::builder()
            // **Load-bearing.** See the module docs: with the default policy, `reqwest` follows the
            // redirect itself and the second URL is connected to before this crate can judge it.
            .redirect(Policy::none())
            .user_agent(USER_AGENT)
            .build()
            .map_err(|err| FetchError::Unavailable {
                rung: RungKind::Http,
                reason: format!(
                    "the HTTP client could not be built: {}",
                    transport_reason(err)
                ),
            })?;

        Ok(Self {
            client,
            admission,
            resolver: Arc::new(SystemResolver),
        })
    }

    /// The rung resolving hostnames through `resolver` instead of the system resolver.
    ///
    /// The production path is [`SystemResolver`]; this hatch exists so a test can dictate
    /// resolutions (loopback, mixed, empty) without owning DNS.
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// The policy every hop is admitted under.
    pub fn admission(&self) -> Admission {
        self.admission
    }

    /// Resolve the target's hostname once and judge every address, off the async runtime.
    ///
    /// WHY `spawn_blocking`: resolution is a blocking `getaddrinfo` call, and a rung must
    /// never stall the runtime on DNS. A refusal arrives as [`FetchError::Blocked`], which
    /// stops the ladder without spending a dearer rung — the same disposition a refused
    /// literal gets.
    async fn pin_target(&self, target: &TargetUrl) -> Result<PinnedTarget, FetchError> {
        let rung = RungKind::Http;
        let target = target.clone();
        let admission = self.admission;
        let resolver = Arc::clone(&self.resolver);
        tokio::task::spawn_blocking(move || target.pin(admission, &*resolver))
            .await
            .map_err(|_| FetchError::Transport {
                rung,
                reason: "the admission task did not complete".to_string(),
            })?
            .map_err(FetchError::Blocked)
    }

    /// The client one admitted hop is sent through.
    ///
    /// An IP literal goes over the shared client: the literal *is* the address, so there is
    /// nothing to rebind. A hostname hop gets a client with `resolve_to_addrs` carrying
    /// exactly the addresses admission approved — the socket can only go where admission
    /// looked, which is what closes the check-then-connect (rebinding) gap.
    fn hop_client(&self, pinned: &PinnedTarget) -> Result<reqwest::Client, FetchError> {
        if pinned.pinned_addrs().is_empty() {
            return Ok(self.client.clone());
        }
        // `pinned_addrs` is non-empty only for hostnames, so the name is there.
        let host = pinned.target().dns_name().unwrap_or_default();
        // Port 0 takes the conventional port for the scheme; an explicit port in the URL
        // always wins over the override, so pinning never changes where the URL points.
        let sock_addrs: Vec<SocketAddr> = pinned
            .pinned_addrs()
            .iter()
            .map(|ip| SocketAddr::new(*ip, 0))
            .collect();
        reqwest::Client::builder()
            .redirect(Policy::none())
            .user_agent(USER_AGENT)
            .resolve_to_addrs(&host, &sock_addrs)
            .build()
            .map_err(|err| FetchError::Unavailable {
                rung: RungKind::Http,
                reason: format!(
                    "the pinned HTTP client could not be built: {}",
                    transport_reason(err)
                ),
            })
    }

    /// Send one request for one already-admitted hop.
    async fn send(
        &self,
        client: &reqwest::Client,
        url: &TargetUrl,
        request: &FetchRequest,
    ) -> Result<reqwest::Response, FetchError> {
        let mut builder = client
            .get(url.request_url().to_string())
            .timeout(request.timeout);

        if let Some(raw) = request.profile.read_cookies() {
            // The value is a credential. A cookie this crate cannot express as a header value is
            // dropped rather than sent malformed — dropping it is the fail-safe direction, and the
            // value is never echoed: `InvalidHeaderValue`'s own `Display` does not carry it.
            if let Ok(value) = HeaderValue::from_str(&raw) {
                builder = builder.header(COOKIE, value);
            }
        }

        builder.send().await.map_err(|err| FetchError::Transport {
            rung: RungKind::Http,
            reason: transport_reason(err),
        })
    }

    /// Resolve a `Location`, admit the result and pin its resolution — **before anything
    /// connects to it**.
    ///
    /// This is the function the redirect commit exists for, extended to hostnames: it runs
    /// between the 3xx and the request that would follow it, so there is no window in which
    /// the redirect target has been contacted, under any spelling of its address.
    async fn admit_redirect(
        &self,
        from: &PinnedTarget,
        location: &HeaderValue,
    ) -> Result<PinnedTarget, FetchError> {
        let rung = RungKind::Http;

        let location = location.to_str().map_err(|_| FetchError::Transport {
            rung,
            reason: "the redirect was not a readable header value".to_string(),
        })?;

        let from_target = from.target().clone();
        let admission = self.admission;
        let resolver = Arc::clone(&self.resolver);
        let location = location.to_string();
        let pinned = tokio::task::spawn_blocking(move || {
            from_target.pin_redirect(admission, &location, &*resolver)
        })
        .await
        .map_err(|_| FetchError::Transport {
            rung,
            reason: "the admission task did not complete".to_string(),
        })?;

        pinned.map_err(|refusal| {
            FetchError::Blocked(TargetRefusal {
                reason: relabel(refusal.reason),
                // The sentence this variant was written for is "*the page* redirected to X", so the
                // display names the page that sent us there rather than the target we refused.
                display: from.target().redacted(),
            })
        })
    }

    /// Read a body, bounded.
    async fn read_body(&self, mut response: reqwest::Response) -> Result<String, FetchError> {
        let rung = RungKind::Http;
        let mut collected: Vec<u8> = Vec::new();

        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if collected.len() + chunk.len() > MAX_BODY_BYTES {
                        return Err(FetchError::TooLarge {
                            rung,
                            bytes: collected.len() + chunk.len(),
                            limit: MAX_BODY_BYTES,
                        });
                    }
                    collected.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(err) => {
                    return Err(FetchError::Transport {
                        rung,
                        reason: transport_reason(err),
                    })
                }
            }
        }

        // Lossy on purpose: a body that declares a text type and then is not valid UTF-8 is still the
        // page, and replacing the bad bytes keeps the readable majority. A binary body was refused by
        // the content-type check before this point.
        Ok(String::from_utf8_lossy(&collected).into_owned())
    }
}

#[async_trait]
impl Fetcher for HttpRung {
    fn kind(&self) -> RungKind {
        RungKind::Http
    }

    fn name(&self) -> &str {
        "http"
    }

    async fn fetch(&self, request: &FetchRequest) -> Result<UntrustedPage, FetchError> {
        let rung = RungKind::Http;
        // The target that was actually fetched. It starts as the caller's requested hop,
        // pinned *before* the first connection (so admission judged the resolution the socket
        // will actually use) and becomes the last admitted redirect, so a page reached through
        // a redirect reports where it really came from.
        let mut current = self.pin_target(&request.target).await?;
        let mut hops = 0usize;

        loop {
            let client = self.hop_client(&current)?;
            let response = self.send(&client, current.target(), request).await?;
            let status = response.status();

            if is_followable(status) {
                if hops >= MAX_REDIRECTS {
                    return Err(FetchError::Http {
                        rung,
                        status: status.as_u16(),
                    });
                }
                let location = response.headers().get(LOCATION).ok_or(FetchError::Http {
                    rung,
                    status: status.as_u16(),
                })?;
                // Admitted before the next send, so nothing connects to an unadmitted hop.
                current = self.admit_redirect(&current, location).await?;
                hops += 1;
                continue;
            }

            if is_wall_status(status) {
                return Err(FetchError::Refused {
                    rung,
                    reason: RefusalReason::Status {
                        status: status.as_u16(),
                    },
                });
            }

            if !status.is_success() {
                return Err(FetchError::Http {
                    rung,
                    status: status.as_u16(),
                });
            }

            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();

            if !is_text(&content_type) {
                return Err(FetchError::NotText { rung, content_type });
            }

            let body = self.read_body(response).await?;

            if let Some(marker) = challenge_marker(&body) {
                return Err(FetchError::Refused {
                    rung,
                    reason: RefusalReason::Challenge {
                        marker: marker.to_string(),
                    },
                });
            }

            return Ok(UntrustedPage::new(
                current.target().clone(),
                status.as_u16(),
                content_type,
                rung,
                body,
            ));
        }
    }
}

/// A transport reason built from a `reqwest::Error` **with the URL removed**.
///
/// `reqwest::Error`'s `Display` appends the URL, and a URL can carry a session token in its query
/// string. `without_url` consumes the error, so the classification is read first.
fn transport_reason(err: reqwest::Error) -> String {
    let kind = if err.is_timeout() {
        "it timed out"
    } else if err.is_connect() {
        "it could not connect"
    } else if err.is_body() {
        "the body failed mid-stream"
    } else if err.is_decode() {
        "the response could not be decoded"
    } else if err.is_builder() {
        "the request could not be built"
    } else if err.is_request() {
        "the request failed"
    } else {
        "the fetch failed"
    };

    format!("{kind}: {}", err.without_url())
}

/// Whether this status is one that carries a `Location` to follow.
///
/// Deliberately not `StatusCode::is_redirection()`, which also covers `304 Not Modified`: a 304 carries
/// no `Location` and means *use your cache*, and a rung with no cache has nothing to follow. Treating it
/// as a redirect would report a missing `Location` as a malformed response instead of as the 304 it is.
fn is_followable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

/// Whether this status is a wall rather than an answer.
///
/// The three that mean *not like that* rather than *not here*: forbidden, rate-limited, unavailable.
/// `401` is not one — it is a missing credential, which a dearer rung does not have either.
fn is_wall_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 403 | 429 | 503)
}

/// Whether a `Content-Type` describes something this rung will hold as text.
///
/// A missing `Content-Type` is treated as text: plenty of static servers omit it, and refusing the page
/// on a header nobody sent would send the ladder to a browser for a working page. A declared binary type
/// is believed, because reading a 4 MB image into a `String` helps nobody.
pub(crate) fn is_text(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    essence.is_empty()
        || essence.starts_with("text/")
        || essence.ends_with("+json")
        || essence.ends_with("+xml")
        || matches!(
            essence.as_str(),
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-javascript"
                | "application/x-ndjson"
                | "application/ld+json"
                | "application/rss+xml"
                | "application/atom+xml"
        )
}

/// The marker that identifies a challenge page, if this body is one.
///
/// The body is untrusted input and may be megabytes of an attacker's choosing; the return value is a
/// fixed marker from [`CHALLENGE_MARKERS`], never a slice of the page. See [`RefusalReason::Challenge`].
pub(crate) fn challenge_marker(body: &str) -> Option<&'static str> {
    let lowered = body.to_ascii_lowercase();
    CHALLENGE_MARKERS
        .iter()
        .find(|marker| lowered.contains(*marker))
        .copied()
}

/// Say *redirected* rather than *private host*, because the two are different events.
///
/// "The target is on the local network" and "the page redirected us to the local network" read almost
/// the same in a log and are not the same thing: only the second means the page's own author chose the
/// destination. A scheme or malformed refusal keeps its own wording, which is already exact.
fn relabel(reason: BlockReason) -> BlockReason {
    match reason {
        BlockReason::PrivateHost { host, reason } => BlockReason::Redirected { host, reason },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_statuses_that_carry_a_location_are_followed() {
        // A 304 means "use your cache". Following it would report a missing `Location` as a malformed
        // response, which is a different and misleading failure.
        for status in [301, 302, 303, 307, 308] {
            assert!(
                is_followable(StatusCode::from_u16(status).unwrap()),
                "{status} carries a Location"
            );
        }
        for status in [304, 300, 305, 306] {
            assert!(
                !is_followable(StatusCode::from_u16(status).unwrap()),
                "{status} is not a redirect to follow"
            );
        }
    }

    #[test]
    fn a_forbidden_or_rate_limited_answer_is_a_wall_and_an_unauthorized_one_is_not() {
        // The distinction the ladder turns on: a wall escalates, a 404 or a 401 does not. A 401 is a
        // missing credential, which a dearer rung does not have either.
        assert!(is_wall_status(StatusCode::FORBIDDEN));
        assert!(is_wall_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_wall_status(StatusCode::SERVICE_UNAVAILABLE));

        assert!(!is_wall_status(StatusCode::UNAUTHORIZED));
        assert!(!is_wall_status(StatusCode::NOT_FOUND));
        assert!(!is_wall_status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(!is_wall_status(StatusCode::OK));
    }

    #[test]
    fn a_text_type_is_read_and_a_binary_one_is_not() {
        assert!(is_text("text/html"));
        assert!(is_text("text/html; charset=UTF-8"));
        assert!(is_text("TEXT/PLAIN"));
        assert!(is_text("application/json"));
        assert!(is_text("application/ld+json"));
        assert!(is_text("application/xhtml+xml"));
        assert!(is_text("application/activity+json"));
        // A missing type is treated as text: static servers omit it, and refusing the page on a header
        // nobody sent would spend a browser on a page that already worked.
        assert!(is_text(""));

        assert!(!is_text("image/png"));
        assert!(!is_text("application/pdf"));
        assert!(!is_text("application/octet-stream"));
        assert!(!is_text("video/mp4"));
    }

    #[test]
    fn a_challenge_marker_is_reported_by_name_and_never_as_a_slice_of_the_page() {
        // What leaves this rung is the marker, never the body: the body is attacker-controlled text and
        // putting it in an error is how it reaches a log or a model.
        let page = "<html><head><title>Just a moment...</title></head><body>SECRET-PAGE-TEXT</body></html>";
        let marker = challenge_marker(page).expect("the marker is recognised");

        assert_eq!(marker, "just a moment");
        assert!(
            !marker.contains("SECRET-PAGE-TEXT"),
            "the marker must not be a slice of the page"
        );

        assert_eq!(
            challenge_marker("<html><body>a real page</body></html>"),
            None
        );
    }

    #[test]
    fn a_refused_redirect_says_redirected_rather_than_private_host() {
        // The same host refused two ways is two different events, and only one of them means the page's
        // author chose the destination.
        let relabelled = relabel(BlockReason::PrivateHost {
            host: "169.254.169.254".to_string(),
            reason: "it is a link-local address",
        });
        assert_eq!(
            relabelled,
            BlockReason::Redirected {
                host: "169.254.169.254".to_string(),
                reason: "it is a link-local address",
            }
        );
        assert!(relabelled.to_string().contains("it redirected to"));

        // A scheme refusal is already exact and keeps its wording.
        let scheme = BlockReason::Scheme {
            scheme: "file".to_string(),
        };
        assert_eq!(relabel(scheme.clone()), scheme);
    }

    #[test]
    fn the_rung_names_itself_without_a_url_or_a_credential() {
        // `name()` reaches a model. It is a constant, and this asserts it stays one.
        let rung = HttpRung::new().expect("a client");
        assert_eq!(rung.name(), "http");
        assert_eq!(rung.kind(), RungKind::Http);
        assert_eq!(rung.admission(), Admission::PublicInternet);
        assert_eq!(
            HttpRung::with_admission(Admission::AllowLocal)
                .unwrap()
                .admission(),
            Admission::AllowLocal
        );
    }

    #[test]
    fn the_rungs_user_agent_says_what_it_is() {
        assert!(USER_AGENT.starts_with("hx-browser/"), "{USER_AGENT}");
        assert!(!USER_AGENT.contains(' '), "{USER_AGENT}");
    }
}
