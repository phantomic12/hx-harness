//! Bearer-token authentication for the daemon's HTTP API.
//!
//! ## Why the daemon has one at all
//!
//! Every route on this surface can read a file, run a command on a configured host, or answer the
//! approval question an agent run is waiting on. Until this module there was **no authentication**:
//! the API was open to anything that could reach the port. On the default loopback bind that is a
//! local-only exposure; under `--bind 0.0.0.0` it is open to whatever can route to the address, and
//! `docs/approvals.md` §9 records exactly that as the hole under the approval ceiling — the answer
//! route requires the *caller* to declare its ceiling, and a declared ceiling is only as trustworthy
//! as the caller. The control that was missing there is this one.
//!
//! ## The two halves
//!
//! - **Fail closed at startup.** [`hx_core::api_auth::require_token_for_bind`] refuses to start when
//!   the bind address is not loopback and no token resolved. A daemon that started anyway with a
//!   warning would be serving an unauthenticated API on a routable interface, and a warning is a
//!   line in a log nobody reads. `hxd` calls it before it binds, so the refusal happens while there
//!   is still nothing listening.
//! - **Optional on loopback.** A token is honoured when set and not required when it is not. This is
//!   the rule that keeps the existing suite green without editing it: those tests bind loopback and
//!   pass no token, which is a legitimate configuration, not a loophole.
//!
//! ## The comparison
//!
//! [`hx_core::api_auth::ApiToken::matches`] compares in constant time — every byte of the longer
//! input is visited and the length difference is folded in as a bit rather than returned early, so a
//! correct prefix costs the same as a wrong first byte. That is defence against a timing comparison
//! and **it is not the whole story**: what is compared is still a bearer token with no rotation, no
//! expiry and no replay protection. Anyone who observes the token can use it for as long as it
//! stands. It is not a session, and "the API is authenticated" is not the same claim as "the API is
//! secure" — the transport is plain HTTP, so over a non-loopback interface the token travels in the
//! clear unless something in front of the daemon terminates TLS. Both limits are stated here rather
//! than implied away, because a control whose boundaries are unstated gets trusted past them.
//!
//! ## What is exempt, and why
//!
//! - `GET /healthz` — a liveness probe. It answers the constant `"ok"` and reveals nothing but the
//!   existence of a listener, and a health check that needs a credential is one a container
//!   orchestrator cannot run. The alternative considered was authenticating it and having every
//!   probe carry the token, which would put the token in a second place for no information gained.
//! - `GET /` — the web client itself. A browser navigation cannot carry an `Authorization` header,
//!   so requiring one here would make the page unreachable exactly when a token is configured. What
//!   is served is a static file embedded in the binary; it carries no daemon state, and every route
//!   that does is behind the token. The page asks for the token once and keeps it.
//!
//! Everything else — including both WebSocket routes — requires a token when one is configured.
//!
//! ## The WebSocket exception to "the header, or nothing"
//!
//! A browser cannot set headers on a WebSocket handshake, so a page that must attach to
//! `/v1/sessions/{id}/ws` has no way to present a bearer header. The WebSocket routes therefore
//! accept the token from `?token=` **only on a WebSocket upgrade request** — a plain `GET` with a
//! query parameter is refused like any other unauthenticated request, and upgrade headers on a
//! non-WebSocket route are ignored. The honest cost, written down rather than hidden: a value in a
//! query string can reach an access log or a `Referer`, which is why the header remains the form
//! the CLI and every non-browser client use, and why the parameter is narrowed to the one request
//! shape that has no alternative. The alternative considered and rejected was exempting the
//! WebSocket routes, which would have left the live event stream and the terminal — the two routes
//! that hand over a shell — unauthenticated.

use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Routes answered without a token. See the module doc for the reasoning behind each.
pub fn is_exempt(path: &str) -> bool {
    path == "/healthz" || path == "/" || is_phone_respond_route(path)
}

/// The phone/lock-screen respond route.
///
/// Exempt from the bearer token **on purpose**: the phone never holds the API's long-lived bearer
/// secret, and this route authenticates with the **one-time** token that travelled inside the pushed
/// `respond_url` instead ([`crate::phone::PhoneApprover`]). The route verifies that token against its own
/// per-approval record and refuses anything else, so exemption here is not an open door — see the doc on
/// that route.
fn is_phone_respond_route(path: &str) -> bool {
    let mut segments = path.split('/');
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ),
        (Some(""), Some("v1"), Some("approvals"), Some(id), Some("respond")) if !id.is_empty()
    )
}


/// Routes that are WebSocket upgrades.
///
/// A browser cannot set an `Authorization` header on a WebSocket handshake, so these routes accept
/// `?token=`. All other routes require the header.
pub fn is_websocket_route(path: &str) -> bool {
    let mut segments = path.split('/');
    // Path must start with '/' (first item "") and have exactly 5 segments:
    // ["", "v1", "sessions" | "terminals", <id>, "ws"]
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ),
        (
            Some(""),
            Some("v1"),
            Some("sessions" | "terminals"),
            Some(id),
            Some("ws"),
            None,
        ) if !id.is_empty()
    )
}

/// The middleware. Applied to the whole router, so a request that fails it never reaches a handler.
pub async fn require_bearer(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = state.api_token.as_ref() else {
        // No token configured: legal only because the daemon refused to start on a non-loopback
        // bind without one. The check that makes that true is at startup, not here, which is why
        // this arm can be a pass-through rather than a second refusal.
        return next.run(request).await;
    };

    if is_exempt(request.uri().path()) {
        return next.run(request).await;
    }

    match presented_token(&request) {
        Some(presented) if expected.matches(&presented) => next.run(request).await,
        // A missing token and a wrong one produce byte-identical responses: the body must not be a
        // way to learn whether a guess was close, or whether a token is configured at all.
        _ => unauthorized(),
    }
}

/// The token a request presents, if any.
///
/// The header is checked first and is the only channel for a non-browser client. The query parameter
/// is consulted only for a WebSocket upgrade on a WebSocket route — see the module doc.
fn presented_token(request: &Request) -> Option<String> {
    if let Some(token) = bearer_from_headers(request.headers()) {
        return Some(token.to_string());
    }
    if is_websocket_route(request.uri().path()) && is_websocket_upgrade(request.headers()) {
        return query_param(request.uri().query(), "token");
    }
    None
}

/// `Authorization: Bearer <token>`, and nothing else.
///
/// A bare token with no scheme, a different scheme (`Basic`, `Token`), or an empty value all return
/// `None` and are refused. Being strict here is the difference between "this API takes a bearer
/// token" and "this API takes whatever is in that header", and the second one is how a value meant
/// for another system gets treated as a credential.
fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Is this a WebSocket handshake?
///
/// Both headers are required by RFC 6455 for an upgrade, and checking them is what keeps the query
/// parameter from becoming a general credential channel.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection = headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        });
    upgrade && connection
}

/// The first value of a `key=value` pair in a query string, percent-decoded.
///
/// Hand-rolled, like the base64 helpers in [`crate::routes`], because the workspace keeps its
/// dependency list small on purpose and this is one parameter read on one route shape. The decoding
/// is the whole reason it is not a `split('=')`: a token may contain `%`-escaped characters, and a
/// value that arrived escaped and was compared unescaped would fail to match for a reason nobody
/// could see.
fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    for pair in query?.split('&') {
        let (name, value) = pair.split_once('=')?;
        if name == key {
            return percent_decode(value);
        }
    }
    None
}

/// `%XX` and `+` decoding. Invalid escapes are left as written rather than erroring: the result is
/// then simply a value that will not match, which is a refusal, not a crash.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// The one refusal this module produces.
///
/// Identical for a missing token, a wrong token and a malformed header — that indistinguishability
/// is the property, not an accident of sharing a function.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        // The challenge is what tells a well-behaved client which scheme to use. It carries no
        // `error=` code, because the codes a bearer challenge can carry (`invalid_token`,
        // `invalid_request`) would distinguish the cases the body deliberately does not.
        [(header::WWW_AUTHENTICATE, "Bearer")],
        axum::Json(serde_json::json!({ "error": "authentication required" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn only_the_bearer_scheme_is_accepted() {
        assert_eq!(
            bearer_from_headers(&headers(&[("authorization", "Bearer abc")])),
            Some("abc")
        );
        // Scheme matching is case-insensitive, as HTTP auth schemes are.
        assert_eq!(
            bearer_from_headers(&headers(&[("authorization", "bearer abc")])),
            Some("abc")
        );
        assert_eq!(
            bearer_from_headers(&headers(&[("authorization", "BEARER abc")])),
            Some("abc")
        );
        // A token padded with spaces still reads as the token.
        assert_eq!(
            bearer_from_headers(&headers(&[("authorization", "Bearer  abc ")])),
            Some("abc")
        );
    }

    #[test]
    fn a_bare_token_or_another_scheme_is_refused() {
        // The shape a caller reaches for when it has the value but not the contract.
        for value in ["abc", "Basic abc", "Token abc", "Bearer", "Bearer ", ""] {
            assert_eq!(
                bearer_from_headers(&headers(&[("authorization", value)])),
                None,
                "{value:?} must not be read as a bearer token"
            );
        }
        assert_eq!(bearer_from_headers(&HeaderMap::new()), None);
    }

    #[test]
    fn the_query_parameter_is_read_only_for_a_websocket_upgrade() {
        // The narrow exception, and the control: the same query string on an ordinary request is
        // not a credential channel. This is the assertion that keeps the exception narrow.
        let ws = headers(&[("upgrade", "websocket"), ("connection", "Upgrade")]);
        assert!(is_websocket_upgrade(&ws));
        assert!(is_websocket_upgrade(&headers(&[
            ("upgrade", "WebSocket"),
            ("connection", "keep-alive, Upgrade")
        ])));
        assert!(!is_websocket_upgrade(&headers(&[("upgrade", "websocket")])));
        assert!(!is_websocket_upgrade(&headers(&[(
            "connection",
            "Upgrade"
        )])));
        assert!(!is_websocket_upgrade(&HeaderMap::new()));
    }

    #[test]
    fn a_query_parameter_is_percent_decoded_so_an_escaped_token_still_matches() {
        assert_eq!(
            query_param(Some("token=abc%2Fdef"), "token").as_deref(),
            Some("abc/def")
        );
        assert_eq!(
            query_param(Some("a=1&token=xyz&b=2"), "token").as_deref(),
            Some("xyz")
        );
        // `+` is a space in a query string, which is what a form-encoded value means.
        assert_eq!(
            query_param(Some("token=a+b"), "token").as_deref(),
            Some("a b")
        );
        assert_eq!(query_param(Some("other=1"), "token"), None);
        assert_eq!(query_param(None, "token"), None);
        // A malformed escape is left as written rather than panicking: it will not match, which is
        // a refusal and not a crash.
        assert_eq!(
            query_param(Some("token=%zz"), "token").as_deref(),
            Some("%zz")
        );
    }

    #[test]
    fn health_and_the_web_page_are_the_only_exempt_paths() {
        assert!(is_exempt("/healthz"));
        assert!(is_exempt("/"));
        for path in [
            "/v1/status",
            "/v1/chat",
            "/v1/sessions/ses_1/ws",
            "/v1/terminals/t/ws",
            // Not a prefix match: a path that merely starts with an exempt one is not exempt.
            "/healthz/../v1/status",
            "/index.html",
        ] {
            assert!(!is_exempt(path), "{path:?} must require a token");
        }
    }

    #[test]
    fn only_websocket_routes_accept_query_credentials() {
        assert!(is_websocket_route("/v1/sessions/ses_1/ws"));
        assert!(is_websocket_route("/v1/terminals/term_1/ws"));
        for path in [
            "/v1/status",
            "/v1/chat",
            "/v1/sessions",
            "/v1/sessions/ses_1",
            "/v1/sessions//ws",
            "/v1/terminals",
            "/v1/terminals/term_1",
            "/v1/terminals/term_1/ws/more",
            "/v2/sessions/ses_1/ws",
            "/healthz",
            "/",
        ] {
            assert!(
                !is_websocket_route(path),
                "{path:?} is not a WebSocket upgrade route"
            );
        }
    }

    #[test]
    fn the_refusal_is_a_401_with_a_bearer_challenge() {
        let response = unauthorized();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );
    }
}
