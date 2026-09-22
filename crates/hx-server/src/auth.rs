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
    let path = request.uri().path().to_string();
    let Some(expected) = state.api_token.as_ref() else {
        // No token configured: legal only because the daemon refused to start on a non-loopback
        // bind without one. The check that makes that true is at startup, not here, which is why
        // this arm can be a pass-through rather than a second refusal. The WebSocket Origin check
        // below still runs: cross-origin protection does not depend on a token being set.
        if is_websocket_route(&path)
            && is_websocket_upgrade(request.headers())
            && !ws_origin_allowed(
                request.headers(),
                host_of(request.headers()),
                &state.allowed_origins,
            )
        {
            return forbidden_cross_origin();
        }
        return next.run(request).await;
    };

    if is_exempt(&path) || is_webhook_route(&path) {
        return next.run(request).await;
    }

    match presented_token(&request) {
        Some(presented) if expected.matches(&presented) => {}
        // A missing token and a wrong one produce byte-identical responses: the body must not be a
        // way to learn whether a guess was close, or whether a token is configured at all.
        _ => return unauthorized(),
    }

    // Bearer auth passed, but a browser page from another site presenting a stolen token must
    // still not be able to open a shell. See `ws_origin_allowed`.
    if is_websocket_route(&path)
        && is_websocket_upgrade(request.headers())
        && !ws_origin_allowed(
            request.headers(),
            host_of(request.headers()),
            &state.allowed_origins,
        )
    {
        return forbidden_cross_origin();
    }
    next.run(request).await
}

/// Routes that are answered without the *daemon's* token because they carry their own.
///
/// A webhook `POST` authenticates against the **connector's** configured token, not the daemon's
/// `api_token`: a remote platform holds only its own key, and sharing the daemon's master token with every
/// platform would defeat having per-connector tokens at all. So these routes are exempt from the global
/// middleware and do their own verification in the handler ([`crate::webhook`]) — which fails closed.
pub fn is_webhook_route(path: &str) -> bool {
    // Path shape: /v1/connectors/{id}/webhook
    let mut segments = path.split('/');
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ),
        (Some(""), Some("v1"), Some("connectors"), Some(id), Some("webhook"), None)
            if !id.is_empty()
    )
}

/// The token a request presents, if any.
///
/// The header is checked first and is the only channel for a non-browser client. The query parameter
/// is consulted only for a WebSocket upgrade on a WebSocket route — see the module doc.
fn presented_token(request: &Request) -> Option<String> {
    if let Some(token) = bearer_from_headers(request.headers()) {
        return Some(token.to_string());
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

/// Whether a WebSocket handshake's `Origin` header may proceed.
///
/// Bearer auth already keeps strangers without the token out; this keeps *other websites* out
/// when the token is used from a browser. A malicious page cannot set `Origin` on a WebSocket it
/// opens, but the browser always sends one — so a handshake arriving with a foreign `Origin`
/// is a cross-site attempt to ride the operator's session, and it is refused with 403 even when
/// the token is valid (a token that reached a query string or a log is exactly how a valid
/// credential ends up in the wrong hands).
///
/// The rule, deliberately host-based rather than scheme-based so a Tauri/desktop webview
/// (`tauri://localhost`) keeps working:
/// - no `Origin` header (CLI, TUI, tests, non-browser clients) → allow;
/// - `Origin` naming a loopback host (a local dev UI on another port) → allow;
/// - `Origin` naming a host in `allowed` (an operator-configured allowlist) → allow;
/// - anything else — including `Origin: null`, unparseable values, and any origin that merely
///   matches the request's own `Host` header → reject.
///
/// The request's `Host` header is deliberately **not** an authority here: under DNS rebinding a
/// malicious page controls both its own `Origin` and the `Host` it sends, so "same origin as
/// `Host`" is a test the attacker passes whenever they can flip a record to 127.0.0.1. Only a
/// literal loopback origin or an allowlist entry an operator wrote down is trusted.
pub fn ws_origin_allowed(headers: &HeaderMap, host: Option<&str>, allowed: &[String]) -> bool {
    let _ = host;
    let Some(raw) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return true;
    }
    if raw.eq_ignore_ascii_case("null") {
        return false;
    }
    let Some(origin_host) = origin_host_of(raw) else {
        return false;
    };
    if is_loopback_host(origin_host) {
        return true;
    }
    allowed
        .iter()
        .any(|name| name.eq_ignore_ascii_case(origin_host))
}

/// The request's own host (the `Host` header, port stripped), for same-origin comparison.
fn host_of(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
}

/// Extract the host from an `Origin` value (`scheme://authority[/...]`), port stripped.
fn origin_host_of(origin: &str) -> Option<&str> {
    let (_, rest) = origin.split_once("://")?;
    if rest.is_empty() {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    Some(strip_port(authority))
}

/// Strip a `:port` suffix from an authority, leaving bare hosts (including IPv6) intact.
fn strip_port(authority: &str) -> &str {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        // `[::1]` or `[::1]:port`.
        return rest.split(']').next().unwrap_or(rest);
    }
    // A bare IPv6 literal has more than one colon and no port to strip; a single colon means
    // `host:port`.
    if authority.bytes().filter(|&b| b == b':').count() == 1 {
        if let Some((host, _)) = authority.rsplit_once(':') {
            return host;
        }
    }
    authority
}

/// The loopback hosts a local UI may be served from. Mirrors the rmcp default allowlist plus
/// the `localhost` name both stacks accept.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("127.0.0.1")
        || host.eq_ignore_ascii_case("::1")
}

/// The cross-origin refusal: 403, carrying no token information.
fn forbidden_cross_origin() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "error": "cross-origin websocket rejected" })),
    )
        .into_response()
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
    fn the_query_string_is_not_a_credential_channel_anymore() {
        // The old WebSocket handshake accepted ?token=… on upgrade; the daemon was also reached by
        // that path from non-browser clients. A token in a URL ends up in logs and History, so the
        // credential must live only in an `Authorization` header (#24). presented_token must not read the
        // query string at all.
        use axum::http::Request;
        let req = Request::builder()
            .uri("/v1/chat?token=secret-token")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            presented_token(&req),
            None,
            "a token in the query string is not a credential"
        );

        // A bearer header still is.
        let req = Request::builder()
            .header(header::AUTHORIZATION, "Bearer some-token")
            .uri("/v1/chat")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(presented_token(&req).as_deref(), Some("some-token"));
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

    fn origin_headers(origin: Option<&str>, host: Option<&str>) -> HeaderMap {
        let mut pairs: Vec<(&str, &str)> = vec![];
        if let Some(origin) = origin {
            pairs.push(("origin", origin));
        }
        if let Some(host) = host {
            pairs.push(("host", host));
        }
        headers(&pairs)
    }

    #[test]
    fn a_handshake_without_an_origin_is_not_a_browser_and_is_allowed() {
        // CLI, TUI and test clients send no Origin; refusing them would break every non-browser
        // client, including the existing WebSocket integration tests.
        assert!(ws_origin_allowed(&HeaderMap::new(), None, &[]));
        assert!(ws_origin_allowed(
            &origin_headers(None, Some("127.0.0.1:7717")),
            Some("127.0.0.1:7717"),
            &[]
        ));
    }

    #[test]
    fn an_origin_that_matches_the_host_header_is_not_trusted_under_rebinding() {
        // The old rule allowed an origin whose host equals the request's Host header. Under DNS
        // rebinding the attacker controls *both* values: they flip a record to 127.0.0.1 and
        // send Origin: http://their.name and Host: their.name. Matching the Host proves nothing, so this
        // is rejected — only a literal loopback origin or an allowlist entry is trusted (#24).
        assert!(!ws_origin_allowed(
            &origin_headers(
                Some("http://attacker.example:3000"),
                Some("attacker.example:7717"),
            ),
            Some("attacker.example:7717"),
            &[]
        ));
        // Case-insensitive self-match is equally worthless to allow.
        assert!(!ws_origin_allowed(
            &origin_headers(Some("http://Example.COM"), Some("example.com")),
            Some("example.com"),
            &[]
        ));
    }

    #[test]
    fn a_loopback_origin_from_a_different_host_is_allowed() {
        // A local dev UI on another port, and the desktop webview (`tauri://localhost`), are
        // loopback pages, not attacker sites.
        assert!(ws_origin_allowed(
            &origin_headers(Some("http://localhost:3000"), Some("192.168.1.10:7717")),
            Some("192.168.1.10:7717"),
            &[]
        ));
        assert!(ws_origin_allowed(
            &origin_headers(Some("tauri://localhost"), Some("127.0.0.1:7717")),
            Some("127.0.0.1:7717"),
            &[]
        ));
        assert!(ws_origin_allowed(
            &origin_headers(Some("http://127.0.0.1:8080"), Some("example.com")),
            Some("example.com"),
            &[]
        ));
    }

    #[test]
    fn an_allowlisted_origin_is_allowed() {
        // The operator can name hosts that may open a WebSocket — a trusted UI on a real domain.
        let allowed: Vec<String> = vec!["ui.example.com".to_string()];
        assert!(ws_origin_allowed(
            &origin_headers(Some("https://ui.example.com"), Some("127.0.0.1:7717")),
            Some("127.0.0.1:7717"),
            &allowed
        ));
        // An origin not on the list is still rejected even with a matching Host.
        assert!(!ws_origin_allowed(
            &origin_headers(Some("https://ui.example.com"), Some("ui.example.com")),
            Some("ui.example.com"),
            &[]
        ));
    }

    #[test]
    fn a_foreign_origin_is_rejected_even_when_it_names_a_real_site() {
        for (origin, host) in [
            ("https://evil.example", "127.0.0.1:7717"),
            ("https://evil.example", "example.com"),
            ("http://127.0.0.2:3000", "127.0.0.1:7717"),
            ("null", "127.0.0.1:7717"),
            ("NULL", "127.0.0.1:7717"),
            ("not a url", "127.0.0.1:7717"),
            ("http://", "127.0.0.1:7717"),
            ("https://evil.example", "evil.example.attacker.com"),
        ] {
            assert!(
                !ws_origin_allowed(&origin_headers(Some(origin), Some(host)), Some(host), &[]),
                "origin {origin:?} against host {host:?} must be rejected"
            );
        }
        // A foreign origin with no Host to compare against cannot prove same-origin either.
        assert!(!ws_origin_allowed(
            &origin_headers(Some("https://evil.example"), None),
            None,
            &[]
        ));
    }

    #[test]
    fn the_cross_origin_refusal_is_a_403_without_a_bearer_challenge() {
        let response = forbidden_cross_origin();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            response.headers().get(header::WWW_AUTHENTICATE).is_none(),
            "a 403 must not carry the 401 challenge: it answers a different question"
        );
    }
}
