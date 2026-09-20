//! Streamable-HTTP transport for `hx`'s MCP server, behind bearer-token authentication.
//!
//! ## The property this module exists to hold
//!
//! **A listening socket is reachable by strangers.** That is why the stdio transport refused to open
//! one, and why this transport exists only behind an authentication story:
//!
//! - **Fail closed at startup.** [`require_token_for_bind`] refuses to start when bound to a
//!   non-loopback address with no token configured. A server that started anyway with a warning would
//!   be serving an unauthenticated tool-execution endpoint to the network, and a warning is a line
//!   in a log nobody reads. Reusing `require_token_for_bind` from `hx-core` means this server applies
//!   the exact same rule `hxd` already enforces.
//! - **Optional on loopback.** A token is honoured when set on a loopback bind, and not required
//!   when it is not. This keeps local testing and development hermetic without forcing dummy tokens
//!   where the network cannot reach.
//! - **Constant-time comparison.** The bearer token is checked using [`ApiToken::matches`], which
//!   compares byte-by-byte without early return so that a correct prefix costs the same as a wrong
//!   first byte.
//! - **Indistinguishable refusals.** A missing token, a wrong token, an unknown scheme, or a malformed
//!   header all produce byte-identical 401 responses with `WWW-Authenticate: Bearer` and an opaque
//!   JSON error body. The response cannot be used as an oracle to determine whether a token is
//!   configured or whether a guess was close.
//!
//! ## The refusal on `Ask` is unchanged
//!
//! The HTTP transport dispatches through the exact same [`McpServer::call`] gate as the stdio
//! transport: `prepare → capability → risk → approval → run`. When the approval policy answers
//! [`hx_core::approval::Verdict::Ask`], this server **refuses the call immediately** with a reason
//! naming the tool, the risk class, and the operator actions needed to allow it. It raises **no**
//! approval request: there is no approver field, no queue to post to, and `session.outstanding()`
//! remains `None`. A remote client cannot make the server publish a prompt it cannot answer, and
//! cannot make it auto-approve either.
//!
//! ## The honest limit
//!
//! The credential is a **bearer token** with no per-client identity, no expiry, and no rotation.
//! Whoever presents the token is granted access; `by:` in audit records remains a declaration by
//! whoever holds it. Furthermore, the transport is plain HTTP: unless a reverse proxy in front of
//! this server terminates TLS, the token travels in the clear across non-loopback networks. Both
//! limits are stated here rather than implied away, because a security control whose boundaries are
//! unstated gets trusted past them.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hx_core::api_auth::{require_token_for_bind, ApiToken};
use hx_core::error::{HxError, Result};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::server::McpServer;

/// Build the axum router serving MCP over streamable HTTP.
///
/// The MCP protocol is mounted at `/mcp` and as the fallback service for the root path.
/// When a token is configured, the `require_bearer` middleware protects all routes except
/// the liveness probe `/healthz`.
pub fn router(server: Arc<McpServer>, token: Option<ApiToken>) -> axum::Router {
    let mut mcp_config = StreamableHttpServerConfig::default().with_sse_keep_alive(None);
    // When bound to non-loopback or custom authorities, disable allowed hosts check so
    // legitimate callers routed to this server are not rejected by DNS rebinding checks.
    mcp_config = mcp_config.disable_allowed_hosts();

    let service: StreamableHttpService<Arc<McpServer>, LocalSessionManager> =
        StreamableHttpService::new(
            {
                let server = Arc::clone(&server);
                move || Ok(Arc::clone(&server))
            },
            Arc::<LocalSessionManager>::default(),
            mcp_config,
        );

    axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .nest_service("/mcp", service.clone())
        .fallback_service(service)
        .layer(axum::middleware::from_fn_with_state(token, require_bearer))
}

/// Liveness probe: returns `ok` and reveals no server state.
async fn healthz() -> &'static str {
    "ok"
}

/// The bearer authentication middleware.
///
/// Refuses missing or mismatched credentials with an opaque 401 response before
/// the request can reach the MCP handler.
pub async fn require_bearer(
    State(expected): State<Option<ApiToken>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = expected.as_ref() else {
        // No token configured: legal only because startup refused non-loopback binds without one.
        return next.run(request).await;
    };

    if request.uri().path() == "/healthz" {
        return next.run(request).await;
    }

    match presented_bearer(request.headers()) {
        Some(presented) if expected.matches(presented) => next.run(request).await,
        _ => unauthorized(),
    }
}

/// Extract a `Bearer <token>` credential from the `Authorization` header.
fn presented_bearer(headers: &HeaderMap) -> Option<&str> {
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

/// The single refusal response this transport produces.
///
/// Indistinguishable between a missing token, a wrong token, an invalid scheme,
/// and a malformed header.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        axum::Json(serde_json::json!({ "error": "authentication required" })),
    )
        .into_response()
}

/// Bind an HTTP listener and serve the MCP server.
///
/// Fails closed before binding if `bind` is not loopback and no token is configured.
pub async fn bind_and_serve(
    server: Arc<McpServer>,
    bind: &str,
    token: Option<ApiToken>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    require_token_for_bind(bind, token.is_some())?;

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(HxError::Io)?;
    let addr = listener.local_addr().map_err(HxError::Io)?;

    let app = router(server, token);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok((addr, task))
}
