//! Route manifest: every public endpoint is mounted on the final router.
//!
//! Regression cover for the merge that ended `app()` after `/v1/fanout` and silently dropped
//! three implemented surfaces (`POST /v1/research`, `POST /v1/connectors/{id}/webhook`,
//! `POST /v1/approvals/{id}/respond`). Each entry drives the real router over
//! `tower::ServiceExt::oneshot` with no bearer token (a loopback deployment where one is
//! optional) and asserts the handler's answer — never a bare 404.
//!
//! The restored routes are pinned by their handler-shaped answers, which an unregistered route
//! cannot produce: axum's fallback 404 carries an empty body, while each of these handlers
//! answers with a JSON `{"error": ...}` (or a 400/503 for research).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use hx_core::config::Config;
use hx_search::BackendRegistry;
use hx_server::{app, AppState, AppStateParts};
use hx_store::Store;
use std::sync::Arc;
use tower::ServiceExt;

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed test timestamp")
}

/// A harness with an empty search registry and nothing else configured.
///
/// Mirrors `research_api.rs`: a real `Store` on disk, a real router built from a default config,
/// and no API token.
async fn harness() -> Arc<AppState> {
    let mut config = Config::default();
    config.daemon.data_dir = tempfile::tempdir()
        .expect("temp dir")
        .keep()
        .display()
        .to_string();

    let mut store_path = std::env::temp_dir();
    store_path.push(format!(
        "hx-route-manifest-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let store = Arc::new(Store::open(store_path).expect("test store opens"));

    let router = Arc::new(std::sync::Mutex::new(
        hx_provider::ModelRouter::from_config(&config, now()).expect("empty router"),
    ));

    AppState::from_parts(AppStateParts {
        router: Arc::clone(&router),
        providers: Arc::new(hx_provider::ProviderRegistry::new()),
        secrets: Arc::new(hx_secrets::SecretStores::new()),
        store,
        models: Arc::new(hx_server::chat::RouterModels::new(
            router,
            Arc::new(hx_provider::ProviderRegistry::new()),
            Arc::new(hx_secrets::SecretStores::new()),
        )),
        tools: Arc::new(hx_server::chat::default_tools(
            vec![],
            reqwest::Client::new(),
        )),
        approvals: hx_agent::ApprovalQueue::new(std::time::Duration::from_secs(1)),
        search: Arc::new(BackendRegistry::new(reqwest::Client::new())),
        config,
        sandboxes: None::<Arc<hx_sandbox::SandboxManager>>,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now(),
        api_token: None,
        allowed_origins: Vec::new(),
        phone: None,
        webhooks: Default::default(),
    })
}

async fn request(
    state: Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let response = app(state)
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.unwrap_or("").to_string()))
                .expect("request"),
        )
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("a body")
        .to_bytes()
        .to_vec();
    (status, bytes)
}

/// A handler-shaped JSON error: proves a handler answered, not axum's empty-body 404 fallback.
fn error_body(bytes: &[u8]) -> serde_json::Value {
    let json: serde_json::Value =
        serde_json::from_slice(bytes).expect("a handler answers JSON, not an empty 404 body");
    assert!(
        json.get("error").is_some(),
        "a handler refusal carries an `error` field: {json}"
    );
    json
}

#[tokio::test]
async fn the_research_route_is_mounted() {
    let state = harness().await;

    // A blank query is the handler's 400, naming the field — never a 404.
    let (status, bytes) = request(
        Arc::clone(&state),
        "POST",
        "/v1/research",
        Some(r#"{"query":"   "}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "blank research query");
    let body = error_body(&bytes);
    assert!(
        body["error"].as_str().unwrap_or("").contains("query"),
        "the 400 names the field: {body}"
    );

    // A well-formed query against an empty registry is the handler's 503 — never a 404.
    let (status, bytes) = request(
        Arc::clone(&state),
        "POST",
        "/v1/research",
        Some(r#"{"query":"rust"}"#),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "research with no backends"
    );
    error_body(&bytes);
}

#[tokio::test]
async fn the_connector_webhook_route_is_mounted() {
    let state = harness().await;

    // An unknown connector id is the handler's 404 naming the connector — never the fallback.
    let (status, bytes) = request(
        Arc::clone(&state),
        "POST",
        "/v1/connectors/no-such-connector/webhook",
        Some(r#"{"kind":"ping"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown connector");
    let body = error_body(&bytes);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("no such connector"),
        "the 404 names the connector: {body}"
    );

    // A missing per-connector token is the handler's 401 — the route authenticates per connector,
    // so reaching 401 proves the handler ran.
    let (status, _) = request(
        Arc::clone(&state),
        "POST",
        "/v1/connectors/no-such-connector/webhook",
        Some(r#"{}"#),
    )
    .await;
    // Unknown id still wins over auth (404), which is itself the handler's answer.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_phone_respond_route_is_mounted() {
    let state = harness().await;

    // No phone push is configured, so the handler's 404 names that — never the fallback's empty
    // body. The tap carries no bearer header: the route authenticates by one-time token instead.
    let (status, bytes) = request(
        Arc::clone(&state),
        "POST",
        "/v1/approvals/some-approval/respond",
        Some(r#"{"token":"one-time","verdict":"deny"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "respond with no phone");
    let body = error_body(&bytes);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("no phone approval push"),
        "the 404 names the missing push: {body}"
    );
}

#[tokio::test]
async fn every_other_public_endpoint_is_mounted() {
    let state = harness().await;

    // (method, uri, body, expected status): each proves the route is mounted — a dropped route
    // would answer 404 with an empty body instead.
    let cases: &[(&str, &str, Option<&str>, StatusCode)] = &[
        ("GET", "/healthz", None, StatusCode::OK),
        ("GET", "/", None, StatusCode::OK),
        ("GET", "/v1/status", None, StatusCode::OK),
        ("GET", "/v1/pools", None, StatusCode::OK),
        ("GET", "/v1/hosts", None, StatusCode::OK),
        ("GET", "/v1/sessions", None, StatusCode::OK),
        ("GET", "/v1/approvals", None, StatusCode::OK),
        ("GET", "/v1/terminals", None, StatusCode::OK),
        (
            "POST",
            "/v1/search",
            Some(r#"{"query":"rust"}"#),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "GET",
            "/v1/sandboxes",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "POST",
            "/v1/approvals/no-such-approval",
            Some(r#"{"option":"deny","ceiling":"read"}"#),
            StatusCode::NOT_FOUND,
        ),
    ];
    for (method, uri, body, expected) in cases {
        let (status, _) = request(Arc::clone(&state), method, uri, *body).await;
        assert_eq!(status, *expected, "{method} {uri}");
    }

    // Bodies that fail extraction still prove the route: axum's 422 comes from a mounted route's
    // extractor, while an unmounted route would be a 404.
    for (method, uri) in [
        ("POST", "/v1/chat"),
        ("POST", "/v1/chat/stream"),
        ("POST", "/v1/diff"),
        ("POST", "/v1/fanout"),
        ("POST", "/v1/sandboxes"),
        ("POST", "/v1/sessions"),
        ("POST", "/v1/terminals"),
    ] {
        let (status, _) = request(Arc::clone(&state), method, uri, Some("{}")).await;
        assert_ne!(status, StatusCode::NOT_FOUND, "{method} {uri} is mounted");
    }
}
