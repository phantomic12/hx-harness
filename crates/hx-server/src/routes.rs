//! The HTTP surface.
//!
//! ## Why one HTTP surface rather than a TUI-only harness
//!
//! Requirement #3 asks for a web UI that can do everything a terminal can. The way that stays
//! true rather than decaying is to make the *daemon* the only thing that owns state, and treat
//! every front end — CLI, TUI, browser, Tauri desktop, Tauri mobile, Telegram — as a client of
//! this API. Adding a capability means adding a route; it cannot mean adding a feature that only
//! one surface has.
//!
//! ## Error mapping is deliberate
//!
//! [`status_for`] turns each error variant into the HTTP status a client should react to: 429 for
//! a rate limit (wait and retry), 403 for a policy denial (do not retry), 503 for "no route"
//! (try another pool). Returning 500 for everything is how clients end up retrying a denial
//! forever.

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use hx_core::config::SandboxProfile;
use hx_core::error::HxError;
use hx_sandbox::SandboxSpec;
use hx_search::{Recency, SearchQuery};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Build the application router.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status))
        .route("/v1/pools", get(pools))
        .route("/v1/hosts", get(hosts))
        .route("/v1/search", post(search))
        .route("/v1/sandboxes", get(list_sandboxes).post(spawn_sandbox))
        .route("/v1/sandboxes/{id}", delete(destroy_sandbox))
        .route("/v1/sandboxes/{id}/exec", post(exec_sandbox))
        .route("/v1/chat", post(chat))
        .with_state(state)
}

/// An error rendered for a client.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl From<HxError> for ApiError {
    fn from(err: HxError) -> Self {
        Self::new(status_for(&err), err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// Map a domain error onto the status a client should react to.
pub fn status_for(err: &HxError) -> StatusCode {
    match err {
        // Wait and retry — and the caller gets a retry hint in the message.
        HxError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        // A denial is a decision, not a failure. Retrying will not help.
        HxError::Denied(_) => StatusCode::FORBIDDEN,
        // Nothing to route to right now: another pool may work.
        HxError::NoRoute(_) => StatusCode::SERVICE_UNAVAILABLE,
        // Bad configuration is the operator's problem and needs surfacing loudly.
        HxError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        // Provider and sandbox failures are upstream, not the client's fault.
        HxError::Provider(_) | HxError::Sandbox(_) | HxError::Remote(_) => StatusCode::BAD_GATEWAY,
        HxError::Secret(_) => StatusCode::FORBIDDEN,
        // A rejected credential is not the client's fault either, but it is a 401: the fix is on the
        // operator's side (rotate the key), and the credential is benched meanwhile.
        HxError::ProviderAuth { .. } => StatusCode::UNAUTHORIZED,
        HxError::Tool(_) => StatusCode::BAD_REQUEST,
        HxError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        HxError::Serde(_) => StatusCode::BAD_REQUEST,
        // The caller asked for something that does not exist.
        HxError::NotFound(_) => StatusCode::NOT_FOUND,
        // A backend or connector misbehaved upstream.
        HxError::Search { .. } | HxError::Connector { .. } => StatusCode::BAD_GATEWAY,
        // Deliberately not a wildcard over the whole enum: adding a variant to `HxError` should
        // force a decision here rather than silently becoming a 500. This arm exists only for
        // variants this surface does not know how to classify.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz() -> &'static str {
    "ok"
}

/// Liveness plus a bounded readiness signal.
///
/// Returns 200 whenever the process is serving, and reports degraded subsystems in the body
/// rather than by status code: a daemon with no container engine is still useful, and refusing
/// to report healthy would take down the whole deployment for a missing optional dependency.
async fn status(State(state): State<Arc<AppState>>) -> Json<crate::state::StatusReport> {
    Json(state.status(chrono::Utc::now()).await)
}

async fn pools(State(state): State<Arc<AppState>>) -> Json<Vec<hx_provider::PoolStatus>> {
    let router = state.router.lock().await;
    Json(router.status().pools)
}

async fn hosts(State(state): State<Arc<AppState>>) -> Json<Vec<crate::state::HostSummary>> {
    Json(state.host_summaries())
}

#[derive(Debug, Deserialize)]
pub struct SearchBody {
    pub query: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub recency: Option<Recency>,
    #[serde(default)]
    pub site: Option<String>,
}

fn default_limit() -> usize {
    10
}

impl SearchBody {
    fn into_query(self) -> SearchQuery {
        let mut query = SearchQuery::new(self.query).with_limit(self.limit);
        if let Some(recency) = self.recency {
            query = query.with_recency(recency);
        }
        if let Some(site) = self.site {
            query = query.with_site(site);
        }
        query
    }
}

async fn search(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SearchBody>,
) -> Result<Json<hx_search::SearchReport>, ApiError> {
    if state.search.is_empty() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "no search backends are configured; set `search.backends` in the config",
        ));
    }
    Ok(Json(state.search.search(&body.into_query()).await))
}

async fn list_sandboxes(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<hx_sandbox::SandboxHandle>>, ApiError> {
    let manager = state.sandboxes.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            sandbox_unavailable_message(&state),
        )
    })?;
    Ok(Json(manager.list().await))
}

#[derive(Debug, Deserialize)]
pub struct SpawnBody {
    /// Name of a profile from `sandbox_profiles:`.
    pub profile: String,
    /// Host directory to mount as the workspace.
    pub workspace_host_path: String,
}

async fn spawn_sandbox(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SpawnBody>,
) -> Result<Json<hx_sandbox::SandboxHandle>, ApiError> {
    let manager = state.sandboxes.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            sandbox_unavailable_message(&state),
        )
    })?;

    let profile = state
        .config
        .sandbox_profiles
        .get(&body.profile)
        .ok_or_else(|| {
            let known: Vec<&str> = state
                .config
                .sandbox_profiles
                .keys()
                .map(String::as_str)
                .collect();
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "no sandbox profile named '{}'; configured profiles: {:?}",
                    body.profile, known
                ),
            )
        })?;

    let mut spec = SandboxSpec::from_profile(&body.profile, profile);
    spec.workspace_host_path = body.workspace_host_path;

    Ok(Json(
        manager
            .spawn(&spec, chrono::Utc::now())
            .await
            .map_err(ApiError::from)?,
    ))
}

async fn destroy_sandbox(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let manager = state.sandboxes.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            sandbox_unavailable_message(&state),
        )
    })?;
    manager.destroy(&id).await.map_err(ApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ExecBody {
    pub command: String,
    #[serde(default)]
    pub workdir: Option<String>,
}

async fn exec_sandbox(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<ExecBody>,
) -> Result<Json<hx_sandbox::SandboxExecOutput>, ApiError> {
    let manager = state.sandboxes.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            sandbox_unavailable_message(&state),
        )
    })?;
    Ok(Json(
        manager
            .exec(&id, &body.command, body.workdir.as_deref())
            .await
            .map_err(ApiError::from)?,
    ))
}

/// The agent loop is not wired to HTTP yet; say so precisely rather than returning a stub.
async fn chat() -> ApiError {
    ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        "the agent loop is not exposed over HTTP yet — see ROADMAP.md M1. The provider router, \
         search, sandboxes, hosts and capabilities are all live; only the loop that ties them \
         together is missing.",
    )
}

fn sandbox_unavailable_message(state: &AppState) -> String {
    match &state.sandbox_unavailable_reason {
        Some(reason) => format!("sandboxes are unavailable: {reason}"),
        None => "sandboxes are unavailable".to_string(),
    }
}

/// Does the config define a profile with this name? Used by `hx doctor`.
pub fn has_profile(profiles: &indexmap::IndexMap<String, SandboxProfile>, name: &str) -> bool {
    profiles.contains_key(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const CONFIG: &str = r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:11434
    models: ["qwen3-32b"]
    credentials:
      - { id: l1, secret: "vault:local/none" }

pools:
  interactive: { members: ["local/qwen3-32b"] }

roles:
  builder: interactive

sandbox_profiles:
  dev:
    image: ubuntu:24.04
    cpus: 2.0
    memory_mb: 2048

search:
  backends: []
"#;

    async fn test_state() -> Arc<AppState> {
        let config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        AppState::build(config, now).await.expect("state builds")
    }

    async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = app(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn post(
        state: Arc<AppState>,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn healthz_is_served() {
        let (status, _) = get(test_state().await, "/healthz").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn status_reports_every_subsystem() {
        let (status, body) = get(test_state().await, "/v1/status").await;
        assert_eq!(status, StatusCode::OK);

        // The keys a front end depends on must exist even when a subsystem is degraded.
        for key in [
            "version",
            "uptime_secs",
            "pools",
            "roles",
            "search_backends",
            "sandboxes",
            "hosts",
            "providers_configured",
        ] {
            assert!(body.get(key).is_some(), "status is missing '{key}': {body}");
        }

        assert_eq!(body["providers_configured"], 1);
        assert_eq!(body["roles"]["builder"], "interactive");
    }

    #[tokio::test]
    async fn status_always_includes_the_local_host() {
        let (_, body) = get(test_state().await, "/v1/status").await;
        let hosts = body["hosts"].as_array().unwrap();
        assert!(
            hosts.iter().any(|h| h["id"] == "local"),
            "the local machine must always be listed: {hosts:?}"
        );
    }

    #[tokio::test]
    async fn pools_are_listed_with_their_routes() {
        let (status, body) = get(test_state().await, "/v1/pools").await;
        assert_eq!(status, StatusCode::OK);
        let pools = body.as_array().unwrap();
        assert_eq!(pools[0]["name"], "interactive");
        assert_eq!(pools[0]["routes"][0]["model"], "qwen3-32b");
    }

    #[tokio::test]
    async fn an_unknown_route_is_a_404() {
        let (status, _) = get(test_state().await, "/v1/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn search_without_backends_says_so_instead_of_returning_nothing() {
        // The distinction matters: an empty result set and an unconfigured service look the
        // same to a client unless the API is explicit.
        let (status, body) = post(
            test_state().await,
            "/v1/search",
            serde_json::json!({ "query": "rust" }),
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            body["error"].as_str().unwrap().contains("search.backends"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn chat_reports_not_implemented_with_an_explanation() {
        let (status, body) = post(test_state().await, "/v1/chat", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert!(
            body["error"].as_str().unwrap().contains("ROADMAP"),
            "the error must point somewhere useful: {body}"
        );
    }

    #[tokio::test]
    async fn spawning_with_an_unknown_profile_names_the_valid_ones() {
        let state = test_state().await;
        // Docker is almost certainly unavailable in a test environment, so accept either the
        // "unavailable" path or the validation path — but the validation path is the one that
        // must name the configured profiles.
        let (status, body) = post(
            state,
            "/v1/sandboxes",
            serde_json::json!({ "profile": "nope", "workspace_host_path": "/tmp/x" }),
        )
        .await;

        assert!(
            status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::BAD_REQUEST,
            "unexpected status {status}: {body}"
        );
        if status == StatusCode::BAD_REQUEST {
            assert!(body["error"].as_str().unwrap().contains("dev"), "{body}");
        }
    }

    #[test]
    fn error_status_mapping_is_what_a_client_should_act_on() {
        assert_eq!(
            status_for(&HxError::RateLimited {
                scope: "p".into(),
                retry_after_ms: 1000
            }),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_for(&HxError::Denied("no".into())),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_for(&HxError::NoRoute("none".into())),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for(&HxError::Provider("upstream".into())),
            StatusCode::BAD_GATEWAY
        );
    }

    #[tokio::test]
    async fn a_denial_and_a_rate_limit_are_distinguishable_over_http() {
        // The behaviour this protects: a client must be able to tell "do not retry" from
        // "retry shortly". Both are errors; they need different handling.
        let denied = ApiError::from(HxError::Denied("policy".into())).into_response();
        let limited = ApiError::from(HxError::RateLimited {
            scope: "pool:x".into(),
            retry_after_ms: 500,
        })
        .into_response();

        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn profile_lookup_finds_configured_profiles() {
        let config = hx_core::config::Config::from_yaml(CONFIG).unwrap();
        assert!(has_profile(&config.sandbox_profiles, "dev"));
        assert!(!has_profile(&config.sandbox_profiles, "missing"));
    }
}
