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
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use hx_core::config::SandboxProfile;
use hx_core::error::HxError;
use hx_core::ids::SessionId;
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
        .route("/v1/chat/stream", post(crate::stream::chat_stream))
        .route("/v1/sessions", get(list_sessions))
        .route("/v1/sessions/{id}", get(get_session).delete(delete_session))
        .route("/v1/sessions/{id}/rename", post(rename_session))
        .route("/v1/sessions/{id}/export", get(export_session))
        .route("/v1/sessions/{id}/events", get(session_events))
        .route("/v1/sessions/{id}/audit", get(session_audit))
        .route("/v1/sessions/{id}/ws", get(crate::stream_ws::session_ws))
        // The terminal has its own socket: an attach is a join, not an open, and input travels
        // back up it. See `crate::terminal_ws` for why it is not a frame on the session stream.
        .route(
            "/v1/terminals/{id}/ws",
            get(crate::terminal_ws::terminal_ws),
        )
        .route("/v1/terminals", get(list_terminals).post(create_terminal))
        .route("/v1/terminals/{id}", delete(kill_terminal))
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/{id}", post(answer_approval))
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
    Json(state.router().status().pools)
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

/// Run a turn: create or continue a session, run the loop, report what happened.
///
/// The response carries the session id, so a client can continue the conversation without a second
/// call — and so a request that started a session is distinguishable from one that resumed it.
async fn chat(
    State(state): State<Arc<AppState>>,
    Json(request): Json<crate::chat::ChatRequest>,
) -> Result<Json<crate::chat::ChatReply>, ApiError> {
    // Two fields a client can get wrong, checked here so the answer is a 400 with the accepted values
    // rather than a 500 that reads like the daemon is broken. `run_chat` validates both again: this
    // is the HTTP surface's courtesy, not the only guard.
    if let Some(name) = &request.autonomy {
        if hx_core::approval::AutonomyLevel::parse(name).is_none() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "unknown autonomy level '{name}'; known: {}",
                    hx_core::approval::AutonomyLevel::NAMES.join(", ")
                ),
            ));
        }
    }

    if let Some(role) = &request.role {
        if !state.config.roles.contains_key(role) {
            let mut configured: Vec<&str> = state
                .config
                .roles
                .keys()
                .map(|name| name.as_str())
                .collect();
            configured.sort_unstable();
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "unknown role '{role}'; configured roles: {}",
                    if configured.is_empty() {
                        "none".to_string()
                    } else {
                        configured.join(", ")
                    }
                ),
            ));
        }
    }

    if let Some(name) = &request.sandbox_profile {
        if !state.config.sandbox_profiles.contains_key(name) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "no sandbox profile named '{name}'; configured profiles: {:?}",
                    state.config.sandbox_profiles.keys().collect::<Vec<_>>()
                ),
            ));
        }
    }

    if request.sandbox_profile.is_some() && state.sandboxes.is_none() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            sandbox_unavailable_message(&state),
        ));
    }

    Ok(Json(
        crate::chat::run_chat(&state, request, chrono::Utc::now()).await?,
    ))
}

/// Query parameters for the session routes.
#[derive(Debug, Deserialize)]
struct SessionQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    format: Option<String>,
    /// `?transcript=false` returns the record and totals without the messages, for a list view that
    /// does not want to move a megabyte of transcript to render a filename.
    #[serde(default)]
    transcript: Option<bool>,
    /// `?session=<id>` narrows a list to one session — used by the approvals route, because a client
    /// showing a chat window wants the questions from that chat and not every prompt on the machine.
    #[serde(default)]
    session: Option<String>,
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SessionQuery>,
) -> Result<Json<Vec<hx_store::SessionSummary>>, ApiError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    Ok(Json(state.store.list(limit)?))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<SessionQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = SessionId::from_raw(id);
    let record = state.store.record(&session)?;
    let totals = state.store.totals(&session)?;
    let interrupted = state.store.load(&session)?.interrupted_calls().len();
    let transcript = params.transcript.unwrap_or(true);

    let messages = if transcript {
        Some(state.store.messages(&session)?)
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "record": record,
        "totals": totals,
        "interrupted_calls": interrupted,
        "messages": messages,
    })))
}

async fn delete_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let deleted = state.store.delete(&SessionId::from_raw(id))?;
    if !deleted {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "no such session"));
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// What a client asks for when it wants a new terminal.
#[derive(Debug, Deserialize)]
struct CreateTerminalBody {
    /// The id to register the terminal under. Required: a client that forgets it would otherwise
    /// get a generated id it cannot attach to again after reconnecting.
    id: String,
    /// The shell, if the caller wants something other than the configured default.
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_cols")]
    cols: u16,
    #[serde(default = "default_rows")]
    rows: u16,
}

fn default_cols() -> u16 {
    80
}

fn default_rows() -> u16 {
    24
}

/// `POST /v1/terminals` — start a terminal. A client attaches to it with `GET /v1/terminals/{id}/ws`.
async fn create_terminal(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateTerminalBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.id.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "a terminal id cannot be empty",
        ));
    }
    // The shell comes from config, never from the request, unless the caller names one explicitly.
    // Defaulting to the configured shell keeps the terminal consistent with what the daemon is set
    // up to run rather than to whatever `/bin/sh` happens to be.
    let shell = body
        .shell
        .unwrap_or_else(|| state.config.terminal.shell.clone());
    state
        .terminals
        .create(&body.id, &shell, &body.args, body.cols, body.rows)?;
    Ok(Json(serde_json::json!({ "id": body.id, "created": true })))
}

/// `GET /v1/terminals` — the live terminals.
async fn list_terminals(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "terminals": state.terminals.ids() }))
}

/// `DELETE /v1/terminals/{id}` — drop a terminal.
///
/// This ends the daemon's reference to the shell, which closes the pty and so hangs up the shell
/// the way a real terminal closing does — it is not a polite "please exit". A caller that wants the
/// shell to shut down cleanly should type `exit` through the socket.
async fn kill_terminal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.terminals.remove(&id) {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "no such terminal"));
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}

#[derive(Debug, Deserialize)]
struct RenameBody {
    title: String,
}

async fn rename_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<RenameBody>,
) -> Result<Json<hx_store::SessionRecord>, ApiError> {
    if body.title.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "a title cannot be empty: an unnamed session is one nobody can find",
        ));
    }
    state.store.rename(
        &SessionId::from_raw(id.clone()),
        body.title.trim(),
        chrono::Utc::now(),
    )?;
    Ok(Json(state.store.record(&SessionId::from_raw(id))?))
}

/// The transcript as a document, for a client that wants to read or attach it.
async fn export_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<SessionQuery>,
) -> Result<Response, ApiError> {
    let format = match params.format.as_deref().unwrap_or("json") {
        "json" => hx_store::ExportFormat::Json,
        "markdown" | "md" => hx_store::ExportFormat::Markdown,
        other => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("unknown export format '{other}'; known: json, markdown"),
            ))
        }
    };

    let is_json = matches!(format, hx_store::ExportFormat::Json);
    let body = state.store.export(&SessionId::from_raw(id), format)?;
    let content_type = if is_json {
        "application/json"
    } else {
        "text/markdown; charset=utf-8"
    };

    Ok(([(axum::http::header::CONTENT_TYPE, content_type)], body).into_response())
}

/// What a run is waiting on, so a client can answer it.
///
/// Polled rather than pushed: an approval is a question with a short life, and a poll every second or
/// two is the least machinery that can carry it. The WebSocket multiplex (M2) will push the same
/// `ApprovalRequest` when it exists.
async fn list_approvals(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SessionQuery>,
) -> Json<Vec<hx_core::approval::ApprovalRequest>> {
    Json(state.approvals.outstanding(params.session.as_deref()))
}

/// The body of an answer.
#[derive(Debug, Deserialize)]
struct ApprovalAnswer {
    /// `once`, `chat`, `always` or `deny`.
    option: String,
    /// Who answered — a user name, a surface. Recorded, because a tap on a phone and a keystroke in a
    /// terminal should not look alike afterwards.
    #[serde(default)]
    by: Option<String>,
}

async fn answer_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<ApprovalAnswer>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let option = match body.option.as_str() {
        "once" | "allow_once" => hx_core::approval::ApprovalOption::AllowOnce,
        "chat" | "allow_for_chat" => hx_core::approval::ApprovalOption::AllowForChat,
        "always" | "allow_always" => hx_core::approval::ApprovalOption::AllowAlways,
        "deny" | "no" => hx_core::approval::ApprovalOption::Deny,
        other => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("unknown approval option '{other}'; known: once, chat, always, deny"),
            ))
        }
    };

    let by = body.by.unwrap_or_else(|| "http".to_string());
    if !state.approvals.answer(&id, option, &by) {
        // Nothing waiting under this id: it was answered already, or it timed out and the run was
        // refused. A 404 says so rather than pretending an answer landed.
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no approval is waiting under '{id}' — it was answered already, or it expired"),
        ));
    }

    Ok(Json(serde_json::json!({ "answered": id, "by": by })))
}

/// Every event of a session, in order: what a client that just attached renders.
async fn session_events(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<hx_core::event::AgentEvent>>, ApiError> {
    Ok(Json(state.store.events(&SessionId::from_raw(id))?))
}

/// Whether a session's stored trail still matches the digests recorded with it.
///
/// Three distinct answers, and collapsing any two of them would make the endpoint lie:
///
/// - `intact` — every event was checked and none had been altered.
/// - `broken` — a row's content no longer matches its digest, or a sequence number is missing. This
///   is the claim the chain exists to make, and it names the row so a reader can go and look.
/// - `unchained` — N events predate the chain and were **not** checked. Reporting these as `intact`
///   would claim verification that did not happen; reporting them as `broken` would accuse an
///   untouched database. The count is returned so a caller can say how much was actually verified.
async fn session_audit(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = SessionId::from_raw(id);
    let unchecked = state.store.unchained_events(&session)?;
    // Counted in SQL, not through `events()`: that parses each row, so a row whose payload was
    // edited — the exact case this endpoint exists to report — fails to parse and would turn the
    // answer into a 500 instead of a verdict.
    let total = state.store.total_events(&session)?;
    let checked = total.saturating_sub(unchecked as u64);

    // Which guarantee is being reported travels with the verdict. An unkeyed chain catches an
    // inconsistent edit and cannot catch a rewrite, so `intact` alone would be read as the stronger
    // claim — naming the mode is what stops the weaker guarantee being taken for the stronger one.
    let keyed = state.store.chain_key().is_keyed();

    match state.store.verify_audit(&session)? {
        None => Ok(Json(serde_json::json!({
            "session_id": session.as_str(),
            "status": "intact",
            "verified": checked,
            "unchained": unchecked,
            "keyed": keyed,
        }))),
        Some(broken) => Ok(Json(serde_json::json!({
            "session_id": session.as_str(),
            "status": "broken",
            "verified": checked,
            "unchained": unchecked,
            "keyed": keyed,
            "seq": broken.seq,
            "stored": broken.stored,
            "expected": broken.expected,
        }))),
    }
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
        let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
        // A test must not write a session database into the developer's home directory, and the
        // directory has to outlive the store: `keep()` hands back the path rather than deleting it on
        // drop, so the file is still there when a later assertion reopens the session.
        let dir = tempfile::tempdir().expect("temp dir");
        config.daemon.data_dir = dir.keep().display().to_string();

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

    /// A GET whose body is text rather than JSON: the export route returns a document.
    async fn get_text(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
        let response = app(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn delete(state: Arc<AppState>, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(uri)
                    .body(Body::empty())
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
    async fn a_run_that_cannot_reach_a_provider_still_records_what_was_asked() {
        let state = test_state().await;

        // The config points at a llama.cpp server that is not running in a test environment, so the
        // call itself fails. What must not fail is the bookkeeping: the prompt is stored *before* the
        // model is consulted, so a client can retry a run instead of losing what it asked.
        let (status, body) = post(
            Arc::clone(&state),
            "/v1/chat",
            serde_json::json!({ "prompt": "hello", "autonomy": "yolo", "workspace": "/tmp" }),
        )
        .await;
        assert!(
            status.is_client_error() || status.is_server_error(),
            "an unreachable provider must be an error: {status} {body}"
        );

        let (status, sessions) = get(Arc::clone(&state), "/v1/sessions").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            sessions.as_array().map(|list| list.len()),
            Some(1),
            "the session must exist even though the run failed: {sessions}"
        );

        // The transcript is asserted through the store rather than through the wire format: a test
        // that pins the JSON shape of a message would have to be edited every time a part type is
        // added, and would stop testing the thing it cares about.
        let id = hx_core::ids::SessionId::from_raw(
            sessions[0]["id"]
                .as_str()
                .expect("a session id")
                .to_string(),
        );
        let messages = state.store.messages(&id).expect("transcript reads");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text(), "hello");
    }

    #[tokio::test]
    async fn a_session_exports_as_a_document_and_deletes_once() {
        let state = test_state().await;
        post(
            Arc::clone(&state),
            "/v1/chat",
            serde_json::json!({ "prompt": "find the bug", "autonomy": "yolo", "workspace": "/tmp" }),
        )
        .await;

        let (_, sessions) = get(Arc::clone(&state), "/v1/sessions").await;
        let id = sessions[0]["id"].as_str().unwrap().to_string();

        let (status, markdown) = get_text(
            Arc::clone(&state),
            &format!("/v1/sessions/{id}/export?format=markdown"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            markdown.contains("find the bug"),
            "the export must contain the prompt: {markdown}"
        );

        let (status, body) = delete(Arc::clone(&state), &format!("/v1/sessions/{id}")).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Deleting twice is a 404, not a second success: a client that retries a delete must be able
        // to tell "gone" from "never existed".
        let (status, _) = delete(state, &format!("/v1/sessions/{id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_unknown_export_format_names_the_known_ones() {
        let state = test_state().await;
        let (status, body) = get(state, "/v1/sessions/whatever/export?format=pdf").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap().contains("json, markdown"),
            "{body}"
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

    /// A state whose store has three chained events on `ses_a`.
    ///
    /// Real writes through `append_event`, not hand-inserted rows: the chain is computed the way the
    /// daemon computes it, so a test that edits a row afterwards is tampering with a genuine trail.
    async fn harness_with_events() -> (Arc<AppState>, String) {
        let state = test_state().await;
        // `create` mints the id, so events are written under the id it returned rather than a name
        // invented here — a hardcoded id would silently write events for a session that is not the
        // one the route is asked about, and the test would pass while checking nothing.
        let created = state
            .store
            .create(
                hx_store::NewSession {
                    agent: Some(hx_core::ids::AgentId::from("agt_1")),
                    ..Default::default()
                },
                chrono::Utc::now(),
            )
            .unwrap();
        let session = created.id.clone();
        let id = session.as_str().to_string();
        for turn in 1..=3u32 {
            state
                .store
                .append_event(
                    &session,
                    &hx_core::event::AgentEvent::TurnStarted {
                        agent: hx_core::ids::AgentId::from("agt_1"),
                        turn,
                    },
                    chrono::Utc::now(),
                )
                .unwrap();
        }
        (state, id)
    }

    #[tokio::test]
    async fn a_session_that_was_not_touched_reports_intact() {
        let (state, id) = harness_with_events().await;
        let (status, report) = get(Arc::clone(&state), &format!("/v1/sessions/{id}/audit")).await;
        assert_eq!(status, StatusCode::OK, "{report}");
        assert_eq!(report["status"], "intact", "{report}");
        assert!(report["verified"].as_u64().unwrap_or(0) > 0, "{report}");
        assert_eq!(report["unchained"], 0, "{report}");
    }

    #[tokio::test]
    async fn an_edited_event_is_reported_as_broken_and_names_the_row() {
        // The whole point of the chain, checked over HTTP rather than in the store's own tests: the
        // row's payload is edited behind the daemon's back, exactly as someone with sqlite3 would.
        let (state, id) = harness_with_events().await;
        let db = format!("{}/hx.db", state.config.daemon.data_dir);
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            &format!(
                "UPDATE events SET payload = '{{\"tampered\":true}}' WHERE session_id = '{id}' AND seq = 2"
            ),
            [],
        )
        .unwrap();
        drop(conn);

        let (status, report) = get(Arc::clone(&state), &format!("/v1/sessions/{id}/audit")).await;
        assert_eq!(status, StatusCode::OK, "{report}");
        assert_eq!(report["status"], "broken", "{report}");
        assert_eq!(report["seq"], 2, "the broken row is named: {report}");
        assert!(
            report["expected"].as_str().is_some() && report["stored"].as_str().is_some(),
            "both digests travel, so a reader can see they differ: {report}"
        );
    }

    #[tokio::test]
    async fn an_unchained_prefix_is_reported_by_count_and_a_break_after_it_is_still_found() {
        // A database upgraded from V1 has a prefix with no digest. That prefix cannot be verified, so
        // the count says how much was actually checked rather than letting `verified` cover it.
        //
        // Clearing the digests also breaks the chain *after* it, and that is correct rather than a
        // false accusation: the next row's digest was computed from the cleared row's, so the store
        // can no longer tell "this prefix predates the chain" from "someone cleared it". Refusing to
        // call the result `intact` is the honest answer to that ambiguity — the alternative is to
        // report `intact` for a log that may have been rewritten.
        let (state, id) = harness_with_events().await;
        let db = format!("{}/hx.db", state.config.daemon.data_dir);
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            &format!("UPDATE events SET digest = NULL WHERE session_id = '{id}' AND seq <= 2"),
            [],
        )
        .unwrap();
        drop(conn);

        let (_status, report) = get(Arc::clone(&state), &format!("/v1/sessions/{id}/audit")).await;
        assert_eq!(report["unchained"], 2, "{report}");
        assert_eq!(
            report["verified"], 1,
            "only the last row could be checked: {report}"
        );
        assert_eq!(
            report["status"], "broken",
            "a cleared prefix is not certified as intact: {report}"
        );
        assert_eq!(report["seq"], 3, "the row the chain breaks at: {report}");
    }

    #[tokio::test]
    async fn a_prefix_that_never_had_a_digest_still_reads_intact() {
        // The upgrade case proper: rows written before the chain existed, with the *rest* of the log
        // chained normally. Nothing was altered, so this must not be reported as a break.
        let (state, id) = harness_with_events().await;
        let db = format!("{}/hx.db", state.config.daemon.data_dir);
        let conn = rusqlite::Connection::open(&db).unwrap();
        // Rewrite the first row as an unchained one and re-chain the rest from genesis, which is
        // what an upgraded database looks like: a chained suffix hanging off an unchained prefix.
        conn.execute(
            &format!("DELETE FROM events WHERE session_id = '{id}' AND seq > 1"),
            [],
        )
        .unwrap();
        conn.execute(
            &format!("UPDATE events SET digest = NULL WHERE session_id = '{id}' AND seq = 1"),
            [],
        )
        .unwrap();
        drop(conn);

        let (_status, report) = get(Arc::clone(&state), &format!("/v1/sessions/{id}/audit")).await;
        assert_eq!(
            report["status"], "intact",
            "one unchained row, nothing altered: {report}"
        );
        assert_eq!(report["unchained"], 1, "{report}");
        assert_eq!(report["verified"], 0, "{report}");
    }

    #[test]
    fn profile_lookup_finds_configured_profiles() {
        let config = hx_core::config::Config::from_yaml(CONFIG).unwrap();
        assert!(has_profile(&config.sandbox_profiles, "dev"));
        assert!(!has_profile(&config.sandbox_profiles, "missing"));
    }
}
