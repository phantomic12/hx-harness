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
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use hx_agent::AnswerResult;
use hx_core::approval::RiskClass;
use hx_core::config::SandboxProfile;
use hx_core::error::HxError;
use hx_core::ids::SessionId;
use hx_sandbox::SandboxSpec;
use hx_search::{
    default_pool_root, select_fetcher, FetchMode, FetchRouteError, Recency, ResearchRequest,
    ResearchTask, SearchQuery,
};
use hx_secrets::Redactor;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The web client: one self-contained page.
///
/// `include_str!` rather than a runtime read, so the binary is the whole daemon and a deployment
/// cannot half-succeed (a working API with a missing UI, or a UI from an older build).
const WEB_CLIENT: &str = include_str!("../static/index.html");

/// Hard cap on a single file served by the host/diff HTTP routes, mirroring the agent
/// `read_file` tool's 512 KiB bound so the HTTP surfaces cannot be used to exhaust the
/// daemon's memory on an oversized or pathological file.
const FILE_READ_CAP: u64 = 512 * 1024;

async fn web_client() -> impl IntoResponse {
    // `text/html` and not `text/plain`, or a browser renders the source. No cache header games: the
    // page is small, and a stale front end against a newer daemon is exactly the mismatch this
    // embedding is meant to make impossible.
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        WEB_CLIENT,
    )
}

/// Build the application router.
///
/// The bearer-token middleware is applied to the whole router, so it runs before routing and before
/// any extractor: a request without a valid token never reaches a handler, and does not get a
/// different answer from an unknown route either. See [`crate::auth`] for what is exempt and why.
pub fn app(state: Arc<AppState>) -> Router {
    let auth = Arc::clone(&state);
    Router::new()
        .route("/healthz", get(healthz))
        // The web client, served at the root. Embedded in the binary rather than read from a path:
        // a daemon that needs a `--static-dir` to be useful is one that is broken by default, and a
        // front end that can drift from the build that serves it is worse.
        .route("/", get(web_client))
        .route("/v1/status", get(status))
        .route("/v1/pools", get(pools))
        .route("/v1/providers", get(list_providers))
        .route("/v1/providers/{name}", put(upsert_provider).delete(remove_provider))
        .route("/v1/login", post(login))
        .route("/v1/hosts", get(hosts))
        // A host is a machine, not just a row: the detail route reports what it is (OS, shell, home,
        // whether it has a PTY), which is what a client needs before it offers to browse or run.
        .route("/v1/hosts/{id}", get(host_detail))
        .route("/v1/hosts/{id}/files", get(host_list_dir))
        .route(
            "/v1/hosts/{id}/file",
            get(host_read_file).put(host_write_file),
        )
        .route("/v1/hosts/{id}/exec", post(host_exec))
        .route("/v1/search", post(search))
        .route("/v1/sandboxes", get(list_sandboxes).post(spawn_sandbox))
        .route("/v1/sandboxes/{id}", delete(destroy_sandbox))
        .route("/v1/sandboxes/{id}/exec", post(exec_sandbox))
        .route("/v1/chat", post(chat))
        .route("/v1/chat/stream", post(crate::stream::chat_stream))
        .route("/v1/sessions", get(list_sessions).post(create_session))
        .route("/v1/sessions/{id}", get(get_session).delete(delete_session))
        .route("/v1/sessions/{id}/rename", post(rename_session))
        .route("/v1/sessions/{id}/export", get(export_session))
        .route("/v1/sessions/{id}/events", get(session_events))
        .route("/v1/sessions/{id}/audit", get(session_audit))
        .route("/v1/sessions/{id}/ws", get(crate::stream_ws::session_ws))
        // The terminal has its own socket: an attach is a join, not an open, and input travels
        // back up it. See `crate::terminal_ws` for why it is not a frame on the session stream.
        //
        // On a host with no PTY the route still exists and answers with a reason. A missing route
        // would read as a client bug, and the honest statement here is that the daemon cannot do
        // this rather than that it does not know the path.
        .route("/v1/terminals/{id}/ws", get(terminal_ws_handler))
        .route("/v1/terminals", get(list_terminals).post(create_terminal))
        .route("/v1/terminals/{id}", delete(kill_terminal))
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/{id}", post(answer_approval))
        // The phone's tap comes back here — see `crate::phone`. Exempt from the bearer token (the
        // route authenticates with the one-time token inside `respond_url`).
        .route("/v1/approvals/{id}/respond", post(respond_approval))
        // The diff/review pane's data source. A diff of file changes is owned by the daemon (it is
        // the only thing that can read the file), so the pane asks for it here rather than inventing it.
        .route("/v1/diff", post(diff_file))
        // The M8 fan-out surface: N child model calls across N distinct pool members, run one at a
        // time, answered per child. This is the first production caller of the spawner that draws from
        // the model pool (see `crate::fanout`). It is gated by the same bearer token as everything
        // else on this router.
        .route("/v1/fanout", post(fanout))
        // The M6 research pipeline's production caller: runs the keyless fan-out, extraction and
        // citation through the fetch selector, behind the same bearer-token gate.
        .route("/v1/research", post(research))
        // M5's webhook half: external platforms `POST` inbound events here, authenticated by their
        // own per-connector bearer token rather than the daemon's (see `crate::auth::is_webhook_route`).
        .merge(crate::webhook::routes())
        .with_state(state)
        // Applied last, so it wraps every route including the WebSocket upgrades. `from_fn_with_state`
        // rather than `from_fn`: the token lives on `AppState`, and reading it from a request
        // extension would be a second place for it to be.
        .layer(axum::middleware::from_fn_with_state(
            auth,
            crate::auth::require_bearer,
        ))
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
        // The caller asked for a bounded input (file read, diff) that is too large to serve in one go.
        HxError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
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

/// List the providers the daemon is running with. Never includes a secret.
async fn list_providers(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<crate::state::ProviderSummary>> {
    Json(state.provider_summaries())
}

/// A login attempt from the web UI: `{ "username": "...", "password": "..." }`.
#[derive(Debug, Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

/// `POST /v1/login` — an account-style login that hands back the API bearer token.
///
/// Exempt from the bearer token in [`crate::auth::is_exempt`] so a fresh browser can reach it.
/// Verifies username + password against `api.admin_username` / `api.admin_password` (constant
/// time), then returns `{ "token": "<the bearer token>" }` on success. A missing or wrong
/// credential, or no configured password, all produce the same 401 so the response leaks nothing.
async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // No daemon bearer token to hand out -> nothing to log in for.
    let Some(api_token) = state.api_token.as_ref() else {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    // No configured password -> refuse every attempt (never compare to a blank).
    let Some(admin_password) = hx_secrets::resolve_admin_password(&state.config, &state.secrets)
        .unwrap_or(None)
    else {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    let username_ok = hx_core::ApiToken::new(state.config.api.admin_username_or_default()).matches(&body.username);
    let password_ok = admin_password.matches(&body.password);
    if !(username_ok && password_ok) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(Json(serde_json::json!({ "token": api_token.expose() })))
}


/// A request to add or edit a provider from the web UI.
#[derive(Debug, Deserialize)]
pub struct ProviderBody {
    pub kind: hx_core::config::ProviderKind,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub routing: hx_core::config::Strategy,
    /// Write-only: when present and non-empty, replaces the provider's key. A stored key is never
    /// echoed back.
    #[serde(default)]
    pub api_key: Option<String>,
}

/// Add or edit a provider, swap the routing surface, and persist. A missing or blank api_key keeps the
/// existing key; a malformed body or unknown kind is a 400.
async fn upsert_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<ProviderBody>,
) -> Result<Json<crate::state::ProviderSummary>, ApiError> {
    state
        .upsert_provider(
            &name,
            body.kind,
            body.base_url,
            body.models,
            body.routing,
            body.api_key,
        )
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;
    let summary = state
        .provider_summaries()
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, format!("no provider '{name}'")))?;
    Ok(Json(summary))
}

/// Remove a provider from the live registry and the config file.
async fn remove_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .remove_provider(&name)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(serde_json::json!({ "removed": name })))
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

/// What a client may ask for when opening a session without running a turn.
#[derive(Debug, Default, Deserialize)]
struct CreateSessionBody {
    /// A title for the session. Absent becomes the store's honest `"untitled"`, the same as a
    /// session a chat run would create.
    #[serde(default)]
    title: Option<String>,
    /// The directory the session will act in. Absent means the daemon's working directory, the
    /// same default a chat run gets.
    #[serde(default)]
    workspace: Option<String>,
}

/// Open a session without running a turn.
///
/// WHY a route for doing nothing: the embedded web client opens a task with `POST /v1/sessions`
/// (`createSession` in `static/index.html`) — on first run, when the store is empty, and whenever
/// the user hits "+ new". A reload resumes the last open task instead (`localStorage` key
/// `hx.session`), so a page load does not mint a session. Sessions were otherwise created only
/// implicitly by `POST /v1/chat`, so on a fresh daemon the create call answered 405, the client
/// fell back to "the most recent session", and an empty store meant "could not open a session"
/// with no way forward. An explicit create is also the honest primitive: a client that wants a
/// titled, empty session to attach a WebSocket to should not have to send a fake first prompt to
/// get one. The body is optional — a bare `POST` opens a session with defaults — and the answer
/// carries the id under both `id` and `session`, the two fields clients read.
async fn create_session(
    State(state): State<Arc<AppState>>,
    body: Option<Json<CreateSessionBody>>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let body = body.map(|Json(inner)| inner).unwrap_or_default();
    // The same identity a chat run would file this session under: a session opened here and a
    // session opened by the first prompt of a run in the same checkout must read as one agent's.
    let workspace = body.workspace.unwrap_or_else(|| state.default_workspace());
    let mut new = hx_store::NewSession::new()
        .in_workspace(&workspace)
        .run_by(crate::chat::agent_id(&workspace));
    new.title = body.title;
    let record = state.store.create(new, chrono::Utc::now())?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": record.id.as_str(),
            "session": record.id.as_str(),
            "created": true,
            "record": record,
        })),
    ))
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
    /// The machine to open the shell on. Absent means the daemon's own host, which is what every
    /// existing caller means and why this defaults rather than being required.
    ///
    /// A host id, never a transport: which of SSH or something else carries it is configuration.
    #[serde(default)]
    host: Option<String>,
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

/// The terminal WebSocket handler: the real one where a PTY exists, an honest refusal where it does
/// not.
///
/// `terminal_ws` operates on a running terminal, and terminals do not exist on a host without a PTY,
/// so that module is Unix-only and this picks the behaviour at compile time. The route exists either
/// way: answering "not on this platform" is clearer to a client than a 404 that reads like a typo.
#[cfg(unix)]
use crate::terminal_ws::terminal_ws as terminal_ws_handler;

#[cfg(not(unix))]
async fn terminal_ws_handler(Path(id): Path<String>) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "terminals need a PTY, which this platform does not have",
            "terminal": id,
        })),
    )
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
    // An interactive shell is the strongest thing this daemon offers a machine: unlike `exec` there
    // is no command line to classify, because the caller types whatever they like afterwards. So a
    // remote shell is gated as an explicit, operator-approved capability rather than being let
    // through by the weaker read check that command execution uses.
    //
    // Gated *before* the connect, so a denied request does not open an SSH connection it will not
    // use — a denial that still dials the machine leaks reachability, which is information an
    // operator denying shell access did not intend to give.
    // `local` is the daemon's own machine and takes the local path below, which is the one that
    // can use the configured shell and args. Anything else is a machine reached through a transport.
    if let Some(host_id) = body.host.as_deref().filter(|h| !crate::hosts::is_local(h)) {
        if let Some(reason) = state.host_denial_for(host_id, hx_core::capability::Action::Execute) {
            return Err(ApiError::new(StatusCode::FORBIDDEN, reason));
        }
        let host = state.resolve_host(host_id).await.map_err(ApiError::from)?;
        // `None` asks for the machine's own default shell, which is the right answer here: the
        // configured shell names a path on *this* machine and would be a guess about another one.
        let session = host
            .open_pty(body.shell.as_deref(), body.cols, body.rows)
            .await
            .map_err(ApiError::from)?;
        state.terminals.create_remote(&body.id, session)?;
        return Ok(Json(serde_json::json!({
            "id": body.id,
            "host": host_id,
            "created": true,
        })));
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
    /// The strongest risk the surface that is answering may authorise — `read`, `mutate`, `external`,
    /// `destructive` or `privileged`.
    ///
    /// **Required, with no default**, and that is the point: the ceiling is what stops a phone from
    /// authorising `rm -rf`, and a field that could be omitted would be a field that silently means
    /// "unbounded". `RiskClass` has no `Default` either, so there is no constructor, no deserializer
    /// and no omission that yields a permissive ceiling — a body without this is a rejection, not a
    /// grant. The queue re-judges it against the risk of the question it is holding, at the moment the
    /// answer arrives, so this is the *declaration* and not the enforcement.
    ///
    /// Why the caller declares it rather than the daemon deriving it: this API has no authentication,
    /// so it cannot tell one local client from another, and per-channel ceilings are not configured yet
    /// (`approval.ask_via` is still a roadmap line). A **channel** does not answer through this route at
    /// all — it answers through `hx-gateway`'s `ApprovalBridge`, whose ceiling comes from the
    /// deployment rather than from the channel. The clients that do use this route are the owner's own
    /// machine-local ones (the `hx` CLI, the embedded web UI), and they declare the terminal's ladder.
    ceiling: RiskClass,
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
    match state.approvals.answer(&id, option, &by, body.ceiling) {
        AnswerResult::Answered => Ok(Json(serde_json::json!({ "answered": id, "by": by }))),
        // Nothing waiting under this id: it was answered already, or it timed out and the run was
        // refused. A 404 says so rather than pretending an answer landed.
        AnswerResult::Unknown => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no approval is waiting under '{id}' — it was answered already, or it expired"),
        )),
        // The question is real and still waiting, and this answer is one the answering surface was
        // never allowed to give. 403 and not 404, because the difference matters to whoever tried: a
        // 404 says "wrong id", and this says "not yours to answer" — and the question stays open, so
        // the run still ends in its own timeout denial rather than in this yes.
        AnswerResult::AboveCeiling { risk, ceiling } => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            format!(
                "a {} action cannot be answered with ceiling {}; the answer was refused and the \
                 question is still waiting",
                risk.label(),
                ceiling.label()
            ),
        )),
    }
}

/// The body of a phone/lock-screen tap.
///
/// The phone taps `POST /v1/approvals/{id}/respond` with a bare `verdict` of `allow` or `deny`.
/// Compare this with [`ApprovalAnswer`]: the phone is a thin approval surface, not a full client, so the
/// choice it sends is a single yes/no and `respond_with` picks the ceiling — `allow` maps to
/// [`ApprovalOption::AllowOnce`] (a one-shot grant, the least the phone can mean by "let it run").
#[derive(Debug, Deserialize)]
pub struct RespondApprovalBody {
    /// The one-time token from the pushed `respond_url`. See [`crate::phone::PhoneApprover`].
    token: String,
    /// `allow` or `deny`.
    verdict: String,
}

/// The phone's tap comes back here, through the `respond_url` the push carried.
///
/// **Why this has no bearer check**: the phone never holds the daemon's long-lived secret. The push put a
/// **one-time** [`crate::phone::PhoneApprover`] token into the `respond_url` it sent, and `approve_phone`
/// verifies that token here against its own per-approval record before acting. A caller who does not know the
/// token is refused, whether or not they hold a bearer token; a caller who does know it holds the proof the
/// push itself issued, which is the phone's grant. The one-time nature means replaying the `respond_url` cannot
/// approve twice.
async fn respond_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<RespondApprovalBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Some(phone) = &state.phone else {
        // No webhook is configured and no push exists under this id: the route is a 404, not a 400,
        // because there is no approval this url could answer.
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "no phone approval push is configured on this daemon",
        ));
    };

    match phone.respond(&id, &body.token, &body.verdict) {
        Ok(()) => {}
        Err(phone_err) => {
            use crate::phone::PhoneRespondError::*;
            return Err(match phone_err {
                Idle => ApiError::new(
                    StatusCode::NOT_FOUND,
                    format!("no approval is waiting under '{id}' — it was answered already, or it expired"),
                ),
                Token => ApiError::new(
                    StatusCode::FORBIDDEN,
                    "the one-time token in this respond_url does not match the approval — refused",
                ),
                Verdict => ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "verdict must be 'allow' or 'deny'",
                ),
            });
        }
    }

    Ok(Json(serde_json::json!({ "responded": id })))
}

/// A diff of a proposed file change, computed from the real file on disk.
///
/// Body `{ "path": "...", "proposed": "..." }`. The current content is read from the local host (via
/// the same read-capability gate the file routes use), and the diff between it and `proposed` is computed
/// on the daemon. The pane never derives a diff from content it does not have: it asks for it and renders
/// the daemon's answer.
///
/// `proposed` is returned as part of the response only redacted: a diff displays file contents, and a
/// proposed edit that embeds a credential must not hand it to the model through the browser untouched. Content
/// that is already on disk (context and removed lines) is left as-is, because it is not new information the
/// diff is *introducing* — see [`crate::diff`] for the exact shapes tested.
#[derive(Debug, Deserialize)]
pub struct DiffBody {
    pub path: String,
    pub proposed: String,
}

#[derive(Debug, Serialize)]
pub struct DiffReply {
    pub path: String,
    /// `true` whenever a diff is served. A missing file surfaces as the read error (matched to a 404 when
    /// possible), exactly like the host file route — see [`host_read_file`].
    pub exists: bool,
    /// `true` when the current file is not valid UTF-8, in which case `diff` is empty and the pane
    /// says why rather than inventing a mangled diff of binary bytes.
    pub binary: bool,
    pub diff: Vec<crate::diff::DiffLine>,
}

async fn diff_file(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DiffBody>,
) -> Result<Json<DiffReply>, ApiError> {
    if body.path.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "a path is required for a diff",
        ));
    }
    // The same read-capability gate the host file route uses — `local` is the daemon's own machine,
    // and the reviews this pane serves are reviews of local file edits.
    let host = resolve_for_use(
        &state,
        crate::hosts::LOCAL_HOST_ID,
        hx_core::capability::Action::Read,
    )
    .await?;

    let bytes = host
        .read_file_capped(&body.path, FILE_READ_CAP)
        .await
        .map_err(ApiError::from)?;
    // A binary file cannot be diffed as text — reporting that honestly beats inventing a diff of mangled
    // bytes. `Some` here means the bytes are not valid UTF-8.
    let binary = String::from_utf8(bytes.clone()).is_err();
    let current = String::from_utf8(bytes).unwrap_or_default();

    let rendered = if binary {
        Vec::new()
    } else {
        let diff = crate::diff::unified_diff(&current, &body.proposed);
        // Redacted here, on the way out — see `crate::diff` for which shapes this covers.
        crate::diff::redact_diff(&diff, &Redactor::new())
    };

    Ok(Json(DiffReply {
        path: body.path,
        exists: true,
        binary,
        diff: rendered,
    }))
}

// ---------------------------------------------------------------------------
// Fan-out: N concurrent child model calls across N distinct pool members
// ---------------------------------------------------------------------------
//
// This is the first *production* surface for the M8 spawner (see `crate::spawn`
// and `crate::fanout`). The spawner owns the pool's per-request health state, so a
// Spawner is built from `Config` + the state's providers/secrets/store for the duration
// of the request — it is not a field on `AppState` (which has no model pool to point at
// until a caller names one). This keeps the M8 pool draw hermetic and per-request.

/// One child call of a fan-out: the session its usage is recorded under, and a prompt.
#[derive(Debug, Deserialize, Serialize)]
pub struct FanOutChild {
    pub session: String,
    pub prompt: String,
}

/// `POST /v1/fanout` — the fan-out request.
///
/// `children` is the list of child calls. The returned outcome has one result per child, in
/// request order. Every child in a fan-out runs against **one** caller session, and the route
/// refuses a request whose children name different sessions (400): silently billing one child's
/// work to another child's session is exactly the surprise the per-row session inputs invite, so
/// mixed sessions are a client error, not a silent re-bill.
///
/// Refused before anything runs: an empty `children` array (400), a child whose prompt is blank
/// (400 — the built-in web client refuses the same row, and a blank prompt is a model call that
/// buys nothing), children naming different sessions (400), and the session the children will be
/// recorded under when it does not exist (404). A refusal spends no provider call and writes
/// nothing.
#[derive(Debug, Deserialize, Serialize)]
pub struct FanOutBody {
    pub children: Vec<FanOutChild>,
}

/// The pool a fan-out draws from when none is named.
///
/// The pool name mirrors the default the agent run picks, so a fan-out caller that omits one
/// draws from the pool the daemon would otherwise use rather than a surprise.
fn default_fanout_pool() -> String {
    "interactive".to_string()
}

/// `POST /v1/fanout` — run N child model calls, one per distinct pool member, concurrently.
///
/// The M8 exit criterion as an HTTP surface: every child is allocated a spec on a *distinct*
/// healthy member before any runs, the children then run **concurrently** (bounded by the
/// configured `agent.fanout_max_parallel`), a short pool fails loudly (no child runs), and a member that
/// dies mid-fan-out fails only its own child while the others complete. Each completed child's
/// response names the member it ran on and its recorded usage; a dying member's error is redacted
/// at the fanout boundary with the member's own credential registered as a literal (see
/// `crate::spawn::Spawner::redact_child_error`).
///
/// The `Spawner` is built per request from `Config` plus the state's providers, secret stores
/// and store. This is the same wiring `AppState::build` uses for the model path, and no new
/// secret-resolution path — the pool's member credentials are resolved through the state's stores.
async fn fanout(
    State(state): State<Arc<AppState>>,
    Json(body): Json<FanOutBody>,
) -> Result<Json<crate::fanout::FanOutOutcome>, ApiError> {
    // An empty fan-out is meaningless and is refused up front (a clear 400 rather than a
    // 200 with nothing in it).
    if body.children.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "a fan-out needs at least one child",
        ));
    }

    // A child with nothing to ask is a provider call that buys nothing, and the built-in web client
    // refuses exactly that row before sending it (`each row needs both a session and a prompt`). The
    // route used to accept it and spend the call, so the two surfaces disagreed; it now names the
    // child and refuses. Whitespace counts as blank for the same reason.
    for (index, child) in body.children.iter().enumerate() {
        if child.prompt.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "child {} has an empty prompt: a fan-out child needs something to ask",
                    index + 1
                ),
            ));
        }
    }

    // `run_fan_out` runs every child against a single caller session. Mixed session ids used to
    // be silently re-billed to the first child's session; now they are refused up front, before
    // any provider call is spent — billing one child's work to another child's session is a
    // client error, not a silent re-bill.
    if body
        .children
        .iter()
        .any(|c| c.session != body.children[0].session)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "a fan-out runs every child against one session: \
             all children must name the same session id",
        ));
    }
    let session = hx_core::ids::SessionId::from_raw(body.children[0].session.clone());

    // The session must already exist — every child's usage is recorded under it, and `hx fan`'s help
    // says so. Without this check the fan-out made the provider call first and failed afterwards
    // inside `Store::record_usage` (`touch` refuses a session that is not there), reporting that as
    // an *errored child* in a 200: a model call paid for, nothing in the audit chain, and an
    // internal store message rendered as the child's failure.
    state.store.record(&session).map_err(|err| match err {
        hx_core::error::HxError::NotFound(_) => ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no such session: {}", session.as_str()),
        ),
        other => ApiError::from(other),
    })?;

    // `default_pool` carries the configured default, which may be empty/absent; fall back to a
    // sensible name when it is. The pool the fan-out draws from is built per request from
    // `Config` (the state carries no `Spawner`, and none is persisted between requests).
    let pool_name = state.config.agent.default_pool.clone();
    let pool_name = if pool_name.is_empty() {
        default_fanout_pool()
    } else {
        pool_name
    };

    let pool = state.config.model_pool(&pool_name).map_err(|e| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("the model pool could not be built: {e}"),
        )
    })?;

    let mut spawner = crate::spawn::Spawner::new(
        pool,
        Arc::new(state.providers.read().expect("providers lock").clone()),
        state.secrets.clone(),
        state.store.clone(),
    );

    let prompts: Vec<&str> = body.children.iter().map(|c| c.prompt.as_str()).collect();

    let outcome = crate::fanout::run_fan_out(
        &mut spawner,
        &session,
        &prompts,
        state.config.agent.fanout_max_parallel,
    )
    .await
    .map_err(|e| {
        let status = match &e {
            // A shortage is the client's to fix (run fewer, retry later) — client error.
            crate::fanout::FanOutError::NotEnoughMembers { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            // An all-down/empty pool is a server-side capability problem.
            crate::fanout::FanOutError::Draw(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        ApiError::new(status, e.to_string())
    })?;

    Ok(Json(outcome))
}

// ---------------------------------------------------------------------------
// Research: the M6 pipeline's production caller
// ---------------------------------------------------------------------------
//
// `hx-search` owns the pipeline (`ResearchTask`) and the fetch decision (`select_fetcher`);
// this route is the caller that runs one through the other. It never reaches the network
// itself: every page fetch goes through the selected `Fetcher`, plain or browser-backed.

/// `POST /v1/research` — the research request.
///
/// `fetch_mode` is the `hx_search::FetchMode` vocabulary (`http`, `auto`, `browser`); omitted
/// means `auto`, the mode the browser rung exists for. `max_sources` caps the cited sources;
/// omitted means the pipeline default.
#[derive(Debug, Deserialize, Serialize)]
pub struct ResearchBody {
    pub query: String,
    #[serde(default)]
    pub max_sources: Option<usize>,
    #[serde(default)]
    pub fetch_mode: Option<FetchMode>,
}

impl ResearchBody {
    /// Split the wire body into the pipeline request and the fetch decision it runs under.
    ///
    /// Pure, so the CLI mapping test and the route share one meaning of the fields rather than
    /// two parsers that can drift.
    pub fn into_request_and_mode(self) -> (ResearchRequest, FetchMode) {
        let mode = self.fetch_mode.unwrap_or(FetchMode::Auto);
        let request = match self.max_sources {
            Some(max) => ResearchRequest::new(self.query).with_max_sources(max),
            None => ResearchRequest::new(self.query),
        };
        (request, mode)
    }
}

/// `POST /v1/research` — the research report, plus which fetcher ran it.
///
/// `fetcher` is `http` or `browser` — the `SelectedFetcher` the selector landed on — and
/// `fetch_note` is its honest record of why (including the `auto` degradation when no browser
/// is installed). The rest is the pipeline's own report.
#[derive(Debug, Serialize)]
pub struct ResearchResponse {
    pub query: String,
    pub fetcher: &'static str,
    pub fetch_note: String,
    pub backends: Vec<hx_search::BackendOutcome>,
    pub sources: Vec<hx_search::Citation>,
    pub paid_calls: usize,
}

/// Turn a refused fetch selection into the status a caller should react to.
///
/// An explicit browser request with no browser installed is `409 Conflict`, not a 500: the
/// daemon is fine, the request asked for a rung this host cannot run. `auto` never reaches
/// here — it degrades inside `select_fetcher` — so this fires only for an explicit mode.
pub fn research_route_error(err: FetchRouteError) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, err.to_string())
}

/// `POST /v1/research` — fan out over the configured backends, extract, and cite.
///
/// The fetcher is chosen by the existing `select_fetcher` — the selection logic lives in
/// `hx-search` and is called here, never duplicated. A blank query is a 400; a daemon with no
/// backends configured is a 503, the same answer `/v1/search` gives.
async fn research(
    State(state): State<Arc<AppState>>,
    body: Result<Json<ResearchBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    // A thin shell over `research_inner`: the extractor plumbing stays trivial and the route's
    // real work is testable as a plain async fn taking the state by value.
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => {
            return ApiError::new(StatusCode::BAD_REQUEST, rejection.body_text()).into_response()
        }
    };
    match research_inner(state, body).await {
        Ok(json) => json.into_response(),
        Err(err) => err.into_response(),
    }
}

/// The route's real work.
async fn research_inner(
    state: Arc<AppState>,
    body: ResearchBody,
) -> Result<Json<ResearchResponse>, ApiError> {
    if body.query.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "a research request needs a non-empty `query`",
        ));
    }
    if state.search.is_empty() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "no search backends are configured; set `search.backends` in the config",
        ));
    }

    let (request, mode) = body.into_request_and_mode();
    let client = state.search.client().clone();
    let selection =
        select_fetcher(&client, mode, default_pool_root()).map_err(research_route_error)?;
    let task = ResearchTask::new(state.search.all(), client, selection.fetcher());
    let report = task.run(&request).await;

    let fetcher = match selection.kind {
        hx_search::SelectedFetcher::Http => "http",
        hx_search::SelectedFetcher::Browser => "browser",
    };
    Ok(Json(ResearchResponse {
        query: report.query,
        fetcher,
        fetch_note: selection.note.to_string(),
        backends: report.backends,
        sources: report.sources,
        paid_calls: report.paid_calls,
    }))
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

// ---------------------------------------------------------------------------
// Hosts: the machine behind a name
// ---------------------------------------------------------------------------
//
// These routes are the client-facing half of `crate::hosts`. They exist so the browser, the TUI, and
// the CLI all reach a remote machine the same way, and so a machine the daemon can *talk* to is also
// a machine a person can look at.
//
// Every one of them resolves the host through `crate::hosts::resolve`, which means the credential
// comes from the vault at connect time and the transport is chosen from configuration rather than
// from the URL. The route names a host; it never names a transport.

/// A host, described well enough for a client to decide what to offer.
#[derive(Debug, Serialize)]
pub struct HostDetail {
    pub id: String,
    pub kind: String,
    pub address: Option<String>,
    pub configured: bool,
    /// `None` when the machine could not be reached. Presence means the daemon actually connected,
    /// so a client can trust `os`/`shell` rather than guessing from the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    /// Whether an SFTP subsystem is available for copying files.
    ///
    /// Omitted when unknown, which is the case for every host today: the capability probes read a
    /// `uname` string or `cmd /C ver`, neither of which says anything about SSH subsystems. It was
    /// `Some(true)` for SSH hosts, from a field hard-coded to `true` by the parser — a capability
    /// report no code had checked, on the one question a client would act on. It now reports what is
    /// known, and nothing is known yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_sftp: Option<bool>,
    /// Why the machine could not be reached, when it could not. Present instead of a 5xx so a client
    /// can still list hosts and show the one broken entry with its reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreachable: Option<String>,
    /// Whether a command would be refused by policy. Informational: the refusal itself is real and
    /// happens on the exec route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<String>,
}

async fn host_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<HostDetail>, ApiError> {
    let summary = state
        .host_summaries()
        .into_iter()
        .find(|h| h.id == id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                crate::hosts::unknown_host_message(&state.config, &id),
            )
        })?;

    // A denial is reported *before* connecting. There is no point holding a handshake to a machine
    // the caller may not use, and the reason is more useful than a connection error would be.
    //
    // The check is for `Read`, not for "lookup": describing a host means listing its directories and
    // reading its files can follow, so it is the read capability that says whether this pane will
    // work at all. A policy that denies shell but allows reading still shows the machine.
    if let Some(reason) = state.host_denial_for(&id, hx_core::capability::Action::Read) {
        return Ok(Json(HostDetail {
            id: summary.id,
            kind: summary.kind,
            address: summary.address,
            configured: summary.configured,
            os: None,
            shell: None,
            arch: None,
            home_dir: None,
            has_sftp: None,
            unreachable: None,
            denied: Some(reason),
        }));
    }

    match state.resolve_host(&id).await {
        Ok(host) => {
            let caps = host.caps();
            Ok(Json(HostDetail {
                id: summary.id,
                kind: summary.kind,
                address: summary.address,
                configured: summary.configured,
                os: Some(format!("{:?}", caps.os).to_lowercase()),
                shell: Some(format!("{:?}", caps.shell).to_lowercase()),
                arch: caps.arch.clone(),
                home_dir: caps.home_dir.clone(),
                // Flattened: the route's `None` and the caps' `None` mean the same thing to a
                // client ("nobody has checked"), so there is no reason to make it distinguish
                // between two flavours of unknown.
                has_sftp: caps.has_sftp,
                unreachable: None,
                denied: None,
            }))
        }
        Err(err) => Ok(Json(HostDetail {
            id: summary.id,
            kind: summary.kind,
            address: summary.address,
            configured: summary.configured,
            os: None,
            shell: None,
            arch: None,
            home_dir: None,
            has_sftp: None,
            unreachable: Some(err.to_string()),
            denied: None,
        })),
    }
}

#[derive(Debug, Deserialize)]
pub struct ListDirQuery {
    /// The directory to list. Absent means the host's home directory, which is the natural landing
    /// spot and saves every client from having to discover it first.
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DirListing {
    pub host: String,
    /// The path actually listed, after the home-directory default was applied. Echoed because a
    /// client that asked for nothing needs to know where it ended up.
    pub path: String,
    pub entries: Vec<EntryOut>,
}

#[derive(Debug, Serialize)]
pub struct EntryOut {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

async fn host_list_dir(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<ListDirQuery>,
) -> Result<Json<DirListing>, ApiError> {
    let host = resolve_for_use(&state, &id, hx_core::capability::Action::Read).await?;
    // No path given: the home directory, which the caps already carry. A host with no known home
    // gets an explicit error rather than an empty listing against a guess.
    let path = match query.path {
        Some(p) if !p.trim().is_empty() => p,
        _ => host.caps().home_dir.clone().ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("host {id:?} has no known home directory; pass ?path="),
            )
        })?,
    };

    let entries = host
        .list_dir(&path)
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .map(|e| EntryOut {
            name: e.name,
            path: e.path,
            is_dir: e.is_dir,
            size: e.size,
        })
        .collect();

    Ok(Json(DirListing {
        host: id,
        path,
        entries,
    }))
}

#[derive(Debug, Deserialize)]
pub struct FileQuery {
    pub path: String,
}

/// A file's bytes, as text or base64.
///
/// `encoding` is reported rather than assumed. A binary file returned as lossy UTF-8 would look like
/// a *corrupt* file to a client, so bytes that are not valid UTF-8 come back base64 and the client is
/// told which it got. Text is the common case and stays readable in a plain `curl`.
#[derive(Debug, Serialize)]
pub struct FileBody {
    pub host: String,
    pub path: String,
    pub size: u64,
    pub encoding: String,
    pub contents: String,
}

async fn host_read_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<FileQuery>,
) -> Result<Json<FileBody>, ApiError> {
    let host = resolve_for_use(&state, &id, hx_core::capability::Action::Read).await?;
    let bytes = host
        .read_file_capped(&query.path, FILE_READ_CAP)
        .await
        .map_err(ApiError::from)?;

    let (encoding, contents) = if let Ok(text) = String::from_utf8(bytes.clone()) {
        ("utf-8".to_string(), text)
    } else {
        ("base64".to_string(), base64_encode(&bytes))
    };

    Ok(Json(FileBody {
        host: id,
        path: query.path,
        size: bytes.len() as u64,
        encoding,
        contents,
    }))
}

#[derive(Debug, Deserialize)]
pub struct WriteFileBody {
    pub path: String,
    pub contents: String,
    /// How to read `contents`. Defaults to utf-8, which is what a person editing a file produces;
    /// a client round-tripping a binary file sends back `base64`.
    #[serde(default)]
    pub encoding: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WriteFileReply {
    pub host: String,
    pub path: String,
    pub written: u64,
}

async fn host_write_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<WriteFileBody>,
) -> Result<Json<WriteFileReply>, ApiError> {
    let host = resolve_for_use(&state, &id, hx_core::capability::Action::Write).await?;

    let bytes = match body.encoding.as_deref().unwrap_or("utf-8") {
        "utf-8" | "utf8" => body.contents.into_bytes(),
        "base64" => base64_decode(&body.contents).map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("contents are not valid base64: {e}"),
            )
        })?,
        other => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("unknown encoding {other:?}; use \"utf-8\" or \"base64\""),
            ))
        }
    };

    let written = bytes.len() as u64;
    host.write_file(&body.path, &bytes)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(WriteFileReply {
        host: id,
        path: body.path,
        written,
    }))
}

#[derive(Debug, Deserialize)]
pub struct HostExecBody {
    pub command: String,
    /// Seconds. Defaults to 30: a route that can be pointed at any machine should not be able to hold
    /// a request open indefinitely by default.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HostExecReply {
    pub host: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// Whether either stream hit the transport's per-stream byte cap and lost its middle.
    pub truncated: bool,
}

async fn host_exec(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<HostExecBody>,
) -> Result<Json<HostExecReply>, ApiError> {
    // The command is classified first, through the same classifier an agent run uses, so `ls` is
    // allowed and `rm -rf /` is not — a single risk class for "runs a command" would refuse both at
    // the default autonomy level and be useless.
    //
    // The command *is* the gate, so there is no second check against a generic `Execute` action: that
    // would be a coarser check running after a finer one, and at the default level it would refuse
    // `hostname` on a machine the operator explicitly configured. The host-level read check still
    // runs, so a host denied outright cannot be reached by any command.
    if let Some(reason) = state.host_command_denial(&id, &body.command) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, reason));
    }
    let host = resolve_for_use(&state, &id, hx_core::capability::Action::Read).await?;
    let timeout = std::time::Duration::from_secs(body.timeout_secs.unwrap_or(30).clamp(1, 600));

    let out = host
        .exec(&body.command, timeout)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(HostExecReply {
        host: id,
        stdout: out.stdout,
        stderr: out.stderr,
        exit_code: out.exit_code,
        duration_ms: out.duration_ms,
        truncated: out.truncated,
    }))
}

/// Resolve a host for a specific action, enforcing the capability and reporting denials as 403.
///
/// One place for the check rather than one per handler: three routes that each spelled this out would
/// be three chances to forget it, and a route that forgets it is a hole in the policy.
async fn resolve_for_use(
    state: &AppState,
    id: &str,
    action: hx_core::capability::Action,
) -> Result<Arc<dyn hx_remote::Host>, ApiError> {
    if let Some(reason) = state.host_denial_for(id, action) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, reason));
    }
    state.resolve_host(id).await.map_err(ApiError::from)
}

/// Base64, hand-rolled rather than pulling a dependency in for two functions.
///
/// The workspace keeps its dependency list small on purpose; this is the standard alphabet with
/// padding, which is all a file round-trip needs.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        // Padding is what makes the length a multiple of four, and a decoder relies on it.
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    // Tolerated on decode but never produced on encode: whitespace is what a wrapped base64 blob
    // carries, and refusing it would make pasted content fail for no good reason.
    fn value(b: u8) -> std::result::Result<u32, String> {
        match b {
            b'A'..=b'Z' => Ok(u32::from(b - b'A')),
            b'a'..=b'z' => Ok(u32::from(b - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(b - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            other => Err(format!("invalid base64 character {:?}", other as char)),
        }
    }

    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    for (i, chunk) in cleaned.chunks(4).enumerate() {
        if chunk.len() < 2 {
            // A single trailing character cannot encode a byte; one or two '=' with one character is
            // truncated input, and silently dropping it would corrupt the file.
            return Err(format!("truncated base64 group at position {}", i * 4));
        }
        let mut n: u32 = 0;
        for (j, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                // Padding must be at the end, and at most two of them.
                if j < 2 || chunk[j..].iter().any(|&c| c != b'=') {
                    return Err(format!("misplaced padding at position {}", i * 4 + j));
                }
                break;
            }
            n |= value(b)? << (18 - 6 * j);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            out.push(n as u8);
        }
    }
    Ok(out)
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

    /// Build state from a config with the ambient API token cleared first.
    ///
    /// `AppState::build` resolves `api.token` and then falls back to `HX_API_TOKEN` in the
    /// environment, which is the form a container and a CI job use. A *test process* must not
    /// inherit a real credential from the developer's shell: with `HX_API_TOKEN` exported — which
    /// `DEPLOY.md` tells operators to do — every request in this module comes back `401` and
    /// twenty-four tests fail for a reason that has nothing to do with what they assert. Clearing
    /// it here rather than handing a token to each test is the point: a test that needed a token
    /// would mean the loopback rule, not the test, was wrong.
    ///
    /// Not a lock, and it does not need to be: every harness in this module wants the same answer,
    /// so a concurrent clear is idempotent. `set_var`/`remove_var` inside a test is the convention
    /// already used by `hx-secrets`, `hx-search`, `hx-store` and `hx-mcp`.
    async fn build_state(config: hx_core::config::Config) -> Arc<AppState> {
        std::env::remove_var(hx_core::api_auth::API_TOKEN_ENV);
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        AppState::build(config, None, now).await.expect("state builds")
    }

    async fn test_state() -> Arc<AppState> {
        let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
        // A test must not write a session database into the developer's home directory, and the
        // directory has to outlive the store: `keep()` hands back the path rather than deleting it on
        // drop, so the file is still there when a later assertion reopens the session.
        let dir = tempfile::tempdir().expect("temp dir");
        config.daemon.data_dir = dir.keep().display().to_string();

        build_state(config).await
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
    async fn login_returns_the_bearer_token_for_a_valid_account() {
        let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
        config.api.token = Some("secret-token-123".into());
        config.api.admin_username = Some("admin".into());
        config.api.admin_password = Some("hunter2".into());
        let state = build_state(config).await;

        let (status, body) = post(
            state.clone(),
            "/v1/login",
            serde_json::json!({ "username": "admin", "password": "hunter2" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "login with correct credentials succeeds");
        assert_eq!(body["token"], "secret-token-123");

        // A wrong password must be refused, and a wrong username too.
        for attempt in [
            serde_json::json!({ "username": "admin", "password": "wrong" }),
            serde_json::json!({ "username": "nobody", "password": "hunter2" }),
        ] {
            let (status, _) = post(state.clone(), "/v1/login", attempt).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "bad credentials refused");
        }
    }

    #[tokio::test]
    async fn login_with_no_password_configured_is_refused() {
        // No admin_password set: every login attempt must 401, never disclose the token.
        let (status, body) = post(
            test_state().await,
            "/v1/login",
            serde_json::json!({ "username": "admin", "password": "anything" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.get("token").is_none(), "no token when no password is set");
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

    // ---- hosts -----------------------------------------------------------
    //
    // These run against the *local* host, which is the one machine a hermetic test can actually
    // drive: it needs no configuration, no credential, and no network. The remote transports are
    // reached through the same `resolve_for_use`, so a bug in the gating or the plumbing shows up
    // here rather than only on a machine with an SSH host to hand.

    async fn put(
        state: Arc<AppState>,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
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
    async fn host_detail_describes_the_local_machine() {
        let state = test_state().await;
        let (status, body) = get(state, "/v1/hosts/local").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], "local");
        // The daemon resolved the machine it runs on, so these are observed rather than guessed.
        assert!(
            body["os"].is_string(),
            "the local host must report its OS: {body}"
        );
        assert!(body["shell"].is_string(), "{body}");
        // Nothing denied by default: the shipped policy has an empty deny list, so a fresh install
        // can browse its own files.
        assert!(body.get("denied").is_none(), "{body}");
    }

    #[tokio::test]
    async fn an_unknown_host_is_a_404_that_lists_the_known_ones() {
        let state = test_state().await;
        let (status, body) = get(state, "/v1/hosts/nowhere").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let message = body["error"].as_str().unwrap_or_default();
        assert!(
            message.contains("local"),
            "must list the known hosts: {message}"
        );
    }

    #[tokio::test]
    async fn listing_the_home_directory_returns_real_entries() {
        let state = test_state().await;
        let (status, body) = get(state, "/v1/hosts/local/files").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // Asking for nothing lands in the home directory, and the response says where that was.
        assert!(
            body["path"].as_str().is_some_and(|p| !p.is_empty()),
            "{body}"
        );
        assert!(body["entries"].is_array(), "{body}");
    }

    #[tokio::test]
    async fn a_file_round_trips_through_write_and_read() {
        // The whole point of these routes: what goes in comes back out, byte for byte.
        let state = test_state().await;
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("round-trip.txt");
        let path = path.display().to_string();

        let (status, body) = put(
            state.clone(),
            "/v1/hosts/local/file",
            serde_json::json!({ "path": path, "contents": "hello from the host pane\n" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["written"], 25);

        let uri = format!("/v1/hosts/local/file?path={path}");
        let (status, body) = get(state, &uri).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["encoding"], "utf-8");
        assert_eq!(body["contents"], "hello from the host pane\n");
        assert_eq!(body["size"], 25);
    }

    #[tokio::test]
    async fn a_binary_file_comes_back_as_base64_rather_than_mangled_text() {
        // A client that received lossy UTF-8 would write back a *different* file, so the encoding is
        // reported and the bytes are preserved.
        let state = test_state().await;
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("blob.bin");
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01, 0x80]).expect("write");
        let path = path.display().to_string();

        let (status, body) = get(state, &format!("/v1/hosts/local/file?path={path}")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["encoding"], "base64", "{body}");
        assert_eq!(body["contents"], "//4AAYA=", "{body}");
    }

    #[tokio::test]
    async fn base64_round_trips_every_length_that_needs_padding() {
        // 0, 1, and 2 bytes are the padding cases and the ones a hand-rolled encoder gets wrong.
        for input in [vec![], vec![0x41], vec![0x41, 0x42], vec![0x41, 0x42, 0x43]] {
            let encoded = base64_encode(&input);
            assert_eq!(encoded.len() % 4, 0, "length must be a multiple of four");
            let decoded = base64_decode(&encoded).expect("decodes");
            assert_eq!(decoded, input, "round trip failed for {input:?}");
        }
    }

    #[tokio::test]
    async fn base64_round_trips_a_large_body() {
        // The 6 KB-class boundary that bit the WinRM write path: a payload that needs several groups
        // and hits every remainder.
        let input: Vec<u8> = (0..6003u32).map(|i| (i % 251) as u8).collect();
        let decoded = base64_decode(&base64_encode(&input)).expect("decodes");
        assert_eq!(decoded, input);
    }

    #[test]
    fn malformed_base64_is_reported_rather_than_silently_truncated() {
        // Silently dropping a bad group would write a shorter file than the caller sent, which is
        // the failure that is hardest to notice.
        assert!(
            base64_decode("A").is_err(),
            "a lone character cannot encode a byte"
        );
        assert!(base64_decode("A===A").is_err(), "padding then more data");
        assert!(base64_decode("****").is_err(), "not base64 at all");
        assert!(
            base64_decode("AAAAA").is_err(),
            "a group with a stray trailing character"
        );
    }

    #[test]
    fn a_three_character_group_is_two_bytes_and_not_an_error() {
        // Not an edge case to reject: three characters with no padding is a legitimate encoding of
        // two bytes, and treating it as truncated would refuse a valid file.
        assert_eq!(base64_decode("AAA").unwrap(), vec![0x00, 0x00]);
    }

    #[test]
    fn base64_decode_tolerates_whitespace_because_wrapped_blobs_carry_it() {
        let wrapped = "aGVsbG8g\n  d29ybGQ=";
        assert_eq!(base64_decode(wrapped).unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn writing_with_an_unknown_encoding_is_a_400_naming_the_valid_ones() {
        let state = test_state().await;
        let (status, body) = put(
            state,
            "/v1/hosts/local/file",
            serde_json::json!({ "path": "/tmp/x", "contents": "a", "encoding": "rot13" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let message = body["error"].as_str().unwrap_or_default();
        assert!(
            message.contains("utf-8") && message.contains("base64"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn exec_runs_a_command_on_the_local_host() {
        // The route's own `timeout_secs` is raised well above the 30s default for the *test's*
        // request, and only for it. This test asserts that `exec` runs the command and returns the
        // result as a 200 — the property under test. The 30s default is the production exec budget
        // (a route pointable at any machine should not hold a request open indefinitely), and it is NOT
        // what this test verifies. On a loaded CI runner, spawning the local shell can exceed 30s,
        // so the default would make the test flake as `remote host error: command timed out after
        // 30.0s` (a 502) even though exec was fine. Giving the request a longer deadline removes
        // that coupling without weakening the assertion: if `exec` genuinely stops working, the
        // `assert_eq!(status, OK)` still fails. The production timeout is deliberately untouched.
        let state = test_state().await;
        let (status, body) = post(
            state,
            "/v1/hosts/local/exec",
            serde_json::json!({
                "command": "printf host-pane-ok",
                "timeout_secs": 120,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["stdout"], "host-pane-ok");
        assert_eq!(body["exit_code"], 0);
    }

    #[tokio::test]
    async fn exec_reports_a_failing_command_rather_than_making_it_a_transport_error() {
        // A non-zero exit is a *result*. Turning it into a 5xx would tell the client the daemon
        // broke, which is the wrong story and the wrong retry decision.
        //
        // As with `exec_runs_a_command_on_the_local_host`, the request's own `timeout_secs` is
        // raised above the production default so a loaded CI runner cannot flake the test with a
        // spurious `timed out after 30.0s` 502. The assertion is unchanged: if `exec` really
        // stops returning exit codes, `assert_eq!(status, OK)` and `assert_eq!(exit_code, 3)`
        // still fail. The production timeout is deliberately untouched.
        let state = test_state().await;
        let (status, body) = post(
            state,
            "/v1/hosts/local/exec",
            serde_json::json!({ "command": "exit 3", "timeout_secs": 120 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["exit_code"], 3, "{body}");
    }

    #[tokio::test]
    async fn exec_on_an_unknown_host_is_a_404() {
        let state = test_state().await;
        let (status, _) = post(
            state,
            "/v1/hosts/nope/exec",
            serde_json::json!({ "command": "id" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_denied_host_is_refused_with_403_before_anything_runs() {
        // The policy has to hold for the HTTP surface, not only for an agent run. A destructive
        // command is denied at the default level, and the refusal must not reach the machine.
        let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
        let dir = tempfile::tempdir().expect("temp dir");
        config.daemon.data_dir = dir.keep().display().to_string();
        // A deny rule that matches the host tool: this is the operator's override, and the route
        // must honour it.
        config.agent.approval = hx_core::approval::ApprovalPolicy {
            deny: vec![hx_core::approval::Rule::tool("shell")],
            ..Default::default()
        };

        let state = build_state(config).await;

        let (status, body) = post(
            state.clone(),
            "/v1/hosts/local/exec",
            serde_json::json!({ "command": "printf should-not-run" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // And the read path is refused too, because the same rule covers it.
        let (status, _) = get(state, "/v1/hosts/local/files").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_denied_host_still_appears_in_the_listing_with_its_reason() {
        // The list must not hide a host just because it is denied: an operator needs to see that the
        // machine is configured and *why* it is unusable, or the config looks broken.
        let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
        let dir = tempfile::tempdir().expect("temp dir");
        config.daemon.data_dir = dir.keep().display().to_string();
        config.agent.approval = hx_core::approval::ApprovalPolicy {
            deny: vec![hx_core::approval::Rule::tool("shell")],
            ..Default::default()
        };

        let state = build_state(config).await;

        let (status, body) = get(state.clone(), "/v1/status").await;
        assert_eq!(status, StatusCode::OK);
        let hosts = body["hosts"].as_array().expect("hosts is a list");
        assert!(
            hosts.iter().any(|h| h["id"] == "local"),
            "local stays listed: {body}"
        );

        let (status, body) = get(state, "/v1/hosts/local").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["denied"].is_string(),
            "the reason must be reported: {body}"
        );
    }
}
