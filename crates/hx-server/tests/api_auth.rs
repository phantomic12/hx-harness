//! The API's bearer token, over the real HTTP surface.
//!
//! `crates/hx-core/src/api_auth.rs` proves the comparison and the startup rule as pure functions.
//! This file is the other half: that the *running daemon* refuses what it should, accepts what it
//! should, and that neither a refusal nor a log line nor a `Debug` rendering ever carries the
//! token.
//!
//! ## Why the "did it reach the handler" assertions are real
//!
//! A 401 proves a status code, not that the work was skipped. The probe here is a `PUT` to the
//! local host's file route aimed at a path inside a temporary directory: if the middleware let the
//! request through, the file appears. That is a side effect outside the process, so it cannot pass
//! for the wrong reason — and its control (the same request *with* the token, which does write the
//! file) is what distinguishes "refused" from "the route is broken".
//!
//! ## The sentinel
//!
//! Every leak assertion searches for `SENTINEL`. It is deliberately not key-shaped, because the
//! read-side redaction that masks key-shaped literals in a file display would hide a key-shaped
//! sentinel from the assertion and make the test pass for the wrong reason.

use std::sync::{Arc, Mutex, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use hx_server::{app, AppState};
use tower::ServiceExt;

/// The token these tests configure, and the value every leak assertion looks for.
const SENTINEL: &str = "hx-api-auth-sentinel-4d2b8e1f";

/// A config with no token, one with a literal token, and one naming an unresolvable reference.
fn config_yaml(token: Option<&str>) -> String {
    let api = match token {
        Some(value) => format!("api:\n  token: \"{value}\"\n"),
        None => String::new(),
    };
    format!(
        r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["dead-model"]
    credentials:
      - {{ id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }}

pools:
  interactive: {{ members: ["local/dead-model"] }}

roles:
  builder: interactive

search:
  backends: []
{api}"#
    )
}

/// The real `AppState::build`, so the token travels the path the daemon's does: `api.token` out of
/// the config, through `hx-secrets`, onto the state. A hand-injected token would test the
/// middleware and not the wiring that decides what the middleware checks.
async fn state(token: Option<&str>) -> Arc<AppState> {
    try_state(token).await.expect("state builds")
}

/// The same, for the cases where building is *supposed* to fail.
///
/// The ambient `HX_API_TOKEN` is cleared first, and that is load-bearing rather than tidiness: this
/// suite asserts things like "a config with no token and no `HX_API_TOKEN` has no token", and
/// `AppState::build` resolves the config and then falls back to that variable — the form a container
/// and a CI job use. A *test process* must not inherit a real credential from the developer's shell,
/// or `a_non_loopback_bind_with_no_token_is_refused...` fails for a reason that has nothing to do
/// with what it asserts. Clearing here rather than handing each test a token is the point: a test
/// that needed one would mean the loopback rule, not the test, was wrong.
///
/// The fallback itself is *not* left untested — it has its own file, `tests/api_token_env.rs`,
/// because `set_var` races any other test running in the same binary.
async fn try_state(token: Option<&str>) -> hx_core::error::Result<Arc<AppState>> {
    let mut config =
        hx_core::config::Config::from_yaml(&config_yaml(token)).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.keep().display().to_string();
    std::env::remove_var(hx_core::api_auth::API_TOKEN_ENV);
    let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    AppState::build(config, None, now).await
}

/// A GET with the `Authorization` header written out verbatim, for the shapes a caller reaches for
/// when it has the value but not the contract.
async fn get_raw(state: Arc<AppState>, uri: &str, authorization: Option<&str>) -> StatusCode {
    let mut request = Request::builder().uri(uri);
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    app(state)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// A GET, optionally presenting `bearer`.
async fn get(state: Arc<AppState>, uri: &str, bearer: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::builder().uri(uri);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app(state)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// A PUT with a JSON body, optionally presenting `authorization` verbatim.
///
/// The raw header is a parameter rather than a token so a test can send a *bare* token or another
/// scheme — the shapes a caller reaches for when it has the value but not the contract.
async fn put_raw(
    state: Arc<AppState>,
    uri: &str,
    body: serde_json::Value,
    authorization: Option<&str>,
) -> (StatusCode, String) {
    let mut request = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    let response = app(state)
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// A `PUT` of a file on the local host, aimed at a fresh path. Returns the path and the reply.
async fn write_probe(state: Arc<AppState>, authorization: Option<&str>) -> (String, StatusCode) {
    let dir = tempfile::tempdir().expect("temp dir");
    // `keep()` so the directory survives the assertion — the test asks whether the file exists,
    // and a directory deleted on drop would make that question unanswerable.
    let root = dir.keep();
    let path = root.join("auth-probe.txt");
    let path = path.display().to_string();
    let (status, _) = put_raw(
        state,
        "/v1/hosts/local/file",
        serde_json::json!({ "path": path, "contents": "written\n" }),
        authorization,
    )
    .await;
    (path, status)
}

#[tokio::test]
async fn a_request_with_no_token_is_a_401_and_does_not_reach_the_handler() {
    let state = state(Some(SENTINEL)).await;
    let (path, status) = write_probe(Arc::clone(&state), None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        !std::path::Path::new(&path).exists(),
        "the write must not have happened: the middleware let the request through"
    );

    // The control, and it is what makes the assertion above mean something: the same request with
    // the token *does* write the file. Without it, a broken route would look like a refusal.
    let (path, status) = write_probe(state, Some(&format!("Bearer {SENTINEL}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        std::path::Path::new(&path).exists(),
        "the control must write the file, or the test above proves nothing"
    );
}

#[tokio::test]
async fn a_request_with_the_correct_token_succeeds() {
    let state = state(Some(SENTINEL)).await;
    let (status, body) = get(state, "/v1/status", Some(SENTINEL)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("providers_configured"), "{body}");
}

#[tokio::test]
async fn a_correct_prefix_of_the_token_is_refused() {
    // The test that catches a comparison which returns on the first differing byte. Every prefix
    // length, so an early return at any offset is caught and not only one at zero.
    let state = state(Some(SENTINEL)).await;
    for cut in 0..SENTINEL.len() {
        let (status, _) = get(Arc::clone(&state), "/v1/status", Some(&SENTINEL[..cut])).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a {cut}-byte prefix of the token was accepted"
        );
    }

    // And the whole thing still works, so the loop above is not passing because everything is
    // refused.
    let (status, _) = get(state, "/v1/status", Some(SENTINEL)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_token_is_accepted_only_as_a_bearer_credential() {
    let state = state(Some(SENTINEL)).await;

    for authorization in [
        // The value on its own, with no scheme.
        SENTINEL.to_string(),
        // Another scheme, including one that is real but not this.
        format!("Basic {SENTINEL}"),
        format!("Token {SENTINEL}"),
        format!("Bearerx {SENTINEL}"),
        // The scheme with no credential.
        "Bearer".to_string(),
        "Bearer ".to_string(),
    ] {
        let status = get_raw(Arc::clone(&state), "/v1/status", Some(&authorization)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{authorization:?} must not be read as a bearer token"
        );
    }

    // The scheme is matched case-insensitively, because HTTP auth schemes are.
    let status = get_raw(state, "/v1/status", Some(&format!("bearer {SENTINEL}"))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_missing_token_and_a_wrong_one_are_indistinguishable() {
    // A body or a challenge that differed would be an oracle: a caller could learn whether a token
    // is configured at all, and could tell a near-miss from a miss. Both must be the same bytes.
    let state = state(Some(SENTINEL)).await;

    let missing = app(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let wrong = app(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/v1/status")
                .header("authorization", "Bearer not-the-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.status(), missing.status());
    let challenge = |response: &axum::http::Response<Body>| {
        response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };
    assert_eq!(
        challenge(&missing).as_deref(),
        Some("Bearer"),
        "the challenge names the scheme a client should use"
    );
    assert_eq!(challenge(&wrong), challenge(&missing));

    let missing_body = missing.into_body().collect().await.unwrap().to_bytes();
    let wrong_body = wrong.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        missing_body, wrong_body,
        "the two refusals must be byte-identical"
    );
    assert!(
        !String::from_utf8_lossy(&missing_body).contains(SENTINEL),
        "and must not carry the token"
    );
}

#[tokio::test]
async fn health_and_the_web_page_answer_without_a_token_and_nothing_else_does() {
    // The two exemptions, as a pair with the routes that are *not* exempt: an exemption that leaked
    // into `/v1/...` would be invisible if only the exempt paths were asserted.
    let state = state(Some(SENTINEL)).await;

    for uri in ["/healthz", "/"] {
        let (status, _) = get(Arc::clone(&state), uri, None).await;
        assert_eq!(status, StatusCode::OK, "{uri} is exempt");
    }

    for uri in ["/v1/status", "/v1/sessions", "/v1/approvals", "/v1/hosts"] {
        let (status, _) = get(Arc::clone(&state), uri, None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{uri} must require a token"
        );
    }
}

#[tokio::test]
async fn a_token_in_a_query_string_is_not_a_credential_on_an_ordinary_request() {
    // The WebSocket exception is narrowed to upgrade requests on purpose. This is the assertion
    // that keeps it narrow: the same query parameter on a plain GET is worth nothing, so a token
    // cannot be smuggled into a URL that ends up in a log or a `Referer` and used against the API.
    let state = state(Some(SENTINEL)).await;
    let (status, _) = get(state, &format!("/v1/status?token={SENTINEL}"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_in_a_query_string_with_upgrade_headers_on_a_non_websocket_route_is_refused() {
    // Finding F2: ?token= is accepted only on routes that genuinely are WebSocket upgrades
    // (/v1/sessions/{id}/ws, /v1/terminals/{id}/ws). An ordinary route claiming upgrade
    // headers must not consult the query parameter as a credential.
    let state = state(Some(SENTINEL)).await;
    let request = Request::builder()
        .uri(format!("/v1/status?token={SENTINEL}"))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();
    let response = app(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_non_loopback_bind_with_no_token_is_refused_by_the_check_the_daemon_runs() {
    // The composition `hxd` performs, asserted on the returned error and not on a log line: a
    // config with no token produces a state with no token, and the startup rule then refuses a
    // routable bind. This is the fail-closed half — the daemon must not start unprotected.
    let state = state(None).await;
    assert!(
        state.api_token.is_none(),
        "a config with no token and no HX_API_TOKEN has no token"
    );

    let err = hx_core::api_auth::require_token_for_bind("0.0.0.0:8787", state.api_token.is_some())
        .unwrap_err()
        .to_string();
    assert!(err.contains("api.token"), "{err}");
    assert!(err.contains("HX_API_TOKEN"), "{err}");
    assert!(err.contains("0.0.0.0:8787"), "{err}");

    // And loopback still starts, which is what keeps the rest of this suite's fixtures legal.
    hx_core::api_auth::require_token_for_bind("127.0.0.1:8787", false)
        .expect("a loopback bind needs no token");
}

#[tokio::test]
async fn a_config_naming_a_token_it_cannot_resolve_fails_to_build_rather_than_serving_without_one()
{
    // The failure that would be worst if it degraded: a deployment whose config says it is
    // authenticated, and which is not.
    let mut config = hx_core::config::Config::from_yaml(&config_yaml(Some("vault:api/daemon")))
        .expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.keep().display().to_string();

    // Matched rather than `expect_err`: `AppState` is not `Debug`, and making it one to satisfy a
    // test would be a test deciding the shape of production code.
    let err = match AppState::build(config, None, chrono::Utc::now()).await {
        Ok(_) => panic!("an unresolvable token reference must not build"),
        Err(err) => err.to_string(),
    };
    assert!(err.contains("api.token"), "{err}");
    assert!(!err.contains(SENTINEL), "{err}");
}

#[tokio::test]
async fn the_token_appears_in_no_error_body_and_no_debug_rendering() {
    // Two of the three places a token leaks: a response and a dump. The third — a log line — is
    // the test below, which captures what the tracing subscriber is actually handed.
    let state = state(Some(SENTINEL)).await;

    let (_, body) = get(Arc::clone(&state), "/v1/status", None).await;
    assert!(
        !body.contains(SENTINEL),
        "the 401 body carried the token: {body}"
    );

    let (_, body) = get(Arc::clone(&state), "/v1/status", Some("wrong")).await;
    assert!(!body.contains(SENTINEL), "{body}");

    // The config is the object a dump of the daemon would print, and it is the one holding the
    // value as written.
    let printed = format!("{:?}", state.config);
    assert!(
        !printed.contains(SENTINEL),
        "a `Debug` dump of the config carried the token"
    );
    assert!(
        printed.contains("<redacted>"),
        "and still says a token is configured: {printed}"
    );

    // The resolved token's own rendering, which is what a `tracing::debug!(?token)` would print.
    let printed = format!("{:?}", state.api_token);
    assert!(!printed.contains(SENTINEL), "{printed}");
}

/// A writer that keeps every byte the tracing subscriber formats, so a test can search it.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn nothing_on_the_refusal_paths_logs_the_token() {
    // A tripwire rather than a description of today's code: the middleware logs nothing at all, so
    // this cannot fail for a reason in the code as written — it fails the moment somebody adds a
    // `tracing::debug!(token = %…)` or an `anyhow` context that quotes the value, which is exactly
    // the change that would otherwise ship silently. The telegram transport's equivalent test found
    // a real leak of the same shape, through `reqwest`'s `Display` of a token-bearing URL.
    //
    // A plain `#[test]` with its own current-thread runtime, because `with_default` installs a
    // thread-local subscriber: it has to be in scope for the whole run, which an `await` in an
    // async test cannot promise across a scheduler.
    let capture = Capture::default();
    let sink = Arc::clone(&capture.0);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        // A marker event of our own, so the "the capture is not empty" control below does not
        // depend on which warnings this environment happens to emit (a machine with a container
        // engine produces none of them).
        tracing::debug!(marker = "hx-auth-log-capture-probe", "capture probe");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            // The 401 path, with the token configured and with a wrong one presented.
            let daemon = state(Some(SENTINEL)).await;
            let _ = get(Arc::clone(&daemon), "/v1/status", None).await;
            let _ = get(Arc::clone(&daemon), "/v1/status", Some("wrong")).await;
            let _ = get(Arc::clone(&daemon), "/v1/status", Some(SENTINEL)).await;
            let _ = write_probe(daemon, None).await;

            // The startup-refusal path.
            let _ = hx_core::api_auth::require_token_for_bind("0.0.0.0:8787", false);
            // And the resolution-failure path, which is where a reference is echoed.
            let _ = try_state(Some("vault:api/daemon")).await;
        });
    });

    let logged = String::from_utf8(sink.lock().unwrap().clone()).unwrap_or_default();
    assert!(
        !logged.contains(SENTINEL),
        "a log line carried the token:\n{logged}"
    );
    // The control: the subscriber is installed and receiving, so the assertion above is about the
    // paths and not about a capture that was never wired up.
    assert!(
        logged.contains("hx-auth-log-capture-probe"),
        "the capture saw nothing, so the absence of the token proves nothing:\n{logged}"
    );
}
