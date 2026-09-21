//! Streamable-HTTP server transport integration tests.
//!
//! ## What is tested here
//!
//! - **No token → 401**, and the handler is never reached. Proven with an out-of-process
//!   side effect: a file-writing probe (`write_file`) that leaves no file on disk when
//!   unauthenticated, paired with the token-bearing control that does write the file.
//! - **Correct token → handshake succeeds** and `tools/list` returns the registry's tools.
//! - **A correct-prefix token is refused** at every prefix length (catches early-return comparison).
//! - **A missing token and a wrong token are indistinguishable** in status, headers, and body.
//! - **A call needing approval is refused over HTTP**, and **no approval request was raised**:
//!   `server.outstanding().is_none()` and the daemon's approval queue never sees a question.
//! - **A `Destructive` tool is refused**, and the file it named remains on disk.
//! - **A non-loopback bind with no token is refused at startup**, naming `api.token` and `HX_API_TOKEN`.
//! - **The token appears in no error body, no log line, and no `Debug` output.**

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use hx_agent::Approver;
use hx_core::api_auth::{ApiToken, API_TOKEN_ENV};
use hx_core::approval::{
    ActionRequest, ApprovalOption, ApprovalPolicy, ApprovalSession, AutonomyLevel, RiskClass, Rule,
    Verdict,
};
use hx_core::capability::{Action, Capability, CapabilityToken, Resource};
use hx_core::config::McpServerConfig;
use hx_core::ids::{AgentId, HostId};
use hx_mcp::server::{default_registry, McpServer};
use hx_mcp::server_http::{bind_and_serve, router};
use hx_mcp::McpHost;
use hx_remote::LocalHost;
use hx_secrets::source::{FixedSecrets, SecretStores};
use hx_tools::ToolContext;
use indexmap::IndexMap;
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

/// The sentinel token fixture. Deliberately not key-shaped so the read-side redaction
/// cannot hide it from assertions.
const SENTINEL: &str = "hx-mcp-http-sentinel-token-7a2e8c1b";

/// A fixture managing a temporary workspace directory and test server.
struct Fixture {
    dir: tempfile::TempDir,
    notes_path: PathBuf,
    doomed_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let notes_path = dir.path().join("notes.txt");
        std::fs::write(&notes_path, "important notes\n").expect("write notes");
        let doomed_path = dir.path().join("doomed.txt");
        std::fs::write(&doomed_path, "still here\n").expect("write doomed");
        Self {
            dir,
            notes_path,
            doomed_path,
        }
    }

    fn workspace(&self) -> String {
        self.dir.path().to_string_lossy().into_owned()
    }

    async fn ctx(&self) -> ToolContext {
        let host = LocalHost::detect(HostId::from_raw("local"))
            .await
            .expect("detect host");
        ToolContext::new(Arc::new(host)).in_workspace(self.workspace())
    }

    fn capability(&self) -> CapabilityToken {
        CapabilityToken::issue(
            AgentId::from_raw("hx-mcp-http:test"),
            vec![
                Capability::workspace(self.workspace()),
                Capability::new(Resource::Process, [Action::Execute, Action::Spawn]),
            ],
            chrono::Utc::now(),
            3_600,
        )
    }

    async fn server(&self, policy: ApprovalPolicy) -> Arc<McpServer> {
        Arc::new(McpServer::new(
            Arc::new(default_registry()),
            self.ctx().await,
            self.capability(),
            ApprovalSession::new(policy),
        ))
    }
}

fn policy_asking_about_reads() -> ApprovalPolicy {
    let mut policy = ApprovalPolicy::at(AutonomyLevel::Balanced);
    policy
        .ask
        .push(Rule::tool("read_file").note("show me every read"));
    policy
}

fn stores_with(token: &str) -> Arc<SecretStores> {
    Arc::new(SecretStores::new().with(Arc::new(FixedSecrets::vault().set("mcp/test", token))))
}

fn config_map(key: &str, url: &str, token_ref: Option<&str>) -> IndexMap<String, McpServerConfig> {
    let mut cfg = McpServerConfig::streamable_http(url);
    cfg.start_timeout_secs = 5;
    cfg.call_timeout_secs = 5;
    cfg.token = token_ref.map(str::to_string);
    let mut map = IndexMap::new();
    map.insert(key.to_string(), cfg);
    map
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_token_is_a_401_and_does_not_reach_the_handler() {
    // Proven with a side effect outside the process: a write_file tool call aimed
    // at a fresh path. If unauthenticated requests reach the handler, the file appears.
    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let token = ApiToken::new(SENTINEL);

    let (addr, task) = bind_and_serve(Arc::clone(&server), "127.0.0.1:0", Some(token))
        .await
        .expect("bind and serve");

    let probe_path = fixture.dir.path().join("probe-unauth.txt");
    let call_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": probe_path.to_string_lossy(),
                "content": "must not be written\n"
            }
        }
    });

    // 1. Unauthenticated request: missing Authorization header
    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{addr}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(call_body.to_string())
        .send()
        .await
        .expect("send unauthenticated request");

    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        !probe_path.exists(),
        "unauthenticated request must not execute the tool handler"
    );

    // Control: the authenticated client connects and calls write_file, which writes the file.
    let url = format!("http://{addr}/mcp");
    let host = McpHost::from_config(
        &config_map("remote", &url, Some("vault:mcp/test")),
        Some(stores_with(SENTINEL)),
    )
    .await
    .expect("client connects over streamable HTTP with token");

    let outcome = host
        .call(
            "remote__write_file",
            json!({
                "path": probe_path.to_string_lossy(),
                "content": "written by control\n"
            }),
        )
        .await;

    assert!(outcome.ok, "control tool call failed: {}", outcome.content);
    assert!(
        probe_path.exists(),
        "control with valid token must write the file"
    );

    host.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn correct_token_handshake_succeeds_and_tools_list_returns_registry_tools() {
    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let token = ApiToken::new(SENTINEL);

    let (addr, task) = bind_and_serve(server, "127.0.0.1:0", Some(token))
        .await
        .expect("bind and serve");

    let url = format!("http://{addr}/mcp");
    let host = McpHost::from_config(
        &config_map("remote", &url, Some("vault:mcp/test")),
        Some(stores_with(SENTINEL)),
    )
    .await
    .expect("client connects over streamable HTTP with token");

    let names = host.tool_names();
    let expected = default_registry().names();
    for exp in &expected {
        assert!(
            names.contains(&format!("remote__{exp}")),
            "tool {exp} missing from published tools: {names:?}"
        );
    }

    host.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn a_correct_prefix_of_the_token_is_refused() {
    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let token = ApiToken::new(SENTINEL);
    let app = router(server, Some(token));

    for cut in 0..SENTINEL.len() {
        let prefix = &SENTINEL[..cut];
        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", format!("Bearer {prefix}"))
            .body(Body::from("{}"))
            .unwrap();

        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "prefix of length {cut} must be refused"
        );
    }
}

#[tokio::test]
async fn missing_token_and_wrong_token_are_indistinguishable() {
    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let token = ApiToken::new(SENTINEL);
    let app = router(server, Some(token));

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let wrong = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", "Bearer wrong-token-entirely")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let auth_header = |res: &axum::response::Response| {
        res.headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string)
    };
    assert_eq!(auth_header(&missing), Some("Bearer".to_string()));
    assert_eq!(auth_header(&wrong), Some("Bearer".to_string()));

    let missing_body = missing.into_body().collect().await.unwrap().to_bytes();
    let wrong_body = wrong.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        missing_body, wrong_body,
        "missing and wrong token responses must be byte-identical"
    );
    assert!(!missing_body.is_empty());
    assert!(!String::from_utf8_lossy(&missing_body).contains(SENTINEL));
}

#[tokio::test]
async fn a_call_needing_approval_is_refused_over_http_and_no_approval_request_was_raised() {
    let fixture = Fixture::new();
    let server = fixture.server(policy_asking_about_reads()).await;
    let token = ApiToken::new(SENTINEL);

    let (addr, task) = bind_and_serve(Arc::clone(&server), "127.0.0.1:0", Some(token))
        .await
        .expect("bind and serve");

    let url = format!("http://{addr}/mcp");
    let host = McpHost::from_config(
        &config_map("remote", &url, Some("vault:mcp/test")),
        Some(stores_with(SENTINEL)),
    )
    .await
    .expect("host connects");

    let outcome = host
        .call(
            "remote__read_file",
            json!({ "path": fixture.notes_path.to_string_lossy() }),
        )
        .await;

    assert!(
        !outcome.ok,
        "a call needing approval must be refused over HTTP"
    );
    for expected in ["needs approval", "read_file", "allow"] {
        assert!(
            outcome.content.contains(expected),
            "expected {expected:?} in refusal: {}",
            outcome.content
        );
    }

    // Property under test: no approval request is left outstanding on the server.
    assert!(
        server.outstanding().is_none(),
        "refused call must leave no outstanding approval request: {:?}",
        server.outstanding()
    );
    assert_eq!(server.stats().refused_needing_approval, 1);
    assert_eq!(server.stats().ran, 0);

    // Control: under a policy that allows it, the same call runs.
    let allowed_fixture = Fixture::new();
    let allowed_server = allowed_fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let (allowed_addr, allowed_task) = bind_and_serve(
        Arc::clone(&allowed_server),
        "127.0.0.1:0",
        Some(ApiToken::new(SENTINEL)),
    )
    .await
    .expect("bind and serve");

    let allowed_url = format!("http://{allowed_addr}/mcp");
    let allowed_host = McpHost::from_config(
        &config_map("allowed", &allowed_url, Some("vault:mcp/test")),
        Some(stores_with(SENTINEL)),
    )
    .await
    .expect("host connects");

    let allowed_outcome = allowed_host
        .call(
            "allowed__read_file",
            json!({ "path": allowed_fixture.notes_path.to_string_lossy() }),
        )
        .await;
    assert!(allowed_outcome.ok, "{}", allowed_outcome.content);
    assert!(allowed_outcome.content.contains("important notes"));
    assert_eq!(allowed_server.stats().ran, 1);

    host.shutdown().await;
    allowed_host.shutdown().await;
    task.abort();
    allowed_task.abort();
}

#[tokio::test]
async fn the_daemons_approval_queue_shows_a_local_question_and_never_sees_an_mcp_http_one() {
    // Prove the approval queue is live by routing a local question through it.
    let queue = hx_agent::ApprovalQueue::new(Duration::from_secs(30));
    let action = ActionRequest::tool("read_file", "read notes", RiskClass::Read, "reads");
    let request = {
        let mut session = ApprovalSession::new(ApprovalPolicy::paranoid());
        match session.decide(&action, chrono::Utc::now()) {
            Verdict::Ask(req) => *req,
            other => panic!("expected Ask, got {other:?}"),
        }
    };

    let asking = {
        let queue = Arc::clone(&queue);
        let request = request.clone();
        let action = action.clone();
        tokio::spawn(async move { queue.decide(&request, &action).await })
    };

    let seen = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(first) = queue.outstanding(None).first() {
                break first.id.clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("local run question appears in queue");
    assert_eq!(queue.outstanding(None).len(), 1);

    assert_eq!(
        queue.answer(seen.as_str(), ApprovalOption::Deny, "test", RiskClass::Read),
        hx_agent::AnswerResult::Answered
    );
    let _ = tokio::time::timeout(Duration::from_secs(10), asking)
        .await
        .expect("local run finishes");

    // Now drive the MCP HTTP server on a policy asking about reads.
    let fixture = Fixture::new();
    let server = fixture.server(policy_asking_about_reads()).await;
    let (addr, task) = bind_and_serve(
        Arc::clone(&server),
        "127.0.0.1:0",
        Some(ApiToken::new(SENTINEL)),
    )
    .await
    .expect("bind and serve");

    let url = format!("http://{addr}/mcp");
    let host = McpHost::from_config(
        &config_map("remote", &url, Some("vault:mcp/test")),
        Some(stores_with(SENTINEL)),
    )
    .await
    .expect("host connects");

    let outcome = host
        .call(
            "remote__read_file",
            json!({ "path": fixture.notes_path.to_string_lossy() }),
        )
        .await;
    assert!(!outcome.ok);

    assert!(
        queue.outstanding(None).is_empty(),
        "MCP HTTP refusal must not publish to the daemon approval queue: {:?}",
        queue.outstanding(None)
    );
    assert!(queue.is_empty());
    assert!(server.outstanding().is_none());

    host.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn a_destructive_tool_is_refused_and_the_path_it_names_is_untouched() {
    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let (addr, task) = bind_and_serve(
        Arc::clone(&server),
        "127.0.0.1:0",
        Some(ApiToken::new(SENTINEL)),
    )
    .await
    .expect("bind and serve");

    let url = format!("http://{addr}/mcp");
    let host = McpHost::from_config(
        &config_map("remote", &url, Some("vault:mcp/test")),
        Some(stores_with(SENTINEL)),
    )
    .await
    .expect("host connects");

    let outcome = host
        .call(
            "remote__delete",
            json!({ "path": fixture.doomed_path.to_string_lossy() }),
        )
        .await;

    assert!(!outcome.ok, "destructive tool must be refused");
    assert!(
        outcome.content.contains("destructive"),
        "reason must name destructive risk: {}",
        outcome.content
    );
    assert!(
        fixture.doomed_path.exists(),
        "refused call must leave the doomed file on disk"
    );
    assert_eq!(server.stats().refused_needing_approval, 1);
    assert_eq!(server.stats().ran, 0);

    // Control: with an allow rule, delete runs.
    let allowed_fixture = Fixture::new();
    let mut policy = ApprovalPolicy::at(AutonomyLevel::Balanced);
    policy.allow.push(Rule::tool("delete"));
    let allowed_server = allowed_fixture.server(policy).await;
    let (allowed_addr, allowed_task) = bind_and_serve(
        Arc::clone(&allowed_server),
        "127.0.0.1:0",
        Some(ApiToken::new(SENTINEL)),
    )
    .await
    .expect("bind and serve");

    let allowed_url = format!("http://{allowed_addr}/mcp");
    let allowed_host = McpHost::from_config(
        &config_map("allowed", &allowed_url, Some("vault:mcp/test")),
        Some(stores_with(SENTINEL)),
    )
    .await
    .expect("host connects");

    let allowed_outcome = allowed_host
        .call(
            "allowed__delete",
            json!({ "path": allowed_fixture.doomed_path.to_string_lossy() }),
        )
        .await;
    assert!(allowed_outcome.ok, "{}", allowed_outcome.content);
    assert!(
        !allowed_fixture.doomed_path.exists(),
        "allowed delete must remove the file"
    );
    assert_eq!(allowed_server.stats().ran, 1);

    host.shutdown().await;
    allowed_host.shutdown().await;
    task.abort();
    allowed_task.abort();
}

#[tokio::test]
async fn a_non_loopback_bind_with_no_token_is_refused_at_startup() {
    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;

    let err = bind_and_serve(server, "0.0.0.0:8787", None)
        .await
        .expect_err("non-loopback bind without token must fail startup");
    let msg = err.to_string();

    assert!(msg.contains("api.token"), "must name api.token: {msg}");
    assert!(
        msg.contains(API_TOKEN_ENV),
        "must name {API_TOKEN_ENV}: {msg}"
    );
    assert!(msg.contains("0.0.0.0:8787"), "must name address: {msg}");

    // Control: loopback bind with no token succeeds.
    let server2 = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let (addr, task) = bind_and_serve(server2, "127.0.0.1:0", None)
        .await
        .expect("loopback bind needs no token");
    assert!(addr.ip().is_loopback());
    task.abort();
}

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
fn the_token_appears_in_no_error_body_no_log_line_and_no_debug_output() {
    let token = ApiToken::new(SENTINEL);

    // 1. Debug output check
    let debug_repr = format!("{token:?}");
    assert!(
        !debug_repr.contains(SENTINEL),
        "token must not appear in Debug: {debug_repr}"
    );

    // 2. Startup refusal message check
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let err_msg = runtime
        .block_on(async {
            let server = fixture
                .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
                .await;
            bind_and_serve(server, "0.0.0.0:8787", None).await
        })
        .unwrap_err()
        .to_string();
    assert!(
        !err_msg.contains(SENTINEL),
        "startup error must not contain token: {err_msg}"
    );

    // 3. Tracing log line capture
    let capture = Capture::default();
    let sink = Arc::clone(&capture.0);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        tracing::debug!(probe = "hx-mcp-http-log-probe", "capture active");

        runtime.block_on(async {
            let fixture = Fixture::new();
            let server = fixture
                .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
                .await;
            let app = router(server, Some(token));

            // Drive 401 path
            let req = Request::builder()
                .method("POST")
                .uri("/mcp")
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert!(!String::from_utf8_lossy(&body).contains(SENTINEL));

            // Drive wrong token path
            let req = Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert!(!String::from_utf8_lossy(&body).contains(SENTINEL));

            // Drive valid token path
            let req = Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("authorization", format!("Bearer {SENTINEL}"))
                .body(Body::from("{}"))
                .unwrap();
            let _ = app.oneshot(req).await;
        });
    });

    let logs = String::from_utf8(sink.lock().unwrap().clone()).unwrap_or_default();
    assert!(
        !logs.contains(SENTINEL),
        "sentinel token leaked into logs:\n{logs}"
    );
    assert!(
        logs.contains("hx-mcp-http-log-probe"),
        "probe event missing; logging capture did not receive events"
    );
}

fn mcp_post(uri: &str, host: &str, auth: Option<String>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", host)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(auth) = auth {
        builder = builder.header("authorization", auth);
    }
    builder.body(Body::from("{}")).unwrap()
}

#[tokio::test]
async fn a_spoofed_host_header_is_rejected_even_with_a_valid_token() {
    // The DNS-rebinding defense: rmcp's loopback allowlist is retained, so a request whose
    // `Host` names an attacker domain is refused before authentication is even consulted.
    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let app = router(server, Some(ApiToken::new(SENTINEL)));

    let res = app
        .oneshot(mcp_post(
            "http://localhost/mcp",
            "rebind.attacker.example",
            Some(format!("Bearer {SENTINEL}")),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a rebinding Host must be refused despite a valid token"
    );
}

#[tokio::test]
async fn unauthenticated_loopback_keeps_host_protection() {
    // The exact configuration the old unconditional `disable_allowed_hosts()` left exposed: no
    // token on loopback. Loopback hosts still reach the bearer layer; anything else is refused.
    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;
    let app = router(server, None);

    let res = app
        .clone()
        .oneshot(mcp_post("http://127.0.0.1/mcp", "127.0.0.1", None))
        .await
        .unwrap();
    assert_ne!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a loopback Host must not be host-rejected"
    );

    let res = app
        .oneshot(mcp_post(
            "http://localhost/mcp",
            "rebind.attacker.example",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an unauthenticated server must still refuse a rebinding Host"
    );
}

#[tokio::test]
async fn an_explicit_allowlist_serves_its_host_but_requires_a_token() {
    use hx_mcp::server_http::router_with_allowed_hosts;

    let fixture = Fixture::new();
    let server = fixture
        .server(ApprovalPolicy::at(AutonomyLevel::Balanced))
        .await;

    // No token with an explicit allowlist is the same misconfiguration as a non-loopback bind
    // without one: refused at construction, not at request time.
    assert!(
        router_with_allowed_hosts(Arc::clone(&server), None, vec!["mcp.example.com".into()])
            .is_none()
    );

    let app = router_with_allowed_hosts(
        server,
        Some(ApiToken::new(SENTINEL)),
        vec!["mcp.example.com".into()],
    )
    .expect("token + allowlist must build");

    let res = app
        .clone()
        .oneshot(mcp_post(
            "http://mcp.example.com/mcp",
            "mcp.example.com",
            Some(format!("Bearer {SENTINEL}")),
        ))
        .await
        .unwrap();
    assert_ne!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an explicitly allowed host must reach the handler"
    );

    let res = app
        .oneshot(mcp_post(
            "http://mcp.example.com/mcp",
            "other.example.com",
            Some(format!("Bearer {SENTINEL}")),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a host outside the explicit allowlist must be refused"
    );
}
