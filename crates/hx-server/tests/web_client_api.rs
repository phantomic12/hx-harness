//! The web client is served, and it is the real page.
//!
//! A front end that 404s, or that is served as text, is a daemon that looks healthy from the API and
//! is unusable from a browser. This checks the one thing an API test cannot: that `GET /` returns
//! HTML which actually contains *this* client — not an empty body and not a placeholder.

use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use hx_agent::{ApprovalQueue, ModelCall};
use hx_core::approval::{
    ActionRequest, ApprovalPolicy, ApprovalRequest, ApprovalSession, AutonomyLevel, Verdict,
};
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use hx_provider::{ChatRequest, ChatResponse, ModelRouter, ProviderRegistry};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, ModelFactory};
use hx_store::Store;

struct DeadModel;

#[async_trait]
impl ModelCall for DeadModel {
    async fn complete(&self, _req: ChatRequest) -> Result<ChatResponse> {
        Err(HxError::Provider("not used in this test".to_string()))
    }
    fn model(&self) -> String {
        "dead".to_string()
    }
    fn provider_id(&self) -> ProviderId {
        ProviderId::from_raw("local")
    }
    fn credential_id(&self) -> CredentialId {
        CredentialId::from_raw("local-1")
    }
}

struct Dead(Arc<DeadModel>);

impl ModelFactory for Dead {
    fn for_role(&self, _role: &str) -> Result<Arc<dyn ModelCall>> {
        Ok(Arc::clone(&self.0) as Arc<dyn ModelCall>)
    }
}

const CONFIG: &str = r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["dead-model"]
    credentials:
      - { id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }

pools:
  interactive: { members: ["local/dead-model"] }

roles:
  builder: interactive

search:
  backends: []
"#;

struct Server {
    addr: String,
    /// The daemon behind the address, so a test can put something into a shared structure (the
    /// approval queue) and then read it back over HTTP — which is the only way to tell "the route
    /// serves it" from "the page's script believes it".
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

async fn harness() -> Server {
    harness_with_token(None).await
}

/// The same daemon, optionally requiring a bearer token.
///
/// The token is passed in rather than read from the environment so the test states its own
/// configuration: a test whose credential came from the ambient environment would pass or fail
/// depending on the machine it ran on.
async fn harness_with_token(token: Option<&str>) -> Server {
    let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.path().join("data").display().to_string();
    let now = chrono::Utc::now();
    let router = ModelRouter::from_config(&config, now).expect("router builds");
    let client = reqwest::Client::new();
    let providers =
        ProviderRegistry::from_config(&config, client.clone()).expect("providers build");
    let search = BackendRegistry::from_config(
        &config.search,
        client.clone(),
        &hx_secrets::SecretStores::new(),
    )
    .expect("search");
    let store = Store::from_config(&config).expect("store opens");

    let state = AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(Mutex::new(router)),
        providers: Arc::new(RwLock::new(providers)),
        provider_configs: Default::default(),
        config_path: None,
        secrets: Arc::new(SecretStores::new().with(Arc::new(EnvSecrets))),
        store: Arc::new(store),
        models: Arc::new(RwLock::new(Arc::new(Dead(Arc::new(DeadModel))))),
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        approvals: ApprovalQueue::new(std::time::Duration::from_secs(1)),
        phone: None,
        search: Arc::new(search),
        sandboxes: None,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now,
        // No token by default: these tests bind loopback, which is exactly the deployment where a
        // token is optional. A test that needed one here would mean the rule, not the test, was
        // wrong.
        api_token: token.map(hx_core::api_auth::ApiToken::new),
        allowed_origins: Vec::new(),
        webhooks: Default::default(),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let router = app(Arc::clone(&state));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    Server {
        addr: addr.to_string(),
        state,
        _dir: dir,
    }
}

#[tokio::test]
async fn the_root_serves_the_web_client_as_html() {
    let server = harness().await;
    let response = reqwest::Client::new()
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "the client must be served"
    );

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "served as {content_type:?}, which a browser would render as source"
    );

    let body = response.text().await.expect("a body");
    assert!(body.contains("<title>hx</title>"), "the title is missing");
    assert!(
        body.contains("/v1/terminals/"),
        "the page must attach a terminal, which is the M2 criterion"
    );
    assert!(
        body.contains("/v1/sessions/") && body.contains("since_seq"),
        "the page must resume the session stream rather than restart it"
    );
    assert!(
        body.contains("/v1/hosts") && body.contains("No hosts are configured."),
        "the page must render the hosts pane from the real /v1/hosts route"
    );
}

#[tokio::test]
async fn the_page_is_served_without_a_token_because_a_browser_cannot_send_one() {
    // The exemption, tested as a pair: the page loads *and* the API behind it does not. Serving
    // `GET /` to a browser is not a hole — it is a static file embedded in the binary, and a
    // navigation cannot carry an `Authorization` header, so requiring one would make the page
    // unreachable exactly when a token is configured.
    let server = harness_with_token(Some("sentinel-token-for-the-web-client-test")).await;
    let client = reqwest::Client::new();

    let page = client
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response");
    assert_eq!(page.status(), reqwest::StatusCode::OK, "the page loads");

    let api = client
        .get(format!("http://{}/v1/status", server.addr))
        .send()
        .await
        .expect("a response");
    assert_eq!(
        api.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "and the API behind it does not answer without the token"
    );
}

#[tokio::test]
async fn the_page_carries_the_bearer_token_on_every_call_it_makes() {
    // A page that renders but sends no token is unusable against a daemon that requires one, so
    // the wiring is part of what "the web client is served" has to mean. These assertions are about
    // the served text, which is the only thing this test can see — the behaviour is the daemon's
    // 401 and the panel is a browser's.
    let server = harness().await;
    let body = reqwest::Client::new()
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response")
        .text()
        .await
        .expect("a body");

    assert!(
        body.contains("Bearer ${token}"),
        "the page must send the token as a bearer credential"
    );
    assert!(
        body.contains("hx.api.token"),
        "and keep it somewhere a reload does not lose it"
    );
    assert!(
        body.contains("id=\"token-input\""),
        "and give the operator somewhere to put it"
    );
    assert!(
        body.contains("?token=") || body.contains("token=${encodeURIComponent"),
        "and carry it on the WebSocket URLs, which cannot take a header"
    );
    // The property that keeps this true as routes are added: every authenticated call goes through
    // the one helper, so a new pane cannot forget the header. The login call is the one exception,
    // and it is one by construction — it has no token yet, and attaching a stale bearer (or letting
    // its 401 open the login panel) is exactly what the comment above `doLogin` refuses.
    let rest = body.as_str();
    if let Some(login) = rest.find("async function doLogin") {
        if let Some(end) = rest[login..].find("\nasync function ") {
            let (before, after_and) = rest.split_at(login);
            let after = &after_and[end..];
            assert!(
                !before.contains("await fetch(`${API}") && !after.contains("await fetch(`${API}"),
                "a call site outside doLogin bypasses apiFetch, and would be sent without the token"
            );
            return;
        }
    }
    assert!(
        !body.contains("await fetch(`${API}"),
        "a call site bypasses apiFetch, and would be sent without the token"
    );
}

/// The remaining unattended budget travels with the question, and it is the run's own number.
///
/// The tempting wrong test is a grep of the served page for the word `unattended`, which passes for
/// a number typed into the HTML just as readily as for a real one. So this drives the value the way
/// the daemon produces it — `hx-core`'s [`ApprovalSession`] decides, its own counter is what the
/// question carries — puts the questions where a run puts them (the shared queue, scoped to a
/// session), and reads them back off `/v1/approvals`.
///
/// The control is the cadence. The two sessions differ in exactly one field, the unattended budget,
/// and the served remainders have to differ by the same amount. A number baked into the page, or a
/// route that dropped the field, cannot satisfy both of the first two assertions.
///
/// The page half is deliberately weaker, and stated as such: the browser stack is not available
/// here, so the page's script is not *driven*. What is asserted is that the served page reads the
/// exact field name the payload carries — which proves the page is not reading a field nobody
/// sends, and does **not** prove the card renders. Rendering is the browser's, and this is the
/// limit of what a test without one can claim.
#[tokio::test]
async fn the_remaining_unattended_budget_travels_with_the_question_and_tracks_the_policy() {
    let server = harness().await;
    let now = chrono::Utc::now();

    // A question asked by a session with `budget`, one unreviewed action into it. Built through
    // `decide` rather than as a literal, so what the route serves is the shape a run produces and
    // not a fixture that can drift away from it.
    let asked = |budget: u64| -> ApprovalRequest {
        let policy = ApprovalPolicy::at(AutonomyLevel::Balanced).with_unattended_budget(budget);
        let mut session = ApprovalSession::new(policy);
        // `ls` is below `balanced`'s threshold, so nobody is asked and the budget is spent by one.
        assert!(
            session
                .decide(&ActionRequest::shell("ls"), now)
                .is_allowed(),
            "the fixture needs one auto-approved action to have spent part of the budget"
        );
        match session.decide(&ActionRequest::shell("rm -rf ./build"), now) {
            Verdict::Ask(request) => *request,
            other => panic!("a destructive command must be asked about, got {other:?}"),
        }
    };
    let tight = asked(3);
    let loose = asked(10);

    // Where a run's question goes. `decide_in` waits for an answer, so it is driven from a task and
    // the shared queue is what the test then reads — the same object `/v1/approvals` serves from.
    let action = ActionRequest::shell("rm -rf ./build");
    for (request, session) in [(&tight, "ses_tight"), (&loose, "ses_loose")] {
        let queue = Arc::clone(&server.state.approvals);
        let request = request.clone();
        let action = action.clone();
        tokio::spawn(async move { queue.decide_in(&request, &action, Some(session)).await });
    }
    // The queue records the question synchronously, before it starts waiting, so yielding is enough
    // to let the spawned tasks reach that point. Yields and not sleeps: nothing here asserts on how
    // long anything took, so a loaded machine cannot make this flake.
    for _ in 0..1_000 {
        if server.state.approvals.len() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        server.state.approvals.len(),
        2,
        "both questions must be waiting before the route is asked for them"
    );

    let payload: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{}/v1/approvals", server.addr))
        .send()
        .await
        .expect("a response")
        .json()
        .await
        .expect("the approvals route answers with JSON");
    let items = payload
        .as_array()
        .expect("the approvals route answers with the list of questions");
    let served = |id: &str| -> (u64, u64) {
        let item = items
            .iter()
            .find(|item| item["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("no served question with id {id}: {payload}"));
        let unattended = &item["unattended"];
        (
            unattended["budget"]
                .as_u64()
                .unwrap_or_else(|| panic!("no budget on the served question: {item}")),
            unattended["remaining"]
                .as_u64()
                .unwrap_or_else(|| panic!("no remaining budget on the served question: {item}")),
        )
    };

    assert_eq!(
        served(tight.id.as_str()),
        (3, 2),
        "the cadence is the policy's and the remainder is the session's: one of three spent"
    );
    assert_eq!(served(loose.id.as_str()), (10, 9));
    assert_ne!(
        served(tight.id.as_str()).1,
        served(loose.id.as_str()).1,
        "two cadences that differ must produce two remainders that differ, or the number is a \
         constant rather than the run's"
    );

    // And the page reads that field. Not a claim that the card renders — see the note above.
    let page = reqwest::Client::new()
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response")
        .text()
        .await
        .expect("a body");
    assert!(
        page.contains("req.unattended"),
        "the page's approval card must read the field the daemon sends"
    );
}

/// The diff/review pane's data source: a diff is computed by the daemon from the real file on disk.
///
/// The tempting wrong test is a grep of the served page — which passes for a diff baked into the HTML.
/// So this drives the route the way the pane does: a file is written to the local host, a proposed
/// revision is posted to `/v1/diff`, and the diff the daemon returns is asserted to *name the real
/// change* (an added line) and stay context-equal where nothing changed. A diff invented in the browser,
/// or a route that echoed the proposed text without reading the file, cannot satisfy both.
///
/// The page half is weaker and stated as such: the browser is not driven here, so what is asserted is that
/// the served page calls the exact `/v1/diff` endpoint — not that the pane renders.
#[tokio::test]
async fn the_diff_route_computes_the_change_against_the_real_file() {
    let server = harness().await;
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("review.rs");
    let path = path.display().to_string();

    // Put a real file on the local host through the file route, then diff a proposed edit to it.
    let client = reqwest::Client::new();
    let put = client
        .put(format!("http://{}/v1/hosts/local/file", server.addr))
        .json(&serde_json::json!({ "path": path, "contents": "fn a() {}\nfn b() {}\n" }))
        .send()
        .await
        .expect("a response");
    assert_eq!(put.status(), reqwest::StatusCode::OK);

    let res = client
        .post(format!("http://{}/v1/diff", server.addr))
        .json(&serde_json::json!({
            "path": path,
            "proposed": "fn a() {}\nfn b() { todo!() }\n"
        }))
        .send()
        .await
        .expect("a response");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["exists"], true, "{body}");
    assert_eq!(body["binary"], false, "{body}");

    let diff = body["diff"].as_array().expect("diff is a list");
    assert!(
        diff.iter().any(|l| l["Removed"] == "fn b() {}"),
        "the removed line is named: {body}"
    );
    assert!(
        diff.iter().any(|l| l["Added"] == "fn b() { todo!() }"),
        "the added line is named: {body}"
    );
    assert!(
        diff.iter().any(|l| l["Context"] == "fn a() {}"),
        "an untouched line stays context: {body}"
    );

    // And the page asks this endpoint for its data — under the same apiFetch wrapper, so it carries the
    // token like every other call.
    let page = reqwest::Client::new()
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response")
        .text()
        .await
        .expect("a body");
    assert!(
        page.contains("/v1/diff"),
        "the pane must read the diff from the daemon, not invent it"
    );
}

/// The fan-out pane's tripwire: the served page carries the rows, the buttons, the result host,
/// and the exact `/v1/fanout` endpoint the pane POSTs its children to.
///
/// The tempting wrong test is driving a real fan-out, which needs a live pool and a model —
/// a static page cannot supply either. What this pins is the half a static page *has*: that the
/// pane exists, that its request names the route's `children` shape, and that its renderer reads
/// the outcome's `Ran`/`Errored` halves rather than a field nobody sends. Rendering is the
/// browser's, and this is the limit of what a test without one can claim.
#[tokio::test]
async fn the_fanout_pane_posts_children_to_the_fanout_route_and_reads_the_outcome() {
    let server = harness().await;
    let page = reqwest::Client::new()
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response")
        .text()
        .await
        .expect("a body");

    for id in [
        "fanout-rows",
        "fanout-add",
        "fanout-run",
        "fanout-error",
        "fanout-out",
    ] {
        assert!(
            page.contains(&format!("id=\"{id}\"")),
            "the fan-out pane's element {id} is missing from the served page"
        );
    }
    assert!(
        page.contains("/v1/fanout"),
        "the pane must run its children through the daemon's fan-out route, not invent them"
    );
    assert!(
        page.contains("children"),
        "the pane's request must carry the route's `children` shape"
    );
    assert!(
        page.contains("child.Ran") && page.contains("child.Errored"),
        "the pane must read the outcome's Ran/Errored halves rather than a field nobody sends"
    );
}

/// The review pane's data source: what a session changed, read off its own transcript.
///
/// The tempting wrong test is a grep of the served page for the word "review", which passes for a
/// list typed into the HTML. So this writes a transcript the way a run does — a `write_file` call
/// and its result, on a real session — writes the file the call names, and asks the route the pane
/// asks. The diff that comes back has to name the line the transcript added and the line the file
/// still has. A route that walked the directory, or one that echoed the proposed text without
/// reading the file, cannot satisfy both.
#[tokio::test]
async fn the_review_route_diffs_the_transcripts_edits_against_the_file_now() {
    use hx_core::ids::ToolCallId;
    use hx_core::message::{Message, Part, Role};

    let server = harness().await;
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("notes.txt");
    let path = path.display().to_string();

    let session = server
        .state
        .store
        .create(
            hx_store::NewSession::new()
                .titled("review")
                .in_workspace("local"),
            chrono::Utc::now(),
        )
        .expect("a session");
    let call = Message {
        role: Role::Assistant,
        parts: vec![Part::ToolCall {
            id: ToolCallId::from_raw("tc_review"),
            name: "write_file".to_string(),
            arguments: serde_json::json!({ "path": path, "content": "kept\nadded by the agent\n" }),
        }],
    };
    server
        .state
        .store
        .append(&session.id, &call, chrono::Utc::now())
        .expect("the call is recorded");
    let result = Message::tool_result(ToolCallId::from_raw("tc_review"), true, "wrote");
    server
        .state
        .store
        .append(&session.id, &result, chrono::Utc::now())
        .expect("the result is recorded");

    let client = reqwest::Client::new();
    let put = client
        .put(format!("http://{}/v1/hosts/local/file", server.addr))
        .json(&serde_json::json!({ "path": path, "contents": "kept\n" }))
        .send()
        .await
        .expect("a response");
    assert_eq!(put.status(), reqwest::StatusCode::OK, "the file is written");

    let res = client
        .get(format!(
            "http://{}/v1/sessions/{}/review",
            server.addr, session.id
        ))
        .send()
        .await
        .expect("a response");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.expect("json");

    // One object per file: `{path, edits, unapplied, diff}`. Not a wrapper — a wrapper would be a
    // second shape for a list that already carries everything a file has to say about itself.
    let files = body.as_array().expect("the review is a list of files");
    assert_eq!(files.len(), 1, "one call, one file: {body}");
    assert_eq!(files[0]["path"], path, "{body}");
    assert_eq!(files[0]["edits"], 1, "{body}");
    assert!(
        files[0]["unapplied"].as_array().unwrap().is_empty(),
        "the write applied cleanly: {body}"
    );
    let diff = files[0]["diff"].as_array().expect("a diff");
    assert!(
        diff.iter().any(|l| l["Added"] == "added by the agent"),
        "the line the transcript added is named: {body}"
    );
    assert!(
        diff.iter().any(|l| l["Context"] == "kept"),
        "the line the file already had stays context: {body}"
    );

    let page = client
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response")
        .text()
        .await
        .expect("a body");
    assert!(
        page.contains("/review"),
        "the pane must read the review from the daemon, not invent it"
    );
    assert!(
        page.contains("data-mode=\"plan\""),
        "the composer must offer the read-only mode"
    );
}
