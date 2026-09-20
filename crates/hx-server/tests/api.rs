//! The HTTP surface, end to end, with a scripted model where the provider would be.
//!
//! What is real here: the loop, the tool registry, the capability token, the approval policy, the
//! session store (a real SQLite file on disk), and the HTTP surface itself. Only the model call is a
//! script — and it is a script *behind the `ModelFactory` seam a daemon uses*, not a test-only path
//! through the code.
//!
//! That is the point of these tests: they cannot pass unless the route, the loop, the tools, the
//! policy and the store agree with one another.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use hx_agent::ApprovalQueue;
use hx_agent::ModelCall;
use hx_core::error::{HxError, Result};
use hx_core::event::AgentEvent;
use hx_core::ids::ToolCallId;
use hx_core::ids::{CredentialId, ProviderId, SessionId};
use hx_core::message::{Message, Part, Role};
use hx_provider::{ChatRequest, ChatResponse, FinishReason, ProviderRegistry, Usage};
use hx_sandbox::SandboxManager;
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, ModelFactory};
use hx_store::Store;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

// -- the scripted model ---------------------------------------------------------------------------

/// Answers from a script, and refuses once it runs out.
///
/// Running out refusing rather than returning a canned answer is deliberate: a test whose script is
/// too short should fail loudly instead of quietly passing on a default reply.
struct ScriptedModel {
    replies: Mutex<VecDeque<Result<ChatResponse>>>,
    /// Every request the loop sent, so a test can assert what the model was *told*.
    seen: Mutex<Vec<ChatRequest>>,
}

impl ScriptedModel {
    fn new(replies: Vec<Result<ChatResponse>>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(VecDeque::from(replies)),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<ChatRequest> {
        self.seen.lock().unwrap().clone()
    }

    /// Add a reply to the script. Lets a test build the script *after* it has set up a fixture the
    /// reply has to name.
    fn push(&self, reply: Result<ChatResponse>) {
        self.replies.lock().unwrap().push_back(reply);
    }
}

#[async_trait]
impl ModelCall for ScriptedModel {
    async fn complete(&self, req: ChatRequest) -> Result<ChatResponse> {
        self.seen.lock().unwrap().push(req);
        self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
            Err(HxError::Provider(
                "the scripted model was asked for more turns than it has answers".to_string(),
            ))
        })
    }

    fn model(&self) -> String {
        "scripted-model".to_string()
    }

    fn provider_id(&self) -> ProviderId {
        ProviderId::from_raw("local")
    }

    fn credential_id(&self) -> CredentialId {
        CredentialId::from_raw("local-1")
    }
}

/// The factory a test injects: one script, whatever role is asked for.
struct Scripted(Arc<ScriptedModel>);

impl ModelFactory for Scripted {
    fn for_role(&self, _role: &str) -> Result<Arc<dyn ModelCall>> {
        Ok(Arc::clone(&self.0) as Arc<dyn ModelCall>)
    }
}

// -- replies --------------------------------------------------------------------------------------

fn usage(input: u64, output: u64) -> Usage {
    Usage {
        input_tokens: input,
        output_tokens: output,
        ..Default::default()
    }
}

fn answer(text: &str) -> ChatResponse {
    ChatResponse {
        message: Message::new(Role::Assistant, vec![Part::text(text)]),
        usage: usage(100, 20),
        finish: FinishReason::Stop,
        model: "scripted-model".to_string(),
        raw: None,
    }
}

/// A turn that calls tools, in one assistant message.
fn calls(list: Vec<(&str, &str, serde_json::Value)>) -> ChatResponse {
    let parts = list
        .into_iter()
        .map(|(id, name, arguments)| Part::ToolCall {
            id: ToolCallId::from(id),
            name: name.to_string(),
            arguments,
        })
        .collect();

    ChatResponse {
        message: Message::new(Role::Assistant, parts),
        usage: usage(50, 10),
        finish: FinishReason::ToolUse,
        model: "scripted-model".to_string(),
        raw: None,
    }
}

#[tokio::test]
async fn an_unknown_chat_sandbox_is_rejected_before_a_session_or_model_call() {
    // A misspelt boundary must never become an unconfined run.
    let h = harness(vec![Ok(answer("must not run"))]).await;
    let (status, reply) = chat(
        &h.state,
        serde_json::json!({
            "prompt": "hello", "sandbox_profile": "missing", "workspace": h.workspace
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(reply.to_string().contains("missing"), "{reply}");
    assert!(h.model.seen().is_empty());
    assert_eq!(h.state.store.count().unwrap(), 0);
}

#[tokio::test]
async fn a_chat_that_requests_a_sandbox_cannot_run_when_the_engine_is_absent() {
    // An explicit boundary is a requirement, not a hint that can be discarded.
    let mut h = harness(vec![Ok(answer("must not run"))]).await;
    Arc::get_mut(&mut h.state)
        .unwrap()
        .config
        .sandbox_profiles
        .insert(
            "dev".into(),
            hx_core::config::SandboxProfile {
                image: "alpine:3.22".into(),
                ..Default::default()
            },
        );
    let (status, reply) = chat(
        &h.state,
        serde_json::json!({
            "prompt": "hello", "sandbox_profile": "dev", "workspace": h.workspace
        }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{reply}");
    assert!(
        reply.to_string().contains("no container engine in a test"),
        "{reply}"
    );
    assert!(h.model.seen().is_empty());
    assert_eq!(h.state.store.count().unwrap(), 0);
}

/// Records engine calls behind the real manager; never executes a command on the host.
#[derive(Default)]
struct ChatSandboxRuntime {
    fail_start: bool,
    specs: Mutex<Vec<hx_sandbox::SandboxSpec>>,
    execs: Mutex<Vec<(String, Option<String>)>>,
}

#[async_trait]
impl hx_sandbox::SandboxRuntime for ChatSandboxRuntime {
    fn name(&self) -> &str {
        "chat-test"
    }
    async fn available(&self) -> bool {
        true
    }
    async fn create(
        &self,
        id: &hx_core::ids::SandboxId,
        spec: &hx_sandbox::SandboxSpec,
        _settings: &hx_sandbox::HostSettings,
    ) -> Result<String> {
        self.specs.lock().unwrap().push(spec.clone());
        Ok(id.to_string())
    }
    async fn start(&self, _id: &str) -> Result<()> {
        if self.fail_start {
            return Err(HxError::Sandbox("test engine cannot start".into()));
        }
        Ok(())
    }
    async fn stop(&self, _id: &str, _grace: i64) -> Result<()> {
        Ok(())
    }
    async fn remove(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn exec(
        &self,
        _id: &str,
        command: &str,
        workdir: Option<&str>,
    ) -> Result<hx_sandbox::SandboxExecOutput> {
        self.execs
            .lock()
            .unwrap()
            .push((command.into(), workdir.map(str::to_string)));
        Ok(hx_sandbox::SandboxExecOutput {
            stdout: "only-the-sandbox-returned-this".into(),
            stderr: String::new(),
            exit_code: 0,
        })
    }
}

#[tokio::test]
async fn a_chat_profile_sends_shell_to_the_sandbox_instead_of_the_host() {
    // A successful HTTP response alone proves nothing: assert the engine call, translated cwd,
    // mounted checkout, returned tool output, and absence of the host-side marker.
    let mut h = harness(vec![]).await;
    let runtime = Arc::new(ChatSandboxRuntime::default());
    let state = Arc::get_mut(&mut h.state).unwrap();
    state.config.sandbox_profiles.insert(
        "dev".into(),
        hx_core::config::SandboxProfile {
            image: "alpine:3.22".into(),
            ..Default::default()
        },
    );
    state.sandboxes = Some(Arc::new(SandboxManager::new(runtime.clone(), 4)));
    h.model.push(Ok(calls(vec![(
        "inside",
        "shell",
        serde_json::json!({
            "cmd": "printf host-ran > host-marker", "workdir": h.workspace
        }),
    )])));
    h.model.push(Ok(answer("done")));
    let (status, reply) = chat(
        &h.state,
        serde_json::json!({
            "prompt": "run command", "sandbox_profile": "dev", "workspace": h.workspace,
            "autonomy": "yolo"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["tool_calls"], 1, "{reply}");
    let execs = runtime.execs.lock().unwrap();
    assert_eq!(execs.len(), 1);
    assert_eq!(execs[0].0, "printf host-ran > host-marker");
    assert_eq!(execs[0].1.as_deref(), Some("/workspace"));
    let specs = runtime.specs.lock().unwrap();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].profile, "dev");
    assert_eq!(specs[0].workspace_host_path, h.workspace.to_str().unwrap());
    assert!(!h.workspace.join("host-marker").exists());
    let seen = h.model.seen();
    assert!(seen[1]
        .messages
        .iter()
        .any(|m| m.text().contains("only-the-sandbox-returned-this")));
}

#[tokio::test]
async fn a_chat_sandbox_start_failure_leaves_no_session_and_never_calls_the_model() {
    // Startup failure must be surfaced before the run can accidentally execute on the host.
    let mut h = harness(vec![Ok(answer("must not run"))]).await;
    let runtime = Arc::new(ChatSandboxRuntime {
        fail_start: true,
        ..Default::default()
    });
    let state = Arc::get_mut(&mut h.state).unwrap();
    state.config.sandbox_profiles.insert(
        "dev".into(),
        hx_core::config::SandboxProfile {
            image: "alpine:3.22".into(),
            ..Default::default()
        },
    );
    state.sandboxes = Some(Arc::new(SandboxManager::new(runtime.clone(), 4)));
    let (status, reply) = chat(
        &h.state,
        serde_json::json!({
            "prompt": "run command", "sandbox_profile": "dev", "workspace": h.workspace
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{reply}");
    assert!(
        reply.to_string().contains("test engine cannot start"),
        "{reply}"
    );
    assert!(h.model.seen().is_empty());
    assert!(runtime.execs.lock().unwrap().is_empty());
    assert_eq!(h.state.store.count().unwrap(), 0);
}

#[tokio::test]
async fn a_profile_naming_an_unknown_host_is_refused_by_name() {
    // The honest failure for a sandbox profile whose `host:` names a machine that does not exist: it is
    // refused with the name in the message, rather than silently falling back to the local daemon (which
    // would make `host:` a suggestion) or failing with a generic error the operator cannot act on. The
    // harness has no `hosts:` at all, so any id is unknown.
    let h = harness(vec![Ok(answer("must not run"))]).await;

    let err = match h.state.sandbox_manager_for(Some("ghost")).await {
        Ok(_) => panic!("an unknown host must be refused"),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(message.contains("ghost"), "names the host: {message}");
    assert!(
        message.contains("no host") || message.contains("not configured"),
        "says it is not configured, not merely that a route choked: {message}"
    );
}

#[tokio::test]
async fn a_profile_with_no_host_resolves_to_the_local_manager() {
    // The control that keeps this feature honest: without it, a blanket "always route every profile to a
    // remote manager" would pass. A profile without a `host` key must keep today's behaviour — the local
    // daemon's `SandboxManager`, the exact `Arc` the state holds. If this test fails, the local path has
    // been disturbed.
    let mut h = harness(vec![Ok(answer("must not run"))]).await;
    let local = Arc::new(SandboxManager::new(
        Arc::new(ChatSandboxRuntime::default()),
        4,
    ));
    let local_arc = Arc::clone(&local);
    Arc::get_mut(&mut h.state).unwrap().sandboxes = Some(local);

    let manager = h
        .state
        .sandbox_manager_for(None)
        .await
        .expect("no host means the local manager");
    assert!(
        Arc::ptr_eq(&manager, &local_arc),
        "a no-host profile returns the local manager, not a fresh remote one"
    );
}

// -- the harness ---------------------------------------------------------------------------------

const CONFIG: &str = r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["scripted-model"]
    price: { input_per_mtok: 1.0, output_per_mtok: 2.0 }
    credentials:
      - { id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }

pools:
  interactive: { members: ["local/scripted-model"] }

roles:
  builder: interactive

search:
  backends: []
"#;

struct Harness {
    state: Arc<AppState>,
    model: Arc<ScriptedModel>,
    workspace: PathBuf,
}

/// Build the daemon with a scripted model and a real store in a temporary directory.
async fn harness(replies: Vec<Result<ChatResponse>>) -> Harness {
    let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.keep();
    config.daemon.data_dir = root.join("data").display().to_string();

    let workspace = root.join("work");
    std::fs::create_dir_all(&workspace).expect("workspace");

    let now = chrono::Utc::now();
    let router = hx_provider::ModelRouter::from_config(&config, now).expect("router builds");
    let providers =
        ProviderRegistry::from_config(&config, reqwest::Client::new()).expect("providers build");
    let secrets = SecretStores::new().with(Arc::new(EnvSecrets));
    let store = Store::from_config(&config).expect("store opens");
    let client = reqwest::Client::new();
    let search = BackendRegistry::from_config(
        &config.search,
        client.clone(),
        &hx_secrets::SecretStores::new(),
    )
    .expect("search");

    let model = ScriptedModel::new(replies);
    let state = AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(Mutex::new(router)),
        providers: Arc::new(providers),
        secrets: Arc::new(secrets),
        store: Arc::new(store),
        models: Arc::new(Scripted(Arc::clone(&model))),
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        // Long enough for the test to answer from another request, which is the shape a real client
        // has: the run waits while the answer comes in over the same surface.
        approvals: ApprovalQueue::new(std::time::Duration::from_secs(1)),
        search: Arc::new(search),
        sandboxes: None::<Arc<SandboxManager>>,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now,
    });

    Harness {
        state,
        model,
        workspace,
    }
}

async fn chat(state: &Arc<AppState>, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let response = app(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat")
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

/// A GET against the app, parsed as JSON. The same shape as `chat`, for the routes that are not a run.
async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// A POST against the app with a JSON body.
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

impl Harness {
    /// A request body that runs in this harness's workspace.
    fn body(&self, prompt: &str) -> serde_json::Value {
        serde_json::json!({
            "prompt": prompt,
            "workspace": self.workspace.display().to_string(),
        })
    }

    fn transcript(&self, session: &str) -> Vec<Message> {
        self.state
            .store
            .messages(&SessionId::from_raw(session.to_string()))
            .expect("transcript reads")
    }

    /// Every message of a session, flattened, for assertions about what was said.
    fn said(&self, session: &str) -> String {
        self.transcript(session)
            .iter()
            .map(|message| message.text())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// -- tests ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_answer_comes_back_with_its_session_cost_and_events() {
    let h = harness(vec![Ok(answer("the answer is 4"))]).await;

    let (status, body) = chat(&h.state, h.body("what is 2+2")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(body["final_text"], "the answer is 4");
    assert_eq!(body["stop"], "completed");
    assert_eq!(body["turns"], 1);
    assert_eq!(body["input_tokens"], 100);
    assert_eq!(body["output_tokens"], 20);
    assert_eq!(body["messages"], 2, "the prompt and the answer: {body}");

    // 100 input at $1/Mtok plus 20 output at $2/Mtok. The price table lives in the router, so this
    // is the daemon pricing the turn rather than the loop guessing.
    let cost = body["cost_usd"].as_f64().expect("a cost");
    assert!(
        (cost - 0.00014).abs() < 1e-9,
        "the turn must be priced from the rate card: {cost}"
    );

    // The session exists on disk with the same transcript the reply described.
    let session = body["session_id"].as_str().expect("a session id");
    assert_eq!(h.transcript(session).len(), 2);
    assert_eq!(
        h.state
            .store
            .totals(&SessionId::from_raw(session.to_string()))
            .expect("totals")
            .provider_calls,
        1
    );

    // And the events the loop emitted were written as they happened, which is what a client that
    // reconnects redraws from.
    let events = h
        .state
        .store
        .events(&SessionId::from_raw(session.to_string()))
        .expect("events");
    let usage_event = events
        .iter()
        .find_map(|event| match event {
            AgentEvent::Usage {
                provider,
                credential,
                ..
            } => Some((
                provider.as_str().to_string(),
                credential.as_str().to_string(),
            )),
            _ => None,
        })
        .expect("a usage event");
    assert_eq!(usage_event, ("local".to_string(), "local-1".to_string()));
}

#[tokio::test]
async fn a_tool_call_runs_and_its_result_goes_back_to_the_model() {
    let h = harness(vec![]).await;

    // The fixture is written first, so the script can name a path that exists.
    let path = h.workspace.join("notes.txt");
    std::fs::write(&path, "hi from the workspace\n").expect("write the fixture");

    h.model.push(Ok(calls(vec![(
        "c1",
        "read_file",
        serde_json::json!({ "path": path.display().to_string() }),
    )])));
    h.model.push(Ok(answer("the file says hi")));

    let (status, body) = chat(&h.state, h.body("read the notes")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tool_calls"], 1, "{body}");
    assert_eq!(body["refusals"], 0);
    assert_eq!(body["final_text"], "the file says hi");

    // The model was told what the tool returned: the second request it saw carries the result.
    let seen = h.model.seen();
    assert_eq!(seen.len(), 2, "one turn per scripted reply");
    let second = seen[1]
        .messages
        .iter()
        .map(|message| message.text())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        second.contains("hi from the workspace"),
        "the tool result must reach the model: {second}"
    );
}

#[tokio::test]
async fn a_write_outside_the_workspace_is_denied_and_never_happens() {
    let target = std::env::temp_dir().join("hx-server-must-not-exist.txt");
    let _ = std::fs::remove_file(&target);

    let h = harness(vec![
        Ok(calls(vec![(
            "c1",
            "write_file",
            serde_json::json!({ "path": target.display().to_string(), "content": "nope" }),
        )])),
        Ok(answer("I could not write that")),
    ])
    .await;

    let (status, body) = chat(&h.state, h.body("write outside the workspace")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["refusals"], 1,
        "a capability denial is a refusal: {body}"
    );

    assert!(
        !target.exists(),
        "a denied write must not touch the filesystem"
    );
    assert!(
        h.said(body["session_id"].as_str().unwrap())
            .contains("capability does not cover"),
        "the refusal must be visible in the transcript"
    );
}

#[tokio::test]
async fn a_shell_command_needs_a_human_and_the_daemon_says_so() {
    // `git push` is classified as external — "sends data outside this machine" — and the default
    // (balanced) policy asks about that class. `echo` would not: the classifier decides what is
    // risky, not the fact that a command line is involved, and a test that used `echo` would be
    // asserting something false about the harness.
    let h = harness(vec![]).await;
    // An explicit `cwd` inside the workspace: a shell tool that runs wherever the daemon happens to
    // be is a tool that can act on the wrong repository. (This test found that the hard way.)
    let cwd = h.workspace.display().to_string();
    h.model.push(Ok(calls(vec![(
        "c1",
        "shell",
        serde_json::json!({ "cmd": "git push", "workdir": cwd }),
    )])));
    h.model.push(Ok(answer("I was not allowed to run that")));

    let (status, body) = chat(&h.state, h.body("push my work")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["refusals"], 1, "{body}");

    let said = h.said(body["session_id"].as_str().unwrap());
    // Silence is a denial, and the refusal says which kind: nobody answered, rather than the
    // operator saying no. A model that cannot tell those apart retries one and not the other.
    assert!(
        said.contains("nobody answered"),
        "the refusal must name the reason: {said}"
    );
    assert!(
        said.contains("git push"),
        "and the action nobody answered about: {said}"
    );
    assert!(
        !said.contains("not a git repository"),
        "the command must not have run: {said}"
    );
}

#[tokio::test]
async fn the_same_command_runs_when_the_request_asks_for_yolo() {
    let h = harness(vec![]).await;
    let cwd = h.workspace.display().to_string();
    h.model.push(Ok(calls(vec![(
        "c1",
        "shell",
        serde_json::json!({ "cmd": "git push", "workdir": cwd }),
    )])));
    h.model.push(Ok(answer("done")));

    let mut body = h.body("push my work");
    body["autonomy"] = serde_json::json!("yolo");

    let (status, reply) = chat(&h.state, body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["tool_calls"], 1, "{reply}");
    assert_eq!(reply["refusals"], 0, "yolo asks nobody: {reply}");

    // It ran: the workspace is not a git repository, and git's own complaint is what proves the
    // command reached a shell rather than stopping at a policy.
    let said = h.said(reply["session_id"].as_str().unwrap());
    assert!(
        said.contains("not a git repository"),
        "the command's output must be in the transcript: {said}"
    );
    assert!(!said.contains("no client is attached"));
}

#[tokio::test]
async fn yolo_asks_nobody_but_it_cannot_lift_the_shipped_floor() {
    // The hole this closes was live: a request with `autonomy: "yolo"` used to be able to run
    // `rm -rf /etc`, because the *level* was applied to a policy that never carried the catastrophe set
    // (and, before that, because writing an `approval:` block replaced it). The two are different
    // questions — the level decides what is *asked*, the floor decides what is *refused* — and no level
    // may answer the second.
    let h = harness(vec![]).await;
    let cwd = h.workspace.display().to_string();
    h.model.push(Ok(calls(vec![(
        "c1",
        "shell",
        serde_json::json!({ "cmd": "rm -rf /etc", "workdir": cwd }),
    )])));
    h.model.push(Ok(answer("understood")));

    let mut body = h.body("clean up the machine");
    body["autonomy"] = serde_json::json!("yolo");

    let (status, reply) = chat(&h.state, body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["refusals"], 1,
        "a yolo run still refuses the catastrophe set: {reply}"
    );
    assert_eq!(reply["tool_calls"], 0, "{reply}");

    let said = h.said(reply["session_id"].as_str().unwrap());
    assert!(
        said.contains("recursive delete of /etc"),
        "and the reason is the shipped one, so the model can read why: {said}"
    );
}

#[tokio::test]
async fn an_ordinary_destructive_command_is_still_questioned_and_not_refused() {
    // The other side of the same coin, and the reason the floor is a list of named paths rather than a
    // pattern: a cleanup in `/tmp` is a question nobody can answer from a rule, so `yolo` runs it and a
    // cautious run asks about it — but neither *refuses* it.
    let h = harness(vec![]).await;
    let cwd = h.workspace.display().to_string();
    h.model.push(Ok(calls(vec![(
        "c1",
        "shell",
        serde_json::json!({ "cmd": "rm -rf /tmp/hx-does-not-exist", "workdir": cwd }),
    )])));
    h.model.push(Ok(answer("done")));

    let mut body = h.body("clean the temp dir");
    body["autonomy"] = serde_json::json!("yolo");

    let (status, reply) = chat(&h.state, body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["refusals"], 0,
        "an ordinary cleanup is not a catastrophe: {reply}"
    );
    assert_eq!(reply["tool_calls"], 1, "{reply}");
}

#[tokio::test]
async fn a_relative_path_from_the_model_is_read_against_the_workspace() {
    // What a real model does: asked to read a file "in this workspace", it writes a relative path.
    // The capability token holds an absolute workspace path, so without the join *every* call it
    // makes is denied — which is exactly what happened the first time a real model was pointed at
    // this harness (35 refusals, no progress, and the model reporting that its grant was too narrow).
    let h = harness(vec![]).await;
    std::fs::write(h.workspace.join("notes.txt"), "relative paths work\n").expect("fixture");

    h.model.push(Ok(calls(vec![(
        "c1",
        "read_file",
        serde_json::json!({ "path": "notes.txt" }),
    )])));
    h.model.push(Ok(answer("read it")));

    let (status, body) = chat(&h.state, h.body("read notes.txt")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["refusals"], 0,
        "a relative path inside the workspace must not be denied: {body}"
    );
    assert_eq!(body["tool_calls"], 1);
    assert!(
        h.said(body["session_id"].as_str().unwrap())
            .contains("relative paths work"),
        "the file's contents must reach the model"
    );
}

#[tokio::test]
async fn a_relative_path_that_climbs_out_of_the_workspace_is_denied() {
    // The join must not launder an escape. `..` survives resolution on purpose, because the token's
    // traversal rule is what catches it — and a rule that never sees the `..` cannot catch anything.
    let h = harness(vec![]).await;

    h.model.push(Ok(calls(vec![(
        "c1",
        "read_file",
        serde_json::json!({ "path": "../../../../etc/passwd" }),
    )])));
    h.model.push(Ok(answer("I could not read that")));

    let (status, body) = chat(&h.state, h.body("read the system file")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["refusals"], 1, "{body}");
    assert!(
        h.said(body["session_id"].as_str().unwrap())
            .contains("does not cover"),
        "the refusal must say why"
    );
}

#[tokio::test]
async fn a_shell_command_runs_in_the_workspace_when_the_model_names_no_directory() {
    // The same root cause as the relative-path bug, one layer down: the tool had no idea which
    // directory the run was in, so a command with no `workdir` ran wherever the daemon happened to
    // be. This is the test that would have caught a test suite pushing a real branch.
    let h = harness(vec![]).await;
    h.model.push(Ok(calls(vec![(
        "c1",
        "shell",
        serde_json::json!({ "cmd": "pwd" }),
    )])));
    h.model.push(Ok(answer("done")));

    let mut body = h.body("where am I");
    body["autonomy"] = serde_json::json!("yolo");

    let (status, reply) = chat(&h.state, body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["tool_calls"], 1, "{reply}");

    let said = h.said(reply["session_id"].as_str().unwrap());
    // The workspace path as the *shell* reports it, rather than as Rust formats it. PowerShell's
    // `pwd` prints a table, and on Windows the same directory can come back with a different
    // spelling than `Path::display()` gives: `Temp\` is an alias, so the shell may answer with the
    // 8.3 short name (`RUNNER~1`) where Rust gives the long one. Comparing the final component is
    // what this test is actually about — that `pwd` ran in the workspace and not in the daemon's
    // directory — and it holds however either side spells the parent.
    let leaf = h
        .workspace
        .file_name()
        .expect("the workspace has a final component")
        .to_string_lossy()
        .to_string();
    assert!(
        said.contains(&leaf),
        "pwd must print the workspace, not the daemon's directory: {said}"
    );
    // And it must not have run in the daemon's own directory, which is the failure this guards.
    assert!(
        !said.contains(".tmp") || said.contains(&leaf),
        "pwd must not report the daemon's directory: {said}"
    );
}

#[tokio::test]
async fn messages_survive_a_run_that_fails_in_the_middle() {
    // The property the second M1 exit criterion rests on: a run that dies at turn two has *already*
    // run the tool in turn one, and its result is the only record of what that call did. Messages go
    // to the store as they are produced, so the failure costs the turn it happened in and nothing
    // before it.
    let h = harness(vec![]).await;
    std::fs::write(h.workspace.join("notes.txt"), "durable\n").expect("fixture");

    h.model.push(Ok(calls(vec![(
        "c1",
        "read_file",
        serde_json::json!({ "path": "notes.txt" }),
    )])));
    // No second reply: the model call for the next turn fails.

    let (status, body) = chat(&h.state, h.body("read the notes")).await;
    assert!(status.is_server_error(), "{status} {body}");

    let sessions = h.state.store.list(10).expect("sessions list");
    assert_eq!(sessions.len(), 1, "the session exists despite the failure");
    let id = sessions[0].record.id.clone();

    let messages = h.state.store.messages(&id).expect("transcript reads");
    assert_eq!(
        messages.len(),
        3,
        "prompt, the assistant's call, and the result of a tool that really ran: {messages:#?}"
    );
    assert_eq!(messages[0].text(), "read the notes");
    assert!(
        messages[2].text().contains("durable"),
        "the tool's output is the record of what it did: {:#?}",
        messages[2]
    );

    // And nothing is left dangling: the call has its result, so resuming this session is a normal
    // continuation rather than a repair.
    let session = h.state.store.load(&id).expect("session loads");
    assert!(
        session.interrupted_calls().is_empty(),
        "the run failed between turns, not inside a call"
    );
}

#[tokio::test]
async fn a_run_that_needs_a_human_waits_and_runs_once_answered() {
    // The point of the channel: a questile call does not have to be refused, and does not have to be
    // waved through with `yolo` either. The run blocks; a client answers over HTTP; the tool runs.
    let h = harness(vec![]).await;
    h.model.push(Ok(calls(vec![(
        "c1",
        "shell",
        serde_json::json!({ "cmd": "git push" }),
    )])));
    h.model.push(Ok(answer("done")));

    // `git push` is External, and the default level is balanced, so this asks.
    let state = Arc::clone(&h.state);
    let body = h.body("push my work");
    let running = tokio::spawn(async move { chat(&state, body).await });

    // The question is visible while the run waits — this is the loop a client actually polls.
    let mut waiting = None;
    for _ in 0..200 {
        let (status, list) = get(Arc::clone(&h.state), "/v1/approvals").await;
        assert_eq!(status, StatusCode::OK);
        if let Some(first) = list.as_array().and_then(|list| list.first()) {
            waiting = Some(first["id"].as_str().expect("an id").to_string());
            assert!(
                first["reason"].as_str().is_some_and(|r| !r.is_empty()),
                "a question carries why it is being asked: {first}"
            );
            assert!(
                first["options"].as_array().map(Vec::len).unwrap_or(0) >= 2,
                "a question offers more than one answer: {first}"
            );
            // …and not every answer: `git push` is `external`, so a permanent approval must not be on
            // the menu. Over-asking is recoverable; over-approving is not.
            let options = first["options"].as_array().cloned().unwrap_or_default();
            assert!(
                !options.iter().any(|o| o == "allow_always"),
                "an external action must not offer a permanent approval: {first}"
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let id = waiting.expect("the question must be visible over HTTP while the run waits");

    // Answer it, attributed to the surface that answered.
    let (status, body) = post(
        Arc::clone(&h.state),
        &format!("/v1/approvals/{id}"),
        serde_json::json!({ "option": "once", "by": "test-client" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["by"], "test-client");

    // The run resumes and the tool runs.
    let (status, reply) = running.await.expect("the run task finishes");
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["tool_calls"], 1, "{reply}");
    assert_eq!(
        reply["refusals"], 0,
        "an answered call is not a refusal: {reply}"
    );
    assert!(
        h.said(reply["session_id"].as_str().unwrap())
            .contains("not a git repository"),
        "the command must have reached a shell"
    );

    // And the queue is empty again: an answered question does not linger for the next client.
    let (_, list) = get(Arc::clone(&h.state), "/v1/approvals").await;
    assert_eq!(list.as_array().map(Vec::len), Some(0), "{list}");

    // Answering something that is not waiting is a 404, not a silent success.
    let (status, body) = post(
        Arc::clone(&h.state),
        &format!("/v1/approvals/{id}"),
        serde_json::json!({ "option": "once" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_request_that_will_not_wait_is_refused_at_once() {
    // The pre-channel behaviour, kept for a client that cannot answer: fail fast with the reason
    // rather than hold the connection open for a minute.
    let h = harness(vec![
        Ok(calls(vec![(
            "c1",
            "shell",
            serde_json::json!({ "cmd": "git push" }),
        )])),
        Ok(answer("I was not allowed")),
    ])
    .await;

    let mut body = h.body("push my work");
    body["approval_wait_secs"] = serde_json::json!(0);

    let (status, reply) = chat(&h.state, body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["refusals"], 1, "{reply}");
    assert!(
        h.said(reply["session_id"].as_str().unwrap())
            .contains("asked not to wait"),
        "the refusal must say why nobody was asked"
    );
}

#[tokio::test]
async fn a_second_request_on_a_session_continues_the_transcript() {
    let h = harness(vec![Ok(answer("first")), Ok(answer("second"))]).await;

    let (_, first) = chat(&h.state, h.body("hello")).await;
    let session = first["session_id"].as_str().unwrap().to_string();

    let mut second_body = h.body("again");
    second_body["session"] = serde_json::json!(session.clone());
    let (status, second) = chat(&h.state, second_body).await;

    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["created"], false, "the session was resumed");
    assert_eq!(second["messages"], 4, "two prompts, two answers: {second}");
    assert_eq!(h.transcript(&session).len(), 4);

    // The model saw the earlier turns rather than starting over.
    let seen = h.model.seen();
    assert_eq!(seen.len(), 2);
    assert!(
        seen[1].messages.len() >= 3,
        "the second call must carry the history: {}",
        seen[1].messages.len()
    );
}

#[tokio::test]
async fn an_unknown_autonomy_level_is_refused_by_name() {
    let h = harness(vec![]).await;

    let mut body = h.body("hello");
    body["autonomy"] = serde_json::json!("reckless");

    let (status, reply) = chat(&h.state, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        reply["error"].as_str().unwrap().contains("yolo"),
        "the error must list what is accepted: {reply}"
    );
}

#[tokio::test]
async fn a_request_for_an_unknown_role_is_refused_by_name() {
    let h = harness(vec![]).await;

    let mut body = h.body("hello");
    body["role"] = serde_json::json!("nobody");

    let (status, reply) = chat(&h.state, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(
        reply["error"].as_str().unwrap().contains("builder"),
        "the error must list the roles that exist: {reply}"
    );
    assert_eq!(
        h.state.store.count().expect("count"),
        0,
        "a request that cannot run must not create a session"
    );
}
