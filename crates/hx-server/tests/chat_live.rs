//! The chat path against a **real** container engine.
//!
//! `tests/api.rs` proves the wiring with a recording runtime: the manager is real, the context is
//! real, and the command that reaches `SandboxExec` is asserted exactly. What a recording runtime
//! cannot prove is that the command *works* inside a container — that the translated workdir exists,
//! that the bind mount is writable by the adopted uid, and that a path built for the host is not
//! silently resolved against the container's own root.
//!
//! That gap is not hypothetical. The first version of the wiring built the command line with
//! `cd '/host/checkout' && …` embedded in the shell source, so the sandbox received a path that does
//! not exist inside it while the adapter was dutifully translating the separate workdir argument into
//! `/workspace`. Every hermetic test passed. A real engine is the only thing that can see it, which
//! is why this file exists next to the mapping tests rather than instead of them.
//!
//! Run it explicitly, on a machine with Docker:
//!
//! ```console
//! $ cargo test -p hx-server --test chat_live -- --ignored --test-threads=1
//! ```
//!
//! `HX_DOCKER_TEST_IMAGE` overrides the image (default `ubuntu:24.04`). The daemon must be able to
//! find it; this test does not pull, so a missing image fails rather than hanging on a network.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use hx_agent::{ApprovalQueue, ModelCall};
use hx_core::config::{Config, IsolationLevel, SandboxProfile};
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use hx_core::message::{Message, Part, Role};
use hx_provider::{ChatRequest, ChatResponse, FinishReason, ModelRouter, ProviderRegistry, Usage};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, ModelFactory};
use hx_store::Store;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// Answers from a script, and refuses once it runs out.
///
/// Running out *refusing* rather than returning a canned reply is deliberate: a test whose script is
/// too short should fail loudly instead of quietly passing on a default answer.
struct ScriptedModel {
    replies: Mutex<VecDeque<Result<ChatResponse>>>,
}

impl ScriptedModel {
    fn new(replies: Vec<Result<ChatResponse>>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(VecDeque::from(replies)),
        })
    }
}

#[async_trait]
impl ModelCall for ScriptedModel {
    async fn complete(&self, _req: ChatRequest) -> Result<ChatResponse> {
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

struct Scripted(Arc<ScriptedModel>);

impl ModelFactory for Scripted {
    fn for_role(&self, _role: &str) -> Result<Arc<dyn ModelCall>> {
        Ok(Arc::clone(&self.0) as Arc<dyn ModelCall>)
    }
}

fn answer(text: &str) -> ChatResponse {
    ChatResponse {
        message: Message::new(Role::Assistant, vec![Part::text(text)]),
        usage: Usage {
            input_tokens: 100,
            output_tokens: 20,
            ..Default::default()
        },
        finish: FinishReason::Stop,
        model: "scripted-model".to_string(),
        raw: None,
    }
}

/// One assistant turn that calls `shell`.
fn shell_call(command: &str, workdir: &str) -> ChatResponse {
    ChatResponse {
        message: Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: hx_core::ids::ToolCallId::from("call-1"),
                name: "shell".to_string(),
                arguments: serde_json::json!({ "cmd": command, "workdir": workdir }),
            }],
        ),
        usage: Usage {
            input_tokens: 50,
            output_tokens: 10,
            ..Default::default()
        },
        finish: FinishReason::ToolUse,
        model: "scripted-model".to_string(),
        raw: None,
    }
}

const CONFIG: &str = r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["scripted-model"]
    credentials:
      - { id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }

pools:
  interactive: { members: ["local/scripted-model"] }

roles:
  builder: interactive

search:
  backends: []
"#;

/// The image to build sandboxes from.
fn image() -> String {
    std::env::var("HX_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "ubuntu:24.04".to_string())
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

/// A daemon wired to a real Docker daemon, or `None` when there is none to talk to.
async fn harness() -> Option<(Arc<AppState>, std::path::PathBuf, tempfile::TempDir)> {
    let manager = match hx_sandbox::docker_manager(4).await {
        Ok(manager) => Arc::new(manager),
        Err(err) => {
            eprintln!("skipped: no reachable Docker daemon: {err}");
            return None;
        }
    };

    let mut config = Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().to_path_buf();
    config.daemon.data_dir = root.join("data").display().to_string();
    config.sandbox_profiles.insert(
        "live".to_string(),
        SandboxProfile {
            image: image(),
            isolation: IsolationLevel::L2,
            cpus: 1.0,
            memory_mb: 512,
            pids_max: 128,
            ttl_secs: 600,
            network: false,
            readonly_rootfs: true,
            ..Default::default()
        },
    );

    let workspace = root.join("work");
    std::fs::create_dir_all(&workspace).expect("workspace");

    let now = chrono::Utc::now();
    let router = ModelRouter::from_config(&config, now).expect("router builds");
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

    let model = ScriptedModel::new(vec![
        Ok(shell_call(
            "printf from-the-container > proof.txt && pwd && id -u",
            workspace.to_str().unwrap(),
        )),
        Ok(answer("done")),
        // The second request in the reuse test needs its own two turns.
        Ok(shell_call("pwd", workspace.to_str().unwrap())),
        Ok(answer("done again")),
    ]);

    let state = AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(Mutex::new(router)),
        providers: Arc::new(providers),
        secrets: Arc::new(secrets),
        store: Arc::new(store),
        models: Arc::new(Scripted(model)),
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        approvals: ApprovalQueue::new(std::time::Duration::from_secs(1)),
        search: Arc::new(search),
        sandboxes: Some(manager),
        sandbox_unavailable_reason: None,
        started_at: now,
    });

    Some((state, workspace, dir))
}

#[tokio::test]
#[ignore = "requires a docker daemon"]
async fn a_chat_request_runs_its_shell_command_inside_a_real_container() {
    let Some((state, workspace, _dir)) = harness().await else {
        return;
    };

    let (status, reply) = chat(
        &state,
        serde_json::json!({
            "prompt": "write a file and report where it ran",
            "sandbox_profile": "live",
            "workspace": workspace.display().to_string(),
            "autonomy": "yolo",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["tool_calls"], 1, "{reply}");
    assert_eq!(reply["refusals"], 0, "{reply}");

    // The bind mount is real: the file the container wrote is on the host.
    let written = workspace.join("proof.txt");
    assert!(
        written.exists(),
        "the container's write did not reach the bind mount at {}",
        written.display()
    );
    assert_eq!(
        std::fs::read_to_string(&written).unwrap().trim(),
        "from-the-container"
    );

    // What the model was told: the container's own path, the uid, and where the command ran. This is
    // what the embedded-`cd` defect broke, and what a recording runtime cannot see.
    let session =
        hx_core::ids::SessionId::from_raw(reply["session_id"].as_str().unwrap().to_string());
    let transcript = state
        .store
        .messages(&session)
        .expect("transcript read back");
    let tool_text = transcript
        .iter()
        .flat_map(|message| message.parts.iter())
        .filter_map(|part| match part {
            Part::ToolResult { content, .. } => Some(content.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        tool_text.contains("/workspace"),
        "the model should be told the sandbox path, not the host's: {tool_text}"
    );
    assert!(
        tool_text.contains("ran in sandbox"),
        "the result should say where it ran: {tool_text}"
    );
    // The command ran as the workspace's owner inside the mount, which is what makes the bind
    // writable — the defect that only a real engine can surface (a CI runner's uid is not 1000).
    let uid_line = tool_text
        .lines()
        .find(|line| line.trim().chars().all(|c| c.is_ascii_digit()) && !line.trim().is_empty())
        .unwrap_or_else(|| panic!("the run reported no uid: {tool_text}"));
    assert_ne!(uid_line.trim(), "0", "the sandbox ran as root: {tool_text}");

    // A cached boundary is the *design* (one container per profile+checkout, kept until the manager
    // reaps it on its TTL), so exactly one is expected to still be there after the run — and it must
    // be the same one a second request reuses rather than a new container.
    let manager = state.sandboxes.as_ref().expect("a manager");
    let open = manager.list().await;
    assert_eq!(open.len(), 1, "one cached boundary per checkout: {open:?}");
    let first = open[0].id.to_string();

    let (status, second) = chat(
        &state,
        serde_json::json!({
            "prompt": "again",
            "sandbox_profile": "live",
            "workspace": workspace.display().to_string(),
            "autonomy": "yolo",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let after = manager.list().await;
    assert_eq!(after.len(), 1, "the second run started a second container");
    assert_eq!(
        after[0].id.to_string(),
        first,
        "the second run reused the boundary"
    );

    // And the run recorded its events.
    let events = state.store.events(&session).expect("events read back");
    assert!(!events.is_empty(), "the run recorded no events");
}

#[tokio::test]
#[ignore = "requires a docker daemon"]
async fn a_chat_request_for_an_unknown_profile_never_reaches_the_engine() {
    let Some((state, workspace, _dir)) = harness().await else {
        return;
    };

    let before = state.sandboxes.as_ref().unwrap().list().await.len();

    let (status, reply) = chat(
        &state,
        serde_json::json!({
            "prompt": "do something",
            "sandbox_profile": "no-such-profile",
            "workspace": workspace.display().to_string(),
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(reply.to_string().contains("no-such-profile"), "{reply}");
    assert_eq!(
        state.sandboxes.as_ref().unwrap().list().await.len(),
        before,
        "a refused request started a container anyway"
    );
    assert_eq!(state.store.count().unwrap(), 0, "a refusal left a session");
}
