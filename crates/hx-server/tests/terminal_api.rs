//! The terminal over a real socket: attach two clients to one shell and see the same bytes.
//!
//! This is M2's exit criterion at the protocol level. The roadmap's version is "open a browser
//! terminal to a shell, run a command, watch the same bytes in the TUI" — a browser is a client of
//! the same contract these tests drive, so what is proven here is the part the front end cannot
//! work around: that the daemon owns the PTY, that a second client joining sees the same output,
//! and that input from a client reaches the shell.
//!
//! Why a real server and a real socket rather than calling the handler: the WebSocket upgrade
//! handshake and the framing cannot be exercised through `tower::oneshot`. A test that called the
//! handler directly would agree with itself about a protocol neither side had to speak.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use hx_agent::{ApprovalQueue, ModelCall};
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use hx_provider::{ChatRequest, ChatResponse, ModelRouter, ProviderRegistry};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, ModelFactory};
use hx_store::Store;
use tokio_tungstenite::tungstenite::Message;

/// The terminal routes need no model at all — a PTY is not an agent. This exists only so the
/// harness builds the same way the daemon does rather than through a test-only constructor that
/// could drift from it.
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

/// A real server on an ephemeral port, plus the temp dir that must outlive it.
struct Server {
    addr: String,
    _dir: tempfile::TempDir,
}

async fn harness() -> Server {
    let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
    // The terminal's shell is pinned rather than inherited from `$SHELL`: the test asserts on shell
    // output, and a developer's interactive shell (a prompt with escape sequences, an rc file that
    // prints) would make the assertions depend on whose machine ran them.
    config.terminal.shell = "/bin/sh".to_string();
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.path().join("data").display().to_string();
    let now = chrono::Utc::now();
    let router = ModelRouter::from_config(&config, now).expect("router builds");
    let client = reqwest::Client::new();
    let providers =
        ProviderRegistry::from_config(&config, client.clone()).expect("providers build");
    let search = BackendRegistry::from_config(&config.search, client.clone()).expect("search");
    let store = Store::from_config(&config).expect("store opens");

    let state = AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(Mutex::new(router)),
        providers: Arc::new(providers),
        secrets: Arc::new(SecretStores::new().with(Arc::new(EnvSecrets))),
        store: Arc::new(store),
        models: Arc::new(Dead(Arc::new(DeadModel))),
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        approvals: ApprovalQueue::new(std::time::Duration::from_secs(1)),
        search: Arc::new(search),
        sandboxes: None,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now,
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
        _dir: dir,
    }
}

/// Read frames until `pred` is satisfied, or fail with what was actually seen.
///
/// Tests that `sleep` and then assert are how a flaky terminal test is written; the deadline below
/// is a bound on failure, not a wait. Everything here reads until the condition holds.
async fn read_until<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
    what: &str,
    mut pred: impl FnMut(&serde_json::Value) -> bool,
) -> Vec<serde_json::Value>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut seen = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let next = tokio::time::timeout(std::time::Duration::from_secs(15), socket.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}; saw {seen:?}"));
        let Some(Ok(Message::Text(text))) = next else {
            continue;
        };
        let value: serde_json::Value = serde_json::from_str(&text).expect("frames are JSON");
        let done = pred(&value);
        seen.push(value);
        if done {
            return seen;
        }
    }
    panic!("never saw {what}; frames seen were {seen:?}");
}

/// Decode the base64 `data` of the first frame of `kind`, concatenated.
fn data_of(frames: &[serde_json::Value], kind: &str) -> String {
    use base64::Engine as _;
    let mut bytes = Vec::new();
    for frame in frames {
        if frame["type"] == kind {
            let raw = frame["data"].as_str().expect("data is a string");
            bytes.extend_from_slice(
                &base64::engine::general_purpose::STANDARD
                    .decode(raw)
                    .expect("data is base64"),
            );
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn two_clients_attach_to_one_terminal_and_both_see_the_same_bytes() {
    let server = harness().await;
    let addr = server.addr.clone();
    let base = format!("http://{addr}");

    // Start the shell through the API, the way a front end does.
    let created: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/v1/terminals"))
        .json(
            &serde_json::json!({ "id": "t-terminal", "shell": "/bin/sh", "cols": 80, "rows": 24 }),
        )
        .send()
        .await
        .expect("create must be accepted")
        .json()
        .await
        .expect("a JSON body");
    assert_eq!(
        created["created"], true,
        "the terminal must be created: {created:?}"
    );

    let ws_url = format!("ws://{addr}/v1/terminals/t-terminal/ws");
    let (mut a, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("client A attaches");
    let (mut b, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("client B attaches");

    // Type through client A. A real shell echoes what is typed, so the output is proof the bytes
    // reached the shell and not merely the socket.
    use base64::Engine as _;
    let typed = base64::engine::general_purpose::STANDARD.encode(b"echo both-clients-see-this\n");
    a.send(Message::Text(
        serde_json::json!({ "type": "input", "data": typed })
            .to_string()
            .into(),
    ))
    .await
    .expect("input must be sent");

    let a_saw = read_until(&mut a, "client A to see the echo", |f| {
        f["type"] == "output"
    })
    .await;
    let b_saw = read_until(&mut b, "client B to see the echo", |f| {
        f["type"] == "output"
    })
    .await;

    let a_text = data_of(&a_saw, "output");
    let b_text = data_of(&b_saw, "output");
    assert!(
        a_text.contains("both-clients-see-this"),
        "the typing client must see the shell's echo, saw {a_text:?}"
    );
    assert!(
        b_text.contains("both-clients-see-this"),
        "the *second* client must see the same bytes — this is M2's claim, saw {b_text:?}"
    );

    let _ = reqwest::Client::new()
        .delete(format!("{base}/v1/terminals/t-terminal"))
        .send()
        .await;
}

#[tokio::test]
async fn a_late_client_is_sent_the_scrollback_before_any_live_output() {
    let server = harness().await;
    let addr = server.addr.clone();
    let base = format!("http://{addr}");

    reqwest::Client::new()
        .post(format!("{base}/v1/terminals"))
        .json(&serde_json::json!({ "id": "t-late", "shell": "/bin/sh" }))
        .send()
        .await
        .expect("create");

    let ws_url = format!("ws://{addr}/v1/terminals/t-late/ws");
    // The first client runs a command and waits for the output to exist.
    let (mut first, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("first");
    use base64::Engine as _;
    let typed = base64::engine::general_purpose::STANDARD.encode(b"echo before-you-arrived\n");
    first
        .send(Message::Text(
            serde_json::json!({ "type": "input", "data": typed })
                .to_string()
                .into(),
        ))
        .await
        .expect("input");
    // Read until the *marker* appears, not merely until a frame of type `output` does: a pty echoes
    // the typed command back before the command's own output, so stopping at the first output frame
    // would assert against the echo of the input rather than on what the shell printed.
    let frames = read_until(&mut first, "the command's output", |f| {
        f["type"] == "output"
    })
    .await;
    let mut text = data_of(&frames, "output");
    while !text.contains("before-you-arrived") {
        let more = read_until(&mut first, "the command's output", |f| {
            f["type"] == "output"
        })
        .await;
        text.push_str(&data_of(&more, "output"));
    }
    assert!(text.contains("before-you-arrived"), "saw {text:?}");
    drop(first);

    // A client attaching *after* the output exists is sent it as scrollback — not as live output,
    // so it can tell history from what happens next.
    let (mut late, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("late client attaches");
    let frames = read_until(&mut late, "the scrollback frame", |f| {
        f["type"] == "scrollback"
    })
    .await;
    let text = data_of(&frames, "scrollback");
    assert!(
        text.contains("before-you-arrived"),
        "a client that attaches late must be shown what it missed, saw {text:?}"
    );

    let _ = reqwest::Client::new()
        .delete(format!("{base}/v1/terminals/t-late"))
        .send()
        .await;
}

#[tokio::test]
async fn attaching_to_a_terminal_that_does_not_exist_is_rejected() {
    let server = harness().await;
    let addr = server.addr.clone();

    // A status, not an upgraded stream that never speaks: a client must be able to tell "no such
    // terminal" from "a terminal with nothing to say yet".
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v1/terminals/nope/ws"))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .expect("a response");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "an unknown terminal must be a 404"
    );
}

#[tokio::test]
async fn a_terminal_created_twice_under_one_id_is_refused() {
    let server = harness().await;
    let addr = server.addr.clone();
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{base}/v1/terminals"))
        .json(&serde_json::json!({ "id": "t-dup", "shell": "/bin/sh" }))
        .send()
        .await
        .expect("create");
    assert_eq!(first.status(), reqwest::StatusCode::OK);

    let second = client
        .post(format!("{base}/v1/terminals"))
        .json(&serde_json::json!({ "id": "t-dup", "shell": "/bin/sh" }))
        .send()
        .await
        .expect("create");
    assert_ne!(
        second.status(),
        reqwest::StatusCode::OK,
        "a second terminal under a live id must be refused — attaching is how to reach the first"
    );

    let _ = client
        .delete(format!("{base}/v1/terminals/t-dup"))
        .send()
        .await;
}

#[tokio::test]
async fn a_detached_client_leaves_the_shell_running_for_the_next_one() {
    // The property that makes the daemon the owner rather than a client: closing a tab must not
    // kill the shell, or two clients can never share one terminal.
    let server = harness().await;
    let addr = server.addr.clone();
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/v1/terminals"))
        .json(&serde_json::json!({ "id": "t-survives", "shell": "/bin/sh" }))
        .send()
        .await
        .expect("create");

    let ws_url = format!("ws://{addr}/v1/terminals/t-survives/ws");
    {
        let (mut first, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .expect("first");
        use base64::Engine as _;
        let typed = base64::engine::general_purpose::STANDARD.encode(b"echo first-session\n");
        first
            .send(Message::Text(
                serde_json::json!({ "type": "input", "data": typed })
                    .to_string()
                    .into(),
            ))
            .await
            .expect("input");
        let frames = read_until(&mut first, "the first session's output", |f| {
            f["type"] == "output"
        })
        .await;
        assert!(data_of(&frames, "output").contains("first-session"));
        // Dropped here: the client detaches.
    }

    // The terminal is still registered, so a new client can attach and sees the earlier output.
    let list: serde_json::Value = client
        .get(format!("{base}/v1/terminals"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("JSON");
    let ids = list["terminals"].as_array().expect("an array");
    assert!(
        ids.iter().any(|v| v == "t-survives"),
        "the shell must outlive the client that opened it, saw {ids:?}"
    );

    let (mut second, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("second client attaches to the same shell");
    let frames = read_until(&mut second, "the previous session's output", |f| {
        f["type"] == "scrollback"
    })
    .await;
    assert!(
        data_of(&frames, "scrollback").contains("first-session"),
        "the surviving shell's earlier output must still be there"
    );

    let _ = client
        .delete(format!("{base}/v1/terminals/t-survives"))
        .send()
        .await;
}
