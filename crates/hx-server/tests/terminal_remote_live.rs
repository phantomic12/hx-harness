//! Live: a terminal on a *remote* machine, through the real HTTP and WebSocket surface.
//!
//! Ignored by default, because it needs a reachable SSH server. To run:
//!
//!   HX_SSH_TEST_HOST=127.0.0.1 HX_SSH_TEST_PORT=2222 HX_SSH_TEST_USER=$(whoami) \
//!   HX_SSH_TEST_KEY=/tmp/hxptytest/user_ed25519 \
//!   cargo test -p hx-server --offline --test terminal_remote_live -- --ignored --test-threads=1
//!
//! This is the test that matters for the feature. The unit tests prove the pty layer and the route
//! separately; this proves a client typing into a WebSocket makes a shell on another machine run
//! something, with every layer in between real — config, secret store, SSH transport, the pump, the
//! broadcast, the socket.

#![cfg(unix)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use hx_agent::{ApprovalQueue, ModelCall};
use hx_core::config::Config;
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use hx_provider::{ChatRequest, ChatResponse, ModelRouter, ProviderRegistry};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, ModelFactory};
use hx_store::Store;
use tokio_tungstenite::tungstenite::Message;

/// The rule an operator writes to permit a shell on a remote machine.
///
/// Built through the same constructor the route is judged by, rather than as a literal, so this
/// cannot drift from the action and risk class the gate actually uses.
struct SshShellAllow;

impl SshShellAllow {
    fn rule() -> hx_core::approval::Rule {
        use hx_core::approval::{RiskClass, Rule};
        Rule::tool("shell").risk(RiskClass::External)
    }
}

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

struct Server {
    addr: String,
    _dir: tempfile::TempDir,
}

/// A server whose config names one SSH host, with the key supplied through the environment rather
/// than written into the test source — the same route a real deployment takes.
///
/// `None` when `HX_SSH_TEST_HOST` is unset, so the file is inert on a machine with no sshd.
async fn harness() -> Option<Server> {
    harness_with_policy(true).await
}

/// The same server with no allow rule, so the refusal can be asserted against a real deployment
/// shape rather than a policy constructed in code that no config could produce.
async fn harness_without_allow() -> Option<Server> {
    harness_with_policy(false).await
}

async fn harness_with_policy(allow_remote_shell: bool) -> Option<Server> {
    let host = std::env::var("HX_SSH_TEST_HOST").ok()?;
    let port: u16 = std::env::var("HX_SSH_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22);
    let user = std::env::var("HX_SSH_TEST_USER").unwrap_or_else(|_| "root".to_string());

    let key_path = std::env::var("HX_SSH_TEST_KEY").unwrap_or_else(|_| "~/.ssh/id_ed25519".into());
    let key_path = match key_path.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => key_path,
    };
    let key = std::fs::read_to_string(&key_path).expect("the test key is readable");
    std::env::set_var("HX_TEST_SSH_KEY", &key);

    let yaml = format!(
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

hosts:
  buildbox:
    kind: ssh
    address: "{host}"
    port: {port}
    user: "{user}"
    auth: {{ kind: key, secret_ref: "env:HX_TEST_SSH_KEY" }}
"#
    );

    let mut config = Config::from_yaml(&yaml).expect("config parses");
    config.terminal.shell = "/bin/sh".to_string();

    // The daemon pins host keys (`HostKeyPolicy::Strict`) against its own file, so the test has to
    // trust the server the way an operator does: `ssh-keyscan` into that file. Seeding it here is
    // not a workaround for the check, it is the check being exercised — without this entry the
    // connect is refused, which the error message at the end of this file describes.
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.path().join("data").display().to_string();
    std::fs::create_dir_all(dir.path().join("data")).expect("data dir");
    let scanned = std::process::Command::new("ssh-keyscan")
        .args(["-p", &port.to_string(), "-T", "5", &host])
        .output();
    match scanned {
        Ok(out) if out.status.success() && !out.stdout.is_empty() => {
            std::fs::write(dir.path().join("data").join("known_hosts"), &out.stdout)
                .expect("known_hosts is writable");
        }
        _ => {
            // No `ssh-keyscan` (or it could not reach the server): the connect below will be
            // refused with the daemon's own message rather than a confusing failure here.
            eprintln!("note: ssh-keyscan unavailable; the host key will not be pinned");
        }
    }

    if allow_remote_shell {
        // An operator opting in to a shell on a remote machine. The `External` risk class the
        // `Execute` action carries is what a rule has to name, and without one the route refuses
        // with a 403 — see `a_remote_shell_without_an_allow_rule_is_refused`.
        config.agent.approval.allow.push(SshShellAllow::rule());
    }
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

    Some(Server {
        addr: addr.to_string(),
        _dir: dir,
    })
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The text of an `output` frame, decoded.
fn output_text(frame: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(frame).ok()?;
    if parsed.get("type")?.as_str()? != "output" {
        return None;
    }
    let data = parsed.get("data")?.as_str()?;
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

/// The text of a `scrollback` frame, decoded.
fn scrollback_text(frame: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(frame).ok()?;
    if parsed.get("type")?.as_str()? != "scrollback" {
        return None;
    }
    let data = parsed.get("data")?.as_str()?;
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
#[ignore]
async fn a_client_typing_into_a_websocket_runs_a_command_on_the_remote_machine() {
    let Some(server) = harness().await else {
        eprintln!("skipping: HX_SSH_TEST_HOST is unset");
        return;
    };
    let base = format!("http://{}", server.addr);
    let client = reqwest::Client::new();

    let created = client
        .post(format!("{base}/v1/terminals"))
        .json(&serde_json::json!({
            "id": "t-remote-live",
            "host": "buildbox",
            "shell": "sh",
            "cols": 80,
            "rows": 24,
        }))
        .send()
        .await
        .expect("create");
    let status = created.status();
    let body = created.text().await.unwrap_or_default();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "creating a terminal on a configured ssh host should work: {body}"
    );
    assert!(
        body.contains("buildbox"),
        "the reply should name the host it landed on; got {body}"
    );

    let ws_url = format!("ws://{}/v1/terminals/t-remote-live/ws", server.addr);
    let (mut socket, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("attach");

    // The remote shell evaluates the arithmetic, so reading back 42 means these bytes reached a
    // shell on the far side rather than being echoed by something on this one.
    socket
        .send(Message::Text(
            serde_json::json!({ "type": "input", "data": b64(b"echo REMOTE_MARKER_$((6*7))\n") })
                .to_string()
                .into(),
        ))
        .await
        .expect("send the input");

    let mut seen = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
    while tokio::time::Instant::now() < deadline && !seen.contains("REMOTE_MARKER_42") {
        match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next()).await {
            Ok(Some(Ok(Message::Text(frame)))) => {
                if let Some(text) = output_text(&frame) {
                    seen.push_str(&text);
                }
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => panic!("the socket failed: {e}"),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    let _ = client
        .delete(format!("{base}/v1/terminals/t-remote-live"))
        .send()
        .await;
    assert!(
        seen.contains("REMOTE_MARKER_42"),
        "the remote shell never printed the marker; saw: {seen:?}"
    );
}

/// A client attaching late is sent the scrollback, on a remote terminal as on a local one.
#[tokio::test]
#[ignore]
async fn a_late_client_on_a_remote_terminal_gets_the_scrollback() {
    let Some(server) = harness().await else {
        eprintln!("skipping: HX_SSH_TEST_HOST is unset");
        return;
    };
    let base = format!("http://{}", server.addr);
    let client = reqwest::Client::new();

    let created = client
        .post(format!("{base}/v1/terminals"))
        .json(&serde_json::json!({
            "id": "t-late",
            "host": "buildbox",
            "shell": "sh",
            "cols": 80,
            "rows": 24,
        }))
        .send()
        .await
        .expect("create");
    assert_eq!(created.status(), reqwest::StatusCode::OK);

    let ws_url = format!("ws://{}/v1/terminals/t-late/ws", server.addr);
    {
        let (mut socket, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .expect("attach");
        socket
            .send(Message::Text(
                serde_json::json!({ "type": "input", "data": b64(b"echo SCROLLBACK_MARKER\n") })
                    .to_string()
                    .into(),
            ))
            .await
            .expect("send");
        let mut seen = String::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
        while tokio::time::Instant::now() < deadline && !seen.contains("SCROLLBACK_MARKER") {
            match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next()).await {
                Ok(Some(Ok(Message::Text(frame)))) => {
                    if let Some(text) = output_text(&frame) {
                        seen.push_str(&text);
                    }
                }
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => panic!("the socket failed: {e}"),
                Ok(None) => break,
                Err(_) => continue,
            }
        }
    } // the socket drops here: this client detaches

    // Attaching now must be handed what the first client already saw. That retention is what makes
    // the daemon the owner of the terminal rather than a client.
    let (mut second, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("attach late");
    let mut seen = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline && !seen.contains("SCROLLBACK_MARKER") {
        match tokio::time::timeout(std::time::Duration::from_secs(5), second.next()).await {
            Ok(Some(Ok(Message::Text(frame)))) => {
                if let Some(text) = scrollback_text(&frame) {
                    seen.push_str(&text);
                }
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => panic!("the socket failed: {e}"),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    let _ = client
        .delete(format!("{base}/v1/terminals/t-late"))
        .send()
        .await;
    assert!(
        seen.contains("SCROLLBACK_MARKER"),
        "a client attaching late must be sent the remote scrollback; saw: {seen:?}"
    );
}

/// The gate itself: without an allow rule, a remote shell is refused rather than quietly permitted.
///
/// This is the security-relevant half of the feature. An interactive shell has no command line to
/// classify — the caller types whatever they like afterwards — so it cannot be judged the way `exec`
/// is judged, and letting it through on the read check would make the policy decorative.
#[tokio::test]
#[ignore]
async fn a_remote_shell_without_an_allow_rule_is_refused() {
    let Some(server) = harness().await else {
        eprintln!("skipping: HX_SSH_TEST_HOST is unset");
        return;
    };
    // A fresh server whose config names the host but grants nothing.
    let Some(strict) = harness_without_allow().await else {
        eprintln!("skipping: HX_SSH_TEST_HOST is unset");
        return;
    };
    let _ = server;
    let base = format!("http://{}", strict.addr);
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{base}/v1/terminals"))
        .json(&serde_json::json!({ "id": "t-denied", "host": "buildbox" }))
        .send()
        .await
        .expect("create");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a remote shell with no allow rule must be refused"
    );
    let body = response.text().await.expect("body");
    assert!(
        body.contains("buildbox"),
        "the refusal should name the host; got {body}"
    );
}
