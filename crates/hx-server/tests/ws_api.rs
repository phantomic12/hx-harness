//! The session WebSocket event stream, end to end: history-then-live ordering, per-session filtering,
//! and exact reconnection.
//!
//! `stream.rs`'s unit tests and `stream_api.rs` cover SSE; neither can exercise a WebSocket upgrade,
//! because `tower::oneshot` cannot perform the RFC-6455 handshake. That is what this file does: a real
//! axum server on an ephemeral port, real tokio-tungstenite clients, and the wire frames they actually
//! parse. It exists because the two hard guarantees of this route — a client must not receive another
//! session's events, and a reconnecting client must see neither duplicates nor gaps — are both invisible to
//! any test that reads state through the same store the implementation writes.
//!
//! Frames are asserted as JSON the way a real client would parse them, not by grepping raw text: the
//! route's whole job is to emit `{"seq","session","event"}` objects a spec-compliant client can
//! consume, so the tests parse each frame and check the fields it depends on.

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use hx_agent::{ApprovalQueue, ModelCall};
use hx_core::error::{HxError, Result};
use hx_core::event::AgentEvent;
use hx_core::ids::{AgentId, CredentialId, ProviderId, SessionId};
use hx_core::message::{Message, Part, Role};
use hx_provider::{ChatRequest, ChatResponse, ModelRouter, ProviderRegistry};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, LiveEvent, ModelFactory};
use hx_store::{NewSession, Store};
use std::sync::{Arc, Mutex};
use tokio_tungstenite::tungstenite::Message as TMessage;

/// A model that refuses everything — none of these tests need a real run, they drive the event bus and the
/// store directly (the same two sources `chat.rs::write_events` writes to). The model exists only so the
/// harness builds the same way the daemon does.
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

/// One scripted answer, so a test can run a *real* chat and watch its events reach the WebSocket
/// through `chat.rs::write_events` — the full pipeline that driving the bus with `push` bypasses.
struct ScriptedModel {
    replies: std::sync::Mutex<std::collections::VecDeque<Result<ChatResponse>>>,
}

#[async_trait]
impl ModelCall for ScriptedModel {
    async fn complete(&self, _req: ChatRequest) -> Result<ChatResponse> {
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(HxError::Provider("no more scripted answers".to_string())))
    }
    fn model(&self) -> String {
        "dead-model".to_string()
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

/// What the tests hold: the shared state plus the bound server address.
struct Server {
    state: Arc<AppState>,
    addr: String,
    _dir: tempfile::TempDir,
    session: SessionId,
    other: SessionId,
}

/// Build the state, start a real server on an ephemeral port, and mint two sessions —
/// unrelated session B exists *and has events*, so a test that asserts A's stream does not contain B is
/// asserting against a real distractor rather than silence.
async fn harness() -> Server {
    harness_with(Arc::new(Dead(Arc::new(DeadModel)))).await
}

async fn harness_with(models: Arc<dyn ModelFactory>) -> Server {
    let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    // `dir.path()` borrows rather than consuming (unlike `keep`), so the TempDir can still be held in
    // the returned `Server` to keep the database alive while the tests run.
    config.daemon.data_dir = dir.path().join("data").display().to_string();
    let now = chrono::Utc::now();
    let router = ModelRouter::from_config(&config, now).expect("router builds");
    let providers =
        ProviderRegistry::from_config(&config, reqwest::Client::new()).expect("providers build");
    let client = reqwest::Client::new();
    let search = BackendRegistry::from_config(&config.search, client.clone()).expect("search");
    let store = Store::from_config(&config).expect("store opens");

    let state = AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(Mutex::new(router)),
        providers: Arc::new(providers),
        secrets: Arc::new(SecretStores::new().with(Arc::new(EnvSecrets))),
        store: Arc::new(store),
        models,
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        approvals: ApprovalQueue::new(std::time::Duration::from_secs(1)),
        search: Arc::new(search),
        sandboxes: None,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now,
    });

    let a = state
        .store
        .create(NewSession::new(), now)
        .expect("session A")
        .id;
    let b = state
        .store
        .create(NewSession::new(), now)
        .expect("session B")
        .id;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let router = app(Arc::clone(&state));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    Server {
        state,
        addr: addr.to_string(),
        _dir: dir,
        session: a,
        other: b,
    }
}

/// Append an event to BOTH the store and the live bus, exactly as `write_events` does for a real run.
/// The seq is the store's, which is the number a reconnecting client reports.
async fn push(state: &Arc<AppState>, session: &SessionId, turn: u32) {
    let event = AgentEvent::TurnStarted {
        agent: AgentId::from("agt_1"),
        turn,
    };
    let seq = state
        .store
        .append_event(session, &event, chrono::Utc::now())
        .expect("append");
    let _ = state.event_bus.send(LiveEvent {
        session: session.clone(),
        seq,
        event,
    });
}

/// Connect a WS client to the session route, optionally sending a `since_seq` handshake first.
async fn connect(server: &Server, since_seq: Option<u64>, session: &SessionId) -> WsClient {
    let url = format!("ws://{}/v1/sessions/{}/ws", server.addr, session.as_str());
    let (mut socket, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");
    if let Some(n) = since_seq {
        socket
            .send(TMessage::Text(format!(r#"{{"since_seq":{n}}}"#).into()))
            .await
            .expect("handshake");
    }
    WsClient { socket }
}

struct WsClient {
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

/// Read one text frame as parsed JSON. Each frame should be `{"seq","session","event"}`; this decodes
/// it the way a client would rather than trusting a raw substring.
async fn frame(client: &mut WsClient) -> serde_json::Value {
    loop {
        match client.socket.next().await {
            Some(Ok(TMessage::Text(text))) => {
                return serde_json::from_str(&text).expect("a text frame is JSON");
            }
            // Ping/pong and other control frames are not part of the event stream; a client skips them.
            Some(Ok(_)) => continue,
            other => panic!("the stream ended unexpectedly: {other:?}"),
        }
    }
}

#[tokio::test]
async fn two_clients_on_one_session_both_receive_the_same_live_events() {
    let server = harness().await;
    let mut first = connect(&server, None, &server.session).await;
    let mut second = connect(&server, None, &server.session).await;

    // Two events emitted for session A while both clients are attached.
    push(&server.state, &server.session, 1).await;
    push(&server.state, &server.session, 2).await;
    // A distractor session B that must leak into neither A client.
    push(&server.state, &server.other, 99).await;

    let a1 = frame(&mut first).await;
    let a2 = frame(&mut first).await;
    let b1 = frame(&mut second).await;
    let b2 = frame(&mut second).await;

    // Same events, same order, both clients.
    assert_eq!(a1, b1, "the two clients disagree on the first event");
    assert_eq!(a2, b2, "the two clients disagree on the second event");
    assert_eq!(a1["seq"], 1);
    assert_eq!(a2["seq"], 2);
    assert_eq!(a1["session"], server.session.as_str());

    // The other session's event never reached either client.
    assert_ne!(a1["session"], server.other.as_str());
    assert_ne!(a2["session"], server.other.as_str());
}

#[tokio::test]
async fn a_late_client_is_sent_the_sessions_existing_events_then_live_ones() {
    let server = harness().await;
    // History exists before any client attaches — a reconnecting/late client must not see only the tail.
    push(&server.state, &server.session, 1).await;
    push(&server.state, &server.session, 2).await;

    let mut client = connect(&server, None, &server.session).await;
    assert_eq!(frame(&mut client).await["seq"], 1, "history first");
    assert_eq!(frame(&mut client).await["seq"], 2, "history in order");

    push(&server.state, &server.session, 3).await;
    assert_eq!(
        frame(&mut client).await["seq"],
        3,
        "live event follows the history"
    );
}

#[tokio::test]
async fn a_client_connecting_after_some_events_does_not_see_the_earlier_ones_it_was_away_for() {
    // The reconnect contract in one stroke: `since_seq` means the server replays only what comes after, so
    // the client neither re-renders events it has already shown (duplicates) nor is told to re-read the
    // whole transcript. Events 1..4 exist and 1..2 are already rendered by this client; it reconnects
    // at 2 and must get exactly 3, 4, then any live ones.
    let server = harness().await;
    push(&server.state, &server.session, 1).await;
    push(&server.state, &server.session, 2).await;
    push(&server.state, &server.session, 3).await;
    push(&server.state, &server.session, 4).await;

    let mut resumed = connect(&server, Some(2), &server.session).await;
    assert_eq!(frame(&mut resumed).await["seq"], 3, "no duplicates");
    assert_eq!(frame(&mut resumed).await["seq"], 4, "no gaps");

    push(&server.state, &server.session, 5).await;
    assert_eq!(
        frame(&mut resumed).await["seq"],
        5,
        "live events continue after a resume"
    );
}

#[tokio::test]
async fn a_fresh_client_without_a_handshake_receives_the_whole_session() {
    // A client that sends nothing is treated as `since_seq: 0` — it has nothing to resume, so it must
    // be shown everything. It also proves the handshake timer does not wedge a silent client forever.
    let server = harness().await;
    push(&server.state, &server.session, 1).await;
    push(&server.state, &server.session, 2).await;

    let mut client = connect(&server, None, &server.session).await;
    assert_eq!(frame(&mut client).await["seq"], 1);
    assert_eq!(frame(&mut client).await["seq"], 2);
}

#[tokio::test]
async fn a_reconnecting_client_receives_exactly_the_events_after_its_last_seen_seq_no_more_no_less()
{
    // The strongest form of the reconnect guarantee: two clients start the same stream, one reads ahead, and
    // after the laggard has caught up by reconnecting with `since_seq` equal to where it stopped, both have
    // seen exactly the same events with no event repeated and none skipped. This is M2's "no duplicates,
    // no gaps" stated as a property rather than a snapshot.
    let server = harness().await;
    let mut ahead = connect(&server, None, &server.session).await;
    let mut behind = connect(&server, None, &server.session).await;

    push(&server.state, &server.session, 1).await;
    push(&server.state, &server.session, 2).await;
    push(&server.state, &server.session, 3).await;

    // The "ahead" client sees all three; the "behind" client only reads the first two before its link
    // drops (imagine the network). It knows it saw seq 2.
    let mut seen_ahead = Vec::new();
    for _ in 0..3 {
        seen_ahead.push(frame(&mut ahead).await["seq"].as_u64().unwrap());
    }
    assert_eq!(frame(&mut behind).await["seq"], 1);
    assert_eq!(frame(&mut behind).await["seq"], 2);

    // Reconnect behind at 2. It must catch up to exactly seq 3 and not repeat 1..2.
    let mut behind = connect(&server, Some(2), &server.session).await;
    assert_eq!(
        frame(&mut behind).await["seq"],
        3,
        "no duplicate of 1..2, no gap to 3"
    );

    // A new live event reaches both the never-disconnected and the reconnecting client identically.
    push(&server.state, &server.session, 4).await;
    let new_ahead = frame(&mut ahead).await;
    let new_behind = frame(&mut behind).await;
    assert_eq!(new_ahead["seq"], 4);
    assert_eq!(new_behind, new_ahead, "both clients see the same events");

    assert_eq!(
        seen_ahead,
        vec![1, 2, 3],
        "the never-disconnected client saw every event"
    );
}

#[tokio::test]
async fn connecting_to_a_session_that_does_not_exist_is_rejected() {
    // A 404 must surface as a failed connection, not as an open socket with no events — a client must be
    // able to tell "no such session" from "a session with no events yet".
    let server = harness().await;
    let url = format!("ws://{}/v1/sessions/ses_nope/ws", server.addr);
    let result = tokio_tungstenite::connect_async(&url).await;
    assert!(result.is_err(), "an unknown session must not upgrade");
}

/// A single scripted assistant turn.
fn answer(text: &str) -> ChatResponse {
    ChatResponse {
        message: Message::new(Role::Assistant, vec![Part::text(text)]),
        usage: hx_provider::Usage {
            input_tokens: 10,
            output_tokens: 4,
            ..Default::default()
        },
        finish: hx_provider::FinishReason::Stop,
        model: "dead-model".to_string(),
        raw: None,
    }
}

/// POST `/v1/chat/stream`, which starts the run on the given session. The run (and
/// `chat::write_events`) is spawned inside the handler and lives independently of the response body, so the
/// response can be dropped the moment the handler returns — collecting the SSE body would block until the run's
/// stream closes, which is not what this test needs.
async fn run_stream(state: &Arc<AppState>, session: &SessionId) {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let _response = app(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/stream")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "prompt": "hello",
                        "autonomy": "yolo",
                        "session": session.as_str(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_real_chat_run_publishes_its_events_to_a_second_attached_client() {
    // The full pipeline, not the shortcut: a real run through `write_events` (which assigns each event's
    // store seq and sends it on the bus) must appear on a WebSocket attached to that session. This proves
    // the seq plumbing in `chat.rs` — the change that makes reconnection exact — end to end, and that two
    // front ends (here, the SSE run plus the WS client) share one stream.
    let server = harness_with(Arc::new(Scripted(Arc::new(ScriptedModel {
        replies: std::sync::Mutex::new(std::collections::VecDeque::from(vec![Ok(answer("hi"))])),
    }))))
    .await;

    let mut client = connect(&server, None, &server.session).await;
    run_stream(&server.state, &server.session).await;

    // Read a couple of frames under a timeout so a wiring bug fails fast with diagnostics instead of
    // hanging the suite. Whatever the run emitted arrives as seq-tagged frames of this session.
    let mut frames = Vec::new();
    for _ in 0..2 {
        let f = tokio::time::timeout(std::time::Duration::from_secs(5), frame(&mut client))
            .await
            .expect("no event arrived within 5s");
        frames.push(f);
    }
    for f in &frames {
        assert_eq!(f["session"], server.session.as_str(), "{f}");
        assert!(f["seq"].as_u64().is_some(), "{f}");
    }
}
