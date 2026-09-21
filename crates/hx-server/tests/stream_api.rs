//! The SSE endpoint, end to end: framing, ordering, and the terminating reply.
//!
//! `tests/api.rs` covers the JSON chat route with a scripted model, and `stream.rs`'s unit tests
//! cover the delta accumulator. What neither can see is whether the *HTTP response* is well-formed
//! SSE — whether a client following the spec would parse it. That is what this file asserts: real
//! `data:` lines, a blank line between events, a named `done` event carrying the reply, and the
//! events arriving in the order the run produced them.
//!
//! It exists because the framing is the half of SSE that a hand-rolled client is most likely to get
//! wrong and that no compiler checks. A stream that emits correct JSON with two newlines instead of
//! one is a stream every spec-compliant client hangs on.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use hx_agent::{ApprovalQueue, ModelCall};
use hx_core::error::{HxError, Result};
use hx_core::event::AgentEvent;
use hx_core::ids::{AgentId, CredentialId, ProviderId, SessionId};
use hx_core::message::{Message, Part, Role};
use hx_provider::{ChatRequest, ChatResponse, FinishReason, ModelRouter, ProviderRegistry, Usage};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, LiveEvent, ModelFactory};
use hx_store::Store;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// Answers from a script, and refuses once it runs out — a short script must fail loudly rather
/// than quietly producing a default reply the test then "passes" against.
struct ScriptedModel {
    replies: Mutex<VecDeque<Result<ChatResponse>>>,
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

async fn harness(replies: Vec<Result<ChatResponse>>) -> Arc<AppState> {
    let model = Arc::new(ScriptedModel {
        replies: Mutex::new(VecDeque::from(replies)),
    });
    build_state(Arc::new(Scripted(Arc::clone(&model))) as Arc<dyn ModelFactory>).await
}

/// A model that holds the run open until the test releases it.
///
/// WHY a gate instead of two racing streams: the leak needs another session's bus events to land
/// *mid-run*, and two runs interleave only by luck. The gate freezes the run after it has
/// subscribed and created its session, so the test can publish foreign events by hand —
/// deterministically the overlap the bug needs, with no sleeps praying for a race.
struct GatedModel {
    replies: Mutex<VecDeque<Result<ChatResponse>>>,
    gate: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl ModelCall for GatedModel {
    async fn complete(&self, _req: ChatRequest) -> Result<ChatResponse> {
        self.gate.notified().await;
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

struct Gated(Arc<GatedModel>);

impl ModelFactory for Gated {
    fn for_role(&self, _role: &str) -> Result<Arc<dyn ModelCall>> {
        Ok(Arc::clone(&self.0) as Arc<dyn ModelCall>)
    }
}

async fn gated_harness(
    replies: Vec<Result<ChatResponse>>,
    gate: Arc<tokio::sync::Notify>,
) -> Arc<AppState> {
    let model = Arc::new(GatedModel {
        replies: Mutex::new(VecDeque::from(replies)),
        gate,
    });
    build_state(Arc::new(Gated(Arc::clone(&model))) as Arc<dyn ModelFactory>).await
}

async fn build_state(models: Arc<dyn ModelFactory>) -> Arc<AppState> {
    let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.keep().join("data").display().to_string();

    let now = chrono::Utc::now();
    let router = ModelRouter::from_config(&config, now).expect("router builds");
    let providers =
        ProviderRegistry::from_config(&config, reqwest::Client::new()).expect("providers build");
    let client = reqwest::Client::new();
    let search = BackendRegistry::from_config(
        &config.search,
        client.clone(),
        &hx_secrets::SecretStores::new(),
    )
    .expect("search");
    // Built before `config` moves into the state below.
    let store = Store::from_config(&config).expect("store opens");

    AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(Mutex::new(router)),
        providers: Arc::new(providers),
        secrets: Arc::new(SecretStores::new().with(Arc::new(EnvSecrets))),
        store: Arc::new(store),
        models,
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        approvals: ApprovalQueue::new(std::time::Duration::from_secs(1)),
        phone: None,
        search: Arc::new(search),
        sandboxes: None,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now,
        // No token: these tests bind loopback, which is exactly the deployment where a token is
        // optional. A test that needed one here would mean the rule, not the test, was wrong.
        api_token: None,
        webhooks: Default::default(),
    })
}

fn answer(text: &str) -> ChatResponse {
    ChatResponse {
        message: Message::new(Role::Assistant, vec![Part::text(text)]),
        usage: Usage {
            input_tokens: 10,
            output_tokens: 4,
            ..Default::default()
        },
        finish: FinishReason::Stop,
        model: "scripted-model".to_string(),
        raw: None,
    }
}

/// POST to the stream route and return the whole response body as text, plus the status.
async fn stream(state: &Arc<AppState>, body: serde_json::Value) -> (StatusCode, String) {
    let response = app(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/stream")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Parse an SSE body into `(event_name, data)` pairs, the way a spec-compliant client would.
///
/// Written as a real parser rather than by grepping the raw text: the point of these tests is that a
/// client following the spec can read the stream, and a regex over the body would pass on a body no
/// such client could consume.
fn parse_sse(body: &str) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    for block in body.split("\n\n").filter(|b| !b.trim().is_empty()) {
        let mut name = None;
        let mut data = String::new();
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                // The space after the colon is part of the framing, not the payload.
                data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            }
        }
        if !data.is_empty() {
            out.push((name, data));
        }
    }
    out
}

#[tokio::test]
async fn a_run_streams_its_events_and_ends_with_the_reply() {
    let state = harness(vec![Ok(answer("hi there"))]).await;

    let (status, body) = stream(
        &state,
        serde_json::json!({ "prompt": "hello", "autonomy": "yolo" }),
    )
    .await;

    // 200 once the first event is written. A validation error after the mode switch has no status
    // to change, which is why the route reports those as an `error` event instead.
    assert_eq!(status, StatusCode::OK, "{body}");

    let events = parse_sse(&body);
    assert!(!events.is_empty(), "the stream carried no events: {body:?}");

    // The last event is the reply, and it is *named*: a client distinguishes the end of the stream
    // from an ordinary event by the name, not by counting.
    let (name, data) = events.last().unwrap();
    assert_eq!(name.as_deref(), Some("done"), "the stream ends with `done`");
    let reply: serde_json::Value = serde_json::from_str(data).expect("the done event is JSON");
    assert_eq!(reply["reply"]["stop"], "completed", "{data}");
    assert_eq!(reply["reply"]["final_text"], "hi there", "{data}");

    // Every other event is an AgentEvent tagged with its session, so a client following two runs
    // can tell them apart.
    for (name, data) in &events[..events.len() - 1] {
        assert_eq!(name.as_deref(), None, "only the terminal event is named");
        let value: serde_json::Value = serde_json::from_str(data).expect("each event is JSON");
        assert!(
            value.get("session").is_some(),
            "tagged with a session: {data}"
        );
        assert!(value.get("event").is_some(), "carries the event: {data}");
    }

    // The run's own events really went out: a start and a finish for one turn.
    let kinds: Vec<String> = events[..events.len() - 1]
        .iter()
        .map(|(_, data)| {
            serde_json::from_str::<serde_json::Value>(data).unwrap()["event"]["event"]
                .as_str()
                .unwrap_or("?")
                .to_string()
        })
        .collect();
    assert!(kinds.contains(&"turn_started".to_string()), "{kinds:?}");
    assert!(kinds.contains(&"turn_finished".to_string()), "{kinds:?}");
}

#[tokio::test]
async fn a_request_that_cannot_run_arrives_as_an_error_event_not_a_status() {
    // An empty prompt is a 400 on `/v1/chat`. Here the mode is already `text/event-stream` by the
    // time it is known, so the only honest place for it is an event — and a client has to be told,
    // because a stream that simply ends looks like a dropped connection.
    let state = harness(vec![]).await;

    let (_status, body) = stream(&state, serde_json::json!({ "prompt": "   " })).await;

    let events = parse_sse(&body);
    let (name, data) = events.last().expect("the stream says something: {body:?}");
    // Terminal, but *named* `error` rather than `done`: `done` means the run finished, and this one
    // did not. A client that keys its read loop on any terminal event ends the same way either way,
    // and one that treats `done` as success is not misled — which is why the distinction is worth
    // asserting rather than collapsing both into one name.
    assert_eq!(
        name.as_deref(),
        Some("error"),
        "a run that could not start ends with an error event"
    );
    assert!(
        data.contains("prompt is empty"),
        "the reason travels to the client: {data}"
    );
}

#[tokio::test]
async fn the_stream_does_not_leak_another_runs_events() {
    // One shared broadcast bus serves every run. A subscriber that relayed everything it saw would
    // hand one client another session's transcript — the kind of leak that is invisible in a
    // single-run test and obvious to anyone running two chats.
    let state = harness(vec![Ok(answer("first")), Ok(answer("second"))]).await;

    let (_, first) = stream(
        &state,
        serde_json::json!({ "prompt": "one", "autonomy": "yolo" }),
    )
    .await;
    let first_sessions: Vec<String> = parse_sse(&first)
        .iter()
        .filter_map(|(name, data)| {
            if name.is_some() {
                return None;
            }
            serde_json::from_str::<serde_json::Value>(data)
                .ok()?
                .get("session")?
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert!(!first_sessions.is_empty(), "{first:?}");

    // A second run: its events must belong to a different session than the first run's.
    let (_, second) = stream(
        &state,
        serde_json::json!({ "prompt": "two", "autonomy": "yolo" }),
    )
    .await;
    let second_sessions: Vec<String> = parse_sse(&second)
        .iter()
        .filter_map(|(name, data)| {
            if name.is_some() {
                return None;
            }
            serde_json::from_str::<serde_json::Value>(data)
                .ok()?
                .get("session")?
                .as_str()
                .map(str::to_string)
        })
        .collect();

    assert!(!second_sessions.is_empty(), "{second:?}");
    assert_ne!(
        first_sessions[0], second_sessions[0],
        "two runs are two sessions"
    );
    assert!(
        !second.contains(&first_sessions[0]),
        "the second run's stream carries the first session's id"
    );
}

/// Publish another session's live events the way a concurrent chat would.
///
/// A raw bus send, not a second run: a second run interleaves only by luck, while a direct send
/// is the exact bytes a concurrent run puts on the bus, under the test's control.
fn publish_foreign_events(state: &Arc<AppState>, foreign: &SessionId, count: u64) {
    for seq in 1..=count {
        state
            .event_bus
            .send(LiveEvent {
                session: foreign.clone(),
                seq,
                event: AgentEvent::TurnStarted {
                    agent: AgentId::from_raw("hxd:foreign"),
                    turn: 1,
                },
            })
            .ok();
    }
}

/// Wait until the store holds a session, and return its id.
///
/// WHY poll the store and not sleep: the stream subscribes before the run creates its session,
/// so a session row proves the subscription predates every foreign event the test publishes next.
/// A fixed sleep proves nothing — on a loaded machine the run may not have started yet, and an
/// event sent before the subscription is missed by every implementation, fixed or not.
async fn wait_for_first_session(state: &Arc<AppState>) -> String {
    for _ in 0..250 {
        if let Some(summary) = state
            .store
            .list(10)
            .expect("store lists")
            .into_iter()
            .next()
        {
            return summary.record.id.as_str().to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the run never created a session");
}

/// Wait until a session's transcript holds a message, proving its run started past creation.
async fn wait_for_transcript(state: &Arc<AppState>, session: &SessionId) {
    for _ in 0..250 {
        if !state
            .store
            .messages(session)
            .expect("store reads")
            .is_empty()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the run never started on session {}", session.as_str());
}

#[tokio::test]
async fn a_new_session_stream_drops_other_sessions_events_published_mid_run() {
    // A request that starts a session cannot name it, so the filter learns the id from the run
    // while foreign events are already arriving. This is the exact window the old code leaked:
    // every bus event forwarded, whatever its session.
    let gate = Arc::new(tokio::sync::Notify::new());
    let state = gated_harness(vec![Ok(answer("hello"))], Arc::clone(&gate)).await;

    let streaming = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            stream(
                &state,
                serde_json::json!({ "prompt": "hi", "autonomy": "yolo" }),
            )
            .await
        }
    });

    let own = wait_for_first_session(&state).await;

    let foreign = SessionId::from_raw("ses_foreigneventsthatmustnotleak");
    publish_foreign_events(&state, &foreign, 3);

    gate.notify_one();
    let (status, body) = streaming.await.expect("the stream task runs");
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains(foreign.as_str()),
        "another session's events leaked into the stream: {body:?}"
    );
    assert!(
        body.contains(own.as_str()),
        "the stream lost its own session's events: {body:?}"
    );
    let events = parse_sse(&body);
    assert_eq!(
        events.last().map(|(name, _)| name.as_deref()),
        Some(Some("done")),
        "the stream still ends with the reply: {body:?}"
    );
}

#[tokio::test]
async fn a_resumed_session_stream_forwards_only_its_own_mid_run_events() {
    // A request that resumes a session filters by the named id from the first byte. A foreign
    // event published mid-run must not appear even though the run is live and the bus is shared.
    let gate = Arc::new(tokio::sync::Notify::new());
    let state = gated_harness(vec![Ok(answer("welcome back"))], Arc::clone(&gate)).await;

    let target = state
        .store
        .create(hx_store::NewSession::new(), chrono::Utc::now())
        .expect("session creates")
        .id;

    let streaming = tokio::spawn({
        let state = Arc::clone(&state);
        let session = target.as_str().to_string();
        async move {
            stream(
                &state,
                serde_json::json!({ "prompt": "again", "session": session, "autonomy": "yolo" }),
            )
            .await
        }
    });

    // The prompt append proves the resumed run is past creation and the stream is subscribed;
    // foreign events from here on are seen by the stream's receiver for certain.
    wait_for_transcript(&state, &target).await;

    let foreign = SessionId::from_raw("ses_resumefiltermustdropthis");
    publish_foreign_events(&state, &foreign, 3);

    gate.notify_one();
    let (status, body) = streaming.await.expect("the stream task runs");
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains(foreign.as_str()),
        "another session's events leaked into the resumed stream: {body:?}"
    );
    assert!(
        body.contains(target.as_str()),
        "the resumed stream lost its own session's events: {body:?}"
    );
}
