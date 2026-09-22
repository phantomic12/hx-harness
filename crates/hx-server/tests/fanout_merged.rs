//! Adversarial integration tests for the **merged** fan-out surface.
//!
//! `POST /v1/fanout`, the model pool with health-aware draw, and the parallel-ish child execution
//! were written by four separate lanes and had never been exercised together. `tests/fanout_api.rs`
//! pins the happy paths (two children over two healthy members, a short pool, an empty body). This
//! file is the adversarial reading of the same merged surface, over the **real router** (and, in
//! `a_real_loopback_daemon_answers_a_fan_out` below, over a real TCP socket):
//!
//! - a dead member mid-fan-out: does it re-route, does it cascade, is its reason redacted;
//! - a short pool: refused loudly, and does it spend anything before refusing;
//! - a session that does not exist: refused, or billed against a session that is not there;
//! - per-child sessions: which one is the one that pays;
//! - token accounting: does the total equal the sum of the children;
//! - the response shape the web pane reads: are `members`/`children` index-aligned;
//! - oversized and malformed bodies: a sentence, never a 500 with a debug string;
//! - concurrency: the children overlap (bounded by `agent.fanout_max_parallel`), and the
//!   outcomes come back in request order.
//!
//! Only the provider call is a script; the `AppState`, the router, the spawner the route builds, the
//! model pool from `Config`, the fan-out module and a real SQLite session store on disk are real.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use hx_core::config::ProviderKind;
use hx_core::error::{HxError, Result as HxResult};
use hx_core::ids::{ProviderId, SessionId};
use hx_core::message::Message;
use hx_core::pool::{MemberHealth, ModelPool, PoolMember};
use hx_provider::{ChatRequest, ChatResponse, FinishReason, Provider, ProviderRegistry, Usage};
use hx_secrets::{FixedSecrets, Secret, SecretStores};
use hx_server::routes::{FanOutBody, FanOutChild};
use hx_server::{app, AppState, AppStateParts};
use hx_store::{NewSession, Store};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed test timestamp")
}

fn member(id: &str) -> PoolMember {
    PoolMember {
        id: id.to_string(),
        // These tests pin fan-out shape, not member routing: the provider is the id so the
        // scripted registries (keyed by id) resolve unchanged, and the model is the id so the
        // route responses keep their names. Routing with distinct names is pinned in
        // `spawn.rs` (`a_child_runs_against_its_members_declared_provider_and_model`) and
        // `hx-core`'s pool/config tests.
        provider: id.to_string(),
        model: id.to_string(),
        base_url: format!("https://{id}.example.test"),
        credential: format!("vault:pool/{id}"),
        accepts: Vec::new(),
        health: MemberHealth::Healthy,
    }
}

fn secrets_for(ids: &[&str]) -> Arc<SecretStores> {
    let mut s = FixedSecrets::new("vault");
    for id in ids {
        s = s.set(format!("pool/{id}"), format!("sentinel-{id}"));
    }
    Arc::new(SecretStores::new().with(Arc::new(s)))
}

/// Secrets whose *values* are given explicitly, so a test can hand a member a credential of a
/// chosen shape (a recognisable `sk-…` key, or an opaque one with no shape at all).
fn secrets_with(pairs: &[(&str, &str)]) -> Arc<SecretStores> {
    let mut s = FixedSecrets::new("vault");
    for (id, value) in pairs {
        s = s.set(format!("pool/{id}"), *value);
    }
    Arc::new(SecretStores::new().with(Arc::new(s)))
}

fn store() -> Arc<Store> {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("hx-fanout-merged-{}-{n}.db", std::process::id()));
    Arc::new(Store::open(path).expect("test store opens"))
}

fn session(store: &Store) -> SessionId {
    store
        .create(NewSession::new(), now())
        .expect("session created")
        .id
}

/// The peak number of provider calls in flight at once, across every scripted member.
///
/// A call enters, yields once (`yield_now`, no wall clock), then leaves. A fan-out that drove its
/// children concurrently would overlap two of them and leave `peak` above one; one that runs them
/// one at a time cannot.
#[derive(Default)]
struct InFlight {
    active: AtomicUsize,
    peak: AtomicUsize,
}

impl InFlight {
    fn enter(&self) {
        let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
    }
    fn leave(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
    fn reset(&self) {
        self.peak.store(0, Ordering::SeqCst);
    }
}

/// What one scripted member answers.
#[derive(Clone, Copy)]
enum Answer {
    Ok {
        input: u64,
        output: u64,
    },
    /// Answers with caller-chosen text, so a test can tell the children's conclusions apart
    /// through the HTTP response.
    Text {
        input: u64,
        output: u64,
        text: &'static str,
    },
    /// A 5xx — the member is dead. Its body echoes back the very credential it was handed, which is
    /// what a real provider's auth-debugging error page does.
    Dead,
}

struct ScriptedProvider {
    id: ProviderId,
    answer: Answer,
    calls: AtomicUsize,
    /// The prompt text of every call this member received, in order — so a test can prove each
    /// child ran its own prompt rather than N copies of one shared string.
    seen: std::sync::Mutex<Vec<String>>,
    in_flight: Arc<InFlight>,
}

impl ScriptedProvider {
    fn new(id: &str, answer: Answer, in_flight: Arc<InFlight>) -> Arc<Self> {
        Arc::new(Self {
            id: ProviderId::from(id),
            answer,
            calls: AtomicUsize::new(0),
            seen: std::sync::Mutex::new(Vec::new()),
            in_flight,
        })
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn prompts(&self) -> Vec<String> {
        self.seen.lock().expect("the seen lock").clone()
    }
}

#[async_trait]
impl Provider for ScriptedProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Openai
    }
    fn models(&self) -> &[String] {
        &[]
    }
    async fn complete(&self, req: ChatRequest, key: &Secret) -> HxResult<ChatResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().expect("the seen lock").push(
            req.messages
                .iter()
                .map(|m| m.text())
                .collect::<Vec<_>>()
                .join("\n"),
        );
        self.in_flight.enter();
        // One yield, so a concurrent caller would overlap and a sequential one could not. No clock,
        // no sleep.
        tokio::task::yield_now().await;
        let response = match self.answer {
            Answer::Ok { input, output } => Ok(ChatResponse {
                message: Message::assistant("done"),
                usage: Usage {
                    input_tokens: input,
                    output_tokens: output,
                    ..Default::default()
                },
                finish: FinishReason::Stop,
                model: self.id.to_string(),
                raw: None,
            }),
            Answer::Text {
                input,
                output,
                text,
            } => Ok(ChatResponse {
                message: Message::assistant(text),
                usage: Usage {
                    input_tokens: input,
                    output_tokens: output,
                    ..Default::default()
                },
                finish: FinishReason::Stop,
                model: self.id.to_string(),
                raw: None,
            }),
            Answer::Dead => Err(HxError::Provider(format!(
                "upstream returned HTTP 500 (key: {})",
                key.expose()
            ))),
        };
        self.in_flight.leave();
        response
    }
}

/// A registry of scripted members, plus the handles a test needs to count calls.
fn registry(answers: &[(&str, Answer)], in_flight: Arc<InFlight>) -> Arc<ProviderRegistry> {
    let mut reg = ProviderRegistry::new();
    for (id, answer) in answers {
        reg.insert(ScriptedProvider::new(id, *answer, Arc::clone(&in_flight)));
    }
    Arc::new(reg)
}

/// A registry whose handles are kept, so a test can assert *how many times* a member was asked.
fn registry_with_handles(
    answers: &[(&str, Answer)],
    in_flight: Arc<InFlight>,
) -> (Arc<ProviderRegistry>, Vec<Arc<ScriptedProvider>>) {
    let mut reg = ProviderRegistry::new();
    let mut handles = Vec::new();
    for (id, answer) in answers {
        let p = ScriptedProvider::new(id, *answer, Arc::clone(&in_flight));
        reg.insert(Arc::clone(&p) as Arc<dyn Provider>);
        handles.push(p);
    }
    (Arc::new(reg), handles)
}

/// Build the real `AppState` the fan-out route reads: the pool comes from `Config::model_pool`, the
/// providers/secrets/store from the state.
async fn harness(
    pool: ModelPool,
    provider: Arc<ProviderRegistry>,
    secrets: Arc<SecretStores>,
) -> Arc<AppState> {
    let member_ids: Vec<String> = pool.members.iter().map(|m| m.id.clone()).collect();
    let mut config = hx_core::config::Config::default();
    let members: Vec<hx_core::pool::ModelPoolMemberConfig> = member_ids
        .into_iter()
        .map(|id| hx_core::pool::ModelPoolMemberConfig {
            id: id.clone(),
            provider: id.clone(),
            model: id.clone(),
            base_url: format!("https://{id}.example.test"),
            credential: format!("vault:pool/{id}"),
            accepts: Vec::new(),
        })
        .collect();
    config
        .model_pools
        .insert("interactive".to_string(), members);
    config.daemon.data_dir = tempfile::tempdir()
        .expect("temp dir")
        .keep()
        .display()
        .to_string();

    let store = store();
    let router = Arc::new(std::sync::Mutex::new(
        hx_provider::ModelRouter::from_config(&config, now()).expect("empty router"),
    ));
    AppState::from_parts(AppStateParts {
        router: Arc::clone(&router),
        providers: Arc::new(RwLock::new(provider)),
        provider_configs: Default::default(),
        config_path: None,        secrets,
        store: store.clone(),
        models: Arc::new(RwLock::new(Arc::new(hx_server::chat::RouterModels::new(
            router,
            Arc::new(ProviderRegistry::new()),
            Arc::new(SecretStores::new()),
        )))),
        tools: Arc::new(hx_server::chat::default_tools(
            vec![],
            reqwest::Client::new(),
        )),
        approvals: hx_agent::ApprovalQueue::new(std::time::Duration::from_secs(1)),
        search: Arc::new(
            hx_search::BackendRegistry::from_config(
                &config.search,
                reqwest::Client::new(),
                &hx_secrets::SecretStores::new(),
            )
            .expect("search registry"),
        ),
        config,
        sandboxes: None::<Arc<hx_sandbox::SandboxManager>>,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now(),
        api_token: None,
        allowed_origins: Vec::new(),
        phone: None,
        webhooks: Default::default(),
    })
}

fn body_for(session: &str, prompts: &[&str]) -> FanOutBody {
    FanOutBody {
        children: prompts
            .iter()
            .map(|p| FanOutChild {
                session: session.to_string(),
                prompt: (*p).to_string(),
            })
            .collect(),
    }
}

async fn post_raw(state: Arc<AppState>, body: Body) -> (StatusCode, String) {
    let response = app(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/fanout")
                .header("content-type", "application/json")
                .body(body)
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// POST a request built exactly the way the web pane builds it, and read the reply as a client.
async fn post(state: Arc<AppState>, body: FanOutBody) -> (StatusCode, serde_json::Value) {
    let (status, text) = post_raw(
        state,
        Body::from(serde_json::to_string(&body).expect("body")),
    )
    .await;
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn child_statuses(out: &serde_json::Value) -> Vec<String> {
    out["children"]
        .as_array()
        .expect("children")
        .iter()
        .map(|c| {
            if c["Ran"].is_object() {
                format!("Ran/{}", c["Ran"]["model"].as_str().unwrap_or("?"))
            } else if c["Errored"].is_object() {
                format!("Errored/{}", c["Errored"]["member"].as_str().unwrap_or("?"))
            } else {
                format!("unreadable/{c}")
            }
        })
        .collect()
}

/// A fan-out refuses a blank prompt: an empty child is an empty model call, and the pane refuses
/// one client-side. If the route keeps accepting it, this test says so out loud instead of pretending.
#[tokio::test]
async fn a_blank_prompt_is_refused_as_a_client_error_rather_than_spending_a_model_call() {
    let in_flight = Arc::new(InFlight::default());
    let (reg, handles) = registry_with_handles(
        &[(
            "a",
            Answer::Ok {
                input: 10,
                output: 5,
            },
        )],
        Arc::clone(&in_flight),
    );
    let state = harness(ModelPool::new(vec![member("a")]), reg, secrets_for(&["a"])).await;
    let sid = session(&state.store).as_str().to_string();

    let (status, out) = post(state, body_for(&sid, &[""])).await;

    assert!(
        status.is_client_error(),
        "a blank prompt must be refused as a client error, got {status}: {out}"
    );
    assert_eq!(
        handles[0].calls(),
        0,
        "a blank prompt must not spend a provider call"
    );
}

/// A member that dies mid-fan-out fails only its own child, is **not** re-routed onto the live
/// member, and the live member is asked exactly once. A re-route would be a silent model switch: the
/// outcome would say `Ran` on the member the child never drew.
#[tokio::test]
async fn a_dead_member_fails_only_its_own_child_and_is_not_rerouted_onto_the_live_one() {
    let in_flight = Arc::new(InFlight::default());
    let (reg, handles) = registry_with_handles(
        &[
            ("a", Answer::Dead),
            (
                "b",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        reg,
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let (status, out) = post(state.clone(), body_for(&sid, &["p1", "p2"])).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    assert_eq!(
        child_statuses(&out),
        vec!["Errored/a".to_string(), "Ran/b".to_string()],
        "the dead member errors its own child, and the other child runs: {out}"
    );
    assert_eq!(
        out["members"],
        serde_json::json!(["a", "b"]),
        "the drawn members are reported in request order: {out}"
    );
    // No re-route: every member was asked exactly once. A re-route would ask `b` twice.
    assert_eq!(handles[0].calls(), 1, "the dead member is asked once");
    assert_eq!(
        handles[1].calls(),
        1,
        "the live member is asked once — a second call would be an undocumented re-route: {out}"
    );

    // The child that errored left no usage; the one that ran left one row.
    let totals = state
        .store
        .totals(&SessionId::from_raw(sid))
        .expect("totals");
    assert_eq!(totals.provider_calls, 1, "one call was recorded, not two");
}

/// DEFECT (verify-merged-fanout): the fan-out's client-visible error string is redacted with the
/// *pattern* pass only, so a credential with **no recognisable shape** that the provider echoes back
/// in its error body reaches the HTTP response verbatim.
///
/// `Spawner::run_child` marks the member down with a literal-registered redaction
/// (`redact_death_reason`), but returns the raw `HxError`; `run_fan_out` then stringifies that raw
/// error through a bare `Redactor::new()`, which has no literal to look for. `crate::fanout`'s own
/// doc admits the boundary ("opaque values with no shape are the spawner's separate job") — but the
/// spawner's job covers the *stored* death reason, not the string the fan-out hands a client.
#[tokio::test]
async fn a_dead_member_that_echoes_an_opaque_credential_does_not_leak_it_to_the_client() {
    // A patternless credential: the `sk-…`/`ghp_…` patterns cannot catch this — only a registered
    // literal can.
    const OPAQUE: &str = "opaque-fanout-merged-sentinel-7d3f1b";
    let in_flight = Arc::new(InFlight::default());
    let (reg, _handles) = registry_with_handles(
        &[
            ("a", Answer::Dead),
            (
                "b",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        reg,
        secrets_with(&[("a", OPAQUE), ("b", "sentinel-b")]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let (status, out) = post(state, body_for(&sid, &["p1", "p2"])).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    let full = out.to_string();
    assert!(
        !full.contains(OPAQUE),
        "the credential member 'a' was handed reached the client in the fan-out response: {full}"
    );
}

/// DEFECT (verify-merged-fanout): the route never checks that the session it is told to bill exists.
///
/// The documented contract — `hx fan`'s help and `ROADMAP.md`'s M8 section — is that "the session
/// must already exist on the daemon". Instead the fan-out allocates, makes the provider call for
/// real, and only then fails inside `Store::record_usage` (a `FOREIGN KEY`/`touch` miss), reporting
/// that as an *errored child* in a 200: money spent, nothing in the audit chain, and an internal
/// store message rendered as a child's failure.
#[tokio::test]
async fn a_session_that_does_not_exist_is_refused_before_any_model_call_is_spent() {
    let in_flight = Arc::new(InFlight::default());
    let (reg, handles) = registry_with_handles(
        &[(
            "a",
            Answer::Ok {
                input: 10,
                output: 5,
            },
        )],
        Arc::clone(&in_flight),
    );
    let state = harness(ModelPool::new(vec![member("a")]), reg, secrets_for(&["a"])).await;

    let (status, out) = post(state, body_for("no-such-session-anywhere", &["p1"])).await;

    assert!(
        status.is_client_error(),
        "a fan-out against a session that does not exist must be refused, got {status}: {out}"
    );
    assert_eq!(
        handles[0].calls(),
        0,
        "and it must refuse before spending a provider call: {out}"
    );
}

/// Children naming different sessions are refused with a 400 before any provider call is
/// spent: billing one child's work to another child's session is a client error, not a silent
/// re-bill. (The route used to accept the mix and record everything under the first child's
/// session; the web pane's per-row session inputs made that a surprise worth refusing.)
#[tokio::test]
async fn children_naming_different_sessions_are_refused_before_any_model_call_is_spent() {
    let in_flight = Arc::new(InFlight::default());
    let (reg, handles) = registry_with_handles(
        &[
            (
                "a",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
            (
                "b",
                Answer::Ok {
                    input: 20,
                    output: 7,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        reg,
        secrets_for(&["a", "b"]),
    )
    .await;
    let first = session(&state.store);
    let second = session(&state.store);

    let body = FanOutBody {
        children: vec![
            FanOutChild {
                session: first.as_str().to_string(),
                prompt: "p1".to_string(),
            },
            FanOutChild {
                session: second.as_str().to_string(),
                prompt: "p2".to_string(),
            },
        ],
    };
    let (status, out) = post(state.clone(), body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "mixed sessions must be refused, got {status}: {out}"
    );
    assert!(
        out["error"]
            .as_str()
            .unwrap_or_default()
            .contains("session"),
        "the refusal names the problem: {out}"
    );
    assert_eq!(
        handles[0].calls(),
        0,
        "a refusal spends no provider call on the first member"
    );
    assert_eq!(
        handles[1].calls(),
        0,
        "a refusal spends no provider call on the second member"
    );
}

/// Each child runs its own prompt and each child's conclusion reaches the client: two children
/// with distinct prompts are asked distinctly and answer distinctly, in request order.
#[tokio::test]
async fn each_childs_prompt_runs_and_each_childs_answer_reaches_the_client() {
    let in_flight = Arc::new(InFlight::default());
    let (reg, handles) = registry_with_handles(
        &[
            (
                "a",
                Answer::Text {
                    input: 10,
                    output: 5,
                    text: "alpha says yes",
                },
            ),
            (
                "b",
                Answer::Text {
                    input: 20,
                    output: 7,
                    text: "bravo says no",
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        reg,
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let (status, out) = post(state, body_for(&sid, &["ask alpha", "ask bravo"])).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    // Draw order follows the pool order: the first child runs on "a" with the first prompt.
    assert_eq!(handles[0].prompts(), vec!["ask alpha".to_string()]);
    assert_eq!(handles[1].prompts(), vec!["ask bravo".to_string()]);

    let children = out["children"].as_array().expect("children");
    assert_eq!(children.len(), 2);
    assert_eq!(
        children[0]["Ran"]["answer"].as_str(),
        Some("alpha says yes"),
        "the first child's conclusion reaches the client: {out}"
    );
    assert_eq!(
        children[1]["Ran"]["answer"].as_str(),
        Some("bravo says no"),
        "the second child's conclusion reaches the client: {out}"
    );
}

/// Token accounting across children: the total is the sum of the children, and each child's record
/// names its own drawn member.
#[tokio::test]
async fn the_recorded_tokens_are_the_sum_of_the_childrens_own_usage() {
    let in_flight = Arc::new(InFlight::default());
    let reg = registry(
        &[
            (
                "a",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
            (
                "b",
                Answer::Ok {
                    input: 20,
                    output: 7,
                },
            ),
            (
                "c",
                Answer::Ok {
                    input: 30,
                    output: 9,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b"), member("c")]),
        reg,
        secrets_for(&["a", "b", "c"]),
    )
    .await;
    let sid = session(&state.store);

    let (status, out) = post(state.clone(), body_for(sid.as_str(), &["p1", "p2", "p3"])).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    let children = out["children"].as_array().expect("children");
    let (input, output): (u64, u64) = children
        .iter()
        .map(|c| {
            (
                c["Ran"]["usage"]["input_tokens"].as_u64().expect("input"),
                c["Ran"]["usage"]["output_tokens"].as_u64().expect("output"),
            )
        })
        .fold((0, 0), |(i, o), (ci, co)| (i + ci, o + co));

    let totals = state.store.totals(&sid).expect("totals");
    assert_eq!(
        (totals.input_tokens, totals.output_tokens),
        (input, output),
        "the session total must be exactly the sum of the children's usage: {out}"
    );
    assert_eq!(totals.provider_calls, 3);
    assert_eq!((input, output), (60, 21), "10+20+30 in, 5+7+9 out");
}

/// A child that errors adds no usage: the total is the sum of the children that ran, and the errored
/// child is not double-counted.
#[tokio::test]
async fn an_errored_child_contributes_no_usage_to_the_total() {
    let in_flight = Arc::new(InFlight::default());
    let reg = registry(
        &[
            ("a", Answer::Dead),
            (
                "b",
                Answer::Ok {
                    input: 20,
                    output: 7,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        reg,
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store);

    let (status, out) = post(state.clone(), body_for(sid.as_str(), &["p1", "p2"])).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    let totals = state.store.totals(&sid).expect("totals");
    assert_eq!(
        totals.provider_calls, 1,
        "only the child that ran is billed"
    );
    assert_eq!(totals.input_tokens, 20, "{out}");
    assert_eq!(totals.output_tokens, 7, "{out}");
}

/// The response shape the web pane reads: `members` and `children` are index-aligned, a `Ran` child
/// carries the `usage` object with numeric token counts, and a credential reference (never a value).
#[tokio::test]
async fn the_outcome_members_and_children_are_index_aligned_for_the_pane() {
    let in_flight = Arc::new(InFlight::default());
    let reg = registry(
        &[
            (
                "a",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
            (
                "b",
                Answer::Ok {
                    input: 20,
                    output: 7,
                },
            ),
            ("c", Answer::Dead),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b"), member("c")]),
        reg,
        secrets_for(&["a", "b", "c"]),
    )
    .await;
    let sid = session(&state.store);

    let (status, out) = post(state, body_for(sid.as_str(), &["p1", "p2", "p3"])).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    let members = out["members"].as_array().expect("members");
    let children = out["children"].as_array().expect("children");
    assert_eq!(
        members.len(),
        children.len(),
        "the pane renders `members[i]` against `children[i]`: {out}"
    );
    // The pane prints `members[i]` as the card's member id; a child that ran must agree with it.
    for (i, child) in children.iter().enumerate() {
        if let Some(rec) = child["Ran"].as_object() {
            assert_eq!(
                rec["model"].as_str().unwrap_or("?"),
                members[i].as_str().unwrap_or("?"),
                "child {i} ran on the member drawn for it: {out}"
            );
            assert!(
                rec["usage"]["input_tokens"].is_u64() && rec["usage"]["output_tokens"].is_u64(),
                "the pane reads numeric token counts: {child}"
            );
            let credential = rec["credential"].as_str().expect("credential");
            assert!(
                !credential.contains("sentinel"),
                "a usage record carries the reference, never the resolved value: {credential}"
            );
        }
        if let Some(err) = child["Errored"].as_object() {
            assert!(
                err["member"].is_string() && err["error"].is_string(),
                "{child}"
            );
        }
    }
}

/// A pool short by one refuses with a sentence that names wanted vs distinct, as a 422 (the client's
/// to fix), and spends nothing: no child runs before the allocation check.
#[tokio::test]
async fn a_pool_short_by_one_refuses_with_422_and_spends_no_model_call() {
    let in_flight = Arc::new(InFlight::default());
    let (reg, handles) = registry_with_handles(
        &[
            (
                "a",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
            (
                "b",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        reg,
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store);

    let (status, out) = post(state.clone(), body_for(sid.as_str(), &["p1", "p2", "p3"])).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a shortage is the client's to fix: {out}"
    );
    let message = out["error"].as_str().unwrap_or_default();
    assert!(
        message.contains('3') && message.contains('2') && message.contains("distinct"),
        "the refusal names wanted vs distinct in a sentence: {out}"
    );
    assert_eq!(
        handles[0].calls() + handles[1].calls(),
        0,
        "allocation fails before any child runs, so nothing is spent"
    );
    assert_eq!(
        state.store.totals(&sid).expect("totals").provider_calls,
        0,
        "and nothing is recorded"
    );
}

/// A `children` array far larger than the pool is still a 422 sentence naming the shortage — not a
/// 500, and not a partially-run fan-out.
#[tokio::test]
async fn a_children_array_larger_than_the_pool_is_a_422_sentence() {
    let in_flight = Arc::new(InFlight::default());
    let reg = registry(
        &[
            (
                "a",
                Answer::Ok {
                    input: 1,
                    output: 1,
                },
            ),
            (
                "b",
                Answer::Ok {
                    input: 1,
                    output: 1,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        reg,
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store);

    let children: Vec<FanOutChild> = (0..100)
        .map(|i| FanOutChild {
            session: sid.as_str().to_string(),
            prompt: format!("p{i}"),
        })
        .collect();
    let (status, out) = post(state, FanOutBody { children }).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{out}");
    let message = out["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("100") && message.contains('2'),
        "the sentence names 100 wanted and 2 distinct: {out}"
    );
}

/// An empty `children` array is refused up front with a 400 whose body is a sentence a person reads.
#[tokio::test]
async fn an_empty_children_array_is_a_400_sentence() {
    let state = harness(
        ModelPool::new(vec![]),
        registry(&[], Arc::new(InFlight::default())),
        secrets_for(&[]),
    )
    .await;

    let (status, out) = post(state, FanOutBody { children: vec![] }).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    let message = out["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("fan-out") && message.contains("child"),
        "the refusal is a sentence about the request, not a debug string: {out}"
    );
}

/// A body that is not the shape at all is a 4xx, never a 500 with a debug string, and never a panic.
#[tokio::test]
async fn a_malformed_children_body_is_a_4xx_not_a_500() {
    let state = harness(
        ModelPool::new(vec![]),
        registry(&[], Arc::new(InFlight::default())),
        secrets_for(&[]),
    )
    .await;

    let (status, text) =
        post_raw(state.clone(), Body::from(r#"{"children": "not an array"}"#)).await;
    assert!(
        status.is_client_error(),
        "a malformed body is the client's problem, got {status}: {text}"
    );

    // A missing field entirely.
    let (status, text) = post_raw(state, Body::from(r#"{}"#)).await;
    assert!(
        status.is_client_error(),
        "a body with no `children` is the client's problem, got {status}: {text}"
    );
}

/// An oversized body (past axum's 2 MiB limit) is refused as a client error — it is not buffered
/// into a 500, and nothing is spent.
#[tokio::test]
async fn an_oversized_children_body_is_refused_without_being_run() {
    let in_flight = Arc::new(InFlight::default());
    let (reg, handles) = registry_with_handles(
        &[(
            "a",
            Answer::Ok {
                input: 10,
                output: 5,
            },
        )],
        Arc::clone(&in_flight),
    );
    let state = harness(ModelPool::new(vec![member("a")]), reg, secrets_for(&["a"])).await;
    let sid = session(&state.store).as_str().to_string();

    // One child, one prompt past the default 2 MiB body limit.
    let huge = "x".repeat(3 * 1024 * 1024);
    let body = serde_json::json!({ "children": [{ "session": sid, "prompt": huge }] });
    let (status, text) = post_raw(state, Body::from(body.to_string())).await;

    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "past axum's 2 MiB `Json` body limit the refusal is a 413, not a 500: {text}"
    );
    assert_eq!(
        handles[0].calls(),
        0,
        "an oversized request must not reach the model"
    );
    assert!(
        !text.contains("panicked"),
        "the refusal must be a status, not a panic: {text}"
    );
}

/// The fan-out runs its children **concurrently**, bounded by `agent.fanout_max_parallel`.
/// `run_fan_out` drives the N allocated lanes over a `FuturesUnordered` pool behind a semaphore,
/// and restores request order through indexed slots on the way out.
///
/// The scripted provider yields once mid-call, so overlapping lanes leave more than one call
/// in flight at once; this asserts the peak reaches all three.
#[tokio::test]
async fn a_fan_out_runs_its_children_concurrently() {
    let in_flight = Arc::new(InFlight::default());
    let (reg, handles) = registry_with_handles(
        &[
            (
                "a",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
            (
                "b",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
            (
                "c",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let secrets = secrets_for(&["a", "b", "c"]);

    // Positive control first: the counter this test judges the fan-out with really does see two
    // calls in flight at once, so a `peak` of 1 after the fan-out is a fact about the fan-out and
    // not a fact about a counter that cannot move.
    let key = secrets
        .resolve_str("vault:pool/a")
        .expect("the fixture credential resolves");
    let request = || ChatRequest::new("a", vec![Message::user("hi")]);
    let (first, second) = tokio::join!(
        handles[0].complete(request(), &key),
        handles[1].complete(request(), &key),
    );
    assert!(
        first.is_ok() && second.is_ok(),
        "the scripted members answer"
    );
    assert_eq!(
        in_flight.peak(),
        2,
        "two concurrent calls must be visible to the counter, or this test cannot judge anything"
    );
    in_flight.reset();

    let state = harness(
        ModelPool::new(vec![member("a"), member("b"), member("c")]),
        reg,
        secrets,
    )
    .await;
    let sid = session(&state.store);

    let (status, out) = post(state, body_for(sid.as_str(), &["p1", "p2", "p3"])).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(
        in_flight.peak(),
        3,
        "the fan-out must overlap its children: a peak of {} means they ran one at a time",
        in_flight.peak()
    );
}

/// The same route, served on a real loopback socket instead of through `tower::oneshot`, returns the
/// same outcome — the fan-out over real HTTP, which is what a browser or `hx fan` actually hits.
#[tokio::test]
async fn a_real_loopback_daemon_answers_a_fan_out() {
    let in_flight = Arc::new(InFlight::default());
    let reg = registry(
        &[
            (
                "a",
                Answer::Ok {
                    input: 10,
                    output: 5,
                },
            ),
            (
                "b",
                Answer::Ok {
                    input: 20,
                    output: 7,
                },
            ),
        ],
        Arc::clone(&in_flight),
    );
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        reg,
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free loopback port");
    let addr = listener.local_addr().expect("addr");
    let router = app(Arc::clone(&state));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    let body = body_for(&sid, &["p1", "p2"]);
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/v1/fanout"))
        .json(&body)
        .send()
        .await
        .expect("a response");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let out: serde_json::Value = response.json().await.expect("json");
    assert_eq!(
        child_statuses(&out),
        vec!["Ran/a".to_string(), "Ran/b".to_string()],
        "{out}"
    );
    assert_eq!(out["members"], serde_json::json!(["a", "b"]), "{out}");
}
