//! `POST /v1/fanout` end to end, with a scripted pool member provider where the network
//! would be — the same `ScriptedProvider` pattern `crate::fanout` uses, driven through
//! the real HTTP surface so the route, the spawner, the fan-out module and the store all
//! have to agree.
//!
//! What is real here: the `AppState`, the HTTP router (including the bearer-token test
//! surface), the `Spawner` the route builds, the fan-out module, and the session store
//! (a real SQLite file on disk). Only the provider call is a script.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use hx_core::config::ProviderKind;
use hx_core::error::{HxError, Result};
use hx_core::ids::{ProviderId, SessionId};
use hx_core::message::Message;
use hx_core::pool::{MemberHealth, ModelPool, PoolMember};
use hx_provider::{ChatRequest, ChatResponse, FinishReason, Provider, ProviderRegistry, Usage};
use hx_secrets::{FixedSecrets, Secret, SecretStores};
use hx_server::routes::{FanOutBody, FanOutChild};
use hx_server::{app, AppState, AppStateParts};
use hx_store::Store;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed test timestamp")
}

fn member(id: &str) -> PoolMember {
    PoolMember {
        id: id.to_string(),
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

fn store() -> Arc<Store> {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let mut path = std::env::temp_dir();
    path.push(format!("hx-fanout-api-{}-{n}.db", std::process::id()));
    Arc::new(Store::open(path).expect("test store opens"))
}

fn session(store: &Store) -> SessionId {
    let rec = store
        .create(hx_store::NewSession::new(), now())
        .expect("session created");
    rec.id
}

/// A provider that answers without a network. `id` is the member it stands in for; `fail` makes
/// its one call error (a dead member) so the route can test non-cascade and redaction.
struct ScriptedProvider {
    id: ProviderId,
    fail: bool,
}

impl ScriptedProvider {
    fn new(id: &str) -> Self {
        Self {
            id: ProviderId::from(id),
            fail: false,
        }
    }
    fn failing(self) -> Self {
        Self { fail: true, ..self }
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
    async fn complete(&self, _req: ChatRequest, key: &Secret) -> Result<ChatResponse> {
        if self.fail {
            return Err(HxError::Provider(format!(
                "upstream returned HTTP 500 (key: {})",
                key.expose()
            )));
        }
        Ok(ChatResponse {
            message: Message::assistant("done"),
            usage: Usage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            },
            finish: FinishReason::Stop,
            model: self.id.to_string(),
            raw: None,
        })
    }
}

fn registry_for(ids: &[&str]) -> Arc<ProviderRegistry> {
    let mut reg = ProviderRegistry::new();
    for id in ids {
        reg.insert(Arc::new(ScriptedProvider::new(id)));
    }
    Arc::new(reg)
}

/// A registry where `die` is a failing provider and `live` answers — for the non-cascade/redaction
/// tests over HTTP.
fn registry_with_dying(die: &str, live: &str) -> Arc<ProviderRegistry> {
    let mut reg = ProviderRegistry::new();
    reg.insert(Arc::new(ScriptedProvider::new(die).failing()));
    reg.insert(Arc::new(ScriptedProvider::new(live)));
    Arc::new(reg)
}

/// Build a full `AppState` from a configured model pool and the scripted registry/secrets, the same
/// way the production route reaches them.
async fn harness(
    pool: ModelPool,
    provider: Arc<ProviderRegistry>,
    secrets: Arc<SecretStores>,
) -> Arc<AppState> {
    // A model pool in the config is what the route reads (`Config::model_pool`), so the pool built
    // here is mirrored into the config's `model_pools` section under the default name.
    let member_ids: Vec<String> = pool.members.iter().map(|m| m.id.clone()).collect();
    let mut config = hx_core::config::Config::default();
    let members: Vec<hx_core::pool::ModelPoolMemberConfig> = member_ids
        .into_iter()
        .map(|id| hx_core::pool::ModelPoolMemberConfig {
            id: id.clone(),
            base_url: format!("{id}.example.test"),
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
    // The route reaches the store/providers/secrets through the state; the pool it draws from comes
    // from the config. Everything else is the standard empty harness.
    // The route draws from the model pool it finds in the config; providers/secrets/store come
    // from the state. The routing table only needs to build (it is unused by the fan-out route).
    let router = Arc::new(std::sync::Mutex::new(
        hx_provider::ModelRouter::from_config(&config, now()).expect("empty router"),
    ));
    AppState::from_parts(AppStateParts {
        router: Arc::clone(&router),
        providers: provider,
        secrets,
        store: store.clone(),
        models: Arc::new(hx_server::chat::RouterModels::new(
            router,
            Arc::new(ProviderRegistry::new()),
            Arc::new(SecretStores::new()),
        )),
        tools: Arc::new(hx_server::chat::default_tools(
            vec![],
            reqwest::Client::new(),
        )),
        approvals: hx_agent::ApprovalQueue::new(std::time::Duration::from_secs(1)),
        phone: None,
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
        webhooks: Default::default(),
    })
}

async fn post_fanout(
    state: Arc<AppState>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/fanout")
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

/// Happy path: two children over two healthy members returns both results, distinct members, per-child
/// attribution and recorded usage — the M8 exit criterion over the real HTTP route.
#[tokio::test]
async fn a_fan_out_over_http_reaches_n_distinct_members_and_records_each() {
    let state = harness(
        ModelPool::new(vec![member("cheap"), member("strong")]),
        registry_for(&["cheap", "strong"]),
        secrets_for(&["cheap", "strong"]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let body = FanOutBody {
        children: vec![
            FanOutChild {
                session: sid.clone(),
                prompt: "do a".to_string(),
            },
            FanOutChild {
                session: sid.clone(),
                prompt: "do b".to_string(),
            },
        ],
    };

    let (status, out) = post_fanout(state.clone(), serde_json::to_value(&body).unwrap()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a fan-out over healthy members succeeds: {out}"
    );

    let members = out["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    let distinct: std::collections::BTreeSet<&str> =
        members.iter().map(|m| m.as_str().unwrap()).collect();
    assert_eq!(
        distinct.len(),
        2,
        "N children reach N distinct members: {out}"
    );

    let children = out["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    // Each child completed and named its member.
    for child in children {
        assert!(
            child["Ran"].is_object() || child["Ran"]["model"].is_string(),
            "every child completed: {child}"
        );
    }
    let models: Vec<&str> = children
        .iter()
        .map(|c| c["Ran"]["model"].as_str().unwrap())
        .collect();
    assert_eq!(
        models,
        vec!["cheap", "strong"],
        "child order maps to member: {out}"
    );

    // The audit chain held two provider calls with the drawn members.
    let totals = state
        .store
        .totals(&SessionId::from_raw(sid))
        .expect("totals");
    assert_eq!(totals.provider_calls, 2);
    assert_eq!(totals.input_tokens, 20);
}

/// Default off over HTTP: a fan-out child names no tools and records none — the child tool loop
/// is opt-in per spec and the route does not opt in, so the record carries an empty `tools_used`.
#[tokio::test]
async fn a_fan_out_without_tools_records_no_tools_used() {
    let state = harness(
        ModelPool::new(vec![member("cheap")]),
        registry_for(&["cheap"]),
        secrets_for(&["cheap"]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let body = FanOutBody {
        children: vec![FanOutChild {
            session: sid,
            prompt: "do a".to_string(),
        }],
    };

    let (status, out) = post_fanout(state, serde_json::to_value(&body).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let children = out["children"].as_array().unwrap();
    assert_eq!(children.len(), 1);
    let rec = children[0]["Ran"].as_object().expect("the child ran");
    assert_eq!(
        rec["tools_used"],
        serde_json::Value::Array(vec![]),
        "no loop ran, so no tools are recorded: {rec:?}"
    );
}

/// A member that dies mid-fan-out fails only its own child; the other completes. Both are reported
/// over HTTP, each a distinct-members allocation.
#[tokio::test]
async fn a_dying_member_over_http_errors_only_its_own_child() {
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        registry_with_dying("a", "b"),
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let body = FanOutBody {
        children: vec![
            FanOutChild {
                session: sid.clone(),
                prompt: "p1".to_string(),
            },
            FanOutChild {
                session: sid.clone(),
                prompt: "p2".to_string(),
            },
        ],
    };

    let (status, out) = post_fanout(state, serde_json::to_value(&body).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    let children = out["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);

    let mut saw_errored = false;
    let mut saw_ran = false;
    for child in children {
        if let Some(err) = child["Errored"].as_object() {
            assert_eq!(err["member"], "a", "the failing member is named: {err:?}");
            saw_errored = true;
        } else if let Some(rec) = child["Ran"].as_object() {
            assert_eq!(rec["model"], "b", "the healthy member completes: {rec:?}");
            saw_ran = true;
        } else {
            panic!("a child must be Errored or Ran: {child}");
        }
    }
    assert!(saw_errored && saw_ran, "one errored, one ran: {out}");
}

/// A dying member that echoes the very credential it was given has that value redacted before it reaches
/// the HTTP response — a client must never read a live key.
#[tokio::test]
async fn a_dead_members_redacted_error_reaches_http_unmasked() {
    let secrets: SecretStores = {
        let mut s = FixedSecrets::new("vault");
        // A real OpenAI-shaped key of pattern length; the fanout boundary must mask it.
        s = s.set("pool/a", "sk-abcdeabcdeabcdeabcde1234567890123xyz");
        s = s.set("pool/b", "sentinel-b");
        SecretStores::new().with(Arc::new(s))
    };
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        registry_with_dying("a", "b"),
        Arc::new(secrets),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let body = FanOutBody {
        children: vec![
            FanOutChild {
                session: sid.clone(),
                prompt: "p1".to_string(),
            },
            FanOutChild {
                session: sid,
                prompt: "p2".to_string(),
            },
        ],
    };

    let (status, out) = post_fanout(state, serde_json::to_value(&body).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    let full = out.to_string();
    assert!(
        !full.contains("sk-abcdeabcdeabcde"),
        "the leaked key reached the HTTP response: {full}"
    );
}

/// A short pool (more children than distinct healthy members) fails loudly with a client error and runs no
/// child — over HTTP this is a readable 4xx, not a 200 with a half-completed result.
#[tokio::test]
async fn a_short_pool_over_http_fails_loudly_and_names_wanted_vs_distinct() {
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        registry_for(&["a", "b"]),
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let body = FanOutBody {
        children: vec![
            FanOutChild {
                session: sid.clone(),
                prompt: "p1".to_string(),
            },
            FanOutChild {
                session: sid.clone(),
                prompt: "p2".to_string(),
            },
            FanOutChild {
                session: sid,
                prompt: "p3".to_string(),
            },
        ],
    };

    let (status, out) = post_fanout(state, serde_json::to_value(&body).unwrap()).await;
    assert_ne!(status.as_u16(), 200, "a short pool is an error: {out}");
    assert!(
        status.is_client_error(),
        "a shortage is the client's to fix: {status}"
    );
    let msg = out["error"].as_str().unwrap_or_default();
    assert!(msg.contains("3"), "names wanted: {msg}");
    assert!(msg.contains("2"), "names distinct: {msg}");
}

/// An empty fan-out is refused up front with a 400 rather than a 200 with nothing in it.
#[tokio::test]
async fn an_empty_fan_out_is_refused_as_bad_request() {
    let state = harness(ModelPool::new(vec![]), registry_for(&[]), secrets_for(&[])).await;
    let body = FanOutBody { children: vec![] };

    let (status, out) = post_fanout(state, serde_json::to_value(&body).unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
}

/// A provider that rendezvous with its sibling on a barrier before answering: both children
/// must be inside `complete` at the same time for either to return.
struct BarrierProvider {
    id: ProviderId,
    barrier: Arc<tokio::sync::Barrier>,
}

#[async_trait]
impl Provider for BarrierProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Openai
    }
    fn models(&self) -> &[String] {
        &[]
    }
    async fn complete(&self, _req: ChatRequest, _key: &Secret) -> Result<ChatResponse> {
        self.barrier.wait().await;
        Ok(ChatResponse {
            message: Message::assistant("done"),
            usage: Usage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            },
            finish: FinishReason::Stop,
            model: self.id.to_string(),
            raw: None,
        })
    }
}

/// Two children whose providers rendezvous on a barrier complete over HTTP: sequential execution
/// would deadlock at the barrier and the timeout would fire, so a 200 with both children `Ran`
/// proves the route runs the fan-out's lanes concurrently, not one after another.
#[tokio::test]
async fn two_children_over_http_run_concurrently() {
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut reg = ProviderRegistry::new();
    for id in ["a", "b"] {
        reg.insert(Arc::new(BarrierProvider {
            id: ProviderId::from(id),
            barrier: Arc::clone(&barrier),
        }));
    }
    let state = harness(
        ModelPool::new(vec![member("a"), member("b")]),
        Arc::new(reg),
        secrets_for(&["a", "b"]),
    )
    .await;
    let sid = session(&state.store).as_str().to_string();

    let body = FanOutBody {
        children: vec![
            FanOutChild {
                session: sid.clone(),
                prompt: "p1".to_string(),
            },
            FanOutChild {
                session: sid,
                prompt: "p2".to_string(),
            },
        ],
    };

    let (status, out) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        post_fanout(state, serde_json::to_value(&body).unwrap()),
    )
    .await
    .expect("both lanes must reach the barrier before the timeout");
    assert_eq!(status, StatusCode::OK, "{out}");
    let children = out["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    for child in children {
        assert!(
            child["Ran"].is_object(),
            "both barrier children completed: {child}"
        );
    }
}
