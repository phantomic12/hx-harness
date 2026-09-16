//! The router-backed model call: which credential is chosen, which model the request carries, and
//! what happens to the reservation when a call fails.
//!
//! Every test here drives the **real** `ModelRouter` over a **real** `ProviderRegistry` — the only
//! fake is the provider adapter itself, because the point of these tests is the wiring between the
//! routing table, the secret resolver and the loop, and stubbing any of those three would leave the
//! wiring untested. The provider records what it was handed, so "which key paid for this call" and
//! "which model answered" are assertions rather than inferences.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hx_agent::{ModelCall, RouterModel};
use hx_core::config::{
    Config, CredentialConfig, Limits, PoolConfig, Price, ProviderConfig, ProviderKind, Strategy,
};
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use hx_core::message::Message;
use hx_provider::{
    ChatRequest, ChatResponse, FinishReason, ModelRouter, Provider, ProviderRegistry, Usage,
};
use hx_secrets::{FixedSecrets, Secret, SecretStores};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn at() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

/// What one provider saw: the model the request named, and the key it was handed.
type Seen = (String, String);

/// An adapter that answers from a script and remembers what it was given.
struct FakeProvider {
    id: ProviderId,
    models: Vec<String>,
    replies: Mutex<VecDeque<Result<ChatResponse>>>,
    seen: Mutex<Vec<Seen>>,
}

impl FakeProvider {
    fn new(id: &str, models: &[&str], replies: Vec<Result<ChatResponse>>) -> Arc<Self> {
        Arc::new(Self {
            id: ProviderId::from(id),
            models: models.iter().map(|m| m.to_string()).collect(),
            replies: Mutex::new(VecDeque::from(replies)),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// How many calls reached this provider — the assertion for "nothing was sent".
    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

#[async_trait]
impl Provider for FakeProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn kind(&self) -> ProviderKind {
        ProviderKind::Openai
    }

    fn models(&self) -> &[String] {
        &self.models
    }

    async fn complete(&self, req: ChatRequest, key: &Secret) -> Result<ChatResponse> {
        self.seen
            .lock()
            .unwrap()
            .push((req.model.clone(), key.expose().to_string()));

        self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
            Err(HxError::Provider(
                "the fake provider was asked for more calls than it has answers".to_string(),
            ))
        })
    }
}

fn answer(text: &str, input_tokens: u64, output_tokens: u64) -> ChatResponse {
    ChatResponse {
        message: Message::assistant(text),
        usage: Usage {
            input_tokens,
            output_tokens,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
        },
        finish: FinishReason::Stop,
        model: "answered-by-the-provider".to_string(),
        raw: None,
    }
}

fn credential(id: &str, secret_ref: &str, limits: Limits) -> CredentialConfig {
    CredentialConfig {
        id: CredentialId::from(id),
        secret: secret_ref.to_string(),
        limits,
        weight: 1,
    }
}

fn provider_config(
    model: &str,
    credentials: Vec<CredentialConfig>,
    price: Option<Price>,
) -> ProviderConfig {
    ProviderConfig {
        kind: ProviderKind::Openai,
        base_url: Some("https://provider.test/v1".to_string()),
        credentials,
        routing: Strategy::Priority,
        models: vec![model.to_string()],
        price,
        priority: 0,
    }
}

/// Two providers, one pool, one role: `builder` → `interactive` → p1/model-a then p2/model-b.
fn config(limits: Limits, price: Option<Price>) -> Config {
    let mut config = Config::default();
    config.providers.insert(
        "p1".to_string(),
        provider_config(
            "model-a",
            vec![
                credential("a1", "vault:p1/one", limits.clone()),
                credential("a2", "vault:p1/two", limits.clone()),
            ],
            price.clone(),
        ),
    );
    config.providers.insert(
        "p2".to_string(),
        provider_config(
            "model-b",
            vec![credential("b1", "vault:p2/one", limits.clone())],
            price,
        ),
    );
    config.pools.insert(
        "interactive".to_string(),
        PoolConfig {
            members: vec!["p1/model-a".to_string(), "p2/model-b".to_string()],
            strategy: Strategy::Priority,
            limits: Limits::default(),
            inherits: None,
        },
    );
    config
        .roles
        .insert("builder".to_string(), "interactive".to_string());
    config
}

fn secrets() -> Arc<SecretStores> {
    Arc::new(
        SecretStores::new().with(Arc::new(
            FixedSecrets::vault()
                .set("p1/one", "sk-first")
                .set("p1/two", "sk-second")
                .set("p2/one", "sk-other-provider"),
        )),
    )
}

struct Harness {
    model: RouterModel,
    router: Arc<Mutex<ModelRouter>>,
    p1: Arc<FakeProvider>,
    p2: Arc<FakeProvider>,
}

fn harness(limits: Limits, price: Option<Price>) -> Harness {
    harness_with(config(limits, price), secrets())
}

fn harness_with(config: Config, secrets: Arc<SecretStores>) -> Harness {
    let router = Arc::new(Mutex::new(
        ModelRouter::from_config(&config, at()).expect("the test config routes"),
    ));

    let p1 = FakeProvider::new("p1", &["model-a"], vec![]);
    let p2 = FakeProvider::new("p2", &["model-b"], vec![]);
    let mut registry = ProviderRegistry::new();
    registry.insert(p1.clone());
    registry.insert(p2.clone());

    let model = RouterModel::new("builder", router.clone(), Arc::new(registry), secrets)
        .expect("the role is bound");

    Harness {
        model,
        router,
        p1,
        p2,
    }
}

fn request() -> ChatRequest {
    ChatRequest::new("ignored-hint", vec![Message::user("do the thing")])
}

fn healthy_credentials(h: &Harness) -> usize {
    let router = h.router.lock().unwrap();
    router.status().pools[0].healthy_credentials
}

// ---------------------------------------------------------------------------------------------
// Which model, which key
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_request_carries_the_model_the_route_chose() {
    let h = harness(Limits::default(), None);
    h.p1.replies
        .lock()
        .unwrap()
        .push_back(Ok(answer("done", 10, 2)));

    let response = h.model.complete(request()).await.unwrap();

    assert_eq!(response.message.text(), "done");
    assert_eq!(
        h.p1.seen(),
        vec![("model-a".to_string(), "sk-first".to_string())],
        "the routed model and the routed credential, not the request's own model field"
    );
    assert_eq!(h.p2.calls(), 0, "the first route served it");

    // The identifiers the loop reports come from the call that just happened.
    assert_eq!(h.model.provider_id().as_str(), "p1");
    assert_eq!(h.model.credential_id().as_str(), "a1");
}

#[tokio::test]
async fn the_request_model_is_rewritten_because_the_hint_is_not_the_route() {
    // The hint is what the role prefers *now*; the answer is what the router chose. Both of p1's
    // credentials are refused one call apart, and only then does the pool move to the next route —
    // the request must name *that* route's model.
    let h = harness(Limits::default(), None);
    h.p1.replies.lock().unwrap().extend([
        Err(HxError::ProviderAuth {
            provider: "p1".to_string(),
            reason: "HTTP 401 — the credential was refused".to_string(),
        }),
        Err(HxError::ProviderAuth {
            provider: "p1".to_string(),
            reason: "HTTP 401 — the credential was refused".to_string(),
        }),
    ]);
    h.p2.replies
        .lock()
        .unwrap()
        .push_back(Ok(answer("second route", 10, 2)));

    let hint_before = h.model.model();

    let err = h.model.complete(request()).await.unwrap_err();
    assert!(err.is_auth_failure(), "{err:?}");
    assert_eq!(h.p1.seen()[0].0, "model-a");

    let err = h.model.complete(request()).await.unwrap_err();
    assert!(err.is_auth_failure(), "{err:?}");
    assert_eq!(
        h.p2.calls(),
        0,
        "p1 still had a credential on the second call"
    );

    // Every credential that route could use has been refused, so the next route serves it.
    let response = h.model.complete(request()).await.unwrap();
    assert_eq!(response.message.text(), "second route");
    assert_eq!(
        h.p2.seen()[0].0,
        "model-b",
        "the request names the model that answered"
    );
    assert_eq!(h.p2.seen()[0].1, "sk-other-provider");
    assert_eq!(h.model.provider_id().as_str(), "p2");

    // The hint did not change: it describes the role's first route, not the last call.
    assert_eq!(h.model.model(), hint_before);
}

#[tokio::test]
async fn a_rejected_credential_is_benched_rather_than_tried_again() {
    let h = harness(Limits::default(), None);
    assert_eq!(healthy_credentials(&h), 3);

    h.p1.replies.lock().unwrap().extend([
        Err(HxError::ProviderAuth {
            provider: "p1".to_string(),
            reason: "HTTP 401".to_string(),
        }),
        Ok(answer("the second key served this", 1, 1)),
    ]);

    h.model.complete(request()).await.unwrap_err();
    assert_eq!(
        healthy_credentials(&h),
        2,
        "the credential that was refused must not be handed out again"
    );

    // The next call still goes to p1 — a refused key is not a refused provider — but with the
    // *other* credential, and p1's scripted second answer is what proves which one served it.
    let response = h.model.complete(request()).await.unwrap();
    assert_eq!(response.message.text(), "the second key served this");
    assert_eq!(
        h.p1.seen().len(),
        2,
        "the route is unchanged, so the provider is asked again"
    );
    assert_eq!(
        h.p1.seen()[1].1,
        "sk-second",
        "and it was handed the credential that is still healthy"
    );
    assert_eq!(h.model.credential_id().as_str(), "a2");
}

#[tokio::test]
async fn the_second_credential_carries_its_own_key() {
    let h = harness(Limits::default(), None);
    h.p1.replies.lock().unwrap().extend([
        Err(HxError::ProviderAuth {
            provider: "p1".to_string(),
            reason: "HTTP 401".to_string(),
        }),
        Ok(answer("a2 served this", 5, 1)),
    ]);

    h.model.complete(request()).await.unwrap_err();
    let response = h.model.complete(request()).await.unwrap();

    assert_eq!(response.message.text(), "a2 served this");
    assert_eq!(
        h.p1.seen()[1],
        ("model-a".to_string(), "sk-second".to_string()),
        "the key follows the credential the pool granted, not the first one it configured"
    );
    assert_eq!(h.model.credential_id().as_str(), "a2");
}

// ---------------------------------------------------------------------------------------------
// The reservation, and what happens to it
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_key_releases_the_reservation_without_benching_the_credential() {
    // The credential's reference points at a name the resolver does not have. Two things must be
    // true afterwards: nothing was sent, and the lease is back — or the next call fails with a
    // concurrency refusal, which reads like a rate limit and is not one.
    let limits = Limits {
        concurrent: Some(1),
        ..Default::default()
    };
    let mut config = config(limits, None);
    config.providers.get_mut("p1").unwrap().credentials[0].secret = "vault:p1/missing".to_string();
    let h = harness_with(config, secrets());

    let err = h.model.complete(request()).await.unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("p1/missing"),
        "the error names the reference: {text}"
    );
    assert!(
        h.p1.calls() == 0 && h.p2.calls() == 0,
        "nothing left the process"
    );

    // Same credential is still chosen (it was not benched), and the lease is back, so the failure
    // is the *same* failure rather than a leaked reservation.
    let err = h.model.complete(request()).await.unwrap_err();
    assert!(err.to_string().contains("p1/missing"), "{err}");
    assert!(
        !err.to_string().contains("at their limits"),
        "a released lease, not a stuck one: {err}"
    );
    assert_eq!(
        healthy_credentials(&h),
        3,
        "a missing key is a deployment problem"
    );
}

#[tokio::test]
async fn a_transient_failure_releases_the_reservation_and_keeps_the_credential() {
    let limits = Limits {
        concurrent: Some(1),
        ..Default::default()
    };
    let h = harness(limits, None);
    h.p1.replies.lock().unwrap().extend([
        Err(HxError::Provider("upstream returned 502".to_string())),
        Ok(answer("retried by the caller", 3, 1)),
    ]);

    let err = h.model.complete(request()).await.unwrap_err();
    assert!(err.is_retryable(), "{err:?}");
    assert_eq!(
        healthy_credentials(&h),
        3,
        "a 502 is not the credential's fault"
    );

    // With `concurrent: 1`, this only succeeds if the first call gave its lease back.
    let response = h.model.complete(request()).await.unwrap();
    assert_eq!(response.message.text(), "retried by the caller");
    assert_eq!(
        h.p1.seen()[1],
        ("model-a".to_string(), "sk-first".to_string())
    );
}

#[tokio::test]
async fn the_surplus_is_refunded_after_every_call() {
    // A budget that covers exactly one pessimistic reservation. Three calls only fit if each one
    // settles to its real cost — which is what "reserve, then reconcile" means in practice.
    // `input_per_mtok` is 1.0, so the estimate is (reservation_tokens / 1e6) dollars.
    let price = Price {
        input_per_mtok: 1.0,
        output_per_mtok: 2.0,
    };
    let est = request().reservation_tokens() as f64 / 1_000_000.0;
    let limits = Limits {
        daily_usd: Some(est * 1.2),
        ..Default::default()
    };
    let h = harness(limits, Some(price));
    h.p1.replies.lock().unwrap().extend([
        Ok(answer("one", 10, 1)),
        Ok(answer("two", 10, 1)),
        Ok(answer("three", 10, 1)),
    ]);

    for expected in ["one", "two", "three"] {
        let response = h.model.complete(request()).await.unwrap();
        assert_eq!(response.message.text(), expected);
    }
}

#[tokio::test]
async fn a_budget_too_small_for_one_reservation_refuses_before_the_call() {
    let price = Price {
        input_per_mtok: 1.0,
        output_per_mtok: 2.0,
    };
    let est = request().reservation_tokens() as f64 / 1_000_000.0;
    let limits = Limits {
        // Half of one reservation: there is no route, however many calls are made.
        daily_usd: Some(est * 0.5),
        ..Default::default()
    };
    let h = harness(limits, Some(price));

    let err = h.model.complete(request()).await.unwrap_err();
    assert!(
        matches!(err, HxError::NoRoute(_) | HxError::RateLimited { .. }),
        "a spent budget is a routing failure, not a provider failure: {err:?}"
    );
    assert_eq!(h.p1.calls(), 0, "the refusal happens before the request");
}

// ---------------------------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_role_with_no_pool_is_refused_when_the_callable_is_built() {
    let config = config(Limits::default(), None);
    let router = Arc::new(Mutex::new(ModelRouter::from_config(&config, at()).unwrap()));
    let mut registry = ProviderRegistry::new();
    registry.insert(FakeProvider::new("p1", &["model-a"], vec![]));

    let err = RouterModel::new("nobody", router, Arc::new(registry), secrets()).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("nobody"), "{text}");
    assert!(text.contains("pool"), "say what is missing: {text}");
}

#[tokio::test]
async fn no_providers_at_all_is_refused_when_the_callable_is_built() {
    let config = config(Limits::default(), None);
    let router = Arc::new(Mutex::new(ModelRouter::from_config(&config, at()).unwrap()));

    let err = RouterModel::new(
        "builder",
        router,
        Arc::new(ProviderRegistry::new()),
        secrets(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("no providers"), "{err}");
}

#[tokio::test]
async fn a_route_to_an_unconfigured_provider_fails_without_being_sent() {
    let config = config(Limits::default(), None);
    let router = Arc::new(Mutex::new(ModelRouter::from_config(&config, at()).unwrap()));
    // Only p2 exists: the pool's first route names a provider the registry has never heard of.
    let mut registry = ProviderRegistry::new();
    registry.insert(FakeProvider::new("p2", &["model-b"], vec![]));

    let model = RouterModel::new("builder", router, Arc::new(registry), secrets()).unwrap();
    let err = model.complete(request()).await.unwrap_err();
    assert!(err.to_string().contains("p1"), "{err}");
}

#[tokio::test]
async fn the_debug_of_a_routed_callable_names_the_role_and_never_a_key() {
    let h = harness(Limits::default(), None);
    let printed = format!("{:?}", h.model);

    assert!(printed.contains("builder"), "{printed}");
    assert!(printed.contains("model-a"), "{printed}");
    assert!(!printed.contains("sk-"), "{printed}");
}
