//! End-to-end tests of the generic webhook route: `POST /v1/connectors/{id}/webhook` authenticates
//! against the **connector's own** token and pushes the parsed envelope into the `hx-gateway`
//! connector's channel that its `receive` reads from. All hermetic — no external service.
//!
//! The webhook route is exempt from the daemon's global bearer middleware (it is its own auth boundary,
//! per connector) and **fails closed**:
//!
//! - unknown connector id → `404`
//! - missing or wrong bearer token → `401`
//! - malformed body → `400`
//!
//! A valid request is `200` and the pushed message arrives through `WebhookConnector::receive`.

use async_trait::async_trait;
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use hx_core::ids::ConnectorId;
use hx_gateway::webhook::WebhookConnector;
use hx_gateway::Connector;
use hx_agent::{ApprovalQueue, ModelCall};
use hx_provider::{ChatRequest, ChatResponse, ModelRouter, ProviderRegistry};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, Secret, SecretStores};
use hx_server::{AppState, AppStateParts, ModelFactory};
use hx_store::Store;
use std::sync::Arc;

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

struct Harness {
    addr: String,
    webhook: WebhookConnector,
}

async fn harness() -> Harness {
    let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.path().join("data").display().to_string();
    let now = chrono::Utc::now();
    let router = ModelRouter::from_config(&config, now).expect("router builds");
    let client = reqwest::Client::new();
    let providers = ProviderRegistry::from_config(&config, client.clone()).expect("providers build");
    let secrets = SecretStores::new().with(Arc::new(EnvSecrets));
    let search = BackendRegistry::from_config(&config.search, client.clone(), &secrets).expect("search");
    let store = Store::from_config(&config).expect("store opens");

    // Register one webhook connector: the sender stays in the registry (what the route pushes into),
    // and the receiver becomes the hx-gateway connector we read from — exactly the runtime relationship.
    let mut webhooks = hx_server::webhook::WebhookRegistry::default();
    let (_, rx) = webhooks.register(&ConnectorId::from("main-web"), hx_core::api_auth::ApiToken::new("supersecret"));

    let state = AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(std::sync::Mutex::new(router)),
        providers: Arc::new(providers),
        secrets: Arc::new(secrets),
        store: Arc::new(store),
        models: Arc::new(Dead(Arc::new(DeadModel))),
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        approvals: ApprovalQueue::new(std::time::Duration::from_secs(1)),
        search: Arc::new(search),
        sandboxes: None,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now,
        api_token: None,
        webhooks,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = hx_server::routes::app(Arc::clone(&state));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let webhook = WebhookConnector::new(
        ConnectorId::from("main-web"),
        None,
        reqwest::Client::new(),
        rx,
    );

    Harness { addr: addr.to_string(), webhook }
}

#[tokio::test]
async fn a_valid_post_pushes_an_inbound_message_into_receive() {
    let h = harness().await;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/connectors/main-web/webhook", h.addr))
        .bearer_auth("supersecret")
        .json(&serde_json::json!({ "chat": "777", "text": "list the repo" }))
        .send()
        .await
        .expect("a response");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let received = h.webhook.receive(&Secret::new("")).await.expect("a message");
    match received {
        Some(hx_gateway::Inbound::Message { conversation, text }) => {
            assert_eq!(conversation.chat.as_str(), "777");
            assert_eq!(conversation.thread.as_str(), "");
            assert_eq!(text, "list the repo");
        }
        other => panic!("expected a message, got {other:?}"),
    }
}

#[tokio::test]
async fn a_wrong_token_is_401() {
    let h = harness().await;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/connectors/main-web/webhook", h.addr))
        .bearer_auth("wrong")
        .json(&serde_json::json!({ "chat": "777", "text": "hi" }))
        .send()
        .await
        .expect("a response");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_missing_token_is_401() {
    let h = harness().await;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/connectors/main-web/webhook", h.addr))
        .json(&serde_json::json!({ "chat": "777", "text": "hi" }))
        .send()
        .await
        .expect("a response");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unknown_connector_id_is_404_even_with_a_token() {
    let h = harness().await;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/connectors/nope/webhook", h.addr))
        .bearer_auth("supersecret")
        .json(&serde_json::json!({ "chat": "777", "text": "hi" }))
        .send()
        .await
        .expect("a response");
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_malformed_body_is_400() {
    let h = harness().await;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/connectors/main-web/webhook", h.addr))
        .bearer_auth("supersecret")
        .json(&serde_json::json!({ "unexpected": true }))
        .send()
        .await
        .expect("a response");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}
