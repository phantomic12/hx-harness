//! The web client is served, and it is the real page.
//!
//! A front end that 404s, or that is served as text, is a daemon that looks healthy from the API and
//! is unusable from a browser. This checks the one thing an API test cannot: that `GET /` returns
//! HTML which actually contains *this* client — not an empty body and not a placeholder.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hx_agent::{ApprovalQueue, ModelCall};
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use hx_provider::{ChatRequest, ChatResponse, ModelRouter, ProviderRegistry};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, ModelFactory};
use hx_store::Store;

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

struct Server {
    addr: String,
    _dir: tempfile::TempDir,
}

async fn harness() -> Server {
    harness_with_token(None).await
}

/// The same daemon, optionally requiring a bearer token.
///
/// The token is passed in rather than read from the environment so the test states its own
/// configuration: a test whose credential came from the ambient environment would pass or fail
/// depending on the machine it ran on.
async fn harness_with_token(token: Option<&str>) -> Server {
    let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.path().join("data").display().to_string();
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
        // No token by default: these tests bind loopback, which is exactly the deployment where a
        // token is optional. A test that needed one here would mean the rule, not the test, was
        // wrong.
        api_token: token.map(hx_core::api_auth::ApiToken::new),
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

#[tokio::test]
async fn the_root_serves_the_web_client_as_html() {
    let server = harness().await;
    let response = reqwest::Client::new()
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "the client must be served"
    );

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "served as {content_type:?}, which a browser would render as source"
    );

    let body = response.text().await.expect("a body");
    assert!(body.contains("<title>hx</title>"), "the title is missing");
    assert!(
        body.contains("/v1/terminals/"),
        "the page must attach a terminal, which is the M2 criterion"
    );
    assert!(
        body.contains("/v1/sessions/") && body.contains("since_seq"),
        "the page must resume the session stream rather than restart it"
    );
    assert!(
        body.contains("/v1/hosts") && body.contains("No hosts are configured."),
        "the page must render the hosts pane from the real /v1/hosts route"
    );
}

#[tokio::test]
async fn the_page_is_served_without_a_token_because_a_browser_cannot_send_one() {
    // The exemption, tested as a pair: the page loads *and* the API behind it does not. Serving
    // `GET /` to a browser is not a hole — it is a static file embedded in the binary, and a
    // navigation cannot carry an `Authorization` header, so requiring one would make the page
    // unreachable exactly when a token is configured.
    let server = harness_with_token(Some("sentinel-token-for-the-web-client-test")).await;
    let client = reqwest::Client::new();

    let page = client
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response");
    assert_eq!(page.status(), reqwest::StatusCode::OK, "the page loads");

    let api = client
        .get(format!("http://{}/v1/status", server.addr))
        .send()
        .await
        .expect("a response");
    assert_eq!(
        api.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "and the API behind it does not answer without the token"
    );
}

#[tokio::test]
async fn the_page_carries_the_bearer_token_on_every_call_it_makes() {
    // A page that renders but sends no token is unusable against a daemon that requires one, so
    // the wiring is part of what "the web client is served" has to mean. These assertions are about
    // the served text, which is the only thing this test can see — the behaviour is the daemon's
    // 401 and the panel is a browser's.
    let server = harness().await;
    let body = reqwest::Client::new()
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("a response")
        .text()
        .await
        .expect("a body");

    assert!(
        body.contains("Bearer ${token}"),
        "the page must send the token as a bearer credential"
    );
    assert!(
        body.contains("hx.api.token"),
        "and keep it somewhere a reload does not lose it"
    );
    assert!(
        body.contains("id=\"token-input\""),
        "and give the operator somewhere to put it"
    );
    assert!(
        body.contains("?token=") || body.contains("token=${encodeURIComponent"),
        "and carry it on the WebSocket URLs, which cannot take a header"
    );
    // The property that keeps this true as routes are added: every call goes through the one
    // helper, so a new pane cannot forget the header.
    assert!(
        !body.contains("await fetch(`${API}"),
        "a call site bypasses apiFetch, and would be sent without the token"
    );
}
