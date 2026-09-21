//! The daemon-wide sandbox reaper visits remote managers, not just the local one.
//!
//! What is real here: [`AppState::reap_all_sandboxes`] against a state whose only manager is
//! a per-host remote one backed by a fake engine. If the reaper only visited the local set,
//! the expired remote sandbox would survive the sweep and this test would fail.

use async_trait::async_trait;
use hx_agent::{ApprovalQueue, ModelCall};
use hx_core::config::IsolationLevel;
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId, SandboxId};
use hx_provider::{ChatRequest, ChatResponse, ProviderRegistry};
use hx_sandbox::{HostSettings, SandboxExecOutput, SandboxManager, SandboxRuntime, SandboxSpec};
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{AppState, AppStateParts, ModelFactory};
use hx_store::Store;
use std::sync::{Arc, Mutex};

/// A model that is never called: these tests never run the agent loop.
struct NeverModel;

#[async_trait]
impl ModelCall for NeverModel {
    async fn complete(&self, _req: ChatRequest) -> Result<ChatResponse> {
        Err(HxError::Provider("no model in this test".to_string()))
    }

    fn model(&self) -> String {
        "never".to_string()
    }

    fn provider_id(&self) -> ProviderId {
        ProviderId::from_raw("test")
    }

    fn credential_id(&self) -> CredentialId {
        CredentialId::from_raw("test")
    }
}

struct NeverFactory;

impl ModelFactory for NeverFactory {
    fn for_role(&self, _role: &str) -> Result<Arc<dyn ModelCall>> {
        Ok(Arc::new(NeverModel))
    }
}

/// Records removals, so the test can tell a reaped sandbox from a merely deregistered one.
#[derive(Default)]
struct FakeEngine {
    removed: Mutex<Vec<String>>,
}

#[async_trait]
impl SandboxRuntime for FakeEngine {
    fn name(&self) -> &str {
        "fake"
    }

    async fn available(&self) -> bool {
        true
    }

    async fn create(
        &self,
        _id: &SandboxId,
        spec: &SandboxSpec,
        _settings: &HostSettings,
    ) -> Result<String> {
        Ok(format!("fake-{}", spec.profile))
    }

    async fn start(&self, _runtime_id: &str) -> Result<()> {
        Ok(())
    }

    async fn stop(&self, _runtime_id: &str, _grace_secs: i64) -> Result<()> {
        Ok(())
    }

    async fn remove(&self, runtime_id: &str) -> Result<()> {
        self.removed.lock().unwrap().push(runtime_id.to_string());
        Ok(())
    }

    async fn exec(
        &self,
        _runtime_id: &str,
        command: &str,
        _workdir: Option<&str>,
    ) -> Result<SandboxExecOutput> {
        Ok(SandboxExecOutput {
            stdout: format!("ran: {command}"),
            stderr: String::new(),
            exit_code: 0,
        })
    }
}

const CONFIG: &str = r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["never"]
    price: { input_per_mtok: 1.0, output_per_mtok: 2.0 }
    credentials:
      - { id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }

pools:
  interactive: { members: ["local/never"] }

roles:
  builder: interactive

search:
  backends: []
"#;

fn spec(ttl_secs: u64) -> SandboxSpec {
    SandboxSpec {
        profile: "dev".into(),
        image: "ubuntu:24.04".into(),
        isolation: IsolationLevel::L2,
        cpus: 2.0,
        memory_mb: 4096,
        pids_max: 1024,
        workspace_mb: 8192,
        ttl_secs,
        egress_allow: Vec::new(),
        network: false,
        readonly_rootfs: true,
        workspace_host_path: "/tmp/hx/ws".into(),
        workspace_path: "/workspace".into(),
        user: None,
        env: Vec::new(),
        runtime: None,
    }
}

/// A daemon with no local sandbox manager: the only container set is a remote host's.
async fn state_without_local_sandboxes() -> Arc<AppState> {
    let mut config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.keep();
    config.daemon.data_dir = root.join("data").display().to_string();

    let now = chrono::Utc::now();
    let router = hx_provider::ModelRouter::from_config(&config, now).expect("router builds");
    let providers =
        ProviderRegistry::from_config(&config, reqwest::Client::new()).expect("providers build");
    let secrets = SecretStores::new().with(Arc::new(EnvSecrets));
    let store = Store::from_config(&config).expect("store opens");
    let client = reqwest::Client::new();
    let search = BackendRegistry::from_config(&config.search, client.clone(), &SecretStores::new())
        .expect("search");

    AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(Mutex::new(router)),
        providers: Arc::new(providers),
        secrets: Arc::new(secrets),
        store: Arc::new(store),
        models: Arc::new(NeverFactory),
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        approvals: ApprovalQueue::new(std::time::Duration::from_secs(1)),
        phone: None,
        search: Arc::new(search),
        // No local manager on purpose: this is the shape that used to skip reaping entirely.
        sandboxes: None::<Arc<SandboxManager>>,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now,
        api_token: None,
        webhooks: Default::default(),
    })
}

#[tokio::test]
async fn reaping_visits_remote_managers_as_well_as_the_local_one() {
    // WHY this test exists: the daemon reaper used to call `state.sandboxes.reap()` only,
    // so an expired sandbox on a remote host was never swept — its container and slot
    // lived until someone called destroy by hand.
    let state = state_without_local_sandboxes().await;

    let engine = Arc::new(FakeEngine::default());
    let remote = Arc::new(SandboxManager::new(engine.clone(), 4));
    let now = chrono::Utc::now();
    let handle = remote.spawn(&spec(60), now).await.unwrap();
    state
        .remote_sandbox_managers
        .lock()
        .await
        .insert("far".to_string(), Arc::clone(&remote));

    let reaped = state
        .reap_all_sandboxes(now + chrono::Duration::seconds(120))
        .await;

    assert_eq!(reaped, vec![handle.id.clone()]);
    assert_eq!(
        engine.removed.lock().unwrap().len(),
        1,
        "the sweep must actually remove the container from the engine, not just forget it"
    );
    assert!(
        remote.get(handle.id.as_str()).await.is_none(),
        "the expired remote sandbox must be gone after the sweep"
    );
}

#[tokio::test]
async fn reaping_a_live_remote_sandbox_leaves_it_alone() {
    // The mirror assertion: visiting remote managers must not mean destroying what still
    // has TTL left. A reaper that over-reaps would take down running remote work.
    let state = state_without_local_sandboxes().await;

    let remote = Arc::new(SandboxManager::new(Arc::new(FakeEngine::default()), 4));
    let now = chrono::Utc::now();
    let handle = remote.spawn(&spec(86_400), now).await.unwrap();
    state
        .remote_sandbox_managers
        .lock()
        .await
        .insert("far".to_string(), Arc::clone(&remote));

    let reaped = state.reap_all_sandboxes(now).await;

    assert!(reaped.is_empty());
    assert!(
        remote.get(handle.id.as_str()).await.is_some(),
        "a live remote sandbox must survive the sweeper"
    );
}

#[tokio::test]
async fn reaping_with_no_managers_reaps_nothing() {
    // A daemon with no container engine at all (and no remote hosts yet) must not error:
    // remote managers appear lazily, so the reaper runs before any exist.
    let state = state_without_local_sandboxes().await;
    assert!(state
        .reap_all_sandboxes(chrono::Utc::now())
        .await
        .is_empty());
}
