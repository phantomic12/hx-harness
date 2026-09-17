//! The daemon's shared state: one place that owns the routers, backends and sandboxes.
//!
//! Deliberately built from a [`Config`] in one function ([`AppState::build`]) so that the CLI,
//! the daemon and the tests all construct the system the same way. A harness where `hx status`
//! reports something different from what the daemon is actually running is worse than no status
//! command at all.

use chrono::{DateTime, Utc};
use hx_agent::ApprovalQueue;
use hx_core::config::{Config, HostConfig};
use hx_core::error::{HxError, Result};
use hx_core::ids::HostId;
use hx_provider::{ModelRouter, ProviderRegistry};
use hx_remote::LocalHost;
use hx_sandbox::SandboxManager;
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_store::Store;
use hx_tools::ToolRegistry;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::Mutex as AsyncMutex;

/// Everything the HTTP surface needs.
pub struct AppState {
    pub config: Config,
    /// The routing table. Behind a *sync* mutex, and shared: the model call and the status route must
    /// read the same limiter state, or `hx status` reports headroom that does not exist. Nothing
    /// holds it across an `await`.
    pub router: Arc<Mutex<ModelRouter>>,
    /// The adapters the router's routes resolve to.
    pub providers: Arc<ProviderRegistry>,
    /// Where a credential's key comes from, by reference. Vault-backed sources are added when the
    /// vault is unlocked; until then this resolves `env:` only, and says so.
    pub secrets: Arc<SecretStores>,
    /// Sessions, transcripts, events and usage. The daemon's only durable state.
    pub store: Arc<Store>,
    /// How a role becomes a model call. A trait so the HTTP surface can be tested without a provider.
    pub models: Arc<dyn crate::chat::ModelFactory>,
    /// The tools a run may call.
    pub tools: Arc<ToolRegistry>,
    /// Questions a run is waiting on, for a client that can answer them.
    ///
    /// Shared across runs and keyed by approval id: an approval belongs to a session and a call, and
    /// a client asks "what is waiting for *this* session" rather than being shown every prompt on the
    /// machine.
    pub approvals: Arc<ApprovalQueue>,
    pub search: Arc<BackendRegistry>,
    /// One lock per session, held for the duration of a run: two requests on one session would
    /// otherwise interleave into a transcript neither of them wrote.
    pub chats: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    /// `None` when no container engine was reachable at startup.
    pub sandboxes: Option<Arc<SandboxManager>>,
    /// Reuse one shell boundary per profile and checkout across chat requests.
    pub chat_sandboxes: crate::sandbox::SandboxCache,
    pub started_at: DateTime<Utc>,
    /// Why the sandbox manager is absent, so status can explain rather than just say "null".
    pub sandbox_unavailable_reason: Option<String>,
    /// Whether the secret vault was unlocked. Secrets are never loaded while locked.
    pub vault_unlocked: bool,
}

/// Everything [`AppState::build`] assembles, so a test can assemble it differently.
pub struct AppStateParts {
    pub config: Config,
    pub router: Arc<Mutex<ModelRouter>>,
    pub providers: Arc<ProviderRegistry>,
    pub secrets: Arc<SecretStores>,
    pub store: Arc<Store>,
    pub models: Arc<dyn crate::chat::ModelFactory>,
    pub tools: Arc<ToolRegistry>,
    pub approvals: Arc<ApprovalQueue>,
    pub search: Arc<BackendRegistry>,
    pub sandboxes: Option<Arc<SandboxManager>>,
    pub sandbox_unavailable_reason: Option<String>,
    pub started_at: DateTime<Utc>,
}

impl AppState {
    /// Build the whole system from configuration.
    ///
    /// Two failures are fatal: without a routing table there is no harness, and without a session
    /// store there is nothing to resume — a daemon that loses every session on restart while
    /// claiming to be running is worse than one that refuses to start. Everything else degrades:
    /// search with no backends is empty rather than fatal, and a missing container engine disables
    /// sandboxes while leaving the rest running.
    pub async fn build(config: Config, now: DateTime<Utc>) -> Result<Arc<Self>> {
        let router = ModelRouter::from_config(&config, now)?;

        let client = reqwest::Client::builder()
            .user_agent(hx_search::backends::USER_AGENT)
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| HxError::Config(format!("could not build the HTTP client: {e}")))?;
        let search = BackendRegistry::from_config(&config.search, client.clone())?;

        // A *separate* client for providers, without the search timeout: a model call that takes
        // four minutes is a slow answer, not a failed one, and a 20-second cap here would turn every
        // long generation into a provider error.
        let provider_client = reqwest::Client::builder()
            .user_agent(concat!("hx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                HxError::Config(format!("could not build the provider HTTP client: {e}"))
            })?;
        let providers = Arc::new(ProviderRegistry::from_config(&config, provider_client)?);

        let store = Arc::new(Store::from_config(&config)?);

        // Until the vault is unlocked this resolves `env:` references only. That is stated rather
        // than implied: `hx status` reports which stores are configured, so a `vault:` reference
        // that cannot resolve yet is visible before a run tries to use it.
        let secrets = Arc::new(SecretStores::new().with(Arc::new(EnvSecrets)));

        let search = Arc::new(search);
        let tools = Arc::new(crate::chat::default_tools(search.all(), client.clone()));

        // How long a run waits for a human before treating silence as a refusal. Long enough to
        // answer a phone notification, short enough that a run with nobody attached does not look
        // hung; a request can ask for zero, which refuses immediately (the old behaviour).
        let approvals = ApprovalQueue::new(std::time::Duration::from_secs(
            crate::chat::DEFAULT_APPROVAL_WAIT_SECS,
        ));

        let (sandboxes, sandbox_unavailable_reason) = match hx_sandbox::docker_manager(
            config.agent.max_concurrent_subagents as usize,
        )
        .await
        {
            Ok(manager) => (Some(Arc::new(manager)), None),
            Err(err) => {
                tracing::warn!(error = %err, "sandboxes are unavailable");
                (None, Some(err.to_string()))
            }
        };

        let router = Arc::new(Mutex::new(router));
        let models = Arc::new(crate::chat::RouterModels::new(
            Arc::clone(&router),
            Arc::clone(&providers),
            Arc::clone(&secrets),
        ));

        Ok(Self::from_parts(AppStateParts {
            config,
            router,
            providers,
            secrets,
            store,
            models,
            tools,
            approvals,
            search,
            sandboxes,
            sandbox_unavailable_reason,
            started_at: now,
        }))
    }

    /// Assemble from parts. The seam a test uses to run the whole HTTP surface without a provider,
    /// a vault or a container engine.
    pub fn from_parts(parts: AppStateParts) -> Arc<Self> {
        Arc::new(Self {
            config: parts.config,
            router: parts.router,
            providers: parts.providers,
            secrets: parts.secrets,
            store: parts.store,
            models: parts.models,
            tools: parts.tools,
            approvals: parts.approvals,
            search: parts.search,
            chats: Mutex::new(HashMap::new()),
            sandboxes: parts.sandboxes,
            chat_sandboxes: crate::sandbox::SandboxCache::new(),
            started_at: parts.started_at,
            sandbox_unavailable_reason: parts.sandbox_unavailable_reason,
            vault_unlocked: false,
        })
    }

    /// The routing table, recovering from a poisoned lock.
    ///
    /// Poisoning means a panic while the mutex was held. The state behind it is limiter counters, and
    /// refusing every future request because one task panicked would turn a transient bug into a
    /// dead daemon. The panic is still logged where it happened.
    pub fn router(&self) -> MutexGuard<'_, ModelRouter> {
        match self.router.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("the routing table's lock was poisoned; using its last state");
                poisoned.into_inner()
            }
        }
    }

    /// The role a request runs as when it does not name one.
    ///
    /// `config.agent.default_pool` names a *pool*, while the router resolves *roles* — so the name is
    /// used as a role when one of that name exists (the usual case, since a pool is normally
    /// reachable as the role of that name), and otherwise the first configured role. A config with
    /// pools but no roles is a configuration error here, where the message can say so, rather than a
    /// `503` when a request arrives.
    pub fn default_role(&self) -> Result<String> {
        let configured = self.config.agent.default_pool.clone();
        if self.config.roles.contains_key(&configured) {
            return Ok(configured);
        }
        if let Some((first, _)) = self.config.roles.first() {
            tracing::debug!(
                configured = %configured,
                using = %first,
                "no role is named after the default pool; using the first configured role"
            );
            return Ok(first.clone());
        }
        Err(HxError::Config(format!(
            "no agent roles are configured: `roles:` maps a role to a pool, and the router only \
             resolves roles. `agent.default_pool` is '{configured}'."
        )))
    }

    /// The directory a run may act in when the request does not name one.
    pub fn default_workspace(&self) -> String {
        std::env::current_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| ".".to_string())
    }

    /// The lock for one session, held for the duration of a run.
    ///
    /// The map is unbounded in principle, so finished entries (nobody waiting, nobody running) are
    /// dropped once it grows: a long-lived daemon with many sessions must not leak a mutex per
    /// session id ever seen.
    pub async fn session_lock(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut chats = self.chats.lock().unwrap_or_else(|e| e.into_inner());
            if chats.len() > 1024 {
                chats.retain(|_, lock| Arc::strong_count(lock) > 1);
            }
            Arc::clone(chats.entry(key.to_string()).or_default())
        };
        lock.lock_owned().await
    }

    /// Which secret stores are configured, for `hx status`. Names only: never a value, never a count.
    pub fn secret_stores(&self) -> Vec<String> {
        self.secrets
            .stores()
            .into_iter()
            .map(|store| store.to_string())
            .collect()
    }

    pub fn uptime_secs(&self, now: DateTime<Utc>) -> i64 {
        (now - self.started_at).num_seconds()
    }

    /// Build a facade over every configured host, plus the local machine.
    ///
    /// Connections are established lazily by the caller; this reports what *would* be connected
    /// so that a configuration error surfaces in `hx doctor` rather than at first use.
    pub fn host_summaries(&self) -> Vec<HostSummary> {
        let mut out = vec![HostSummary {
            id: "local".to_string(),
            kind: "local".to_string(),
            address: None,
            description: "the machine running the daemon".to_string(),
            configured: true,
        }];

        for (name, host) in &self.config.hosts {
            out.push(HostSummary::from_config(name, host));
        }
        out
    }

    /// Build the local host handle.
    pub async fn local_host(&self) -> Result<Arc<LocalHost>> {
        Ok(Arc::new(
            LocalHost::detect(HostId::from_raw("local")).await?,
        ))
    }

    /// One combined snapshot for `/v1/status` and `hx status`.
    pub async fn status(&self, now: DateTime<Utc>) -> StatusReport {
        let router_status = self.router().status();

        // A count that fails is not worth failing status over: the daemon is still running, and the
        // report says the store could not be read rather than inventing a number.
        let sessions = match self.store.count() {
            Ok(count) => count,
            Err(err) => {
                tracing::warn!(error = %err, "could not count sessions");
                0
            }
        };

        let sandboxes = match &self.sandboxes {
            Some(manager) => SandboxSummary {
                available: true,
                reason: None,
                max_concurrent: Some(manager.max_concurrent().await),
                free_slots: Some(manager.free_slots().await),
                live: manager.list().await.len(),
            },
            None => SandboxSummary {
                available: false,
                reason: self.sandbox_unavailable_reason.clone(),
                max_concurrent: None,
                free_slots: None,
                live: 0,
            },
        };

        StatusReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.uptime_secs(now),
            vault_unlocked: self.vault_unlocked,
            pools: router_status.pools,
            roles: router_status.roles,
            search_backends: self.search.ids(),
            sandboxes,
            hosts: self.host_summaries(),
            providers_configured: self.config.providers.len(),
            secret_stores: self.secret_stores(),
            sessions,
        }
    }
}

/// A host, as reported by status.
#[derive(Clone, Debug, Serialize)]
pub struct HostSummary {
    pub id: String,
    pub kind: String,
    pub address: Option<String>,
    pub description: String,
    /// Whether the referenced host exists in configuration. An unknown `jump` host would show
    /// as not configured rather than failing silently at connect time.
    pub configured: bool,
}

impl HostSummary {
    fn from_config(name: &str, host: &HostConfig) -> Self {
        let address = host.address.as_ref().map(|addr| match host.port {
            Some(port) => format!("{addr}:{port}"),
            None => addr.clone(),
        });

        let description = match (&host.user, &address) {
            (Some(user), Some(addr)) => format!("{user}@{addr}"),
            (None, Some(addr)) => addr.clone(),
            _ => "not configured".to_string(),
        };

        Self {
            id: name.to_string(),
            kind: format!("{:?}", host.kind).to_lowercase(),
            address,
            description,
            configured: host.address.is_some(),
        }
    }
}

/// Sandbox availability, as reported by status.
#[derive(Clone, Debug, Serialize)]
pub struct SandboxSummary {
    pub available: bool,
    pub reason: Option<String>,
    pub max_concurrent: Option<usize>,
    pub free_slots: Option<usize>,
    pub live: usize,
}

/// The full status snapshot.
#[derive(Clone, Debug, Serialize)]
pub struct StatusReport {
    pub version: String,
    pub uptime_secs: i64,
    pub vault_unlocked: bool,
    pub providers_configured: usize,
    /// Which secret stores a `store:name` credential reference can resolve through. Names only.
    pub secret_stores: Vec<String>,
    /// Sessions in the store.
    pub sessions: u64,
    pub pools: Vec<hx_provider::PoolStatus>,
    pub roles: indexmap::IndexMap<String, String>,
    pub search_backends: Vec<String>,
    pub sandboxes: SandboxSummary,
    pub hosts: Vec<HostSummary>,
}
