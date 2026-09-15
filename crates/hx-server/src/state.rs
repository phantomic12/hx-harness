//! The daemon's shared state: one place that owns the routers, backends and sandboxes.
//!
//! Deliberately built from a [`Config`] in one function ([`AppState::build`]) so that the CLI,
//! the daemon and the tests all construct the system the same way. A harness where `hx status`
//! reports something different from what the daemon is actually running is worse than no status
//! command at all.

use chrono::{DateTime, Utc};
use hx_core::config::{Config, HostConfig};
use hx_core::error::{HxError, Result};
use hx_core::ids::HostId;
use hx_provider::ModelRouter;
use hx_remote::LocalHost;
use hx_sandbox::SandboxManager;
use hx_search::BackendRegistry;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Everything the HTTP surface needs.
pub struct AppState {
    pub config: Config,
    /// The routing table. Behind a mutex because acquisition mutates limiter state.
    pub router: Mutex<ModelRouter>,
    pub search: BackendRegistry,
    /// `None` when no container engine was reachable at startup.
    pub sandboxes: Option<Arc<SandboxManager>>,
    pub started_at: DateTime<Utc>,
    /// Why the sandbox manager is absent, so status can explain rather than just say "null".
    pub sandbox_unavailable_reason: Option<String>,
    /// Whether the secret vault was unlocked. Secrets are never loaded while locked.
    pub vault_unlocked: bool,
}

impl AppState {
    /// Build the whole system from configuration.
    ///
    /// Only a failure to build the *routing table* is fatal: without providers there is no
    /// harness. Everything else degrades — search with no backends is empty rather than fatal,
    /// and a missing container engine disables sandboxes while leaving the rest running.
    pub async fn build(config: Config, now: DateTime<Utc>) -> Result<Arc<Self>> {
        let router = ModelRouter::from_config(&config, now)?;

        let client = reqwest::Client::builder()
            .user_agent(hx_search::backends::USER_AGENT)
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| HxError::Config(format!("could not build the HTTP client: {e}")))?;
        let search = BackendRegistry::from_config(&config.search, client)?;

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

        Ok(Arc::new(Self {
            config,
            router: Mutex::new(router),
            search,
            sandboxes,
            started_at: now,
            sandbox_unavailable_reason,
            vault_unlocked: false,
        }))
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
        let router = self.router.lock().await;
        let router_status = router.status();
        drop(router);

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
    pub pools: Vec<hx_provider::PoolStatus>,
    pub roles: indexmap::IndexMap<String, String>,
    pub search_backends: Vec<String>,
    pub sandboxes: SandboxSummary,
    pub hosts: Vec<HostSummary>,
}
