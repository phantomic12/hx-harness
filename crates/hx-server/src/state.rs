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
use hx_core::event::AgentEvent;
use hx_core::ids::{HostId, SandboxId, SessionId};
use hx_provider::{ModelRouter, ProviderRegistry};
use hx_remote::LocalHost;
use hx_sandbox::SandboxManager;
use hx_search::BackendRegistry;
use hx_secrets::{EnvSecrets, SecretStores};
use hx_store::Store;
use hx_tools::ToolRegistry;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use tokio::sync::broadcast;
use tokio::sync::Mutex as AsyncMutex;
use indexmap::IndexMap;

/// One event on the live bus, tagged with the session it belongs to and its store sequence.
///
/// Tagged so a client subscribed to more than one run can tell them apart without the daemon opening
/// one channel per session. The session filters the bus; the event is the same [`AgentEvent`] the
/// store records, so a live surface renders the same thing a late reader does.
///
/// `seq` is the position the event was (or will be) stored at, assigned by the store's
/// `append_event`. It is what makes the stream **resumable**: a client that reconnects says "start me
/// at seq N", and the server replays the store from there and then skips any live event whose seq it
/// already sent. Without it a client could only reconnect by receiving duplicates (re-fetch the whole
/// store and miss what happened in between) or by missing exactly the events emitted in the gap.
#[derive(Clone)]
pub struct LiveEvent {
    pub session: SessionId,
    pub seq: u64,
    pub event: AgentEvent,
}

/// Everything the HTTP surface needs.
pub struct AppState {
    pub config: Config,
    /// The routing table. Behind a *sync* mutex, and shared: the model call and the status route must
    /// read the same limiter state, or `hx status` reports headroom that does not exist. Nothing
    /// holds it across an `await`.
    pub router: Arc<Mutex<ModelRouter>>,
    /// The adapters the router's routes resolve to. Behind a read-write lock so a provider can be
    /// added or edited at runtime (the web UI's providers pane) without restarting the daemon: the
    /// sweep swaps in a freshly built [`ProviderRegistry`] and callers read the current one for the
    /// duration of a single route.
    pub providers: Arc<RwLock<ProviderRegistry>>,
    /// The provider *configs* (kind, base_url, models, routing), kept in step with [`Self::providers`]
    /// as the web UI adds and edits providers. Mirrors the subset of `config.providers` the daemon is
    /// actually running with; persisted to the config file on every edit so a restart keeps them.
    pub provider_configs: Arc<RwLock<IndexMap<String, hx_core::config::ProviderConfig>>>,
    /// Where a credential's key comes from, by reference. Vault-backed sources are added when the
    /// vault is unlocked; until then this resolves `env:` only, and says so.
    pub secrets: Arc<SecretStores>,
    /// Sessions, transcripts, events and usage. The daemon's only durable state.
    pub store: Arc<Store>,
    /// How a role becomes a model call. A trait so the HTTP surface can be tested without a provider.
    /// Behind a read-write lock so a runtime provider edit can swap the model factory the same way it
    /// swaps the registry.
    pub models: Arc<RwLock<Arc<dyn crate::chat::ModelFactory>>>,
    /// The tools a run may call.
    pub tools: Arc<ToolRegistry>,
    /// Questions a run is waiting on, for a client that can answer them.
    ///
    /// Shared across runs and keyed by approval id: an approval belongs to a session and a call, and
    /// a client asks "what is waiting for *this* session" rather than being shown every prompt on the
    /// machine.
    pub approvals: Arc<ApprovalQueue>,
    /// The phone/lock-screen approval push, when `config.approval.push_url` is set.
    ///
    /// `None` when no webhook is configured: a daemon that names no push posts nothing, and the respond
    /// route refuses every token (there is nothing for a token to authorise). See [`crate::phone`].
    pub phone: Option<Arc<crate::phone::PhoneApprover>>,
    pub search: Arc<BackendRegistry>,
    /// One lock per session, held for the duration of a run: two requests on one session would
    /// otherwise interleave into a transcript neither of them wrote.
    pub chats: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    /// The server-side terminals. Owned by the daemon, not by a connection: a shell outlives the
    /// client that opened it, which is what lets two clients attach to one terminal and see the
    /// same bytes.
    pub terminals: Arc<crate::terminal::Terminals>,
    /// Live events, broadcast to SSE subscribers as a run produces them.
    ///
    /// Events are also persisted, so this is the *live* half of the same stream a late reader gets
    /// from the store. One bus, tagged by session, is all the multiplex a live surface needs; a
    /// per-session channel per subscriber would be a second mechanism solving the same problem.
    pub event_bus: broadcast::Sender<LiveEvent>,
    /// `None` when no container engine was reachable at startup.
    pub sandboxes: Option<Arc<SandboxManager>>,
    /// One remote `SandboxManager` per named host, built lazily. Sharing one per host is what keeps
    /// two requests for the same host from creating two managers (and thus two invisible container sets
    /// the reaper cannot see): see [`AppState::sandbox_manager_for`].
    pub remote_sandbox_managers: AsyncMutex<std::collections::HashMap<String, Arc<SandboxManager>>>,
    /// Reuse one shell boundary per profile and checkout across chat requests.
    pub chat_sandboxes: crate::sandbox::SandboxCache,
    pub started_at: DateTime<Utc>,
    /// Why the sandbox manager is absent, so status can explain rather than just say "null".
    pub sandbox_unavailable_reason: Option<String>,
    /// Whether the secret vault was unlocked. Secrets are never loaded while locked.
    pub vault_unlocked: bool,
    /// The bearer token every route but [`crate::auth::is_exempt`]'s two requires.
    ///
    /// Resolved **once**, in [`AppState::build`], from `api.token` or `HX_API_TOKEN` — not per
    /// request, so a long-running daemon cannot be made to re-read an unlocked vault from a stray
    /// request, and so the answer to "what is this daemon checking" cannot change under it.
    ///
    /// `None` means no token, which is a legitimate configuration on a loopback bind and a
    /// configuration that never starts on any other. The check that makes that true is
    /// [`hx_core::api_auth::require_token_for_bind`], called by `hxd` before it binds.
    pub api_token: Option<hx_core::api_auth::ApiToken>,
    /// Hostnames allowed to open a WebSocket on the daemon, beyond loopback.
    ///
    /// A WebSocket handshake's `Origin` is accepted when it names a loopback host (the local dev
    /// UI) or a name in this list. The request's own `Host` header is deliberately *not* an
    /// allowlist — it is attacker-controlled under DNS rebinding, so "same origin as Host" proves
    /// nothing. See [`crate::auth::ws_origin_allowed`] and `ApiConfig::allowed_origins`.
    pub allowed_origins: Vec<String>,
    /// The generic webhook connectors' push endpoints and verification tokens, keyed by connector id.
    ///
    /// Populated from `config.connectors` with `kind: webhook`; each registers a token and the
    /// sender end of the channel the matching `hx-gateway::WebhookConnector` reads from, so
    /// `POST /v1/connectors/{id}/webhook` can be authenticated and pushed in one place.
    pub webhooks: crate::webhook::WebhookRegistry,
    /// The harness session each webhook conversation bridges into, by
    /// [`Conversation::canonical`](hx_gateway::Conversation::canonical).
    ///
    /// The [`crate::webhook_bridge`] loop finds or creates one session per conversation here, so
    /// every message from one chat lands in one transcript instead of opening a session per push.
    /// In-memory on purpose: it is routing, not history — the transcript itself is durable in the
    /// store, and a restarted daemon re-creates sessions rather than resurrecting stale ids.
    pub webhook_sessions: Mutex<HashMap<String, SessionId>>,
    /// The on-disk config file, so a runtime provider edit can be persisted. See [`Self::provider_configs`].
    pub config_path: Option<PathBuf>,
}

/// Everything [`AppState::build`] assembles, so a test can assemble it differently.
pub struct AppStateParts {
    pub config: Config,
    pub router: Arc<Mutex<ModelRouter>>,
    pub providers: Arc<RwLock<ProviderRegistry>>,
    pub provider_configs: IndexMap<String, hx_core::config::ProviderConfig>,
    pub secrets: Arc<SecretStores>,
    pub store: Arc<Store>,
    pub models: Arc<RwLock<Arc<dyn crate::chat::ModelFactory>>>,
    pub tools: Arc<ToolRegistry>,
    pub approvals: Arc<ApprovalQueue>,
    /// The phone approval push, or `None`. See [`AppState::phone`].
    pub phone: Option<Arc<crate::phone::PhoneApprover>>,
    pub search: Arc<BackendRegistry>,
    pub sandboxes: Option<Arc<SandboxManager>>,
    pub sandbox_unavailable_reason: Option<String>,
    pub started_at: DateTime<Utc>,
    /// The API's bearer token, or `None` for an unauthenticated loopback deployment. A test that
    /// wants the authenticated surface passes one here; a test that does not passes `None`, which
    /// is the same thing a default-config daemon does.
    pub api_token: Option<hx_core::api_auth::ApiToken>,
    /// Hosts (beyond loopback) allowed to open a WebSocket. See [`AppState::allowed_origins`].
    pub allowed_origins: Vec<String>,
    /// The generic webhook connectors' push endpoints and verification tokens.
    ///
    /// Populated from `config.connectors` with `kind: webhook`: each registers a token and a channel
    /// that its `hx_gateway::WebhookConnector` reads from. A webhook connector with no configured
    /// secrets still registers — the [`crate::webhook`] route fails closed on an unknown id.
    pub webhooks: crate::webhook::WebhookRegistry,
    /// The on-disk config file providers and other settings were read from, so a runtime edit
    /// (the web UI's providers pane) can be persisted back to the same file. `None` when the daemon
    /// was built without a file on disk (an in-memory test config), in which case edits cannot persist.
    pub config_path: Option<PathBuf>,
}

impl AppState {
    /// Build the whole system from configuration.
    ///
    /// Two failures are fatal: without a routing table there is no harness, and without a session
    /// store there is nothing to resume — a daemon that loses every session on restart while
    /// claiming to be running is worse than one that refuses to start. Everything else degrades:
    /// search with no backends is empty rather than fatal, and a missing container engine disables
    /// sandboxes while leaving the rest running.
    pub async fn build(
        config: Config,
        config_path: Option<PathBuf>,
        now: DateTime<Utc>,
    ) -> Result<Arc<Self>> {
        let router = ModelRouter::from_config(&config, now)?;

        let client = reqwest::Client::builder()
            .user_agent(hx_search::backends::USER_AGENT)
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| HxError::Config(format!("could not build the HTTP client: {e}")))?;

        // Until the vault is unlocked this resolves `env:` references only. That is stated rather
        // than implied: `hx status` reports which stores are configured, so a `vault:` reference
        // that cannot resolve yet is visible before a run tries to use it.
        //
        // Built *before* the search registry, because the registry resolves the credential
        // references in `search.credentials` once, at construction — a long-running daemon that
        // touched the vault per query would be one that can be made to read an unlocked vault from
        // a stray request.
        let secrets = Arc::new(SecretStores::new().with(Arc::new(EnvSecrets)));
        let search = BackendRegistry::from_config(&config.search, client.clone(), &secrets)?;

        // The API's bearer token, resolved once here rather than per request. A config that names a
        // token it cannot resolve is a **startup failure**, not a daemon that quietly serves
        // without one: `resolve_api_token` returning `Err` propagates out of `build`, and a
        // `vault:` reference against a deployment with no vault is exactly the case where
        // "degrade to no token" would leave a non-loopback daemon unprotected while its
        // configuration says otherwise. Whether *having* no token is acceptable is a separate
        // question, asked by `hxd` against the bind address.
        let api_token = hx_secrets::resolve_api_token(&config, &secrets)?;

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

        // The chain's key comes from the environment, named by the config rather than stored in it:
        // a key in a committed file is a key an attacker already has.
        let chain_key = hx_store::audit::ChainKey::from_env(&config.daemon.audit_key_env);
        if !chain_key.is_keyed() {
            tracing::warn!(
                var = %config.daemon.audit_key_env,
                "no audit chain key is set: the chain detects an inconsistent edit but not a rewrite"
            );
        }
        let store = Arc::new(Store::from_config_with_key(&config, chain_key)?);

        let search = Arc::new(search);
        let tools = Arc::new(crate::chat::default_tools(search.all(), client.clone()));

        // How long a run waits for a human before treating silence as a refusal. Long enough to
        // answer a phone notification, short enough that a run with nobody attached does not look
        // hung; a request can ask for zero, which refuses immediately (the old behaviour).
        let approvals = ApprovalQueue::new(std::time::Duration::from_secs(
            crate::chat::DEFAULT_APPROVAL_WAIT_SECS,
        ));

        // The phone push, enabled only when a webhook is configured. `respond_base` is the daemon's
        // public origin; a daemon without one cannot build a `respond_url`, so on the loopback default
        // the push is off unless the operator names a base. The wait matches the queue's, so a phone that
        // answers wins the same race a queue client would.
        let phone = config.approval.push_url.as_ref().map(|push_url| {
            let respond_base = crate::phone::origin_of(&config.daemon.http_addr);
            crate::phone::PhoneApprover::new(
                push_url.clone(),
                respond_base,
                std::time::Duration::from_secs(crate::chat::DEFAULT_APPROVAL_WAIT_SECS),
            )
        });

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
        let models: Arc<dyn crate::chat::ModelFactory> =
            Arc::new(crate::chat::RouterModels::new(
                Arc::clone(&router),
                Arc::clone(&providers),
                Arc::clone(&secrets),
            ));

        // M5's webhook half: every `kind: webhook` connector is registered once here, so
        // `POST /v1/connectors/{id}/webhook` can authenticate against its own token and push into the
        // channel the runtime `hx-gateway::WebhookConnector` reads from. A token that cannot be
        // resolved is a **startup failure** — a webhook route with no verifiable token would push into the
        // harness from anyone who guesses a URL, which is the exposure the per-connector token exists to
        // close. See `crate::webhook`.
        //
        // WHY the driver is built and retained here rather than just registering the sender: `register`
        // hands back the receiver, and a receiver dropped at the end of this loop closes the channel —
        // after which every `POST` is a `409` against a connector that is configured and looks healthy.
        // Building the `WebhookConnector` from the receiver and retaining it in the registry keeps the
        // channel open for the daemon's lifetime and gives the runtime a ready driver to read from.
        let mut webhooks = crate::webhook::WebhookRegistry::default();
        for (id, connector) in &config.connectors {
            if connector.kind != hx_core::config::ConnectorKind::Webhook {
                continue;
            }
            let Some(token_ref) = connector.token.as_deref() else {
                return Err(HxError::Config(format!(
                    "webhook connector '{id}' has no `token`; a webhook needs a bearer token to \
                     verify its callers, so this is a startup error, not a route left open"
                )));
            };
            let secret = secrets.resolve_str(token_ref).map_err(|err| {
                HxError::Config(format!(
                    "webhook connector '{id}' references a token that cannot be resolved: {err}"
                ))
            })?;
            let connector_id = hx_core::ids::ConnectorId::from(id.clone());
            let (_sender, receiver) = webhooks.register_with_capacity(
                &connector_id,
                hx_core::api_auth::ApiToken::new(secret.expose()),
                connector
                    .queue_capacity
                    .unwrap_or(crate::webhook::DEFAULT_WEBHOOK_QUEUE_CAPACITY),
            );
            webhooks.retain_driver(
                &connector_id.to_string(),
                hx_gateway::webhook::WebhookConnector::new(
                    connector_id,
                    connector.outbound_url.clone(),
                    client.clone(),
                    receiver,
                ),
            );
        }

        let ws_allowed_origins = config.api.allowed_origins.clone();
        let provider_configs = config.providers.clone();
        let providers: Arc<RwLock<ProviderRegistry>> =
            Arc::new(RwLock::new((*providers).clone()));
        Ok(Self::from_parts(AppStateParts {
            config,
            router,
            providers,
            provider_configs,
            secrets,
            store,
            models: Arc::new(RwLock::new(models)),
            tools,
            approvals,
            phone,
            search,
            sandboxes,
            sandbox_unavailable_reason,
            config_path,
            started_at: now,
            api_token,
            allowed_origins: ws_allowed_origins,
            webhooks,
        }))
    }

    /// Assemble from parts. The seam a test uses to run the whole HTTP surface without a provider,
    /// a vault or a container engine.
    ///
    /// Starting the [`crate::webhook_bridge`] loops is part of assembly, not of `build` alone: a
    /// retained webhook driver nobody reads is a queue that fills and then `429`s forever (#73),
    /// and that is true no matter which constructor retained it.
    pub fn from_parts(parts: AppStateParts) -> Arc<Self> {
        let state = Arc::new(Self {
            config: parts.config,
            router: parts.router,
            providers: parts.providers,
            provider_configs: Arc::new(RwLock::new(parts.provider_configs)),
            secrets: parts.secrets,
            store: parts.store,
            models: parts.models,
            tools: parts.tools,
            approvals: parts.approvals,
            phone: parts.phone,
            search: parts.search,
            chats: Mutex::new(HashMap::new()),
            terminals: Arc::new(crate::terminal::Terminals::new()),
            // Capacity generous enough that a burst of token deltas does not drop a subscriber;
            // a slow reader is *supposed* to lag (reconnecting redraws from the store), but a
            // normal live client must not lose events it was awake for.
            event_bus: broadcast::channel(2048).0,
            sandboxes: parts.sandboxes,
            remote_sandbox_managers: AsyncMutex::new(HashMap::new()),
            chat_sandboxes: crate::sandbox::SandboxCache::new(),
            started_at: parts.started_at,
            sandbox_unavailable_reason: parts.sandbox_unavailable_reason,
            vault_unlocked: false,
            api_token: parts.api_token,
            allowed_origins: parts.allowed_origins,
            webhooks: parts.webhooks,
            webhook_sessions: Mutex::new(HashMap::new()),
            config_path: parts.config_path,
        });
        crate::webhook_bridge::spawn_webhook_bridges(&state);
        state
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

    /// The [`SandboxManager`] a sandbox profile resolves to: the local one for `None`, or a remote
    /// one for a named host.
    ///
    /// `None` (a profile without a `host` key) means the local daemon — today's behaviour unchanged —
    /// and returns [`AppState::sandboxes`], so a profile with no host stays on the local engine and a
    /// profile that names one goes remote. `Some(id)` resolves the host through [`AppState::resolve_host`]
    /// — the one sanctioned way anything obtains a remote handle — wraps it in a
    /// [`HostCommandRunner`](crate::remote_sandbox::HostCommandRunner) and a
    /// [`RemoteSandboxRuntime`], and hands the [`SandboxManager`] that results to the existing
    /// [`SandboxCache`](crate::sandbox::SandboxCache).
    ///
    /// ## Concurrency: one manager per host
    ///
    /// Managers are cached per host id. Two concurrent requests for the same host must not each build (and
    /// then use) their own manager: each [`SandboxManager`] owns a `live` set the TTL reaper never
    /// sees, so an uncached manager created per request would be a container set with no reaper. The
    /// pattern is *resolve outside the lock, install once*: look up the cache; on a miss, drop the
    /// lock, resolve and build, then re-check and insert only if the host still has none. A second
    /// request racing the first may build a temporarily-extra manager, but only the installed one is ever
    /// handed out and the loser is dropped unused (its `live` set is empty), so no container ever lands
    /// in an unreaped manager.
    pub async fn sandbox_manager_for(&self, host: Option<&str>) -> Result<Arc<SandboxManager>> {
        match host {
            None | Some("local") => self.sandboxes.as_ref().cloned().ok_or_else(|| {
                HxError::Sandbox(
                    self.sandbox_unavailable_reason
                        .clone()
                        .unwrap_or_else(|| "sandboxes are unavailable".into()),
                )
            }),
            Some(id) => {
                {
                    let cache = self.remote_sandbox_managers.lock().await;
                    if let Some(manager) = cache.get(id) {
                        return Ok(Arc::clone(manager));
                    }
                }
                let manager = self.build_remote_manager(id).await?;
                let mut cache = self.remote_sandbox_managers.lock().await;
                Ok(Arc::clone(cache.entry(id.to_string()).or_insert(manager)))
            }
        }
    }

    /// Reap expired sandboxes from the local manager *and* every cached remote manager.
    ///
    /// WHY this exists instead of reaping `state.sandboxes` alone: TTL enforcement lives
    /// inside [`SandboxManager::reap`], and each remote host gets its own manager cached in
    /// `remote_sandbox_managers`. A reaper that only visits the local manager leaves every
    /// remote container set to grow until its TTL-bearing owner happens to call `destroy` —
    /// which is the same leak the local reaper was built to close, on someone else's disk.
    /// Managers are snapshotted under the lock and reaped after releasing it, so a slow
    /// engine on one host cannot stall manager creation for the others.
    pub async fn reap_all_sandboxes(&self, now: DateTime<Utc>) -> Vec<SandboxId> {
        let mut managers: Vec<Arc<SandboxManager>> = Vec::new();
        if let Some(local) = self.sandboxes.as_ref() {
            managers.push(Arc::clone(local));
        }
        managers.extend(self.remote_sandbox_managers.lock().await.values().cloned());

        let mut reaped = Vec::new();
        for manager in managers {
            match manager.reap(now).await {
                Ok(ids) => {
                    for id in ids {
                        tracing::info!(sandbox = %id, "reaped expired sandbox");
                        reaped.push(id);
                    }
                }
                Err(err) => tracing::warn!(error = %err, "the sandbox reaper failed"),
            }
        }
        reaped
    }

    /// Build a fresh remote [`SandboxManager`] for `id`, without touching the per-host cache.
    ///
    /// Resolving and connecting is async and must not happen while holding the cache lock (it can run for
    /// a credential read and an SSH handshake); only the install is serialised. See
    /// [`AppState::sandbox_manager_for`] for how a raced build is dropped unused.
    async fn build_remote_manager(&self, id: &str) -> Result<Arc<SandboxManager>> {
        let host = self
            .resolve_host(id)
            .await
            .map_err(|err| HxError::Sandbox(format!("cannot run sandbox on host {id:?}: {err}")))?;
        let runner = Arc::new(crate::remote_sandbox::HostCommandRunner::new(host));
        let runtime = Arc::new(self.remote_runtime_for(id, runner));
        Ok(Arc::new(hx_sandbox::SandboxManager::new(
            runtime,
            self.config.agent.max_concurrent_subagents as usize,
        )))
    }

    /// The [`RemoteSandboxRuntime`](hx_sandbox::RemoteSandboxRuntime) for host `id`, over `runner`.
    ///
    /// Split out from [`AppState::build_remote_manager`] so the wiring from a host's config to the
    /// runtime is one testable act rather than a line buried in an async resolve. What it carries
    /// that matters: the far host's `hx-egress-proxy` path, from that host's own
    /// [`HostConfig::egress_proxy_bin`](hx_core::config::HostConfig::egress_proxy_bin), because the
    /// binary must exist on the *far* filesystem and only the deployment knows where it put it there.
    /// Without it the runtime refuses every remote spec with an allowlist ("no proxy binary path was
    /// configured") — which is exactly what the daemon did, so "remote egress is enforced" was true
    /// of the library and of the live test but not of the daemon. It is left unset rather than
    /// guessed: a path invented here would be wrong at runtime, and the refusal names the config key.
    pub fn remote_runtime_for(
        &self,
        id: &str,
        runner: Arc<dyn hx_sandbox::RemoteCommandRunner>,
    ) -> hx_sandbox::RemoteSandboxRuntime {
        hx_sandbox::RemoteSandboxRuntime::new(runner).with_proxy_bin(self.egress_proxy_bin_for(id))
    }

    /// The `hx-egress-proxy` path configured for host `id`, or `None` when it names none.
    ///
    /// The config half of [`AppState::remote_runtime_for`]: this is the one line that decides whether
    /// a remote sandbox with an allowlist can be enforced at all.
    pub fn egress_proxy_bin_for(&self, id: &str) -> Option<String> {
        self.config
            .hosts
            .get(id)
            .and_then(|host| host.egress_proxy_bin.clone())
    }

    /// Resolve a host id to something that can be driven.
    ///
    /// Delegates to [`crate::hosts::resolve`], which reads the credential from the vault at connect
    /// time. This is the only way a route or tool obtains a remote handle.
    pub async fn resolve_host(&self, id: &str) -> Result<Arc<dyn hx_remote::Host>> {
        crate::hosts::resolve(&self.config, &self.secrets, id).await
    }

    /// Whether a command on `id` would be refused, and why.
    ///
    /// `None` means the policy does not deny it. This is *not* "it is allowed": an [`Verdict::Ask`]
    /// returns `None` here, because a prompt is not a refusal and the caller decides what to do with
    /// it. The distinction matters on the HTTP surface, where there is no one to answer a prompt —
    /// see [`AppState::host_denial_for`], which is what the routes use.
    pub fn host_denial(&self, id: &str) -> Option<String> {
        // Resolving the *name* is itself subject to policy: a host that is not in the allow list at
        // all cannot be looked at, let alone reached.
        self.policy_verdict_for(host_lookup_request(id))
            .and_then(|v| match v {
                hx_core::approval::Verdict::Deny { why } => Some(why),
                _ => None,
            })
    }

    /// Whether `action` on `id` would be refused, and why, for a route that can only allow or deny.
    ///
    /// A [`Verdict::Ask`] is reported as a denial *with an explanation*, because these routes have no
    /// approver attached: the request arrives over HTTP and the response goes back to it, so there is
    /// nobody positioned to answer a prompt. Refusing is the honest outcome — an `Ask` that silently
    /// proceeded would be the policy failing open, and an `Ask` that hung would be a request that
    /// never returns. The message says which knob would allow it, so the operator can act rather than
    /// guess.
    pub fn host_denial_for(&self, id: &str, action: hx_core::capability::Action) -> Option<String> {
        self.host_denial_request(id, host_action_request(id, action))
    }

    /// Whether running `command` on `id` would be refused, and why.
    ///
    /// The command goes through the *real* classifier (`ActionRequest::shell`), the same one an agent
    /// run uses, so `ls` and `rm -rf /` are classified differently here exactly as they are there.
    /// Hand-picking a risk class per route would have made every command on every host equally
    /// dangerous, which is both wrong and useless: it refuses `hostname` at the default autonomy
    /// level.
    pub fn host_command_denial(&self, id: &str, command: &str) -> Option<String> {
        let mut request = hx_core::approval::ActionRequest::shell(command);
        // The command runs *on the host*, which is what the confinement axis reports. A rule written
        // as `confined: true` therefore does not silently authorise this.
        request.confined = hx_core::approval::Confinement::Host;
        request.tool = "shell".to_string();
        request.summary = format!("{command} (on host {id})");
        self.host_denial_request(id, request)
    }

    /// Evaluate a prepared request against the policy, turning any non-allow into a reason.
    fn host_denial_request(
        &self,
        id: &str,
        request: hx_core::approval::ActionRequest,
    ) -> Option<String> {
        let label = request.risk.label();
        match self.policy_verdict_for(request)? {
            hx_core::approval::Verdict::Allow { .. } => None,
            hx_core::approval::Verdict::Deny { why } => Some(why),
            hx_core::approval::Verdict::Ask(_) => Some(format!(
                "host {id:?} requires approval ({label}) but no approver is attached to this route; \
                 allow it in the policy or run the command through a chat session, where a prompt can \
                 be answered"
            )),
        }
    }

    /// Evaluate one request against the configured policy.
    ///
    /// The policy is rebuilt per call rather than cached: `.hx/allow.toml` is read from the
    /// workspace at use time on the agent path, and a cached policy here would mean an edit to the
    /// allowlist needed a daemon restart to take effect — the difference between a policy and a
    /// suggestion. The fold is cheap.
    fn policy_verdict_for(
        &self,
        request: hx_core::approval::ActionRequest,
    ) -> Option<hx_core::approval::Verdict> {
        let mut policy = self.config.agent.approval.clone().with_floor();
        // The project allowlist, folded the same way `chat.rs` folds it. A malformed file is a hard
        // error there and is treated as one here too: silently dropping a policy somebody relies on
        // is the fail-open this must not do. The difference is that a route has to *report* it
        // rather than abort a run, so it becomes a denial with the parse error in it.
        let allow_path =
            std::path::Path::new(&self.default_workspace()).join(hx_core::allowlist::ALLOW_FILE);
        match hx_core::allowlist::AllowFile::load(&allow_path) {
            Ok(list) => {
                let mut rules = list.into_rules();
                policy.allow.append(&mut rules);
            }
            Err(hx_core::allowlist::AllowlistError::NotFound(_)) => {}
            Err(err) => {
                return Some(hx_core::approval::Verdict::Deny {
                    why: format!("cannot use {}: {err}", allow_path.display()),
                })
            }
        }

        let mut session = hx_core::approval::ApprovalSession::new(policy);
        Some(session.decide(&request, chrono::Utc::now()))
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
            providers_configured: self.providers.read().expect("providers lock").len(),
            secret_stores: self.secret_stores(),
            sessions,
            // WHY here: a webhook queue that only grows is a connector nobody drains, and the route
            // answers `429` while the status page says everything is fine unless the depths are in
            // the same snapshot. Depth beside capacity tells "busy" from "stuck".
            webhook_queues: self.webhooks.queue_depths(),
        }
    }

    /// The providers the daemon is currently running with, for the web UI's providers pane.
    pub fn provider_summaries(&self) -> Vec<ProviderSummary> {
        self.provider_configs
            .read()
            .expect("provider config lock")
            .iter()
            .map(|(name, pc)| ProviderSummary {
                name: name.clone(),
                kind: pc.kind.to_string(),
                base_url: pc.base_url.clone(),
                models: pc.models.clone(),
                routing: pc.routing.to_string(),
                secret_set: !pc.credentials.is_empty(),
            })
            .collect()
    }

    /// Add or edit a provider at runtime, then swap the routing surface and persist the config file.
    ///
    /// `api_key`: when `Some`, replaces the provider's credentials with a single credential referencing
    /// `env:HX_PROVIDER_<NAME>_KEY`, and writes that key to the sibling secrets file next to the
    /// config. When `None` and the provider already exists, its existing credentials are kept.
    pub fn upsert_provider(
        &self,
        name: &str,
        kind: hx_core::config::ProviderKind,
        base_url: Option<String>,
        models: Vec<String>,
        routing: hx_core::config::Strategy,
        api_key: Option<String>,
    ) -> Result<()> {
        if name.is_empty() {
            return Err(HxError::Config("provider name cannot be empty".into()));
        }
        if base_url.as_deref().map_or(true, |u| u.trim().is_empty()) {
            return Err(HxError::Config(format!(
                "provider '{name}' needs a base_url"
            )));
        }

        // Build the new credential set, preserving the old secret when no new key was given.
        let mut cfg = self
            .provider_configs
            .read()
            .expect("provider config lock")
            .clone();
        let credentials = match api_key {
            Some(key) if !key.trim().is_empty() => {
                self.write_provider_key(name, &key)?;
                vec![hx_core::config::CredentialConfig {
                    id: hx_core::CredentialId::new(),
                    secret: format!("env:HX_PROVIDER_{}_KEY", name.to_uppercase()),
                    limits: Default::default(),
                    weight: 1,
                }]
            }
            _ => cfg
                .get(name)
                .map(|pc| pc.credentials.clone())
                .unwrap_or_default(),
        };

        cfg.insert(
            name.to_string(),
            hx_core::config::ProviderConfig {
                kind,
                base_url,
                credentials,
                routing,
                models,
                price: None,
                priority: 0,
            },
        );

        self.rebuild_and_persist(&cfg)
    }

    /// Remove a provider and its key from the secrets file, then swap the routing surface and persist.
    pub fn remove_provider(&self, name: &str) -> Result<()> {
        let mut cfg = self
            .provider_configs
            .read()
            .expect("provider config lock")
            .clone();
        if cfg.shift_remove(name).is_none() {
            return Err(HxError::Config(format!("no provider named '{name}'")));
        }
        let _ = self.remove_provider_key(name);
        self.rebuild_and_persist(&cfg)
    }

    /// Rebuild the live registry, router and model factory from an updated provider set, persist the config
    /// file, and swap everything in.
    fn rebuild_and_persist(
        &self,
        provider_configs: &IndexMap<String, hx_core::config::ProviderConfig>,
    ) -> Result<()> {
        let now = Utc::now();

        // A full config for building the router/registry and for persisting: everything unchanged except
        // the provider subsection we just edited.
        let mut full = self.config.clone();
        full.providers = provider_configs.clone();

        let provider_client = reqwest::Client::builder()
            .user_agent(concat!("hx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                HxError::Config(format!("could not build the provider HTTP client: {e}"))
            })?;

        let registry: Arc<ProviderRegistry> =
            Arc::new(hx_provider::ProviderRegistry::from_config(&full, provider_client)?);
        let router = hx_provider::ModelRouter::from_config(&full, now)?;

        // A model factory over the *new* registry and router, so a swap keeps all three consistent.
        let models: Arc<dyn crate::chat::ModelFactory> =
            Arc::new(crate::chat::RouterModels::new(
                Arc::clone(&self.router),
                Arc::clone(&registry),
                Arc::clone(&self.secrets),
            ));

        // Swap the live surface: registry, router, model factory, then the visible provider configs.
        *self.providers.write().expect("providers lock") = (*registry).clone();
        *self.router.lock().expect("router lock") = router;
        *self.models.write().expect("model factory lock") = models;
        *self
            .provider_configs
            .write()
            .expect("provider config lock") = provider_configs.clone();

        // Persist, but only if there is a real file to write back to. A config assembled in memory
        // (a test, or a `--check`) is not a file the daemon owns.
        if let Some(path) = &self.config_path {
            let yaml = full.to_yaml()?;
            std::fs::write(path, yaml).map_err(|e| {
                HxError::Config(format!("could not write config to {}: {e}", path.display()))
            })?;
        }
        Ok(())
    }

    /// Append or replace the provider's key in the secrets file that sits beside the config.
    fn write_provider_key(&self, name: &str, key: &str) -> Result<()> {
        let Some(path) = &self.config_path else {
            return Ok(());
        };
        let secrets_path = path.with_file_name("hx.secrets.env");
        let mut entries: indexmap::IndexMap<String, String> = if secrets_path.exists() {
            std::fs::read_to_string(&secrets_path)
                .map(|s| {
                    s.lines()
                        .filter_map(|l| {
                            let (k, v) = l.split_once('=')?;
                            Some((k.trim().to_string(), v.trim().to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Default::default()
        };
        entries.insert(format!("HX_PROVIDER_{}_KEY", name.to_uppercase()), key.to_string());
        let contents = entries
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&secrets_path, contents).map_err(|e| {
            HxError::Config(format!(
                "could not write secrets file {}: {e}",
                secrets_path.display()
            ))
        })?;
        // The whole point is that these are not world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &secrets_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        Ok(())
    }

    fn remove_provider_key(&self, name: &str) -> Result<()> {
        let Some(path) = &self.config_path else {
            return Ok(());
        };
        let secrets_path = path.with_file_name("hx.secrets.env");
        if !secrets_path.exists() {
            return Ok(());
        }
        let contents = std::fs::read_to_string(&secrets_path).unwrap_or_default();
        let key = format!("HX_PROVIDER_{}_KEY", name.to_uppercase());
        let kept = contents
            .lines()
            .filter(|l| !l.starts_with(&format!("{key}=")))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&secrets_path, kept).map_err(|e| {
            HxError::Config(format!(
                "could not write secrets file {}: {e}",
                secrets_path.display()
            ))
        })
    }
}

/// A provider, as the web UI lists it. Deliberately never carries a secret.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ProviderSummary {
    pub name: String,
    pub kind: String,
    pub base_url: Option<String>,
    pub models: Vec<String>,
    pub routing: String,
    pub secret_set: bool,
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
    /// One depth-and-bound per webhook connector, sorted by id. Empty when no webhook connector is
    /// configured — which is the common case, and must render as `[]` rather than `null`.
    pub webhook_queues: Vec<crate::webhook::WebhookQueueDepth>,
}

// ---------------------------------------------------------------------------
// Host policy requests
// ---------------------------------------------------------------------------
//
// A host route has to answer "may this be used?" through the same machinery an agent run uses, or
// the policy would hold for the agent and not for the browser — and the browser is the surface a
// person is more likely to point at a machine by accident.
//
// The requests below are built with `ActionRequest::tool` rather than a bespoke struct so the risk
// classes, the rule keys, and the allow/deny matching are the agent's, not a second implementation
// that could drift.

/// The request for "may I look at this host at all".
fn host_lookup_request(id: &str) -> hx_core::approval::ActionRequest {
    hx_core::approval::ActionRequest::tool(
        "host",
        format!("look at host {id}"),
        // Listing and describing is observation. It is `Read` even for a host whose credentials
        // exist: no command runs and no byte of the remote filesystem is touched, so a policy that
        // permits reading is enough to see the machine is there.
        hx_core::approval::RiskClass::Read,
        "reading host metadata",
    )
}

/// The request for "may I do `action` to this host".
///
/// `Execute` is the strongest of the three actions the host routes need, so it maps to the risk class
/// a shell command would carry. Read and write map to the matching class and no higher: a policy that
/// allows reading a host should not be forced to allow running commands on it to browse a directory.
fn host_action_request(
    id: &str,
    action: hx_core::capability::Action,
) -> hx_core::approval::ActionRequest {
    use hx_core::approval::{ActionRequest, RiskClass};
    let label = action_label(action);
    let (risk, reason) = match action {
        hx_core::capability::Action::Read => (RiskClass::Read, "reading from a remote machine"),
        hx_core::capability::Action::Write => (RiskClass::Mutate, "writing to a remote machine"),
        _ => (RiskClass::External, "running a command on a remote machine"),
    };
    ActionRequest::tool("shell", format!("{label} on host {id}"), risk, reason)
}

/// A stable human name for an action, for messages a person reads.
pub(crate) fn action_label(action: hx_core::capability::Action) -> &'static str {
    use hx_core::capability::Action;
    match action {
        Action::Read => "read",
        Action::Write => "write",
        Action::Execute => "execute",
        Action::Connect => "connect",
        Action::Spawn => "spawn",
        Action::Delete => "delete",
        Action::Admin => "admin",
    }
}
