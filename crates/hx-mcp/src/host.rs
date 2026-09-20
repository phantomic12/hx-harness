//! The supervisor: what is up, what is down, and what to do about it.
//!
//! ## The one property this module exists to hold
//!
//! **A dead, wedged or misbehaving MCP server must never wedge a run.** Every path out of
//! [`McpHost::call`] is a [`ToolOutcome`] — a string a model can read — and every path is bounded by
//! a timeout. There is no `?` on a connection, no unbounded `await`, and no state in which the
//! caller waits for a server that is never going to answer. That is why the module is written as a
//! supervisor rather than as a client: the interesting cases are all the ones where the server is
//! *not* working.
//!
//! ## The three ways a server is not working, kept apart
//!
//! - **It is down.** The handshake failed, the child exited, the HTTP session closed. `hx` will try
//!   to bring it back, and a call made while it is down returns a sentence saying so, naming the
//!   server and the reason.
//! - **It is wedged.** It is connected and does not answer. The call is cut off at the configured
//!   `call_timeout_secs` and reported as a failure. The connection is deliberately *not* torn down:
//!   a slow server and a dead one look the same from here, and killing a server for being slow is
//!   how a working deployment becomes a flapping one.
//! - **It has been given up on.** It failed more times than `max_restarts` allows inside
//!   `restart_window_secs`. `hx` stops trying, says so, and keeps saying so on every call — a
//!   bounded respawn loop is the difference between one broken config and a machine that spawns
//!   processes forever. Recovery is an operator action (fix it, or set `enabled: false`), and the
//!   message names it.
//!
//! ## Why restarts are bounded by a window and not by a counter
//!
//! A plain counter means a server that crashes once a week is permanently dead after three weeks. A
//! window means "three failures in five minutes is a broken server; three failures in three weeks is
//! a server with a bad day". [`RestartBudget`] takes `now` as an argument rather than reading a
//! clock, so the policy is testable without sleeping.
//!
//! ## Why a failed startup is not a failed daemon
//!
//! [`McpHost::from_config`] connects eagerly — an operator wants to know at startup which servers
//! are broken rather than discovering it in the middle of a run — but a *connection* failure is
//! recorded, not returned. Only a config error (a missing `command`, a literal where a `vault:`
//! reference belongs) fails construction, because that is the operator's typo and it is the only
//! class of problem that will not fix itself.
//!
//! ## Locks, and why the call path does not hold the restart lock
//!
//! Per server: a `tokio::sync::RwLock` over the connection state, plus a separate `Mutex` that
//! serialises restarts. A call takes a *read* guard, so several calls to one server run
//! concurrently; a restart takes the write guard, so it waits for in-flight calls to finish rather
//! than pulling a connection out from under one. The restart mutex is what stops two concurrent
//! calls that both find the server down from spawning two children.

use crate::conn::{self, Connection};
use crate::names;
use crate::stdio::StderrTail;
use crate::tool::{McpTool, RemoteTool};
use hx_core::config::{McpServerConfig, McpTransport};
use hx_core::error::{HxError, Result as HxResult};
use hx_secrets::SecretStores;
use hx_tools::{Tool, ToolOutcome, ToolRegistry};
use indexmap::IndexMap;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use rmcp::service::ServiceError;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// How long a restart may take to close the old connection before it is abandoned to the
/// transport's own drop guard.
///
/// Bounded because this runs on the call path: a server that will not shut down cleanly must not be
/// able to hold a tool call open while it sulks. The child is killed by `TokioChildProcess`'s drop
/// guard regardless, so nothing is orphaned either way.
const REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// How many restarts a server may spend inside a window before `hx` gives up on it.
///
/// Pure, and it takes `now` rather than reading a clock — the same rule `hx-core`'s approval engine
/// holds to, and for the same reason: a policy whose tests have to sleep is a policy whose tests
/// get deleted.
#[derive(Clone, Debug)]
pub struct RestartBudget {
    max: u32,
    window: Duration,
    spent: VecDeque<Instant>,
}

impl RestartBudget {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            spent: VecDeque::new(),
        }
    }

    /// How many restarts have been spent inside the window ending at `now`.
    pub fn spent(&self, now: Instant) -> u32 {
        let window = self.window;
        self.spent
            .iter()
            .filter(|at| now.duration_since(**at) < window)
            .count() as u32
    }

    /// The configured ceiling.
    pub fn max(&self) -> u32 {
        self.max
    }

    /// The window, in seconds, for a message a person reads.
    pub fn window_secs(&self) -> u64 {
        self.window.as_secs()
    }

    /// Record a restart at `now`, or refuse because the budget is spent.
    ///
    /// `false` is the answer that matters: it is what turns "respawn" into "stop".
    pub fn spend(&mut self, now: Instant) -> bool {
        // Forget the ones that have aged out first, so the deque cannot grow without bound on a
        // long-lived server that restarts occasionally forever.
        let window = self.window;
        self.spent.retain(|at| now.duration_since(*at) < window);
        if self.spent.len() as u32 >= self.max {
            return false;
        }
        self.spent.push_back(now);
        true
    }
}

/// What `hx` knows about one server right now.
///
/// Readable by an operator *and* safe to put in front of a model: it carries reasons, counts and
/// tool names, and it can never carry a child's stderr (see [`crate::stdio`]) or a credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHealth {
    /// The config key.
    pub server: String,
    /// The namespace its tools are published under.
    pub namespace: String,
    /// `"stdio"` or `"streamable_http"`.
    pub transport: &'static str,
    pub state: HealthState,
    /// Restarts spent inside the current window.
    pub restarts: u32,
    /// Lines the child has written to stderr. A count, deliberately, and not the lines.
    pub stderr_lines: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthState {
    /// Connected, with the namespaced names of the tools it last advertised.
    ///
    /// Names rather than whole tools because this is what an operator's `hx mcp` output and a
    /// health report want; the descriptions and schemas live in the catalogue, where a model reads
    /// them, and a health report is not a place a server's prose belongs.
    Up { tools: Vec<String> },
    /// Not connected. `retrying` says whether the next call will try to bring it back.
    Down { reason: String, retrying: bool },
    /// Out of restart budget. `hx` will not try again.
    GivenUp { reason: String },
    /// `enabled: false` in the config: nothing is spawned and no tools are offered.
    Disabled,
}

/// The live state of one server's connection.
enum ServerState {
    Up {
        connection: Connection,
        /// What the server advertised when it was last brought up, descriptions and schemas
        /// included. Kept whole rather than reduced to names, because a description is what a model
        /// prices a tool on — see [`crate::tool`].
        tools: Vec<RemoteTool>,
    },
    Down {
        reason: String,
    },
    GivenUp {
        reason: String,
    },
    Disabled,
}

/// One server: its config, its connection, and its restart accounting.
struct ServerHandle {
    key: String,
    namespace: String,
    config: McpServerConfig,
    secrets: Option<Arc<SecretStores>>,
    stderr: StderrTail,
    state: tokio::sync::RwLock<ServerState>,
    budget: tokio::sync::Mutex<RestartBudget>,
    /// Held across a restart so two concurrent calls cannot both spawn a child.
    restarting: tokio::sync::Mutex<()>,
}

impl ServerHandle {
    fn call_timeout(&self) -> Duration {
        Duration::from_secs(self.config.call_timeout_secs.max(1))
    }

    fn start_timeout(&self) -> Duration {
        Duration::from_secs(self.config.start_timeout_secs.max(1))
    }

    async fn is_up(&self) -> bool {
        match &*self.state.read().await {
            // Both halves matter. `is_closed` catches a service we cancelled; `is_transport_closed`
            // catches a child that exited or an HTTP session that ended, which is the case that
            // actually happens and which a naive `is_closed` would miss entirely.
            ServerState::Up { connection, .. } => {
                !connection.is_closed() && !connection.is_transport_closed()
            }
            _ => false,
        }
    }

    /// What this server is, in one phrase, for a message.
    fn describe(&self) -> String {
        format!("mcp server `{}`", self.key)
    }

    async fn reason(&self) -> Option<String> {
        match &*self.state.read().await {
            ServerState::Up { .. } => None,
            ServerState::Down { reason } | ServerState::GivenUp { reason } => Some(reason.clone()),
            ServerState::Disabled => Some("disabled in the config".to_string()),
        }
    }

    /// Move the connection out of the state and close it, so the child is reaped.
    async fn take_connection(&self) -> Option<Connection> {
        let mut guard = self.state.write().await;
        match std::mem::replace(
            &mut *guard,
            ServerState::Down {
                reason: "the connection was closed".to_string(),
            },
        ) {
            ServerState::Up { connection, .. } => Some(connection),
            other => {
                *guard = other;
                None
            }
        }
    }

    async fn mark_down(&self, reason: String) {
        if let Some(mut connection) = self.take_connection().await {
            // `close_with_timeout` cancels the service and awaits its cleanup — which includes the
            // transport's own close, which is what kills and reaps the child. The timeout is what
            // keeps a server that will not die from holding a tool call open.
            let _ = connection.close_with_timeout(REAP_TIMEOUT).await;
        }
        *self.state.write().await = ServerState::Down { reason };
    }

    async fn mark_given_up(&self, reason: String) {
        if let Some(mut connection) = self.take_connection().await {
            let _ = connection.close_with_timeout(REAP_TIMEOUT).await;
        }
        *self.state.write().await = ServerState::GivenUp { reason };
    }

    /// Bring the server up if it is not already, spending one restart.
    ///
    /// `Err` is the outcome a model reads; it is never a hang and never a panic.
    async fn ensure_up(&self) -> Result<(), ToolOutcome> {
        if self.is_up().await {
            return Ok(());
        }

        // One restart at a time per server. Two concurrent calls that both find it down must not
        // spawn two children; the second one re-checks under this lock and finds it up.
        let _serialised = self.restarting.lock().await;
        if self.is_up().await {
            return Ok(());
        }

        // Read the state out and drop the guard before any `await` on another lock: holding a read
        // guard across `budget.lock()` is the shape that deadlocks the moment the two orders meet.
        let given_up = match &*self.state.read().await {
            ServerState::GivenUp { reason } => Some(reason.clone()),
            _ => None,
        };
        if let Some(reason) = given_up {
            let budget = self.budget.lock().await;
            let (max, window_secs) = (budget.max(), budget.window_secs());
            drop(budget);
            return Err(ToolOutcome::failed(given_up_message(
                &self.key,
                &reason,
                max,
                window_secs,
            )));
        }

        let mut budget = self.budget.lock().await;
        if !budget.spend(Instant::now()) {
            let max = budget.max();
            let window_secs = budget.window_secs();
            drop(budget);
            let reason = self.reason().await.unwrap_or_else(|| "unknown".to_string());
            self.mark_given_up(reason.clone()).await;
            // The tail goes to the debug log, never to the model. A server that died on startup is
            // the case where its own stderr is the diagnosis — and the case where echoing it would
            // put arbitrary text in front of a model.
            self.stderr.log_tail(&self.key);
            return Err(ToolOutcome::failed(given_up_message(
                &self.key,
                &reason,
                max,
                window_secs,
            )));
        }
        let used = budget.spent(Instant::now());
        let max = budget.max();
        let window_secs = budget.window_secs();
        drop(budget);

        match conn::connect(
            &self.key,
            &self.config,
            self.secrets.as_ref(),
            self.start_timeout(),
            self.stderr.clone(),
        )
        .await
        {
            Ok(connection) => {
                let tools = match self.list_tools(&connection).await {
                    Ok(tools) => tools,
                    Err(reason) => {
                        // It answered `initialize` and then would not list its tools. That is a
                        // broken server, not a broken connection, and it is recorded as down with
                        // the server's own reason.
                        let mut connection = connection;
                        let _ = connection.close_with_timeout(REAP_TIMEOUT).await;
                        *self.state.write().await = ServerState::Down {
                            reason: reason.clone(),
                        };
                        return Err(ToolOutcome::failed(format!(
                            "{} is not running: {reason}",
                            self.describe()
                        )));
                    }
                };
                *self.state.write().await = ServerState::Up { connection, tools };
                Ok(())
            }
            Err(err) => {
                let reason = err.to_string();
                self.stderr.log_tail(&self.key);
                *self.state.write().await = ServerState::Down {
                    reason: reason.clone(),
                };
                Err(ToolOutcome::failed(format!(
                    "{} is not running: {reason}. hx will try to restart it on the next call \
                     ({used} of {max} restarts used in the last {window_secs}s).",
                    self.describe()
                )))
            }
        }
    }

    /// Ask a live connection for its tool list.
    async fn list_tools(&self, connection: &Connection) -> Result<Vec<RemoteTool>, String> {
        let listed = tokio::time::timeout(self.start_timeout(), connection.list_all_tools()).await;
        match listed {
            Err(_elapsed) => Err(format!(
                "it did not answer tools/list within {}s",
                self.start_timeout().as_secs()
            )),
            Ok(Err(err)) => Err(format!("tools/list failed: {err}")),
            Ok(Ok(tools)) => Ok(tools
                .iter()
                .map(|tool| RemoteTool::from_rmcp(&self.key, &self.namespace, tool))
                .collect()),
        }
    }

    /// The server's own name for a tool, as the last `tools/list` spelled it.
    ///
    /// The namespaced name in the catalogue is `sanitize_tool(name)` — folded to the provider
    /// charset — so it is not always the name to send back. A tool genuinely called `a b` arrives as
    /// `ns__a_b`, and calling `a_b` would be calling a tool the server never offered. Resolving here,
    /// against what the server actually advertised, is what keeps the two apart.
    async fn tool_name_for(&self, namespaced: &str) -> Option<String> {
        match &*self.state.read().await {
            ServerState::Up { tools, .. } => tools
                .iter()
                .find(|tool| tool.namespaced == namespaced)
                .map(|tool| tool.name.clone()),
            _ => None,
        }
    }

    /// Call one tool, by the namespaced name a model used. Every return is a result the model can
    /// read.
    ///
    /// `hint` is the server's own name for the tool as it was last known. It is only a fallback, for
    /// the case where the server is up and has stopped advertising the tool: the call then goes out
    /// anyway and comes back as the server's own refusal, which is a better answer than a guess made
    /// here about a tool that may have been renamed.
    async fn call(&self, namespaced: &str, hint: Option<&str>, args: Value) -> ToolOutcome {
        let disabled = matches!(*self.state.read().await, ServerState::Disabled);
        if disabled {
            return ToolOutcome::failed(format!(
                "{} is disabled in this deployment's config (`mcp_servers.{}.enabled: false`), so \
                 its tools are not available.",
                self.describe(),
                self.key
            ));
        }

        if let Err(outcome) = self.ensure_up().await {
            return outcome;
        }

        // Resolved *after* `ensure_up`, because a restart can rename a tool: the catalogue the caller
        // routed with may be one connection old.
        let tool = match self.tool_name_for(namespaced).await {
            Some(tool) => tool,
            None => match hint {
                Some(hint) => hint.to_string(),
                None => {
                    return ToolOutcome::failed(format!(
                        "{} is running but does not offer `{namespaced}` any more. It may have \
                         changed its tool list since hx last listed it.",
                        self.describe()
                    ));
                }
            },
        };
        let tool = tool.as_str();

        let arguments = match args {
            Value::Object(map) => Some(map),
            Value::Null => None,
            other => {
                return ToolOutcome::failed(format!(
                    "`{tool}` takes an object of arguments, and hx was asked to pass {}",
                    kind_of(&other)
                ));
            }
        };

        let params = match arguments {
            Some(map) => CallToolRequestParams::new(tool.to_string()).with_arguments(map),
            None => CallToolRequestParams::new(tool.to_string()),
        };

        let timeout = self.call_timeout();
        let call = async {
            let guard = self.state.read().await;
            match &*guard {
                ServerState::Up { connection, .. } => connection.call_tool(params).await,
                // The server went down between `ensure_up` and here. Not a panic and not a hang:
                // the same error a dead transport produces, which the arm below turns into a
                // readable failure and a marked-down server.
                _ => Err(ServiceError::TransportClosed),
            }
        };

        match tokio::time::timeout(timeout, call).await {
            Err(_elapsed) => ToolOutcome::failed(format!(
                "{} did not answer `{tool}` within {}s. It is still connected, so hx has left it \
                 running — a slow server and a dead one look the same from here.",
                self.describe(),
                timeout.as_secs()
            )),
            Ok(Ok(result)) => render(tool, &result),
            Ok(Err(err)) if is_fatal(&err) => {
                let reason = format!("the connection dropped during `{tool}`: {err}");
                self.mark_down(reason.clone()).await;
                self.stderr.log_tail(&self.key);
                ToolOutcome::failed(format!(
                    "{} is not running: {reason}. hx will try to restart it on the next call.",
                    self.describe()
                ))
            }
            Ok(Err(err)) => {
                // The server answered, and the answer was a refusal: a bad argument, a missing file,
                // a tool that decided not to. That is a result, not a death, and the connection
                // stays up — tearing it down would turn every argument error into a restart.
                ToolOutcome::failed(format!("{} refused `{tool}`: {err}", self.describe()))
            }
        }
    }

    async fn health(&self) -> ServerHealth {
        let (state, restarts) = {
            let guard = self.state.read().await;
            let state = match &*guard {
                ServerState::Up { connection, tools } => {
                    if connection.is_closed() || connection.is_transport_closed() {
                        HealthState::Down {
                            reason: "the connection closed".to_string(),
                            retrying: true,
                        }
                    } else {
                        HealthState::Up {
                            tools: tools.iter().map(|tool| tool.namespaced.clone()).collect(),
                        }
                    }
                }
                ServerState::Down { reason } => HealthState::Down {
                    reason: reason.clone(),
                    retrying: true,
                },
                ServerState::GivenUp { reason } => HealthState::GivenUp {
                    reason: reason.clone(),
                },
                ServerState::Disabled => HealthState::Disabled,
            };
            (state, self.budget.lock().await.spent(Instant::now()))
        };

        ServerHealth {
            server: self.key.clone(),
            namespace: self.namespace.clone(),
            transport: match self.config.transport {
                McpTransport::Stdio => "stdio",
                McpTransport::StreamableHttp => "streamable_http",
            },
            state,
            restarts,
            stderr_lines: self.stderr.lines_seen(),
        }
    }
}

/// The set of MCP servers a deployment consumes.
///
/// Built from `Config::mcp_servers` (see `hx-core`'s config module), and the one thing an agent
/// needs from `hx-mcp`: its tools, and a way to call them that cannot hang.
pub struct McpHost {
    servers: IndexMap<String, Arc<ServerHandle>>,
    /// The tool catalogue, refreshed whenever a server reconnects.
    ///
    /// A `std::sync::RwLock` rather than an async one because it is read from synchronous code —
    /// `ToolRegistry::register`, a UI listing tools — and never held across an `await`.
    catalogue: RwLock<Vec<RemoteTool>>,
}

impl McpHost {
    /// Validate the config, then bring up every enabled server.
    ///
    /// A config error fails here (the operator's typo, and the only class of problem that will not
    /// fix itself). A *connection* failure does not: it is recorded, reported by [`Self::health`],
    /// and surfaces to a model as a readable tool result. A daemon that refused to start because a
    /// third-party `npx` package was down would be a daemon nobody could use.
    pub async fn from_config(
        servers: &IndexMap<String, McpServerConfig>,
        secrets: Option<Arc<SecretStores>>,
    ) -> HxResult<Self> {
        let mut handles: IndexMap<String, Arc<ServerHandle>> = IndexMap::new();

        // Collision detection before anything is spawned. Sanitising a namespace is lossy (see
        // `crate::names`), so two config keys can fold onto one namespace — and letting the second
        // server quietly take over the first one's names is precisely the failure namespacing exists
        // to prevent.
        let mut by_namespace: HashMap<String, String> = HashMap::new();
        for (key, config) in servers {
            if !config.enabled {
                continue;
            }
            let namespace = names::sanitize(config.namespace(key));
            if let Some(existing) = by_namespace.insert(namespace.clone(), key.clone()) {
                return Err(HxError::Config(format!(
                    "mcp servers {existing:?} and {key:?} both publish their tools under the \
                     namespace {namespace:?}, so one would silently shadow the other. Give one of \
                     them a `namespace:` of its own."
                )));
            }
        }

        for (key, config) in servers {
            config.validate(key)?;

            let namespace = names::sanitize(config.namespace(key));
            let handle = Arc::new(ServerHandle {
                key: key.clone(),
                namespace,
                config: config.clone(),
                secrets: secrets.clone(),
                stderr: StderrTail::default(),
                state: tokio::sync::RwLock::new(if config.enabled {
                    ServerState::Down {
                        reason: "not started yet".to_string(),
                    }
                } else {
                    ServerState::Disabled
                }),
                budget: tokio::sync::Mutex::new(RestartBudget::new(
                    config.max_restarts,
                    Duration::from_secs(config.restart_window_secs.max(1)),
                )),
                restarting: tokio::sync::Mutex::new(()),
            });
            handles.insert(key.clone(), handle);
        }

        let host = Self {
            servers: handles,
            catalogue: RwLock::new(Vec::new()),
        };

        // Eagerly, and deliberately: an operator wants to know at startup which servers are broken,
        // rather than discovering it in the middle of a run. Each attempt is bounded by that
        // server's own `start_timeout_secs`, and the failures are recorded rather than raised.
        for handle in host.servers.values() {
            if matches!(*handle.state.read().await, ServerState::Disabled) {
                continue;
            }
            if let Err(outcome) = handle.ensure_up().await {
                tracing::warn!(
                    server = handle.key,
                    "mcp server did not start: {}",
                    outcome.content
                );
            }
        }
        host.refresh_catalogue().await;

        Ok(host)
    }

    /// An empty host. Useful for a deployment with no MCP servers and for tests that only want the
    /// config plumbing.
    pub fn empty() -> Self {
        Self {
            servers: IndexMap::new(),
            catalogue: RwLock::new(Vec::new()),
        }
    }

    /// The config of a server, by key. Panics only for a key that came from this host's own
    /// catalogue, which is a programming error rather than a runtime one.
    pub(crate) fn config_of(&self, server: &str) -> &McpServerConfig {
        &self
            .servers
            .get(server)
            .unwrap_or_else(|| panic!("no mcp server {server:?} in this host"))
            .config
    }

    /// Every tool every up server offers, in config order.
    pub fn list_tools(&self) -> Vec<RemoteTool> {
        match self.catalogue.read() {
            Ok(catalogue) => catalogue.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The namespaced names, for an error message or a UI.
    pub fn tool_names(&self) -> Vec<String> {
        self.list_tools()
            .into_iter()
            .map(|tool| tool.namespaced)
            .collect()
    }

    /// A callable form of every tool, ready to register.
    ///
    /// Returned rather than registered so the caller decides where they go: an agent's registry, a
    /// subagent's smaller one, or a test's. Each tool holds the host, not a connection — see
    /// [`McpTool::new`].
    pub fn tools(self: &Arc<Self>) -> Vec<Arc<dyn Tool>> {
        self.list_tools()
            .iter()
            .map(|remote| Arc::new(McpTool::new(self.clone(), remote)) as Arc<dyn Tool>)
            .collect()
    }

    /// Register every tool into a registry, returning the names it added.
    ///
    /// A name already in the registry is *replaced*, which is `ToolRegistry`'s documented behaviour
    /// and the right one here: an MCP tool that shadows a built-in is a config decision the operator
    /// made by naming a server after it.
    pub fn register_into(self: &Arc<Self>, registry: &mut ToolRegistry) -> Vec<String> {
        let tools = self.tools();
        let names: Vec<String> = tools.iter().map(|tool| tool.name().to_string()).collect();
        for tool in tools {
            registry.register(tool);
        }
        names
    }

    /// Call a tool by its namespaced name.
    ///
    /// The one entry point that matters, and the one that holds the property in the module doc: a
    /// down server, a dead child, a wedged connection and an unknown tool all come back as a
    /// [`ToolOutcome`] a model can read. This never returns an error and never waits past the
    /// server's `call_timeout_secs`.
    ///
    /// Note that routing does *not* require the server to be up. A tool registered while a server was
    /// healthy has to keep routing to that server after it died, or the restart-on-next-call design
    /// would never fire: the catalogue would have shrunk to nothing and every call would read as
    /// "no such tool". Routing is by namespace, which is unique by construction (see
    /// [`Self::from_config`]'s collision check).
    pub async fn call(&self, name: &str, args: Value) -> ToolOutcome {
        let Some((handle, hint)) = self.route(name) else {
            let known = self.tool_names();
            return ToolOutcome::failed(if known.is_empty() {
                format!(
                    "no MCP tool named `{name}`: this deployment has no MCP tools available \
                     (configure `mcp_servers` and check `hx mcp` for why each one is down)."
                )
            } else {
                format!(
                    "no MCP tool named `{name}`. Available MCP tools: {}",
                    known.join(", ")
                )
            });
        };

        let outcome = handle.call(name, hint.as_deref(), args).await;
        // The catalogue follows the connection rather than the startup moment: a call that failed
        // because the server was down may have brought it back up, and one that succeeded may have
        // brought back a server whose tool list has changed.
        self.refresh_catalogue().await;
        outcome
    }

    /// The handle for a namespaced tool name, and the server's own name for it when it is known.
    ///
    /// The catalogue is consulted first, because it carries the server's exact spelling of the tool.
    /// Falling back to the namespace is what keeps a call routing after the server has gone down —
    /// and the exact spelling is recovered in `ServerHandle::call` once the server is back up.
    fn route(&self, name: &str) -> Option<(Arc<ServerHandle>, Option<String>)> {
        {
            let catalogue = match self.catalogue.read() {
                Ok(catalogue) => catalogue,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(remote) = catalogue.iter().find(|tool| tool.namespaced == name) {
                if let Some(handle) = self.servers.get(&remote.server) {
                    return Some((handle.clone(), Some(remote.name.clone())));
                }
            }
        }

        let (namespace, _tool) = names::split(name)?;
        let handle = self
            .servers
            .values()
            .find(|handle| handle.namespace == namespace)?;
        Some((handle.clone(), None))
    }

    /// Rebuild the catalogue from what the servers currently advertise.
    ///
    /// Called after a call, so a server that restarted with a different tool set is described by what
    /// it says now. A server that is down contributes nothing — which is the honest answer, and the
    /// reason a restart that fails does not leave a stale tool list behind. Routing survives it
    /// because [`Self::route`] falls back to the namespace.
    async fn refresh_catalogue(&self) {
        let mut catalogue = Vec::new();
        for handle in self.servers.values() {
            let guard = handle.state.read().await;
            if let ServerState::Up { tools, .. } = &*guard {
                // The tools are kept whole — descriptions and schemas included — because a
                // description is what a model prices a tool on, and because the server's own spelling
                // of the name is what a call has to send back.
                catalogue.extend(tools.iter().cloned());
            }
        }
        match self.catalogue.write() {
            Ok(mut current) => *current = catalogue,
            Err(poisoned) => *poisoned.into_inner() = catalogue,
        }
    }

    /// What `hx` knows about every server, without touching the network.
    pub async fn status(&self) -> Vec<ServerHealth> {
        let mut report = Vec::with_capacity(self.servers.len());
        for handle in self.servers.values() {
            report.push(handle.health().await);
        }
        report
    }

    /// A real health check: liveness *and* a `tools/list` round trip.
    ///
    /// `tools/list` rather than MCP's `ping`, because `rmcp`'s client peer does not expose `ping`
    /// and because listing is the more useful probe anyway — a server that answers `ping` and cannot
    /// list its tools is not healthy. Bounded by each server's `call_timeout_secs`. A server that
    /// fails the probe is marked down, so the next call restarts it (subject to the budget).
    pub async fn health(&self) -> Vec<ServerHealth> {
        for handle in self.servers.values() {
            if !handle.is_up().await {
                continue;
            }
            let connection = {
                let guard = handle.state.read().await;
                match &*guard {
                    ServerState::Up { connection, .. } => connection.peer().clone(),
                    _ => continue,
                }
            };
            let probe = tokio::time::timeout(handle.call_timeout(), connection.list_all_tools());
            match probe.await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => {
                    handle
                        .mark_down(format!("tools/list failed during a health check: {err}"))
                        .await;
                }
                Err(_elapsed) => {
                    handle
                        .mark_down(format!(
                            "it did not answer tools/list within {}s",
                            handle.call_timeout().as_secs()
                        ))
                        .await;
                }
            }
        }
        self.refresh_catalogue().await;
        self.status().await
    }

    /// Close every connection, reaping every child.
    ///
    /// Bounded per server by [`REAP_TIMEOUT`], and the transport's own drop guard is the backstop, so
    /// a server that ignores a close still does not keep the process alive. The close is *awaited*
    /// rather than left to a drop: `close_with_timeout` is what cancels the service and waits for the
    /// transport's cleanup, which is the step that kills and reaps the child. Dropping the connection
    /// instead detaches that cleanup, which is how a host shutdown leaves an orphan.
    pub async fn shutdown(&self) {
        for handle in self.servers.values() {
            if let Some(mut connection) = handle.take_connection().await {
                let _ = connection.close_with_timeout(REAP_TIMEOUT).await;
            }
        }
    }

    /// How many servers are configured, including disabled ones.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

/// Whether a service error means the connection is gone, as opposed to the server answering.
///
/// The distinction is the whole of "a server that dies is detected": these are the errors that make
/// `hx` mark a server down, reap it, and offer a restart — while an argument error or a tool's own
/// refusal leaves the connection alone.
fn is_fatal(err: &ServiceError) -> bool {
    matches!(
        err,
        ServiceError::TransportClosed
            | ServiceError::TransportSend(_)
            | ServiceError::Cancelled { .. }
    )
}

/// A name for a JSON value's kind, for an argument error a person reads.
fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Turn a server's answer into the text a model reads.
///
/// The server's `is_error` becomes [`ToolOutcome::failed`], because that is exactly what it means
/// and because a model that sees `ok: false` adapts while a model that sees a success flag on an
/// error message does not. Content kinds `hx` does not render are named rather than dropped
/// silently, so a model knows a picture or a resource was there and it is not seeing it.
fn render(tool: &str, result: &CallToolResult) -> ToolOutcome {
    let mut parts: Vec<String> = Vec::new();
    for block in &result.content {
        parts.push(render_block(block));
    }

    if parts.iter().all(|part| part.trim().is_empty()) {
        parts.clear();
        // Structured output is the fallback when there is no prose: for a tool that answers with a
        // JSON object, this is the answer, and dropping it would leave the model with nothing.
        if let Some(structured) = &result.structured_content {
            parts.push(
                serde_json::to_string_pretty(structured).unwrap_or_else(|_| structured.to_string()),
            );
        }
    }

    let text = if parts.is_empty() {
        format!("the server returned no content for `{tool}`")
    } else {
        parts.join("\n")
    };

    if result.is_error.unwrap_or(false) {
        ToolOutcome::failed(text)
    } else {
        ToolOutcome::ok(text)
    }
}

fn render_block(block: &ContentBlock) -> String {
    match block {
        ContentBlock::Text(text) => text.text.clone(),
        ContentBlock::Image(image) => format!(
            "[the server returned an image ({}) and hx does not render image content]",
            image.mime_type
        ),
        ContentBlock::Audio(audio) => format!(
            "[the server returned audio ({}) and hx does not render audio content]",
            audio.mime_type
        ),
        ContentBlock::Resource(_) => {
            "[the server returned an embedded resource, which hx does not render]".to_string()
        }
        ContentBlock::ResourceLink(link) => {
            format!("[the server linked the resource {}]", link.uri)
        }
        // `ContentBlock` is `#[non_exhaustive]`: the spec adds kinds, and refusing to parse a
        // response because a future server used a newer one would take a run down for no reason.
        _ => "[the server returned a content kind hx does not render]".to_string(),
    }
}

/// The message a call gets when a server is down and out of restart budget.
///
/// Written for a model *and* for the operator reading the transcript afterwards: it says what is
/// wrong, how `hx` got there, and the two ways out. It never suggests retrying, because retrying is
/// what `hx` has already decided to stop doing.
fn given_up_message(server: &str, reason: &str, max: u32, window_secs: u64) -> String {
    format!(
        "mcp server `{server}` is down and hx has stopped restarting it: {reason}. It failed {max} \
         times in the last {window_secs}s, which is the configured budget \
         (`mcp_servers.{server}.max_restarts`). Fix the server, raise the budget, or set \
         `enabled: false` for it."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of `RestartBudget` taking `now`: a policy about time that can only be tested
    /// by waiting is a policy whose tests get deleted. Every assertion here is a count.
    #[test]
    fn the_budget_refuses_a_restart_once_it_is_spent_inside_the_window() {
        let mut budget = RestartBudget::new(2, Duration::from_secs(60));
        let now = Instant::now();

        assert!(budget.spend(now), "the first restart is allowed");
        assert!(budget.spend(now), "the second is allowed");
        assert_eq!(budget.spent(now), 2);
        assert!(
            !budget.spend(now),
            "the third is refused, and `false` is what turns 'respawn' into 'stop'"
        );
        assert_eq!(
            budget.spent(now),
            2,
            "a refused restart is not recorded — otherwise the count would grow without bound"
        );
    }

    /// A plain counter would make a server that crashes once a week permanently dead after three
    /// weeks. A window is what keeps "three failures in five minutes" apart from "three failures in
    /// three weeks".
    #[test]
    fn a_restart_that_has_aged_out_of_the_window_does_not_count_against_the_budget() {
        let window = Duration::from_secs(300);
        let mut budget = RestartBudget::new(1, window);
        let start = Instant::now();

        assert!(budget.spend(start));
        assert!(!budget.spend(start + window / 2), "still inside the window");

        // One second past the window: the earlier failure is no longer evidence about this server.
        let later = start + window + Duration::from_secs(1);
        assert_eq!(budget.spent(later), 0, "the aged-out restart is forgotten");
        assert!(
            budget.spend(later),
            "a server with a bad day three weeks ago gets its budget back"
        );
    }

    /// The deque is pruned on `spend`, not only on `spent`, so a long-lived server that restarts
    /// occasionally forever cannot grow this without bound.
    #[test]
    fn the_record_of_spent_restarts_cannot_grow_without_bound() {
        let window = Duration::from_secs(10);
        let mut budget = RestartBudget::new(1, window);
        let start = Instant::now();

        for step in 0..1_000u32 {
            let now = start + window * (step + 1);
            assert!(
                budget.spend(now),
                "one restart per window is always allowed"
            );
        }
        assert_eq!(
            budget.spent(start + window * 1_001),
            0,
            "1,000 restarts over 1,000 windows leave nothing behind"
        );
    }

    #[test]
    fn the_ceiling_and_the_window_are_reported_for_a_message_a_person_reads() {
        let budget = RestartBudget::new(3, Duration::from_secs(300));
        assert_eq!(budget.max(), 3);
        assert_eq!(budget.window_secs(), 300);
    }

    /// The message is the only thing a model sees when a server has been given up on, so it has to
    /// name the server, the reason, the budget and the way out — and it must not invite a retry,
    /// because retrying is the thing that has just been decided against.
    #[test]
    fn the_given_up_message_names_the_server_the_reason_and_the_two_ways_out() {
        let message = given_up_message("files", "could not start `npx`: No such file", 3, 300);

        for expected in [
            "files",
            "could not start `npx`",
            "3",
            "300",
            "max_restarts",
            "enabled: false",
        ] {
            assert!(
                message.contains(expected),
                "{expected:?} missing from: {message}"
            );
        }
        assert!(
            !message.to_lowercase().contains("try again"),
            "a message that suggests retrying contradicts the state it reports: {message}"
        );
    }

    #[test]
    fn a_json_value_is_described_by_its_kind_for_an_argument_error() {
        // The argument error a model reads has to say what it *sent*, not just that it was wrong.
        assert_eq!(kind_of(&Value::Null), "null");
        assert_eq!(kind_of(&Value::String("x".into())), "a string");
        assert_eq!(kind_of(&Value::Array(vec![])), "an array");
        assert_eq!(kind_of(&Value::Object(Default::default())), "an object");
    }
}
