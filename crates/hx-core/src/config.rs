//! Configuration model.
//!
//! Parsing lives here (pure); file reading lives in `hxd`, so this crate stays IO-free.
//!
//! Note the deliberate `deny_unknown_fields` on every struct: a typo'd key is a hard error
//! rather than a silently-ignored setting. That failure mode ("I set `max_turn` and nothing
//! happened") is worth more than the flexibility of tolerating extras.

use crate::approval::ApprovalPolicy;
use crate::error::{HxError, Result};
use crate::ids::{CredentialId, HostId, ProviderId};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Top level
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub providers: IndexMap<String, ProviderConfig>,
    #[serde(default)]
    pub pools: IndexMap<String, PoolConfig>,
    /// Maps an agent role (`builder`, `scout`, `reviewer`) to a pool name.
    #[serde(default)]
    pub roles: IndexMap<String, String>,
    #[serde(default)]
    pub hosts: IndexMap<String, HostConfig>,
    #[serde(default)]
    pub sandbox_profiles: IndexMap<String, SandboxProfile>,
    #[serde(default)]
    pub connectors: IndexMap<String, ConnectorConfig>,
    #[serde(default)]
    pub search: SearchConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub terminal: TerminalConfig,
}

/// The server-side terminal: what a client's `POST /v1/terminals` runs when it does not say.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TerminalConfig {
    /// The shell a new terminal starts.
    ///
    /// Configurable rather than hardcoded because the right answer depends on the machine: a
    /// daemon on a minimal image has no `bash`, and one on a developer host usually wants it.
    #[serde(default = "default_terminal_shell")]
    pub shell: String,
}

fn default_terminal_shell() -> String {
    // `$SHELL` if the daemon inherited one, else `/bin/sh`, which POSIX guarantees exists. Reading
    // the environment here rather than at spawn keeps the default visible in a dumped config.
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            shell: default_terminal_shell(),
        }
    }
}

impl Config {
    /// Parse a configuration, folding the shipped approval floor into whatever it says.
    ///
    /// The fold happens *here*, at the boundary between a file and a policy, rather than in the policy's
    /// `Deserialize`: a config is the only thing that inherits the floor, and doing it in `Deserialize`
    /// would hand it to every in-code policy that happens to round-trip through YAML. See
    /// [`ApprovalPolicy::inherit_denials`] for why the floor is layered rather than defaulted.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let mut config: Self = serde_yaml::from_str(yaml)?;
        config.agent.approval = config.agent.approval.with_floor();
        Ok(config)
    }

    /// Resolve the pool a role should use, following `inherits` chains.
    ///
    /// Guards against cycles and dangling references, because a config loop here would
    /// otherwise hang the daemon at startup.
    pub fn pool_for_role(&self, role: &str) -> Result<&PoolConfig> {
        let name = self
            .roles
            .get(role)
            .ok_or_else(|| HxError::Config(format!("no pool mapped for role {role:?}")))?;
        self.resolve_pool(name)
    }

    pub fn resolve_pool(&self, name: &str) -> Result<&PoolConfig> {
        let mut seen: Vec<&str> = Vec::new();
        let mut current = name;

        loop {
            if seen.contains(&current) {
                return Err(HxError::Config(format!(
                    "pool inheritance cycle: {} -> {current}",
                    seen.join(" -> ")
                )));
            }
            seen.push(current);

            let pool = self
                .pools
                .get(current)
                .ok_or_else(|| HxError::Config(format!("pool {current:?} not found")))?;

            match &pool.inherits {
                Some(parent) => current = parent.as_str(),
                None => return Ok(pool),
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default = "default_socket")]
    pub socket: String,
    #[serde(default = "default_http_addr")]
    pub http_addr: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default)]
    pub log_json: bool,
    /// Environment variable holding the key the audit chain is written with.
    ///
    /// A variable name rather than the secret itself, so the key does not sit in a config file that
    /// is committed, copied between machines, or read by anything that can read the repo. Empty or
    /// unset leaves the chain unkeyed, which is reported rather than assumed: an unkeyed chain still
    /// catches an inconsistent edit and cannot catch a rewrite.
    #[serde(default = "default_audit_key_env")]
    pub audit_key_env: String,
}

fn default_audit_key_env() -> String {
    "HX_AUDIT_KEY".to_string()
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            http_addr: default_http_addr(),
            data_dir: default_data_dir(),
            log_json: false,
            audit_key_env: default_audit_key_env(),
        }
    }
}

fn default_socket() -> String {
    "unix://$XDG_RUNTIME_DIR/hx/hxd.sock".into()
}
fn default_http_addr() -> String {
    "127.0.0.1:8787".into()
}
fn default_data_dir() -> String {
    "~/.hx".into()
}

// ---------------------------------------------------------------------------
// Providers and pools
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    /// Any OpenAI-compatible `/v1/chat/completions` endpoint — OpenRouter, DeepSeek, Groq,
    /// Together, vLLM, llama.cpp, litellm, and most resellers.
    Openai,
    Anthropic,
    Google,
    Ollama,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default)]
    pub credentials: Vec<CredentialConfig>,
    #[serde(default)]
    pub routing: Strategy,
    /// Optional model list for `cheapest_capable` selection and for validating routes.
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<Price>,
    /// Lower sorts first when a pool uses `priority`.
    #[serde(default)]
    pub priority: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    pub id: CredentialId,
    /// A `vault:` reference. Credentials are never written inline in config.
    pub secret: String,
    #[serde(default)]
    pub limits: Limits,
    /// Relative weight for `weighted` routing.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
}

/// Limits, at credential level or pool level. `None` means unbounded in that dimension.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Requests per minute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpm: Option<u32>,
    /// Tokens per minute — reserved before send, reconciled after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm: Option<u64>,
    /// Requests per day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpd: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrent: Option<u32>,
}

impl Limits {
    pub fn is_unbounded(&self) -> bool {
        self.rpm.is_none()
            && self.tpm.is_none()
            && self.rpd.is_none()
            && self.daily_usd.is_none()
            && self.concurrent.is_none()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Weighted,
    RoundRobin,
    #[default]
    LeastLoaded,
    Priority,
    /// Pick the cheapest member that can serve the request at all.
    CheapestCapable,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    /// `provider/model-glob` entries, e.g. `anthropic-main/claude-*`.
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub strategy: Strategy,
    /// Pool-level ceiling, applied *in addition to* each credential's own limits.
    /// This is how a cron job is stopped from eating your interactive quota.
    #[serde(default)]
    pub limits: Limits,
    /// Inherit members and limits from another pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherits: Option<String>,
}

/// A parsed `provider/model` reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    pub provider: ProviderId,
    pub model: String,
}

impl ModelRef {
    /// Parse `"anthropic-main/claude-*"`. The model part is required and may contain globs.
    pub fn parse(s: &str) -> Result<Self> {
        let (provider, model) = s.split_once('/').ok_or_else(|| {
            HxError::Config(format!(
                "invalid model reference {s:?}: expected \"provider/model\""
            ))
        })?;
        if provider.is_empty() || model.is_empty() {
            return Err(HxError::Config(format!(
                "invalid model reference {s:?}: provider and model must both be non-empty"
            )));
        }
        Ok(Self {
            provider: ProviderId::from_raw(provider),
            model: model.to_string(),
        })
    }

    pub fn matches(&self, provider: &ProviderId, model: &str) -> bool {
        &self.provider == provider && glob_match(&self.model, model)
    }
}

impl std::fmt::Display for ModelRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.provider, self.model)
    }
}

/// Minimal glob: `*` matches any run of characters, `?` exactly one.
///
/// Re-exported from [`crate::approval`], where the same matcher is used for approval [`Rule`]s.
/// One implementation, so a model pattern and an approval rule can never disagree about what
/// `claude-*` means.
///
/// [`Rule`]: crate::approval::Rule
pub use crate::approval::glob_match;

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostKind {
    Local,
    Ssh,
    /// Fallback for Windows hosts that cannot run an SSH server.
    Winrm,
}

/// How a host authenticates.
///
/// Internally tagged (`kind:`) rather than serde's default external tagging, because
/// `serde_yaml` reads externally-tagged enums as YAML `!tags`, which nobody writing a config
/// file expects. This keeps the YAML plain and predictable:
/// `auth: { kind: key, secret_ref: "vault:ssh/buildbox" }`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethod {
    /// Delegate to a running ssh-agent. Nothing secret in the config at all.
    #[default]
    Agent,
    Key {
        secret_ref: String,
    },
    Password {
        secret_ref: String,
    },
    /// Whatever the platform default is (e.g. current Windows credentials).
    Platform,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub kind: HostKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default)]
    pub auth: AuthMethod,
    /// Reach this host through another registered host (bastion / jump box).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<HostId>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Path of the compiled `hx-egress-proxy` binary **on this host**, for a remote sandbox
    /// created here with a non-empty egress allowlist.
    ///
    /// It has to be named per host, because the binary must exist on the *far* machine and the
    /// daemon has no way to know where a deployment put it there: the local `default_proxy_bin`
    /// rule (sibling of the running executable) describes the near host's filesystem, which is not
    /// the far host's. Guessing would fail at the worst moment — the first sandbox that asked for
    /// an allowlist — so this is left unset rather than defaulted, and a spec that needs it without
    /// it is **refused**, with a message naming this key.
    ///
    /// `#[serde(default)]` so every existing config still parses: this key is additive, and a
    /// deployment that never runs a remote egress sandbox never needs to write it. See
    /// `AppState::build_remote_manager` for the wiring and
    /// `RemoteSandboxRuntime::with_proxy_bin` for what it means to the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_proxy_bin: Option<String>,
}

/// A `vault:<name>` reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub store: String,
    pub name: String,
}

impl SecretRef {
    pub fn parse(s: &str) -> Result<Self> {
        let (store, name) = s.split_once(':').ok_or_else(|| {
            HxError::Config(format!(
                "invalid secret reference {s:?}: expected \"store:name\" (e.g. vault:anthropic/key1)"
            ))
        })?;
        if store.is_empty() || name.is_empty() {
            return Err(HxError::Config(format!(
                "invalid secret reference {s:?}: store and name must both be non-empty"
            )));
        }
        Ok(Self {
            store: store.to_string(),
            name: name.to_string(),
        })
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.store, self.name)
    }
}

// ---------------------------------------------------------------------------
// Sandboxes
// ---------------------------------------------------------------------------

/// Isolation tiers. See `ARCHITECTURE.md` §3.2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolationLevel {
    /// Rootless container + namespaces + cgroup limits. Fast, for trusted code.
    L1,
    /// gVisor (`runsc`): syscall interception. The default for agent-authored code.
    #[default]
    L2,
    /// Firecracker / Kata microVM. Requires KVM.
    L3,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxProfile {
    #[serde(default)]
    pub isolation: IsolationLevel,
    #[serde(default = "default_image")]
    pub image: String,
    #[serde(default = "default_cpus")]
    pub cpus: f64,
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,
    /// Workspace volume quota. Enforced at the filesystem layer, not by asking nicely.
    #[serde(default = "default_workspace_mb")]
    pub workspace_mb: u64,
    #[serde(default = "default_pids")]
    pub pids_max: u64,
    /// Wall-clock lifetime. Teardown does not depend on the agent's cooperation.
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
    /// Egress allowlist. Empty + `network: false` means no network at all.
    #[serde(default)]
    pub egress: Vec<String>,
    #[serde(default)]
    pub network: bool,
    #[serde(default = "default_true")]
    pub readonly_rootfs: bool,
    /// The remote host this sandbox runs on. `None` (or absent) means the local daemon — today's
    /// behaviour, unchanged. `Some(id)` names a host from `hosts:`; the daemon resolves it through
    /// its `Host` and creates the sandbox there via [`RemoteSandboxRuntime`]. `#[serde(default)]`
    /// keeps every existing profile (which never had the key) parsing unchanged.
    #[serde(default)]
    pub host: Option<String>,
}

impl Default for SandboxProfile {
    fn default() -> Self {
        Self {
            isolation: IsolationLevel::default(),
            image: default_image(),
            cpus: default_cpus(),
            memory_mb: default_memory_mb(),
            workspace_mb: default_workspace_mb(),
            pids_max: default_pids(),
            ttl_secs: default_ttl(),
            egress: Vec::new(),
            network: false,
            readonly_rootfs: true,
            host: None,
        }
    }
}

fn default_image() -> String {
    "docker.io/library/debian:stable-slim".into()
}
fn default_cpus() -> f64 {
    2.0
}
fn default_memory_mb() -> u64 {
    2048
}
fn default_workspace_mb() -> u64 {
    4096
}
fn default_pids() -> u64 {
    512
}
fn default_ttl() -> u64 {
    1800
}
fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Connectors, search, agent
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectorKind {
    Telegram,
    Discord,
    Slack,
    Matrix,
    Email,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    pub kind: ConnectorKind,
    /// `vault:` reference to the bot token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Allowlist of platform user/chat ids. Empty means deny everyone (fail closed).
    #[serde(default)]
    pub allow_from: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchConfig {
    /// Backend ids in preference order: `searxng`, `ddg`, `mojeek`, `marginalia`, `brave`,
    /// `google_cse`, `wikipedia`.
    #[serde(default = "default_backends")]
    pub backends: Vec<String>,
    /// How many backends to query in parallel per search.
    #[serde(default = "default_fanout")]
    pub fanout: usize,
    /// How many results to return after fusion.
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub searxng_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brave_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_cse_cx: Option<String>,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            backends: default_backends(),
            fanout: default_fanout(),
            top_k: default_top_k(),
            searxng_url: None,
            brave_key: None,
            google_cse_cx: None,
            cache_ttl_secs: default_cache_ttl(),
        }
    }
}

fn default_backends() -> Vec<String> {
    vec![
        "searxng".into(),
        "ddg".into(),
        "mojeek".into(),
        "marginalia".into(),
        "wikipedia".into(),
    ]
}
fn default_fanout() -> usize {
    4
}
fn default_top_k() -> usize {
    10
}
fn default_cache_ttl() -> u64 {
    3600
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
    /// Compact the transcript once it exceeds this estimate.
    #[serde(default = "default_compact_at")]
    pub compact_at_tokens: usize,
    /// The baseline answer to "how often should this stop and ask?".
    ///
    /// Per-chat sessions override this at runtime ([`crate::approval::ApprovalSession::set_level`]);
    /// this value is the starting point for a new chat.
    #[serde(default = "deployment_approval")]
    pub approval: ApprovalPolicy,
    #[serde(default = "default_concurrent")]
    pub max_concurrent_subagents: u32,
    #[serde(default = "default_pool_name")]
    pub default_pool: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_turns: default_max_turns(),
            compact_at_tokens: default_compact_at(),
            // `deployment_approval()`, not `ApprovalPolicy::default()`: `Config`'s `agent` field is
            // `#[serde(default)]`, so this is what a config that mentions no policy at all gets — and
            // "the config was silent" must not be the one shape that loses the catastrophe set. The
            // blank policy stays what a *library caller* builds in code.
            approval: deployment_approval(),
            max_concurrent_subagents: default_concurrent(),
            default_pool: default_pool_name(),
        }
    }
}

fn default_max_turns() -> u32 {
    90
}
fn default_compact_at() -> usize {
    120_000
}
fn default_concurrent() -> u32 {
    3
}
fn default_pool_name() -> String {
    "interactive".into()
}

/// The approval policy a *configuration* starts from.
///
/// Not `ApprovalPolicy::default()`: that one is blank so library callers and tests are not handed an
/// opinion. A deployment gets the floor — `balanced`, with the catastrophe set denied — and can still
/// delete a rule it disagrees with, in writing, which is the review.
fn deployment_approval() -> ApprovalPolicy {
    ApprovalPolicy::deployment_default().with_floor()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pool design from `ARCHITECTURE.md` §3.4, parsed as-is. If this test breaks, the
    /// documented config surface and the real one have diverged.
    const EXAMPLE: &str = r#"
daemon:
  http_addr: "127.0.0.1:8787"
providers:
  anthropic-main:
    kind: anthropic
    credentials:
      - id: a1
        secret: "vault:anthropic/key1"
        limits: { rpm: 50, tpm: 40000, rpd: 1000, daily_usd: 25 }
      - id: a2
        secret: "vault:anthropic/key2"
        limits: { rpm: 50, tpm: 40000 }
    routing: least_loaded
pools:
  interactive:
    members: ["anthropic-main/claude-*", "openai-main/gpt-*"]
    strategy: priority
    limits: { tpm: 80000, concurrent: 4 }
  background:
    members: ["local/qwen3-32b"]
    strategy: cheapest_capable
    limits: { daily_usd: 5 }
  scout:
    inherits: background
    limits: { daily_usd: 2 }
roles:
  builder: interactive
  scout: scout
  reviewer: interactive
hosts:
  buildbox:
    kind: ssh
    address: "10.0.0.5"
    user: "yoav"
    auth: { kind: key, secret_ref: "vault:ssh/buildbox" }
sandbox_profiles:
  untrusted:
    isolation: l2
    cpus: 4.0
    memory_mb: 8192
    egress: ["*.crates.io", "github.com"]
connectors:
  main-tg:
    kind: telegram
    token: "vault:telegram/bot"
    allow_from: ["12345"]
"#;

    #[test]
    fn documented_config_parses() {
        let c = Config::from_yaml(EXAMPLE).expect("example config must parse");
        assert_eq!(c.providers.len(), 1);
        assert_eq!(c.pools.len(), 3);

        let p = &c.providers["anthropic-main"];
        assert_eq!(p.kind, ProviderKind::Anthropic);
        assert_eq!(p.routing, Strategy::LeastLoaded);
        assert_eq!(p.credentials.len(), 2);
        assert_eq!(p.credentials[0].limits.rpm, Some(50));
        assert_eq!(p.credentials[0].limits.daily_usd, Some(25.0));
        assert!(p.credentials[1].limits.daily_usd.is_none());
    }

    #[test]
    fn role_resolves_through_inheritance() {
        let c = Config::from_yaml(EXAMPLE).unwrap();
        let scout = c.pool_for_role("scout").unwrap();
        // `scout` inherits `background`, so resolving yields the parent's members.
        assert_eq!(scout.strategy, Strategy::CheapestCapable);
        assert_eq!(scout.members, vec!["local/qwen3-32b"]);
        assert_eq!(scout.limits.daily_usd, Some(5.0));
    }

    #[test]
    fn builder_role_resolves_directly() {
        let c = Config::from_yaml(EXAMPLE).unwrap();
        assert_eq!(
            c.pool_for_role("builder").unwrap().strategy,
            Strategy::Priority
        );
    }

    #[test]
    fn unknown_role_is_an_error() {
        let c = Config::from_yaml(EXAMPLE).unwrap();
        assert!(c.pool_for_role("nope").is_err());
    }

    #[test]
    fn inheritance_cycle_is_detected_not_hung() {
        let yaml = r#"
pools:
  a: { inherits: b }
  b: { inherits: a }
roles:
  x: a
"#;
        let c = Config::from_yaml(yaml).unwrap();
        let err = c.pool_for_role("x").unwrap_err();
        assert!(err.to_string().contains("cycle"), "got: {err}");
    }

    #[test]
    fn unknown_key_in_config_is_rejected() {
        let yaml = "agent:\n  max_turn: 10\n"; // typo for max_turns
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("max_turn"), "got: {err}");
    }

    #[test]
    fn defaults_apply_when_sections_are_absent() {
        let c = Config::from_yaml("{}").unwrap();
        assert_eq!(c.agent.max_turns, 90);
        assert_eq!(
            c.agent.approval.level,
            crate::approval::AutonomyLevel::Balanced
        );
        assert_eq!(c.sandbox_profiles.len(), 0);
        assert!(!c.search.backends.is_empty());
        assert_eq!(c.daemon.http_addr, "127.0.0.1:8787");
    }

    #[test]
    fn sandbox_profile_defaults_are_conservative() {
        let p = SandboxProfile::default();
        assert_eq!(
            p.isolation,
            IsolationLevel::L2,
            "agent code should default to gVisor"
        );
        assert!(!p.network, "network must default off");
        assert!(p.readonly_rootfs);
        assert_eq!(p.ttl_secs, 1800);
    }

    #[test]
    fn a_sandbox_profile_without_a_host_key_parses_as_local_and_one_with_it_goes_remote() {
        // The `host` field is additive and optional: every existing profile that never had the key must
        // keep parsing (now as `None`, the local daemon), and a profile that adds it must round-trip to
        // `Some(id)`. Without the `#[serde(default)]`, adding the field would have broken every existing
        // config, which is exactly what this test guards.
        let yaml = r#"
sandbox_profiles:
  local_dev:
    isolation: l2
  remote_build:
    host: buildbox
"#;
        let c = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            c.sandbox_profiles["local_dev"].host, None,
            "a profile without `host` stays local"
        );
        assert_eq!(
            c.sandbox_profiles["remote_build"].host.as_deref(),
            Some("buildbox"),
            "a profile with `host` names the machine"
        );
    }

    #[test]
    fn a_host_config_without_an_egress_proxy_bin_still_parses_and_one_with_it_round_trips() {
        // The key is additive, so the test that matters most is the first half: every config written
        // before it existed must keep parsing, and a host that never runs a remote egress sandbox
        // must never have to write it. The second half is that when it *is* written it arrives —
        // it is the only way the daemon can tell the runtime where the far host's binary lives.
        let yaml = r#"
hosts:
  buildbox:
    kind: ssh
    address: "10.0.0.5"
    user: "yoav"
    auth: { kind: key, secret_ref: "vault:ssh/buildbox" }
  egressbox:
    kind: ssh
    address: "10.0.0.6"
    user: "yoav"
    auth: { kind: agent }
    egress_proxy_bin: /opt/hx/hx-egress-proxy
"#;
        let c = Config::from_yaml(yaml).expect("both hosts must parse");
        assert_eq!(
            c.hosts["buildbox"].egress_proxy_bin, None,
            "a host that never names it parses as unset rather than being refused"
        );
        assert_eq!(
            c.hosts["egressbox"].egress_proxy_bin.as_deref(),
            Some("/opt/hx/hx-egress-proxy")
        );

        // And it survives a round-trip, so a dumped config is a config that still says where the
        // binary is.
        let json = serde_json::to_string(&c.hosts["egressbox"]).unwrap();
        assert!(json.contains("/opt/hx/hx-egress-proxy"), "{json}");
        let back: HostConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c.hosts["egressbox"]);
    }

    #[test]
    fn model_ref_parsing_round_trips() {
        let r = ModelRef::parse("anthropic-main/claude-opus-4-7").unwrap();
        assert_eq!(r.provider.as_str(), "anthropic-main");
        assert_eq!(r.model, "claude-opus-4-7");
        assert_eq!(r.to_string(), "anthropic-main/claude-opus-4-7");
    }

    #[test]
    fn model_ref_rejects_malformed_input() {
        assert!(ModelRef::parse("no-slash").is_err());
        assert!(ModelRef::parse("/model-only").is_err());
        assert!(ModelRef::parse("provider-only/").is_err());
    }

    #[test]
    fn model_ref_globs_match_as_documented() {
        let r = ModelRef::parse("anthropic-main/claude-*").unwrap();
        assert!(r.matches(&ProviderId::from_raw("anthropic-main"), "claude-opus-4-7"));
        assert!(!r.matches(&ProviderId::from_raw("anthropic-main"), "gpt-5"));
        assert!(!r.matches(&ProviderId::from_raw("openai-main"), "claude-opus-4-7"));
    }

    #[test]
    fn glob_handles_wildcards_question_marks_and_anchoring() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("claude-*", "claude-opus-4-7"));
        assert!(glob_match("gpt-?.?", "gpt-5.5"));
        assert!(!glob_match("gpt-?.?", "gpt-55.5"));
        assert!(
            !glob_match("claude-*", "xclaude-1"),
            "must be anchored at the start"
        );
        assert!(
            !glob_match("a*b", "ac"),
            "trailing literal must be required"
        );
        assert!(glob_match("a*b*c", "axxbyyc"));
    }

    #[test]
    fn secret_ref_parsing() {
        let s = SecretRef::parse("vault:anthropic/key1").unwrap();
        assert_eq!(s.store, "vault");
        assert_eq!(s.name, "anthropic/key1");
        assert_eq!(s.to_string(), "vault:anthropic/key1");
        assert!(SecretRef::parse("nocolon").is_err());
        assert!(SecretRef::parse("vault:").is_err());
    }

    #[test]
    fn unbounded_limits_are_recognised() {
        assert!(Limits::default().is_unbounded());
        assert!(!Limits {
            rpm: Some(1),
            ..Default::default()
        }
        .is_unbounded());
    }

    /// The trap this field exists to close: the *shortest* config an operator writes to stop being
    /// prompted used to remove the entire catastrophe set with it, because a config deserialises into a
    /// policy and a list that is written replaces a list that was there.
    ///
    /// The looser the setting, the more the floor mattered — which is the worst shape a safety default can
    /// have, so the floor is layered on unless the file says otherwise. These are the three shapes.
    #[test]
    fn a_config_that_writes_a_policy_still_gets_the_shipped_floor() {
        for yaml in [
            // The one that used to be dangerous: loosens the level and mentions nothing else.
            "agent:\n  approval:\n    level: yolo\n",
            // Writing its own deny list. It replaces *its own* rules, not the floor.
            "agent:\n  approval:\n    deny:\n      - { tool: shell, command: \"*my-own-rule*\" }\n",
            // And writing every other field, which is what a careful operator does.
            "agent:\n  approval:\n    level: trusting\n    ceiling: mutate\n    unattended_budget: 10\n             \n    allow:\n      - { tool: shell, command: \"cargo test*\" }\n",
        ] {
            let config = Config::from_yaml(yaml).expect("must parse");
            let policy = &config.agent.approval;
            assert!(
                policy.has_floor(),
                "the floor must survive this config: {yaml}\n{policy:?}"
            );
            assert!(
                policy.refuse_unenumerable_deletions,
                "and so must the refusal of a delete nobody can enumerate: {yaml}"
            );

            // The behaviour, not the bookkeeping: a yolo chat still refuses the catastrophe.
            let mut session = crate::approval::ApprovalSession::new(policy.clone());
            let verdict = session.decide(
                &crate::approval::ActionRequest::shell("rm -rf /etc"),
                chrono::Utc::now(),
            );
            assert!(verdict.is_denied(), "in {yaml}: {verdict:?}");
        }
    }

    #[test]
    fn the_floor_is_dropped_only_when_the_file_says_so_in_so_many_words() {
        let yaml = "agent:\n  approval:\n    level: yolo\n    inherit_denials: false\n";
        let config = Config::from_yaml(yaml).unwrap();
        let policy = &config.agent.approval;

        assert!(!policy.has_floor());
        assert!(!policy.refuse_unenumerable_deletions);

        // Which is a real choice with a real consequence, and it is the operator's to make — stated in the
        // file, reviewable in a diff, and visible in `hx policy` (which prints "none of the shipped
        // catastrophe set: this config's `deny` list replaced it").
        let mut session = crate::approval::ApprovalSession::new(policy.clone());
        let verdict = session.decide(
            &crate::approval::ActionRequest::shell("rm -rf /etc"),
            chrono::Utc::now(),
        );
        assert!(!verdict.is_denied(), "{verdict:?}");
    }

    #[test]
    fn a_config_own_rule_for_the_same_command_wins_over_the_shipped_one() {
        // Prepend, not append: `deny` is a first-match list, so the operator's rule has to come first for
        // the note they wrote to be the one that explains the refusal. Both stay in force.
        let yaml = "agent:\n  approval:\n    deny:\n      - { tool: shell, command: \"rm -rf /\", note: \"no — ask the team first\" }\n";
        let config = Config::from_yaml(yaml).unwrap();
        let policy = &config.agent.approval;

        let mut session = crate::approval::ApprovalSession::new(policy.clone());
        let verdict = session.decide(
            &crate::approval::ActionRequest::shell("rm -rf /"),
            chrono::Utc::now(),
        );
        assert!(verdict.is_denied());
        assert!(
            verdict.why().contains("ask the team first"),
            "the operator's own words, not the shipped note: {verdict:?}"
        );
        assert!(
            policy.has_floor(),
            "and the rest of the floor is still there"
        );
    }

    #[test]
    fn a_library_policy_built_in_code_never_acquires_the_floor() {
        // `ApprovalPolicy::default()` is what a test or an embedder builds. Folding a deployment's
        // opinions into it would replace one trap with another — a library caller's blank policy would
        // suddenly refuse fourteen commands it never heard of.
        let policy = crate::approval::ApprovalPolicy::default();
        assert!(policy.deny.is_empty());
        assert_eq!(policy.inherit_denials, None);
        assert!(!policy.has_floor());
        assert!(!policy.clone().with_floor().has_floor(), "None is not true");
    }

    /// The file we tell people to copy has to parse against the schema we actually have.
    ///
    /// `hx.example.yaml` promises in its own header that a typo'd key fails loudly, and the file is
    /// what a first run is built from — so a stale example is the worst kind of documentation: it is
    /// the thing people type, and nothing notices until their first launch fails. This also pins the
    /// *behaviour* the example claims by omission: with no `agent:` section, a deployment carries the
    /// floor (`balanced`, catastrophe set denied, unenumerable deletions refused).
    #[test]
    fn the_shipped_example_config_parses_and_carries_the_floor() {
        let yaml = include_str!("../../../hx.example.yaml");
        let config = Config::from_yaml(yaml).expect("hx.example.yaml must parse");

        assert!(
            !config.providers.is_empty(),
            "it should show, not just tell"
        );
        assert!(!config.pools.is_empty());
        assert!(!config.roles.is_empty());

        let approval = &config.agent.approval;
        assert_eq!(approval.level, crate::approval::AutonomyLevel::Balanced);
        assert!(
            approval.refuse_unenumerable_deletions,
            "the example documents the refusal, so omitting `agent:` must produce it"
        );
        assert!(
            approval.deny.len() >= 10,
            "and the catastrophe set with it: {:?}",
            approval.deny
        );
    }
}
