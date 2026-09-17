//! The agent loop, reachable: one request, one session, one run.
//!
//! ## What this module is responsible for
//!
//! The loop itself lives in `hx-agent` and knows nothing about HTTP, sessions or credentials. This
//! is the layer that answers the questions a loop cannot: *which* model callable a role resolves to,
//! *which* capability token the run holds, *who* answers a prompt, and *where* the transcript and
//! the events end up. It is deliberately the only place that knows all four, because that is what
//! makes "the daemon owns the state and every front end is a client" true rather than aspirational.
//!
//! ## Decisions worth arguing with
//!
//! **A missing client is a refusal, not a yes.** The approval queue waits for a client over HTTP;
//! silence expires into a denial, and a request can choose not to wait. Autonomy is the
//! request field that decides whether a prompt happens at all: `yolo` runs unattended because the
//! operator asked for it in this request, and it can still be capped by the policy's `ceiling` —
//! which is the property that makes a per-request grant safe to allow.
//!
//! **The prompt is stored before the model is called.** A request whose run dies has still been
//! asked; a transcript that loses the question makes the interruption unexplainable.
//!
//! **Events and messages are stored as they happen.** The transcript sink persists each append so a
//! killed run can be repaired without losing completed tool results. An explicitly selected sandbox
//! must start before any prompt is persisted; startup failure never becomes host execution.

use crate::state::AppState;
use chrono::{DateTime, Utc};
use hx_agent::{
    AgentLoop, AlwaysAllow, Approver, Limits, ModelCall, RefusingApprover, RouterModel, RunOutcome,
    SessionScopedQueue, TranscriptSink,
};
use hx_core::approval::{ApprovalSession, AutonomyLevel};
use hx_core::capability::{Action, Capability, CapabilityToken, Resource};
use hx_core::error::{HxError, Result};
use hx_core::event::AgentEvent;
use hx_core::ids::{AgentId, HostId, ProviderId, SessionId};
use hx_core::message::Message;
use hx_provider::{ModelRouter, ProviderRegistry, Usage};
use hx_secrets::SecretStores;
use hx_store::{NewSession, Store, UsageRecord};
use hx_tools::web::SEARCH_RESOURCE_HOST;
use hx_tools::{ToolContext, ToolRegistry};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// The default deadline for a request, when the request does not set one.
///
/// A daemon call with no bound is a call that can hold a session forever; `max_turns` alone does not
/// bound it, because one turn can hang inside a provider that never answers.
const DEFAULT_DEADLINE_SECS: u64 = 600;

/// Capability tokens are issued per run, and the run is what they are for.
const TOKEN_TTL_SECS: i64 = 3600;

/// How long a run waits for an answer before silence counts as a refusal.
///
/// Long enough to answer a phone notification, short enough that a run with no client attached fails
/// instead of looking hung. A request can ask to wait zero seconds, which is the pre-channel
/// behaviour: refuse at once and say why.
pub const DEFAULT_APPROVAL_WAIT_SECS: u64 = 60;

/// Where a role's model call comes from.
///
/// A trait because the daemon's answer (the routing table) is not the only useful one: the HTTP
/// tests need a scripted model, and they need it *without* a real provider or a real key. Making
/// that injectable is what keeps the route's behaviour (session handling, capability defaults,
/// refusals, persistence) testable on its own.
pub trait ModelFactory: Send + Sync {
    fn for_role(&self, role: &str) -> Result<Arc<dyn ModelCall>>;
}

/// The real one: a routed call, which reserves capacity and resolves its own credential.
pub struct RouterModels {
    router: Arc<Mutex<ModelRouter>>,
    providers: Arc<ProviderRegistry>,
    secrets: Arc<SecretStores>,
}

impl RouterModels {
    pub fn new(
        router: Arc<Mutex<ModelRouter>>,
        providers: Arc<ProviderRegistry>,
        secrets: Arc<SecretStores>,
    ) -> Self {
        Self {
            router,
            providers,
            secrets,
        }
    }
}

impl ModelFactory for RouterModels {
    fn for_role(&self, role: &str) -> Result<Arc<dyn ModelCall>> {
        Ok(Arc::new(RouterModel::new(
            role,
            Arc::clone(&self.router),
            Arc::clone(&self.providers),
            Arc::clone(&self.secrets),
        )?))
    }
}

/// A request body for `POST /v1/chat`.
#[derive(Clone, Debug, Deserialize)]
pub struct ChatRequest {
    pub prompt: String,
    /// Continue an existing session. Absent means "start one", and the reply carries its id.
    #[serde(default)]
    pub session: Option<String>,
    /// Which role (and therefore which pool) to run as. Defaults to the configured one.
    #[serde(default)]
    pub role: Option<String>,
    /// The directory the run may read and write. Defaults to the daemon's working directory.
    #[serde(default)]
    pub workspace: Option<String>,
    /// Confine shell calls to this configured sandbox profile. Other tools still use the host.
    /// Absent means host execution; a named boundary that cannot start fails the request.
    #[serde(default)]
    pub sandbox_profile: Option<String>,
    /// `paranoid`, `balanced`, `trusting`, `yolo`. Defaults to the configured policy's level.
    #[serde(default)]
    pub autonomy: Option<String>,
    #[serde(default)]
    pub max_turns: Option<u32>,
    #[serde(default)]
    pub deadline_secs: Option<u64>,
    /// A title for a session this request creates.
    #[serde(default)]
    pub title: Option<String>,
    /// How long to wait for a human if a call needs approval. `0` refuses immediately.
    ///
    /// Defaults to the daemon's wait. The number matters to a client: it is how long the HTTP request
    /// stays open before the answer becomes "nobody came".
    #[serde(default)]
    pub approval_wait_secs: Option<u64>,
}

/// What a run did.
#[derive(Clone, Debug, Serialize)]
pub struct ChatReply {
    pub session_id: String,
    /// True when this request created the session.
    pub created: bool,
    /// Tool calls closed because a previous run died between the call and its result.
    pub repaired: usize,
    pub stop: String,
    pub turns: u32,
    pub tool_calls: u32,
    pub refusals: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Priced from the provider's rate card; `0.0` means no rate card is configured, which is not
    /// the same claim as "this was free".
    pub cost_usd: f64,
    pub final_text: String,
    /// The transcript length now, so a client can tell a resumed session from a fresh one.
    pub messages: usize,
    pub totals: hx_store::Totals,
}

/// Where a run's messages go while it is still running: the session store, one row at a time.
///
/// This is what makes a killed daemon resumable rather than merely restartable. Events already went
/// out live; messages used to wait for the run to return, so a `kill -9` at turn three lost two turns
/// of work *after* the tools in them had already run — the transcript could not say what they did.
struct StoreSink {
    store: Arc<Store>,
    session: SessionId,
}

impl TranscriptSink for StoreSink {
    fn appended(&self, message: &Message) -> Result<()> {
        self.store.append(&self.session, message, Utc::now())?;
        Ok(())
    }
}

/// Run one request against one session.
pub async fn run_chat(
    state: &Arc<AppState>,
    request: ChatRequest,
    now: DateTime<Utc>,
) -> Result<ChatReply> {
    if request.prompt.trim().is_empty() {
        return Err(HxError::Config("prompt is empty".to_string()));
    }

    let role = match &request.role {
        Some(role) => role.clone(),
        None => state.default_role()?,
    };
    let workspace = match &request.workspace {
        Some(path) => path.clone(),
        None => state.default_workspace(),
    };
    let level = match &request.autonomy {
        Some(name) => AutonomyLevel::parse(name).ok_or_else(|| {
            HxError::Config(format!(
                "unknown autonomy level '{name}'; known: {}",
                AutonomyLevel::NAMES.join(", ")
            ))
        })?,
        None => state.config.agent.approval.level,
    };

    // The model call a role resolves to, before anything is written: a role that does not exist is a
    // configuration mistake, and a request that cannot run should not leave a session behind for it.
    let model = state.models.for_role(&role)?;

    // Resolve the requested boundary before persisting a prompt or calling the model. A failed
    // start must never turn a request for confinement into a host run.
    let sandbox = if let Some(name) = &request.sandbox_profile {
        let profile = state
            .config
            .sandbox_profiles
            .get(name)
            .ok_or_else(|| HxError::Config(format!("no sandbox profile named '{name}'")))?;
        let manager = state.sandboxes.as_ref().ok_or_else(|| {
            HxError::Sandbox(
                state
                    .sandbox_unavailable_reason
                    .clone()
                    .unwrap_or_else(|| "sandboxes are unavailable".into()),
            )
        })?;
        let mut spec = hx_sandbox::SandboxSpec::from_profile(name, profile);
        spec.workspace_host_path = workspace.clone();
        spec.adopt_workspace_owner()
            .map_err(|err| HxError::Sandbox(err.to_string()))?;
        Some(
            state
                .chat_sandboxes
                .get(manager, &spec, std::time::Duration::from_secs(900))
                .await?,
        )
    } else {
        None
    };

    // One run per session at a time. Two requests on one session would interleave into a transcript
    // neither of them wrote, which is the kind of corruption that looks like a model that "forgot".
    let _run_guard = state
        .session_lock(&session_key(request.session.as_deref()))
        .await;

    let (session_id, created, repaired) = match &request.session {
        Some(id) => {
            let session = SessionId::from_raw(id.clone());
            // A transcript that ended between a tool call and its result is one no provider accepts.
            // Repairing it here — before the model sees it — is what turns "the daemon was killed"
            // into a resumable session instead of a permanent one.
            let repaired = state.store.close_interrupted(
                &session,
                "the previous run ended before this call returned",
                now,
            )?;
            state.store.record(&session)?; // fails loudly for an unknown id
            (session, false, repaired.len())
        }
        None => {
            let mut new = NewSession::new()
                .in_workspace(&workspace)
                .run_by(agent_id(&workspace));
            new.title = request.title.clone();
            let record = state.store.create(new, now)?;
            (record.id, true, 0)
        }
    };

    // Stored first: a run that dies has still been asked.
    let prompt = Message::user(request.prompt.clone());
    state.store.append(&session_id, &prompt, now)?;

    let host = state.local_host().await?;
    // `with_floor()` again, and not because the config forgot: a request may arrive with a policy that
    // never went through `Config::from_yaml` (a test's `AppState::from_parts`, a future hot-reload), and the
    // fold is idempotent. The order that matters is here — `set_level` changes the *threshold*, and the
    // floor is a list of refusals that no level can lift, so folding after it is what keeps
    // `autonomy: "yolo"` from being a way to drop the catastrophe set.
    let mut policy = state.config.agent.approval.clone().with_floor();
    // Then the project's own grants, from `.hx/allow.toml` in *this* checkout (`docs/approvals.md`
    // §5). Loading here, from the run's resolved workspace, is what scopes a grant to one repository: a
    // grant written in one worktree is folded only for a run whose workspace is that worktree. A malformed
    // allowlist is a hard error, not a silent skip — a policy somebody was relying on being dropped is
    // exactly the fail-open this must not do.
    match hx_core::allowlist::AllowFile::load(
        &std::path::Path::new(&workspace).join(hx_core::allowlist::ALLOW_FILE),
    ) {
        Ok(list) => {
            let mut rules = list.into_rules();
            policy.allow.append(&mut rules);
        }
        Err(hx_core::allowlist::AllowlistError::NotFound(_)) => {}
        Err(err) => {
            return Err(HxError::Config(format!(
                "cannot use {}: {err}",
                std::path::Path::new(&workspace)
                    .join(hx_core::allowlist::ALLOW_FILE)
                    .display()
            )))
        }
    }
    let mut approvals = ApprovalSession::new(policy);
    approvals.set_level(level);

    // Who answers a prompt, in the order of how much waiting is warranted.
    let approver: Arc<dyn Approver> = match level {
        // Nothing is prompted at this level, so the approver is never consulted. Selecting
        // `AlwaysAllow` anyway would be a lie in the direction of "this run could have asked".
        AutonomyLevel::Yolo => Arc::new(AlwaysAllow),
        // A client that has said it will not wait gets the old answer at once, with the reason and
        // the escape hatch, rather than a minute of silence.
        _ if request.approval_wait_secs == Some(0) => Arc::new(RefusingApprover::new(
            "this request asked not to wait for approvals. Re-send with a non-zero \
             `approval_wait_secs` and a client polling GET /v1/approvals, or run with \
             `autonomy: \"yolo\"` if the work is safe to do unattended.",
        )),
        _ => SessionScopedQueue::new(
            Arc::clone(&state.approvals),
            session_id.as_str().to_string(),
        ),
    };

    let ttl = {
        let mut limits = Limits::default();
        if let Some(max_turns) = request.max_turns {
            limits.max_turns = max_turns;
        }
        limits.deadline = Some(std::time::Duration::from_secs(
            request.deadline_secs.unwrap_or(DEFAULT_DEADLINE_SECS),
        ));
        limits
    };

    let (events_tx, events_rx) = mpsc::channel(256);
    let agent = agent_id(&workspace);

    let mut transcript = state.store.messages(&session_id)?;
    // No push: the store already ends with the prompt this request appended, and handing the model a
    // transcript with the question twice is the kind of duplicate that looks like a model ignoring
    // the second half of what it was told.

    // Events are written as they happen, so a client that reconnects mid-run can redraw what has
    // already occurred rather than being told to wait for the end.
    let writer = tokio::spawn(write_events(
        Arc::clone(state),
        session_id.clone(),
        events_rx,
    ));

    let loop_ = AgentLoop::new(
        agent,
        model,
        Arc::clone(&state.tools),
        default_capability(agent_id(&workspace), &workspace, now),
        approvals,
        approver,
    )
    .with_limits(ttl)
    .with_events(events_tx)
    .with_transcript_sink(Arc::new(StoreSink {
        store: Arc::clone(&state.store),
        session: session_id.clone(),
    }));

    // The context the run acts in: the host, and the workspace every relative path is resolved
    // against. A run whose tools do not know its workspace denies the paths the model naturally
    // writes (`Cargo.toml`), and a shell command with no directory of its own runs wherever the
    // daemon happens to be.
    let mut ctx = ToolContext::new(host).in_workspace(workspace.clone());
    if let Some(sandbox) = sandbox {
        ctx = ctx.with_sandbox(sandbox);
    }

    let run = loop_.run(&mut transcript, &ctx).await;
    // The sender lives in the loop, which is dropped here — that is what ends the writer.
    drop(loop_);
    let priced = writer.await.unwrap_or_default();

    let outcome = run?;

    // No batch append: every message the loop produced went to the store as it was produced, through
    // the sink. What is left is to notice if that ever stops being true — a transcript in memory that
    // is longer than the one on disk means a message a kill would have lost, and the run that
    // reported success would have been lying about what is resumable.
    let stored = state.store.message_count(&session_id)? as usize;
    if stored != transcript.len() {
        tracing::warn!(
            session = %session_id.as_str(),
            in_memory = transcript.len(),
            stored,
            "the transcript on disk does not match the one the run produced"
        );
    }

    let totals = state.store.totals(&session_id)?;

    Ok(ChatReply {
        session_id: session_id.as_str().to_string(),
        created,
        repaired,
        stop: stop_name(&outcome),
        turns: outcome.turns,
        tool_calls: outcome.tool_calls,
        refusals: outcome.refusals,
        input_tokens: outcome.usage.input_tokens,
        output_tokens: outcome.usage.output_tokens,
        cost_usd: priced,
        final_text: outcome.final_text,
        messages: transcript.len(),
        totals,
    })
}

/// Store the events a run emits, and price the turns as they go past.
///
/// Returns the run's cost in dollars, summed from the usage events. A usage row is written per turn
/// with the provider and credential that actually served it, because "which key paid" is a question
/// an audit needs answered per call rather than per session.
async fn write_events(
    state: Arc<AppState>,
    session: SessionId,
    mut rx: mpsc::Receiver<AgentEvent>,
) -> f64 {
    let mut cost = 0.0;
    while let Some(event) = rx.recv().await {
        let now = Utc::now();
        if let AgentEvent::Usage {
            provider,
            credential,
            model,
            input_tokens,
            output_tokens,
            ..
        } = &event
        {
            let usage = Usage {
                input_tokens: *input_tokens,
                output_tokens: *output_tokens,
                ..Default::default()
            };
            let priced = state
                .router
                .lock()
                .map(|router| router.cost_for(provider, &usage))
                .unwrap_or(0.0);
            cost += priced;
            let mut record = UsageRecord::new(
                provider.as_str(),
                credential.as_str(),
                model.clone(),
                *input_tokens,
                *output_tokens,
            );
            record.cost_usd = priced;
            if let Err(err) = state.store.record_usage(&session, &record, now) {
                tracing::warn!(error = %err, "could not record usage");
            }
        }
        if let Err(err) = state.store.append_event(&session, &event, now) {
            tracing::warn!(error = %err, "could not record an event");
        }
    }
    cost
}

/// The capability token a daemon run holds.
///
/// The workspace, read and write; the ability to spawn processes (shell commands are classified for
/// *risk* by the approval layer, so a token that refused them all would make the harness useless
/// rather than safe); and the search resource the web tool declares. Nothing else: a run that wants
/// to touch a path outside its workspace is denied by the token, cannot be approved past it, and
/// says so in the transcript.
///
/// A narrower grant needs somewhere to write it down, which is a `capabilities` section in the
/// config rather than a default in code. Until that exists this is the honest default, and it is
/// stated here rather than buried.
pub fn default_capability(agent: AgentId, workspace: &str, now: DateTime<Utc>) -> CapabilityToken {
    CapabilityToken::issue(
        agent,
        vec![
            Capability::workspace(workspace),
            Capability::new(Resource::Process, [Action::Execute, Action::Spawn]),
            Capability::new(
                Resource::NetworkHost {
                    host: SEARCH_RESOURCE_HOST.to_string(),
                },
                [Action::Connect],
            ),
        ],
        now,
        TOKEN_TTL_SECS,
    )
}

/// Build the tool registry a daemon run uses.
pub fn default_tools(
    search: Vec<Arc<dyn hx_search::SearchBackend>>,
    client: reqwest::Client,
) -> ToolRegistry {
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(hx_tools::ReadFileTool::new()));
    tools.register(Arc::new(hx_tools::WriteFileTool::new()));
    tools.register(Arc::new(hx_tools::PatchTool::new()));
    // `delete` sits next to `shell`, not instead of it: the tool moves a named path to the trash and
    // reports what it moved, while `rm` stays available through `shell` for the cases a single path
    // cannot express — classified `Destructive`, and refused outright when a pattern or a variable
    // stands where a target belongs.
    tools.register(Arc::new(hx_tools::DeleteTool::new()));
    tools.register(Arc::new(hx_tools::ShellTool::new()));
    tools.register(Arc::new(hx_tools::TodoTool::new()));
    if !search.is_empty() {
        tools.register(Arc::new(hx_tools::WebSearchTool::new(search, client)));
    }
    tools
}

/// A stable agent id for a workspace, so the same checkout keeps the same identity across runs.
fn agent_id(workspace: &str) -> AgentId {
    AgentId::from_raw(format!("hxd:{}", workspace.trim_end_matches('/')))
}

fn session_key(id: Option<&str>) -> String {
    id.unwrap_or("<new>").to_string()
}

fn stop_name(outcome: &RunOutcome) -> String {
    format!("{:?}", outcome.stop).to_lowercase()
}

/// The sandbox host id a run would use, for a caller that wants to target one.
pub fn host_id() -> HostId {
    HostId::from_raw("local")
}

/// A provider id, mostly so tests and callers do not have to import `hx-provider` for one type.
pub fn provider(id: &str) -> ProviderId {
    ProviderId::from_raw(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn the_default_token_covers_the_workspace_and_the_search_resource() {
        let now = Utc::now();
        let agent = AgentId::from_raw("test");
        let token = default_capability(agent.clone(), "/work/repo", now);

        let inside = Resource::FsPath {
            path: "/work/repo/src/lib.rs".to_string(),
        };
        assert!(token.check(&inside, Action::Read, now).is_allowed());
        assert!(token.check(&inside, Action::Write, now).is_allowed());

        // Outside the workspace is denied — and unlike an approval, this is not a decision a client
        // can talk its way past.
        let outside = Resource::FsPath {
            path: "/etc/shadow".to_string(),
        };
        assert!(!token.check(&outside, Action::Read, now).is_allowed());

        assert!(token
            .check(&Resource::Process, Action::Execute, now)
            .is_allowed());
        assert!(token
            .check(
                &Resource::NetworkHost {
                    host: SEARCH_RESOURCE_HOST.to_string()
                },
                Action::Connect,
                now
            )
            .is_allowed());

        // A secret is not part of the default grant: a run that needs one needs a capability for it.
        assert!(!token
            .check(
                &Resource::Secret {
                    name: "anthropic/main".to_string()
                },
                Action::Read,
                now
            )
            .is_allowed());
    }

    #[test]
    fn the_token_expires() {
        let now = Utc::now();
        let token = default_capability(AgentId::from_raw("test"), "/work", now);
        let later = now + Duration::seconds(TOKEN_TTL_SECS + 1);
        assert!(!token
            .check(
                &Resource::FsPath {
                    path: "/work/x".to_string()
                },
                Action::Read,
                later
            )
            .is_allowed());
    }

    #[test]
    fn a_workspace_run_keeps_one_agent_identity() {
        assert_eq!(agent_id("/work/repo/"), agent_id("/work/repo"));
        assert_ne!(agent_id("/work/repo"), agent_id("/work/other"));
    }
}
