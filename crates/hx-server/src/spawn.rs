//! The spawner that draws a child from the model pool (M8), and the model that travels with it.
//!
//! ## What this module is, said plainly
//!
//! There is still no subagent runtime in this repository — no orchestrator, no fan-out, no
//! `delegate`. What M8's "Still to come" named is the **spawner that draws from the pool**, and
//! that is what lives here, as the **narrowest real thing** that exercises the path:
//!
//! 1. [`Spawner::build_spec`] draws a **healthy** member from the pool and clamps the requested
//!    parameters to what that member accepts, producing a [`ChildSpec`] that carries **the drawn
//!    member as its model**, its endpoint, its credential reference, and the clamps that were applied.
//!    This is the "per-child model selection": the model is part of the spec, chosen at spawn and
//!    carried *with the child* — not read from a process-global at the moment of use.
//! 2. [`Spawner::run_child`] takes a spec and makes **one provider call** through `hx-provider`
//!    against the **drawn member's** endpoint and credential with the **clamped** parameters, and on
//!    success records a [`UsageRecord`] against the session whose `model` is the **drawn member** —
//!    the "per-child model + cost in the audit chain" half. A call that fails marks the member down, so
//!    the next draw comes from a healthy member.
//! 3. [`Spawner::run_lane`] is the **re-route on member death across a running child**: it draws a
//!    healthy member, makes **one** provider call against it, and if that member **dies** while running
//!    (the pool's [`member_death`] rule: a 5xx/timeout/404, an exhausted quota, a refused
//!    credential) it marks the member down and **re-draws onto the pool's next healthy member**, running
//!    the same prompt there. It fails bounded when every member is down, and it records **both** the
//!    members that died and the one that finished on the returned [`ChildRecord`] — a re-route is never
//!    silent. A failure that is the child's own (a refused request, a policy denial) does **not**
//!    re-route: it would be deterministic across every member.
//!
//! **What it does *not* run**, and which it names rather than claims: it does not start a
//! general agent loop. `run_child` is a single provider call against the drawn member — unless the
//! spec opts into the **bounded child tool loop** (`ChildSpec::tools` non-empty), in which case it
//! runs provider call → `read_file`/`write_file` tool calls → tool results, capped at
//! `ChildSpec::max_tool_iters` and gated by the child's capability token. `run_lane` is a single
//! prompt run that re-draws on member death. Neither is a fan-out — the spawner draws one lane,
//! narrow and real.
//!
//! The pool, the clamp rule, and [`DrawError`] all live in `hx-core` (`pool.rs`); this module
//! **reuses** them rather than inventing a second error type or a second clamp. A spec construction on
//! an empty pool or an all-down pool returns the pool's own [`DrawError`].
//!
//! ## Hermetic by construction
//!
//! The tests here use a **scripted pool and a scripted provider** — no network. A member that fails
//! causes the next child to be drawn from a healthy one; a member whose parameters reject
//! `reasoning_effort` is clamped and run rather than failing at spawn (that is the exit criterion, and
//! the `HTTP 400` it prevents is a real observed failure mode, not hypothetical). Every assertion is
//! proven to fail by a mutation.

use chrono::Utc;
use hx_core::capability::{CapabilityToken, Decision};
use hx_core::error::{HxError, Result};
use hx_core::ids::{ProviderId, SessionId};
use hx_core::message::{Message, Part};
use hx_core::pool::{member_death, DrawError, ModelPool, Param, ParamClamp};
use hx_provider::{ChatRequest, Provider, ProviderRegistry, ToolSpec, Usage};
use hx_secrets::{Redactor, Secret, SecretStores};
use hx_store::UsageRecord;
use hx_tools::{ToolContext, ToolRegistry};
use serde::Serialize;
use std::sync::Arc;

/// The tool names a fan-out child may execute, and nothing else.
///
/// DECIDED: `read_file` and `write_file` only. Shell/terminal execution inside a
/// child is a separate review — unattended command execution needs its own threat
/// model — so a child that names anything else is refused, not executed, even when
/// that name exists in the registry.
const CHILD_TOOL_ALLOWLIST: &[&str] = &["read_file", "write_file"];

/// The iterations a child tool loop runs before it stops asking, when the spec does
/// not say otherwise.
///
/// A named constant rather than a literal so the bound test can pin it: raising this
/// value must turn `an_always_tool_calling_child_stops_at_max_tool_iters` red.
pub const DEFAULT_MAX_TOOL_ITERS: u32 = 8;

/// A child, as chosen at spawn: the model it will run on, its endpoint, its credential
/// **reference**, and the parameters (with their clamps) that will be sent.
///
/// The model is **part of the spec**, recorded here rather than read from a global at the moment of
/// use. "Which model did this child run on" is answerable from the spec alone, before the child runs
/// and after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildSpec {
    /// The pool member this child was drawn from. It is the model (its `id`), the endpoint and the
    /// credential — all in one, because a pool member *is* a drawable model.
    pub member_id: String,
    pub base_url: String,
    /// A credential **reference** (`vault:…` / `env:…`), never a value — same discipline as the
    /// pool and `hx-secrets`.
    pub credential: String,
    /// The effective parameters the member will receive: every requested parameter it accepts, plus the
    /// clamped ones. This is what would be sent; a member that rejects a kind never receives it.
    pub params: Vec<Param>,
    /// The clamps that were applied at spawn, recorded with the child so "what was clamped" is
    /// answerable after the fact rather than sent and hoped for.
    pub clamps: Vec<ParamClamp>,
    /// Names of tools this child may call. Empty by default — no loop, exactly today's single
    /// provider call. Non-empty opts into the bounded tool loop in [`Spawner::run_child`]; every
    /// name must be in the child allow-list (`read_file`, `write_file`), anything else is refused,
    /// not executed.
    pub tools: Vec<String>,
    /// Cap on tool-executing iterations of the child loop. Defaults to
    /// [`DEFAULT_MAX_TOOL_ITERS`]; unused when `tools` is empty.
    pub max_tool_iters: u32,
}

impl ChildSpec {
    /// The model id this child runs on — the **drawn member**, not a global.
    pub fn model(&self) -> &str {
        &self.member_id
    }

    /// Opt this child into the bounded tool loop with these allowed tool names.
    ///
    /// Every name must be in the child allow-list (`read_file`, `write_file`); anything else
    /// fails the child when it runs — the check lives at execution, where the refusal is
    /// observable, not here where it would be a silent clamp.
    pub fn with_tools(mut self, tools: Vec<String>) -> Self {
        self.tools = tools;
        self
    }

    /// Override the cap on tool-executing iterations of the child loop.
    pub fn with_max_tool_iters(mut self, max_tool_iters: u32) -> Self {
        self.max_tool_iters = max_tool_iters;
        self
    }
}

/// Redact a failure reason before it is stored on a member or returned as a death reason.
///
/// A provider failure's message includes the upstream error body (see `classify_error` in
/// `hx-provider`), and a provider can echo the very key it was given back inside that body
/// (an auth-debugging page, a `?token=` URL, an opaque key value). That reason is written
/// into the pool's `mark_down` health state and returned on [`ChildRecord::dead_members`], both
/// of which a caller (and eventually an HTTP client) reads — so a credential that leaks into the
/// body must not reach either verbatim. The key resolved for this member is registered as a literal
/// (the defense for opaque values with no shape) and the message is run through the shared
/// [`Redactor`]'s pattern pass as well.
fn redact_death_reason(key: &Secret, err: &HxError) -> String {
    let mut redactor = Redactor::new();
    redactor.register(key.expose());
    redactor.redact(&err.to_string()).text
}

/// What one prepared child's run produced: either its record, or its member's death.
///
/// `Failed` carries **both** redactions' inputs: `reason` is the death reason already redacted
/// with the resolved key as a registered literal (what `mark_down` stores), and `error` is the
/// raw provider error for the caller to redact at its own boundary (what the fan-out reports).
/// A store-write failure is not a member death, so it is a `Result::Err` instead — no member is
/// benched for it, exactly as `run_child`'s `?` behaved.
pub enum PreparedOutcome {
    /// The child completed. Carries the same [`ChildRecord`] `run_child` would have returned.
    Ran(ChildRecord),
    /// The provider call failed. `member` is the member the child was drawn to run on.
    Failed {
        member: String,
        reason: String,
        error: HxError,
    },
}

/// One allocated child with everything its run needs, owned rather than borrowed.
///
/// Built by [`Spawner::prepare_child`]; run with [`PreparedChild::run`].
pub struct PreparedChild {
    provider: Arc<dyn Provider>,
    key: Secret,
    spec: ChildSpec,
    store: Arc<hx_store::Store>,
}

impl PreparedChild {
    /// Make the child's one provider call and record its usage — shareably.
    ///
    /// This is the `&mut`-free middle of `run_child`: the same request, the same record, the
    /// same redacted death reason. The pool-health write is the caller's job
    /// ([`Spawner::mark_down`]), applied after the concurrent join.
    pub async fn run(self, session: &SessionId, prompt: &str) -> Result<PreparedOutcome> {
        let request = ChatRequest::new(self.spec.model(), vec![Message::user(prompt)]);
        let response = match self.provider.complete(request, &self.key).await {
            Ok(response) => response,
            Err(err) => {
                return Ok(PreparedOutcome::Failed {
                    member: self.spec.member_id.clone(),
                    reason: redact_death_reason(&self.key, &err),
                    error: err,
                });
            }
        };

        let usage = response.usage;
        let record = UsageRecord::new(
            self.spec.member_id.clone(),
            self.spec.credential.clone(),
            self.spec.model(),
            usage.input_tokens,
            usage.output_tokens,
        )
        .cached(usage.cached_input_tokens)
        .reasoning(usage.reasoning_tokens);
        self.store.record_usage(session, &record, Utc::now())?;

        Ok(PreparedOutcome::Ran(ChildRecord {
            model: self.spec.model().to_string(),
            credential: self.spec.credential.clone(),
            clamps: self.spec.clamps.clone(),
            usage: record,
            base_url: self.spec.base_url.clone(),
            dead_members: Vec::new(),
            tools_used: Vec::new(),
        }))
    }
}

/// The spawner that draws children from a model pool.
///
/// Owns the pool (and its health state), and the provider resolution, secret resolution and store it
/// needs to make the narrowest real call and to record it.
/// What a child tool loop executes against: the tool registry, the host and workspace the
/// tools act in, and the capability token that gates them.
///
/// A spawner built with [`Spawner::new`] holds none of this and runs the single-call path
/// exactly as before. [`Spawner::with_child_tools`] opts in; a spec that names tools on a
/// spawner without one fails honestly instead of running unconfined.
pub struct ChildToolEnv {
    pub registry: Arc<ToolRegistry>,
    pub ctx: ToolContext,
    pub capability: CapabilityToken,
}

/// The spawner that draws children from a model pool.
///
/// Owns the pool (and its health state), and the provider resolution, secret resolution and store it
/// needs to make the narrowest real call and to record it.
pub struct Spawner {
    pool: ModelPool,
    providers: Arc<ProviderRegistry>,
    secrets: Arc<SecretStores>,
    store: Arc<hx_store::Store>,
    child_tools: Option<ChildToolEnv>,
}

impl Spawner {
    pub fn new(
        pool: ModelPool,
        providers: Arc<ProviderRegistry>,
        secrets: Arc<SecretStores>,
        store: Arc<hx_store::Store>,
    ) -> Self {
        Self {
            pool,
            providers,
            secrets,
            store,
            child_tools: None,
        }
    }

    /// Opt this spawner into the child tool loop: specs naming tools execute them against this
    /// registry, host/workspace and capability token. Specs naming no tools are unaffected.
    pub fn with_child_tools(mut self, env: ChildToolEnv) -> Self {
        self.child_tools = Some(env);
        self
    }

    /// Draw a healthy member and clamp the requested parameters to it, producing the child's spec.
    ///
    /// Fails loudly (with the pool's own [`DrawError`]) when the pool is empty or every member is
    /// down — it never silently returns the first member. The clamp is applied **here, at spawn**, so a
    /// member that rejects a requested kind never reaches the wire with it: that is what prevents the
    /// `HTTP 400`. The clamps are recorded on the spec, with the child.
    pub fn build_spec(&mut self, requested: &[Param]) -> Result<ChildSpec, DrawError> {
        let member = self.pool.draw()?;
        let effective = member.clamp(requested);
        Ok(ChildSpec {
            member_id: member.id.clone(),
            base_url: member.base_url.clone(),
            credential: member.credential.clone(),
            params: effective.params,
            clamps: effective.clamps,
            // Default off: no tools, so `run_child` takes exactly today's single-call path.
            tools: Vec::new(),
            max_tool_iters: DEFAULT_MAX_TOOL_ITERS,
        })
    }

    /// Run one child: one provider call against the spec's (drawn) member, then record its usage.
    ///
    /// The provider is resolved by the **drawn member's id** and the request is built with the
    /// **drawn member's** model, so the recorded [`UsageRecord`]'s `model` is the member this spec
    /// drew — not the first member, not a global. On a failed call the member is marked down, so the
    /// next [`Self::build_spec`] draws from a healthy member. This is the narrow one-shot form; for a
    /// run that **re-routes onto a healthy member when the drawn one dies**, use [`Self::run_lane`].
    ///
    /// When the spec names tools ([`ChildSpec::tools`] non-empty) this runs the bounded child tool
    /// loop instead ([`Self::run_child_loop`]): provider call → tool calls → tool results, until the
    /// model answers without a tool call or `max_tool_iters` is hit. Empty `tools` keeps exactly
    /// today's single call — same request, same recording, same cost.
    pub fn prepare_child(&self, spec: &ChildSpec) -> Result<PreparedChild> {
        let provider = self
            .providers
            .resolve(&ProviderId::from(spec.member_id.clone()), spec.model())
            .map_err(|err| hx_core::error::HxError::NoRoute(err.to_string()))?;
        let key = self
            .secrets
            .resolve_str(&spec.credential)
            .map_err(|err| hx_core::error::HxError::Secret(err.to_string()))?;
        Ok(PreparedChild {
            provider,
            key,
            spec: spec.clone(),
            store: Arc::clone(&self.store),
        })
    }

    /// Bench a member with a reason, timestamped now.
    ///
    /// This is the pool-health half of a failed child run, exposed so the fan-out can apply it
    /// serially after its concurrent join. Same write `run_child` always did, same clock.
    pub fn mark_down(&mut self, member: &str, reason: String) {
        self.pool.mark_down(member, reason, Utc::now());
    }

    pub async fn run_child(
        &mut self,
        spec: &ChildSpec,
        session: &SessionId,
        prompt: &str,
    ) -> Result<ChildRecord> {
        let provider = self
            .providers
            .resolve(&ProviderId::from(spec.member_id.clone()), spec.model())
            .map_err(|err| hx_core::error::HxError::NoRoute(err.to_string()))?;
        let key = self
            .secrets
            .resolve_str(&spec.credential)
            .map_err(|err| hx_core::error::HxError::Secret(err.to_string()))?;

        if !spec.tools.is_empty() {
            return self
                .run_child_loop(spec, session, prompt, &provider, &key)
                .await;
        }

        let request = ChatRequest::new(spec.model(), vec![Message::user(prompt)]);
        let response = match provider.complete(request, &key).await {
            Ok(response) => response,
            Err(err) => {
                self.pool
                    .mark_down(&spec.member_id, redact_death_reason(&key, &err), Utc::now());
                return Err(err);
            }
        };

        let usage = response.usage;
        let record = UsageRecord::new(
            spec.member_id.clone(),
            spec.credential.clone(),
            spec.model(),
            usage.input_tokens,
            usage.output_tokens,
        )
        .cached(usage.cached_input_tokens)
        .reasoning(usage.reasoning_tokens);
        self.store.record_usage(session, &record, Utc::now())?;

        Ok(ChildRecord {
            model: spec.model().to_string(),
            credential: spec.credential.clone(),
            clamps: spec.clamps.clone(),
            usage: record,
            base_url: spec.base_url.clone(),
            dead_members: Vec::new(),
            tools_used: Vec::new(),
        })
    }

    /// The opt-in bounded tool loop: provider call → tool calls → tool results, until the model
    /// answers without a tool call, `max_tool_iters` tool-executing iterations run, or a tool is
    /// denied.
    ///
    /// Deliberately **not** `hx-agent`'s loop: that loop is coupled to sessions, the transcript
    /// store, the approval queue and a human approver, and reusing it would pull the daemon's
    /// session machinery into a child. A child has no approver to ask, so the gate is the
    /// capability token alone — the same two phases a normal run applies *before* approval
    /// (`prepare`, then the capability check): an unknown tool or unusable arguments comes back as
    /// a tool result the model can act on, while a capability denial fails the child as a recorded
    /// error, never a bypass, and there is no approval prompt to answer.
    ///
    /// Only [`CHILD_TOOL_ALLOWLIST`] names may run (`read_file`, `write_file`): a call for any
    /// other name — outside the allow-list, or simply not in this spec's `tools` — is refused, not
    /// executed, and fails the child. Token usage is summed across iterations and recorded once,
    /// on the final answer; a child that never answers (bound hit, denial, provider failure)
    /// records nothing, the same as any failed single call.
    async fn run_child_loop(
        &mut self,
        spec: &ChildSpec,
        session: &SessionId,
        prompt: &str,
        provider: &Arc<dyn Provider>,
        key: &Secret,
    ) -> Result<ChildRecord> {
        let env = self.child_tools.as_ref().ok_or_else(|| {
            HxError::Config(format!(
                "child '{}' names tools ({}) but this spawner was built without a tool \
                 environment; refusing to run unconfined",
                spec.member_id,
                spec.tools.join(", ")
            ))
        })?;
        for name in &spec.tools {
            if !CHILD_TOOL_ALLOWLIST.contains(&name.as_str()) {
                return Err(HxError::Denied(format!(
                    "child tool '{name}' is not in the child allow-list ({}); refused, not executed",
                    CHILD_TOOL_ALLOWLIST.join(", ")
                )));
            }
        }
        // Advertise exactly the allowed tools — and only ones the registry actually holds. An
        // allowed name with no implementation is refused now, not mid-loop.
        let mut tool_specs = Vec::new();
        for info in env.registry.describe() {
            if spec.tools.iter().any(|name| name == &info.name) {
                tool_specs.push(ToolSpec {
                    name: info.name,
                    description: info.description,
                    input_schema: info.schema,
                });
            }
        }
        for name in &spec.tools {
            if !tool_specs.iter().any(|tool| &tool.name == name) {
                return Err(HxError::Denied(format!(
                    "child tool '{name}' is allowed but no such tool is registered; refused, not executed"
                )));
            }
        }

        let mut messages = vec![Message::user(prompt)];
        let mut tools_used: Vec<String> = Vec::new();
        let mut total = Usage::default();
        for _ in 0..spec.max_tool_iters {
            let request =
                ChatRequest::new(spec.model(), messages.clone()).with_tools(tool_specs.clone());
            let response = match provider.complete(request, key).await {
                Ok(response) => response,
                Err(err) => {
                    self.pool
                        .mark_down(&spec.member_id, redact_death_reason(key, &err), Utc::now());
                    return Err(err);
                }
            };
            total.input_tokens += response.usage.input_tokens;
            total.output_tokens += response.usage.output_tokens;
            total.cached_input_tokens += response.usage.cached_input_tokens;
            total.reasoning_tokens += response.usage.reasoning_tokens;

            let calls: Vec<(hx_core::ids::ToolCallId, String, serde_json::Value)> = response
                .message
                .parts
                .iter()
                .filter_map(|part| match part {
                    Part::ToolCall {
                        id,
                        name,
                        arguments,
                    } => Some((id.clone(), name.clone(), arguments.clone())),
                    _ => None,
                })
                .collect();
            messages.push(response.message);
            if calls.is_empty() {
                let record = UsageRecord::new(
                    spec.member_id.clone(),
                    spec.credential.clone(),
                    spec.model(),
                    total.input_tokens,
                    total.output_tokens,
                )
                .cached(total.cached_input_tokens)
                .reasoning(total.reasoning_tokens);
                self.store.record_usage(session, &record, Utc::now())?;
                return Ok(ChildRecord {
                    model: spec.model().to_string(),
                    credential: spec.credential.clone(),
                    clamps: spec.clamps.clone(),
                    usage: record,
                    base_url: spec.base_url.clone(),
                    dead_members: Vec::new(),
                    tools_used,
                });
            }

            for (id, name, arguments) in calls {
                // The model was advertised exactly `spec.tools`: anything else is refused, not
                // executed — even when the registry holds that name.
                if !spec.tools.iter().any(|allowed| allowed == &name) {
                    return Err(HxError::Denied(format!(
                        "child called tool '{name}', which is not in its allowed tools ({}); \
                         refused, not executed",
                        spec.tools.join(", ")
                    )));
                }
                let prepared = match env.registry.prepare(&name, arguments, &env.ctx) {
                    Ok(prepared) => prepared,
                    Err(err) => {
                        messages.push(Message::tool_result(
                            id,
                            false,
                            format!("could not run {name}: {err}"),
                        ));
                        continue;
                    }
                };
                if let Some(requirement) = prepared.requirement() {
                    match env
                        .capability
                        .check(&requirement.resource, requirement.action, Utc::now())
                    {
                        Decision::Allow => {}
                        Decision::Deny(reason) => {
                            return Err(HxError::Denied(format!(
                                "child tool '{name}' denied: {reason}; never a bypass"
                            )));
                        }
                    }
                }
                match prepared.run(&env.ctx).await {
                    Ok(outcome) => {
                        tools_used.push(name);
                        messages.push(Message::tool_result(id, outcome.ok, outcome.content));
                    }
                    Err(err) => {
                        messages.push(Message::tool_result(
                            id,
                            false,
                            format!("{name} failed: {err}"),
                        ));
                    }
                }
            }
        }
        Err(HxError::Tool(format!(
            "child tool loop hit its bound of {} iterations without a final answer",
            spec.max_tool_iters
        )))
    }

    /// Run a child that **re-routes on member death** and continues, rather than failing the lane.
    ///
    /// This is the half of M8 this module previously named out of scope ("needs running children").
    /// It draws a healthy member from the pool, makes **one** provider call against it; if that member
    /// **dies** while running — per [`member_death`], a 5xx/timeout/404, an exhausted quota, or a
    /// refused credential — it marks the member down, **re-draws** onto the pool's next healthy member
    /// and runs the same prompt there, and keeps going. It fails **bounded**: when the pool can draw
    /// no healthy member it fails with the pool's own [`DrawError::AllDown`] (or `Empty`), exactly
    /// as `build_spec` would — it never retries forever, and it never returns a success it did not
    /// earn. The bound is "every member tried once each", stated as the loop's stop condition.
    ///
    /// **Audit.** The returned [`ChildRecord`] carries **both** sides of the re-route: the dying
    /// members in [`ChildRecord::dead_members`] (each `id` with the reason it died) and the member
    /// that **finished** as [`ChildRecord::model`], the one whose `UsageRecord` is persisted to the
    /// store. A silent model switch — the audit showing the first member and nothing else — is the
    /// failure mode this field exists to make impossible.
    ///
    /// **Only on death.** A failure that is the **child's own** — a [`HxError::ProviderRejected`]
    /// 400/422 on the request, a policy denial, an unresolved credential reference, a missing route —
    /// is deterministic: every member refuses it the same way. It **does not** trigger a re-route, and
    /// it does **not** bench the member (the member is not down for a request it never saw); the run
    /// returns that error directly. Re-routing a deterministic failure would turn one error into one per
    /// member.
    ///
    /// The pool alone decides health: a member that dies here is marked down on the shared pool, so it
    /// is gone for **subsequent** draws by other children, not just this one (`mark_down` is the
    /// mechanism, not a lane-local flag).
    ///
    /// Hermetic: a scripted pool plus a scripted provider, no network; the only loop is over the
    /// pool's own members, so it is bounded by construction and needs no wall-clock or sleep.
    pub async fn run_lane(
        &mut self,
        session: &SessionId,
        prompt: &str,
        requested: &[Param],
    ) -> Result<ChildRecord, hx_core::error::HxError> {
        let mut dead_members: Vec<(String, String)> = Vec::new();
        let mut spec = match self.build_spec(requested) {
            Ok(spec) => spec,
            Err(DrawError::Empty) => {
                return Err(HxError::NoRoute(
                    "the model pool has no members".to_string(),
                ))
            }
            Err(DrawError::AllDown { members }) => {
                let detail = members
                    .iter()
                    .map(|(id, reason)| format!("{id} ({reason})"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(HxError::Provider(format!(
                    "every member of the model pool is down: {detail}"
                )));
            }
        };
        loop {
            let provider = self
                .providers
                .resolve(&ProviderId::from(spec.member_id.clone()), spec.model())
                .map_err(|err| hx_core::error::HxError::NoRoute(err.to_string()))?;
            let key = self
                .secrets
                .resolve_str(&spec.credential)
                .map_err(|err| hx_core::error::HxError::Secret(err.to_string()))?;

            let request = ChatRequest::new(spec.model(), vec![Message::user(prompt)]);
            match provider.complete(request, &key).await {
                Ok(response) => {
                    let usage = response.usage;
                    let record = UsageRecord::new(
                        spec.member_id.clone(),
                        spec.credential.clone(),
                        spec.model(),
                        usage.input_tokens,
                        usage.output_tokens,
                    )
                    .cached(usage.cached_input_tokens)
                    .reasoning(usage.reasoning_tokens);
                    self.store.record_usage(session, &record, Utc::now())?;
                    return Ok(ChildRecord {
                        model: spec.model().to_string(),
                        credential: spec.credential.clone(),
                        clamps: spec.clamps.clone(),
                        usage: record,
                        base_url: spec.base_url.clone(),
                        dead_members,
                        // `run_lane` is a single prompt run that re-draws on death; it never runs
                        // the child tool loop, so there are no tools to record.
                        tools_used: Vec::new(),
                    });
                }
                Err(err) => {
                    if !member_death(&err) {
                        // The child's own fault: deterministic across every member, so it must not
                        // re-route and must not bench a member that never saw the bad request.
                        return Err(err);
                    }
                    // The member died: mark it down (shared pool health, so later draws skip it) and,
                    // if the pool still has a healthy member, re-draw and continue.
                    self.pool.mark_down(
                        &spec.member_id,
                        redact_death_reason(&key, &err),
                        Utc::now(),
                    );
                    dead_members.push((spec.member_id.clone(), redact_death_reason(&key, &err)));
                    // Re-draw onto a healthy member. AllDown / Empty means every member has been tried
                    // once — the bound — so re-use the pool's own error rather than a second type.
                    spec = match self.build_spec(requested) {
                        Ok(next) => next,
                        Err(DrawError::Empty) => {
                            return Err(HxError::NoRoute(
                                "the model pool has no members".to_string(),
                            ))
                        }
                        Err(DrawError::AllDown { members }) => {
                            let detail = members
                                .iter()
                                .map(|(id, reason)| format!("{id} ({reason})"))
                                .collect::<Vec<_>>()
                                .join("; ");
                            return Err(HxError::Provider(format!(
                                "every member of the model pool is down: {detail}"
                            )));
                        }
                    };
                }
            }
        }
    }
}

/// What a run produced and recorded for a child.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ChildRecord {
    /// The model (drawn member) this child **finished** on.
    pub model: String,
    /// The credential **reference** that paid for it.
    pub credential: String,
    /// The clamps that were applied at spawn, carried to the record's caller.
    pub clamps: Vec<ParamClamp>,
    /// The recorded usage row: the half of "which model did this work and did this lane spend money"
    /// that is answerable after the fact.
    pub usage: UsageRecord,
    pub base_url: String,
    /// The members that **died** while this child ran, in order, each `(member id, reason)`, before
    /// the child re-routed and finished on [`ChildRecord::model`]. Empty when there was no re-route.
    /// This is the audit half of a re-route: it shows both the member that died *and* the member that
    /// finished, so a model switch is never silent.
    pub dead_members: Vec<(String, String)>,
    /// The tools this child executed, in order, one entry per execution (repeats included).
    /// Empty when the loop never ran — every single-call child and every `run_lane` run.
    pub tools_used: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hx_core::config::ProviderKind;
    use hx_core::error::{HxError, Result};
    use hx_core::pool::{MemberHealth, PoolMember, ReasoningEffort};
    use hx_provider::{Provider, Usage};
    use hx_secrets::FixedSecrets;
    use hx_store::NewSession;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed test timestamp")
    }

    fn member(id: &str, accepts: &[Param]) -> PoolMember {
        PoolMember {
            id: id.to_string(),
            base_url: format!("{id}.example.test"),
            credential: format!("vault:pool/{id}"),
            accepts: accepts.to_vec(),
            health: MemberHealth::Healthy,
        }
    }

    /// One provider call, as the provider saw it.
    ///
    /// Recorded so a test can ask what the call actually carried: the model string, the credential
    /// *value* that was resolved for it, and the request as the wire would see it.
    #[derive(Clone, Debug)]
    struct Seen {
        model: String,
        credential: String,
        request: String,
    }

    /// The scripted answer a provider returns instead of a success.
    #[derive(Clone, Copy)]
    enum ScriptedErr {
        /// Answer normally.
        None,
        /// A 5xx — the member itself failed, a death the re-route acts on.
        Die,
        /// A refused request — the child's fault, deterministic across every member.
        Reject,
        /// A policy denial — the same decision on every member, so it must not re-route.
        Denied,
        /// A secret-resolution failure reported by the provider/client — a deployment fact,
        /// not this member's health, so it must not re-route.
        Secret,
    }

    /// A provider that answers without a network. The id is the member it stands in for.
    ///
    /// `err` scripts *how* the member answers when it does not succeed, so tests can distinguish a
    /// member death (a 5xx — worth re-routing) from a request the member refused (a 400 — not).
    struct ScriptedProvider {
        id: ProviderId,
        err: ScriptedErr,
        /// The model the upstream *echoes back*. `None` means the member's own id, which is the
        /// trap: a fixture whose echo is the id cannot tell a record that took its model from the
        /// drawn member from one that took it from the response.
        echoes: Option<String>,
        seen: std::sync::Mutex<Vec<Seen>>,
    }

    impl ScriptedProvider {
        fn new(id: &str) -> Arc<Self> {
            Arc::new(Self {
                id: ProviderId::from(id),
                err: ScriptedErr::None,
                echoes: None,
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn failing(self: &Arc<Self>) -> Arc<Self> {
            Arc::new(Self {
                id: self.id.clone(),
                err: ScriptedErr::Die,
                echoes: self.echoes.clone(),
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        /// The upstream names a different model than the pool member's id.
        fn echoing(self: &Arc<Self>, model: &str) -> Arc<Self> {
            Arc::new(Self {
                id: self.id.clone(),
                err: self.err,
                echoes: Some(model.to_string()),
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> usize {
            self.seen.lock().expect("the seen lock").len()
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().expect("the seen lock").clone()
        }
    }

    /// A registry holding one scripted provider for `member_id`, plus the provider itself so a test
    /// can read back what it was handed.
    fn registry_and_provider(member_id: &str) -> (Arc<ProviderRegistry>, Arc<ScriptedProvider>) {
        let provider = ScriptedProvider::new(member_id);
        let mut reg = ProviderRegistry::new();
        reg.insert(provider.clone());
        (Arc::new(reg), provider)
    }

    fn provider_registry_for(member_id: &str) -> Arc<ProviderRegistry> {
        registry_and_provider(member_id).0
    }

    /// The usage rows the store actually wrote, read back out of the database file rather than out of
    /// the record this module returns: `(provider, credential, model)`, in write order.
    ///
    /// A store's own reader cannot answer this — `Totals` has no model — and the durable row is the
    /// claim ("the recorded `UsageRecord`'s model is the drawn member"), so it is read the way a
    /// later auditor would.
    fn durable_usage_rows(
        store: &hx_store::Store,
        session: &SessionId,
    ) -> Vec<(String, String, String)> {
        let path = store
            .path()
            .expect("a store opened on a path knows its path");
        let conn = rusqlite::Connection::open(path).expect("the store file opens");
        let mut stmt = conn
            .prepare(
                "SELECT provider, credential, model FROM usage WHERE session_id = ?1 ORDER BY id",
            )
            .expect("the usage query prepares");
        stmt.query_map([session.as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .expect("the usage query runs")
        .map(|row| row.expect("a usage row"))
        .collect()
    }

    fn secrets_for(id: &str) -> Arc<SecretStores> {
        Arc::new(SecretStores::new().with(Arc::new(
            FixedSecrets::new("vault").set(format!("pool/{id}"), "sentinel"),
        )))
    }

    fn store() -> Arc<hx_store::Store> {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!("hx-spawner-{}-{n}.db", std::process::id()));
        Arc::new(hx_store::Store::open(path).expect("test store opens"))
    }

    fn session(store: &hx_store::Store) -> hx_store::Session {
        let rec = store
            .create(NewSession::new(), now())
            .expect("session created");
        store.load(&rec.id).expect("session loads")
    }

    #[async_trait]
    impl Provider for ScriptedProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> ProviderKind {
            ProviderKind::Openai
        }
        fn models(&self) -> &[String] {
            &[]
        }
        async fn complete(
            &self,
            req: ChatRequest,
            key: &hx_secrets::Secret,
        ) -> Result<hx_provider::ChatResponse> {
            self.seen.lock().expect("the seen lock").push(Seen {
                model: req.model.clone(),
                // Named `expose` so the call site is greppable: this is a test double reading the
                // credential it was handed, which is the only way to see *which* member paid.
                credential: key.expose().to_string(),
                request: format!("{req:?}"),
            });
            match self.err {
                ScriptedErr::Die => {
                    // Simulate a provider that echoes the very key it was given back in its error
                    // body — the leak `redact_death_reason` is there to catch.
                    return Err(HxError::Provider(format!(
                        "upstream returned HTTP 500 (key: {})",
                        key.expose()
                    )));
                }
                ScriptedErr::Reject => {
                    return Err(HxError::ProviderRejected {
                        provider: self.id.to_string(),
                        reason: "the request was rejected (HTTP 400): unknown parameter"
                            .to_string(),
                    })
                }
                ScriptedErr::Denied => {
                    return Err(HxError::Denied(
                        "writes outside the workspace are not allowed".to_string(),
                    ))
                }
                ScriptedErr::Secret => {
                    return Err(HxError::Secret(
                        "no store could resolve the credential reference".to_string(),
                    ))
                }
                ScriptedErr::None => {}
            }
            let usage = Usage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            };
            Ok(hx_provider::ChatResponse {
                message: hx_core::message::Message::assistant("done"),
                usage,
                finish: hx_provider::FinishReason::Stop,
                model: self.echoes.clone().unwrap_or_else(|| self.id.to_string()),
                raw: None,
            })
        }
    }

    #[tokio::test]
    async fn build_spec_carries_the_drawn_member_and_its_identity() {
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("cheap", &[]), member("strong", &[])]),
            provider_registry_for("cheap"),
            secrets_for("cheap"),
            store(),
        );
        let spec = pen.build_spec(&[]).expect("both healthy");
        assert_eq!(spec.model(), "cheap", "the first draw is the first member");
        assert!(spec.clamps.is_empty());
        assert_eq!(spec.base_url, "cheap.example.test");
        assert_eq!(spec.credential, "vault:pool/cheap");
    }

    #[tokio::test]
    async fn a_member_that_rejects_reasoning_effort_is_clamped_and_runs_not_errored_at_spawn() {
        // strong accepts only Low; we ask for High. The exit criterion: it is clamped at spawn and
        // the child runs — not a spawn-time failure and not a 400.
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member(
                "strong",
                &[Param::reasoning_effort(ReasoningEffort::Low)],
            )]),
            provider_registry_for("strong"),
            secrets_for("strong"),
            st.clone(),
        );
        let requested = [Param::reasoning_effort(ReasoningEffort::High)];
        let spec = pen.build_spec(&requested).expect("clamped, not failed");
        assert_eq!(
            spec.params,
            vec![Param::reasoning_effort(ReasoningEffort::Low)],
            "High is clamped to the member's only accepted value"
        );
        assert_eq!(
            spec.clamps,
            vec![ParamClamp {
                requested: Param::reasoning_effort(ReasoningEffort::High),
                sent: Some(Param::reasoning_effort(ReasoningEffort::Low)),
            }]
        );

        let s = session(&st);
        let rec = pen
            .run_child(&spec, s.id(), "hi")
            .await
            .expect("a clamped child runs");
        assert_eq!(rec.usage.model, "strong");
        assert_eq!(rec.usage.input_tokens, 10);
    }

    #[tokio::test]
    async fn a_failed_member_marks_down_and_the_next_spec_draws_a_healthy_one() {
        // The registry resolves a member's id to its own provider; a is scripted to fail.
        let mut reg = ProviderRegistry::new();
        reg.insert(ScriptedProvider::new("a").failing());
        reg.insert(ScriptedProvider::new("b"));
        let mut secrets = FixedSecrets::new("vault").set("pool/a", "sentinel-a");
        secrets = secrets.set("pool/b", "sentinel-b");
        let secrets = Arc::new(SecretStores::new().with(Arc::new(secrets)));
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            Arc::new(reg),
            secrets,
            st.clone(),
        );
        let spec_a = pen.build_spec(&[]).expect("draws");
        assert_eq!(spec_a.model(), "a");
        let s = session(&st);
        let err = pen
            .run_child(&spec_a, s.id(), "hi")
            .await
            .expect_err("a fails");
        assert!(err.to_string().contains("HTTP 500"), "{err}");

        // Many draws must never come back to a while b is healthy — only mark_down makes that true.
        for _ in 0..10 {
            let spec = pen.build_spec(&[]).expect("b is healthy");
            assert_eq!(
                spec.model(),
                "b",
                "a down member is not drawn while a healthy one remains"
            );
        }
    }

    #[tokio::test]
    async fn the_recorded_model_is_the_drawn_member_not_the_first_or_a_global() {
        // Mark "a" down so the draw skips the first member: the recorded model must be b, not a.
        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[])]);
        pool.mark_down("a", "boom", now());
        let st = store();
        let mut pen = Spawner::new(
            pool,
            provider_registry_for("b"),
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("b is healthy");
        assert_eq!(spec.model(), "b");

        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");
        assert_eq!(rec.usage.model, "b");
        assert_eq!(rec.model, "b");
        // Read back out of the database, not out of the record this module just handed us: the claim
        // is about what was *recorded*, and a returned record agreeing with itself proves nothing.
        // (This assertion replaced `assert_eq!(s.record.id.as_str(), s.id().as_str())`, which
        // compared a value to the value it was built from and therefore could not fail.)
        assert_eq!(
            durable_usage_rows(&st, s.id()),
            vec![("b".to_string(), "vault:pool/b".to_string(), "b".to_string())],
            "the durable row names the drawn member and the reference that paid"
        );
    }

    #[tokio::test]
    async fn run_child_makes_exactly_one_provider_call() {
        // "one provider call" is a claim in the module doc, and a hidden retry would spend a second
        // call's money while recording one row.
        let (reg, provider) = registry_and_provider("b");
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("b", &[])]),
            reg,
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        assert_eq!(provider.calls(), 1, "one child is one provider call");
        assert_eq!(
            provider.seen()[0].model,
            "b",
            "and the request asked the drawn member's provider for the drawn member's model"
        );
        assert_eq!(
            st.totals(s.id()).expect("totals read").provider_calls,
            1,
            "and exactly one row for it"
        );
    }

    #[tokio::test]
    async fn a_successful_call_leaves_the_member_healthy() {
        // A single-member pool on purpose. With two healthy members the round-robin hands out the
        // other one whether or not the first was marked down, so a two-member fixture cannot see a
        // success that wrongly marks its member down — this one can: the pool would be all-down.
        let (reg, _provider) = registry_and_provider("only");
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("only", &[])]),
            reg,
            secrets_for("only"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        let next = pen
            .build_spec(&[])
            .expect("a member that answered must still be drawable");
        assert_eq!(next.model(), "only");
    }

    #[tokio::test]
    async fn two_spawns_in_a_row_draw_two_different_healthy_members() {
        // `build_spec` must go through the pool's own draw, not pick the first healthy member: the
        // cursor is what spreads children across a pool, and a first-healthy pick is invisible to
        // every other test in this module.
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            provider_registry_for("a"),
            secrets_for("a"),
            store(),
        );
        assert_eq!(pen.build_spec(&[]).expect("draws").model(), "a");
        assert_eq!(
            pen.build_spec(&[]).expect("draws").model(),
            "b",
            "the second draw is the next healthy member, not the first one again"
        );
        assert_eq!(
            pen.build_spec(&[]).expect("draws").model(),
            "a",
            "and it cycles"
        );
    }

    #[tokio::test]
    async fn the_recorded_model_is_the_drawn_member_even_when_the_upstream_names_another_model() {
        // A real provider answers with the checkpoint it ran, which is not the pool member's id.
        // This is the only fixture that can tell a record built from the drawn member from one built
        // from the response.
        let provider = ScriptedProvider::new("b").echoing("upstream-2026-01-01");
        let mut reg = ProviderRegistry::new();
        reg.insert(provider.clone());
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("b", &[])]),
            Arc::new(reg),
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        assert_eq!(
            rec.usage.model, "b",
            "the drawn member is the model of record, not the upstream's name for it"
        );
        assert_eq!(rec.model, "b");
        assert_eq!(
            durable_usage_rows(&st, s.id())[0].2,
            "b",
            "and the durable row says the same"
        );
    }

    #[tokio::test]
    async fn the_drawn_members_credential_pays_and_only_its_reference_is_recorded() {
        // Two members, the first down, with *different* secret values: so "the drawn member's
        // credential" is distinguishable from "the first member's", and the resolved value is
        // distinguishable from the reference that names it.
        let mut reg = ProviderRegistry::new();
        reg.insert(ScriptedProvider::new("a"));
        let provider_b = ScriptedProvider::new("b");
        reg.insert(provider_b.clone());
        let mut secrets = FixedSecrets::new("vault").set("pool/a", "sentinel-a");
        secrets = secrets.set("pool/b", "sentinel-b");
        let secrets = Arc::new(SecretStores::new().with(Arc::new(secrets)));

        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[])]);
        pool.mark_down("a", "boom", now());
        let st = store();
        let mut pen = Spawner::new(pool, Arc::new(reg), secrets, st.clone());
        let spec = pen.build_spec(&[]).expect("b is healthy");
        assert_eq!(spec.credential, "vault:pool/b");

        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        // The value really was resolved and really was handed over. Without this, "the value is not
        // recorded" would pass against a spawner that resolved nothing at all.
        let seen = provider_b.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].credential, "sentinel-b",
            "the drawn member's secret is what paid for the call"
        );
        assert!(
            !rec.credential.contains("sentinel"),
            "the record carries the reference, not the value: {:?}",
            rec.credential
        );

        let rows = durable_usage_rows(&st, s.id());
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].1, "vault:pool/b",
            "the durable row holds the reference, never the resolved value"
        );
        assert!(
            !rows[0].1.contains("sentinel"),
            "a usage row is not a place a live credential may land: {:?}",
            rows[0].1
        );
    }

    /// DEFECT (verify-spawner): the clamped parameters never reach the provider call.
    ///
    /// The module doc says `run_child` makes its call "with the **clamped** parameters", and that the
    /// clamp applied at spawn "is what prevents the `HTTP 400`". It does not: `hx-provider`'s
    /// `ChatRequest` has no field for a pool `Param`, and `run_child` fills none, so a parameter a
    /// member would reject is never sent — and neither is one it would accept. The clamp is recorded
    /// on the spec and on the record and stops there. Un-ignore this when `ChatRequest` grows the
    /// field and `run_child` sets it from `spec.params`.
    #[tokio::test]
    #[ignore = "the clamped parameters do not reach the request: hx-provider's ChatRequest has no field for a pool Param"]
    async fn the_clamped_parameter_reaches_the_provider_call() {
        let (reg, provider) = registry_and_provider("strong");
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member(
                "strong",
                &[Param::reasoning_effort(ReasoningEffort::Low)],
            )]),
            reg,
            secrets_for("strong"),
            st.clone(),
        );
        let requested = [Param::reasoning_effort(ReasoningEffort::High)];
        let spec = pen.build_spec(&requested).expect("clamped, not failed");
        let s = session(&st);
        pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        let seen = provider.seen();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].request.contains("reasoning_effort"),
            "the clamped parameter must reach the request the provider is handed: {}",
            seen[0].request
        );
    }

    #[tokio::test]
    async fn the_recorded_cost_and_model_survive_into_the_store_totals() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("b", &[])]),
            provider_registry_for("b"),
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");
        assert_eq!(rec.usage.model, "b");
        let totals = st.totals(s.id()).expect("totals read");
        assert_eq!(totals.provider_calls, 1);
        assert_eq!(totals.input_tokens, 10);
    }

    #[tokio::test]
    async fn a_spec_cannot_be_built_from_an_empty_pool() {
        let mut pen = Spawner::new(
            ModelPool::new(vec![]),
            provider_registry_for("x"),
            secrets_for("x"),
            store(),
        );
        assert_eq!(pen.build_spec(&[]), Err(DrawError::Empty));
    }

    #[tokio::test]
    async fn a_spec_cannot_be_built_when_every_member_is_down() {
        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[])]);
        pool.mark_down("a", "boom-a", now());
        pool.mark_down("b", "boom-b", now());
        let mut pen = Spawner::new(pool, provider_registry_for("a"), secrets_for("a"), store());
        match pen.build_spec(&[]) {
            Err(DrawError::AllDown { members }) => {
                assert_eq!(members.len(), 2);
            }
            other => panic!("must be AllDown, got {other:?}"),
        }
    }

    /// Build a registry with one scripted provider per `(id, err)` entry, so each member can be
    /// scripted independently (die, reject, or succeed).
    fn scripted_registry(specs: &[(&str, ScriptedErr)]) -> Arc<ProviderRegistry> {
        let mut reg = ProviderRegistry::new();
        for &(id, err) in specs {
            reg.insert(Arc::new(ScriptedProvider {
                id: ProviderId::from(id),
                err,
                echoes: None,
                seen: std::sync::Mutex::new(Vec::new()),
            }));
        }
        Arc::new(reg)
    }

    /// Secrets for a list of member ids, each under `vault:pool/<id>`.
    fn scripted_secrets(ids: &[&str]) -> Arc<SecretStores> {
        let mut built = FixedSecrets::new("vault");
        for id in ids {
            built = built.set(format!("pool/{id}"), format!("sentinel-{id}"));
        }
        Arc::new(SecretStores::new().with(Arc::new(built)))
    }

    /// A member that dies mid-flight is re-drawn onto a healthy member and the child continues — and the
    /// audit shows **both**: the dying member in `dead_members`, the finishing member as the model.
    #[tokio::test]
    async fn a_member_that_dies_mid_flight_reroutes_and_records_both_members() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Die), ("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let rec = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect("the child re-routes and continues");

        // The child finished on the healthy member…
        assert_eq!(rec.model, "b", "the finish is on the healthy member");
        assert_eq!(rec.usage.model, "b");
        // …and the audit names the one that died and why — a model switch is never silent.
        assert_eq!(rec.dead_members.len(), 1, "{:?}", rec.dead_members);
        assert_eq!(rec.dead_members[0].0, "a");
        assert!(
            rec.dead_members[0].1.contains("500"),
            "{:?}",
            rec.dead_members
        );
        // Health is shared: a dead member stays down for a subsequent draw.
        let spec = pen.build_spec(&[]).expect("b remains healthy");
        assert_eq!(spec.model(), "b");
    }

    /// When every member dies, the run fails bounded with the pool's own AllDown error — it never retries
    /// forever and never returns a success it did not earn.
    #[tokio::test]
    async fn a_run_where_every_member_dies_fails_bounded_and_names_each_member() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Die), ("b", ScriptedErr::Die)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("every member is down");
        let text = err.to_string();
        assert!(
            text.contains("every member of the model pool is down"),
            "{text}"
        );
        assert!(text.contains("a") && text.contains("b"), "{text}");
        // Bounded: exactly the pool's members were tried, once each.
        assert_eq!(
            pen.pool
                .members
                .iter()
                .filter(|m| matches!(m.health, MemberHealth::Down { .. }))
                .count(),
            2
        );
    }

    /// A failure that is the child's own — a refused request — does **not** re-route and does **not**
    /// bench the member that refused it: retrying it across the pool would make one error into N.
    #[tokio::test]
    async fn a_refused_request_does_not_reroute_and_does_not_bench_the_member() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Reject), ("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("the request is refused, not the member");
        assert!(matches!(err, HxError::ProviderRejected { .. }), "{err:?}");
        // a (which never actually failed) is still healthy — a refused request must not bench the member.
        assert_eq!(
            pen.pool.members[0].health,
            MemberHealth::Healthy,
            "a refused request must not bench the member"
        );
        // A subsequent draw reaches the healthy set (b, by the round-robin cursor) and can still run.
        let spec = pen.build_spec(&[]).expect("a healthy member remains");
        assert_eq!(spec.model(), "b");
    }

    /// A missing provider route is a configuration fact (NoRoute), not a member death:
    /// it must not re-route and must not bench.
    #[tokio::test]
    async fn a_missing_provider_route_is_not_a_member_death_and_does_not_reroute() {
        let st = store();
        // a draws, but no provider is registered for it.
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("no route to a is a config fact, not a death");
        assert!(matches!(err, HxError::NoRoute(_)), "{err:?}");
        // a is not benched: a missing provider route is a config fact, not a health one.
        assert_eq!(
            pen.pool.members[0].health,
            MemberHealth::Healthy,
            "a missing route is not a member death"
        );
    }

    /// A policy denial is the same decision on every member, so it must not re-route (one denial
    /// would become one per member) and must not bench the member that never saw the bad request.
    #[tokio::test]
    async fn a_policy_denial_does_not_reroute_and_does_not_bench_the_member() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Denied), ("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("a denial is not a death, so the run returns it directly");
        assert!(matches!(err, HxError::Denied(_)), "{err:?}");
        // a stayed healthy: a policy denial benches nothing.
        assert_eq!(
            pen.pool.members[0].health,
            MemberHealth::Healthy,
            "a policy denial must not bench the member"
        );
    }

    /// A secret-resolution failure reported by the provider is a deployment fact, not this member's
    /// health: it must not re-route and must not bench.
    #[tokio::test]
    async fn a_secret_failure_does_not_reroute_and_does_not_bench_the_member() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Secret), ("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("a secret failure is not a death, so the run returns it directly");
        assert!(matches!(err, HxError::Secret(_)), "{err:?}");
        assert_eq!(
            pen.pool.members[0].health,
            MemberHealth::Healthy,
            "a secret failure must not bench the member"
        );
    }

    /// A leaked credential inside a dead member's failure reason is masked before it is stored on the
    /// pool and returned on the record — the provider can echo the very key it was given in its error body.
    #[tokio::test]
    async fn a_dead_members_reason_has_a_leaked_key_masked() {
        let st = store();
        // The sentinel is a *patternless* opaque value: it is caught only because the spawner
        // registers the resolved key as a literal before redacting the reason.
        let mut secrets = FixedSecrets::new("vault");
        secrets = secrets
            .set("pool/a", "opaque-credential-value-that-leaks")
            .set("pool/b", "sentinel-b");
        let secrets = Arc::new(SecretStores::new().with(Arc::new(secrets)));
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Die), ("b", ScriptedErr::None)]),
            secrets,
            st.clone(),
        );
        let s = session(&st);
        let rec = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect("b still runs after a dies");
        // a died; its reason must not carry the credential "a" was given.
        assert_eq!(rec.dead_members.len(), 1);
        let (member, reason) = &rec.dead_members[0];
        assert_eq!(member, "a");
        assert!(
            !reason.contains("opaque-credential-value-that-leaks"),
            "the leaked key reached the record: {reason}"
        );
        // The pool's stored reason is the same masked one.
        match &pen.pool.members[0].health {
            MemberHealth::Down { reason, .. } => {
                assert!(
                    !reason.contains("opaque-credential-value-that-leaks"),
                    "the leaked key reached pool health: {reason}"
                );
            }
            other => panic!("a must be down, got {other:?}"),
        }
    }

    /// A returned `ChildRecord`'s `Debug` must not carry the resolved credential value — only its
    /// reference — so a log line or an error trace never prints a live key.
    #[tokio::test]
    async fn a_child_records_debug_never_carries_the_resolved_credential() {
        let (reg, _provider) = registry_and_provider("b");
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("b", &[])]),
            reg,
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");
        let debug = format!("{rec:?}");
        assert!(
            !debug.contains("sentinel"),
            "the record's Debug leaked the credential value: {debug}"
        );
        assert!(
            debug.contains("vault:pool/b"),
            "the reference is what the record names: {debug}"
        );
    }

    /// Credential isolation survives a re-route: when member a dies and the lane re-draws onto b,
    /// b is paid with b's own credential value, never a's.
    #[tokio::test]
    async fn a_rerouted_member_is_paid_with_its_own_credential_not_the_dead_members() {
        // Capture each provider so the *value* each was handed can be read back.
        let provider_a = ScriptedProvider::new("a").failing();
        let provider_b = ScriptedProvider::new("b");
        let mut reg = ProviderRegistry::new();
        reg.insert(provider_a.clone());
        reg.insert(provider_b.clone());
        let mut secrets = FixedSecrets::new("vault");
        secrets = secrets
            .set("pool/a", "secret-for-a")
            .set("pool/b", "secret-for-b");
        let secrets = Arc::new(SecretStores::new().with(Arc::new(secrets)));
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            Arc::new(reg),
            secrets,
            st.clone(),
        );
        let s = session(&st);
        pen.run_lane(s.id(), "hi", &[])
            .await
            .expect("re-routes to b");

        // b (which finished) was handed b's own value, not a's — one member's credential never pays
        // for another's work.
        let b_seen = provider_b.seen();
        assert_eq!(b_seen.len(), 1, "b was called exactly once");
        assert_eq!(
            b_seen[0].credential, "secret-for-b",
            "the finishing member is paid with its own credential"
        );
        assert_ne!(
            b_seen[0].credential, "secret-for-a",
            "one member's credential must never pay for another member's call"
        );
    }

    // -----------------------------------------------------------------------------------------
    // The bounded child tool loop.
    // -----------------------------------------------------------------------------------------

    use hx_core::capability::{Capability, CapabilityToken};
    use hx_core::ids::{AgentId, ToolCallId};
    use hx_core::message::{Part, Role};
    use hx_tools::testing::FakeHost;
    use hx_tools::{ReadFileTool, ShellTool, ToolContext, ToolRegistry, WriteFileTool};
    use std::collections::VecDeque;

    /// One scripted turn of a loop provider: either a tool call the child must execute or the
    /// final answer that ends the loop.
    #[derive(Clone)]
    enum LoopTurn {
        Call {
            name: String,
            arguments: serde_json::Value,
        },
        Final(String),
    }

    /// A provider that answers from a script so the loop can be driven without a network. Every
    /// call is recorded as a debug string of the request — the messages array included — so a test
    /// can ask whether a tool result actually reached the model. When the script runs out, `drain`
    /// answers instead: `Final` for a provider that eventually answers, `Call` for one that never
    /// does (the bound test).
    struct LoopProvider {
        id: ProviderId,
        turns: std::sync::Mutex<VecDeque<LoopTurn>>,
        drain: LoopTurn,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl LoopProvider {
        fn new(id: &str, turns: Vec<LoopTurn>, drain: LoopTurn) -> Arc<Self> {
            Arc::new(Self {
                id: ProviderId::from(id),
                turns: std::sync::Mutex::new(turns.into()),
                drain,
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> usize {
            self.seen.lock().expect("the seen lock").len()
        }

        fn seen(&self) -> Vec<String> {
            self.seen.lock().expect("the seen lock").clone()
        }
    }

    #[async_trait]
    impl hx_provider::Provider for LoopProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> ProviderKind {
            ProviderKind::Openai
        }
        fn models(&self) -> &[String] {
            &[]
        }
        async fn complete(
            &self,
            req: ChatRequest,
            _key: &hx_secrets::Secret,
        ) -> Result<hx_provider::ChatResponse> {
            self.seen
                .lock()
                .expect("the seen lock")
                .push(format!("{req:?}"));
            let turn = self
                .turns
                .lock()
                .expect("the turn lock")
                .pop_front()
                .unwrap_or_else(|| self.drain.clone());
            let message = match turn {
                LoopTurn::Call { name, arguments } => Message::new(
                    Role::Assistant,
                    vec![Part::ToolCall {
                        id: ToolCallId::from_raw(format!("tc_{}", self.calls())),
                        name,
                        arguments,
                    }],
                ),
                LoopTurn::Final(text) => Message::assistant(text),
            };
            Ok(hx_provider::ChatResponse {
                message,
                usage: Usage {
                    input_tokens: 10,
                    output_tokens: 5,
                    ..Default::default()
                },
                finish: hx_provider::FinishReason::ToolUse,
                model: self.id.to_string(),
                raw: None,
            })
        }
    }

    /// The tool environment a child loop test runs in: the real `read_file`/`write_file` tools on
    /// an in-memory host, gated by a workspace-scoped capability token — the same two phases
    /// (`prepare`, then the capability check) a normal run applies before approval.
    ///
    /// `shell` is registered on purpose: it is outside the child allow-list, so a test where the
    /// model calls it proves the *allow-list* refused — a registry without `shell` could not tell
    /// "refused" from "unknown tool".
    ///
    /// The token is issued at the real now, not the fixed test timestamp: the loop checks it
    /// against `Utc::now`, and a token issued at the fixed 2023 timestamp would already be expired.
    fn child_env(host: Arc<FakeHost>, workspace: &str) -> ChildToolEnv {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(ReadFileTool::new()));
        registry.register(Arc::new(WriteFileTool::new()));
        registry.register(Arc::new(ShellTool::new()));
        ChildToolEnv {
            registry: Arc::new(registry),
            ctx: ToolContext::new(host as Arc<dyn hx_remote::Host>)
                .in_workspace(workspace.to_string()),
            capability: CapabilityToken::issue(
                AgentId::from_raw("test-child"),
                vec![Capability::workspace(workspace)],
                chrono::Utc::now(),
                3600,
            ),
        }
    }

    fn loop_spawner(
        provider: Arc<LoopProvider>,
        host: Arc<FakeHost>,
        workspace: &str,
    ) -> (Spawner, Arc<LoopProvider>, Arc<FakeHost>) {
        let member_id = provider.id.to_string();
        let mut reg = ProviderRegistry::new();
        reg.insert(provider.clone());
        let st = store();
        let pen = Spawner::new(
            ModelPool::new(vec![member(&member_id, &[])]),
            Arc::new(reg),
            secrets_for(&member_id),
            st,
        )
        .with_child_tools(child_env(host.clone(), workspace));
        (pen, provider, host)
    }

    /// A scripted provider emits one `read_file` call, then a final answer: the file's content
    /// must reach the model (visible in the next request) and `tools_used` must name the tool.
    #[tokio::test]
    async fn a_child_tool_call_reads_a_file_and_its_result_reaches_the_model() {
        let host = Arc::new(
            FakeHost::unix().with_file("/work/notes.txt", "the-launch-code-is-seven"),
        );
        let provider = LoopProvider::new(
            "b",
            vec![
                LoopTurn::Call {
                    name: "read_file".to_string(),
                    arguments: serde_json::json!({"path": "notes.txt"}),
                },
                LoopTurn::Final("got it".to_string()),
            ],
            LoopTurn::Final("done".to_string()),
        );
        let (mut pen, provider, _host) = loop_spawner(provider, host, "/work");
        let spec = pen
            .build_spec(&[])
            .expect("draws")
            .with_tools(vec!["read_file".to_string()]);
        let st = pen.store.clone();
        let s = session(&st);
        let rec = pen
            .run_child(&spec, s.id(), "read the notes")
            .await
            .expect("the loop answers");
        assert_eq!(rec.tools_used, vec!["read_file".to_string()]);
        assert_eq!(provider.calls(), 2, "one tool turn, then the final answer");
        let second_request = &provider.seen()[1];
        assert!(
            second_request.contains("the-launch-code-is-seven"),
            "the tool result reached the model: {second_request}"
        );
        // Two provider calls at 10 input tokens each are recorded once, summed.
        assert_eq!(rec.usage.input_tokens, 20);
    }

    /// A provider that always emits a tool call never gets a final answer: the loop must stop at
    /// `max_tool_iters`. The `8` below is a literal on purpose: it pins [`DEFAULT_MAX_TOOL_ITERS`],
    /// so raising the constant turns this test red (asserting against the constant itself would
    /// agree with any value and could never fail).
    #[tokio::test]
    async fn an_always_tool_calling_child_stops_at_max_tool_iters() {
        let host = Arc::new(FakeHost::unix().with_file("/work/notes.txt", "x"));
        let always_call = LoopTurn::Call {
            name: "read_file".to_string(),
            arguments: serde_json::json!({"path": "notes.txt"}),
        };
        let provider = LoopProvider::new("b", vec![], always_call);
        let (mut pen, provider, _host) = loop_spawner(provider, host, "/work");
        // The default cap, not an override: the mutation this pins is the constant itself.
        let spec = pen
            .build_spec(&[])
            .expect("draws")
            .with_tools(vec!["read_file".to_string()]);
        assert_eq!(spec.max_tool_iters, DEFAULT_MAX_TOOL_ITERS);
        let st = pen.store.clone();
        let s = session(&st);
        let err = pen
            .run_child(&spec, s.id(), "never answer")
            .await
            .expect_err("a child that never answers fails");
        assert!(
            err.to_string().contains("bound"),
            "the failure names the bound: {err}"
        );
        assert_eq!(
            provider.calls(),
            8,
            "exactly the default cap, no more provider calls"
        );
    }

    /// A tool call for a path outside the workspace is denied by the capability token: the child
    /// errors, the outside file is byte-identical, and only the one provider call ever happened —
    /// the denied content never reached the model.
    #[tokio::test]
    async fn a_child_tool_call_outside_the_workspace_is_denied_and_reads_nothing() {
        let host = Arc::new(
            FakeHost::unix()
                .with_file("/work/notes.txt", "x")
                .with_file("/outside/secret.txt", "top-secret"),
        );
        let provider = LoopProvider::new(
            "b",
            vec![LoopTurn::Call {
                name: "read_file".to_string(),
                arguments: serde_json::json!({"path": "/outside/secret.txt"}),
            }],
            LoopTurn::Final("done".to_string()),
        );
        let (mut pen, provider, host) = loop_spawner(provider, host, "/work");
        let spec = pen
            .build_spec(&[])
            .expect("draws")
            .with_tools(vec!["read_file".to_string()]);
        let st = pen.store.clone();
        let s = session(&st);
        let err = pen
            .run_child(&spec, s.id(), "read outside")
            .await
            .expect_err("an outside-workspace read fails the child");
        assert!(
            err.to_string().contains("denied"),
            "the failure is a denial, never a bypass: {err}"
        );
        assert_eq!(provider.calls(), 1, "no second call carried denied content");
        assert_eq!(
            host.file("/outside/secret.txt").as_deref(),
            Some("top-secret"),
            "the outside file is untouched"
        );
    }

    /// A tool call for a path outside the workspace fails closed on writes too: the file is never
    /// created on the host.
    #[tokio::test]
    async fn a_child_tool_write_outside_the_workspace_is_denied_and_writes_nothing() {
        let host = Arc::new(FakeHost::unix().with_file("/work/notes.txt", "x"));
        let provider = LoopProvider::new(
            "b",
            vec![LoopTurn::Call {
                name: "write_file".to_string(),
                arguments: serde_json::json!({"path": "/outside/pwned.txt", "content": "pwned"}),
            }],
            LoopTurn::Final("done".to_string()),
        );
        let (mut pen, provider, host) = loop_spawner(provider, host, "/work");
        let spec = pen
            .build_spec(&[])
            .expect("draws")
            .with_tools(vec!["write_file".to_string()]);
        let st = pen.store.clone();
        let s = session(&st);
        let err = pen
            .run_child(&spec, s.id(), "write outside")
            .await
            .expect_err("an outside-workspace write fails the child");
        assert!(
            err.to_string().contains("denied"),
            "the failure is a denial, never a bypass: {err}"
        );
        assert_eq!(provider.calls(), 1);
        assert!(
            host.file("/outside/pwned.txt").is_none(),
            "the denied write created nothing"
        );
    }

    /// A tool call for a name outside the spec's `tools` is refused, not executed — even though
    /// `shell` is registered in the environment. The host ran nothing.
    #[tokio::test]
    async fn a_child_tool_call_for_a_name_outside_tools_is_refused_not_executed() {
        let host = Arc::new(FakeHost::unix().with_file("/work/notes.txt", "x"));
        let provider = LoopProvider::new(
            "b",
            vec![LoopTurn::Call {
                name: "shell".to_string(),
                arguments: serde_json::json!({"command": "touch /work/pwned"}),
            }],
            LoopTurn::Final("done".to_string()),
        );
        let (mut pen, provider, host) = loop_spawner(provider, host, "/work");
        let spec = pen
            .build_spec(&[])
            .expect("draws")
            .with_tools(vec!["read_file".to_string()]);
        let st = pen.store.clone();
        let s = session(&st);
        let err = pen
            .run_child(&spec, s.id(), "run a shell")
            .await
            .expect_err("an unallowed tool fails the child");
        assert!(
            err.to_string().contains("refused"),
            "the failure is a refusal, not an execution: {err}"
        );
        assert!(
            host.commands().is_empty(),
            "the refused tool never ran: {:?}",
            host.commands()
        );
        assert_eq!(provider.calls(), 1);
    }

    /// A spec naming a tool outside the child allow-list is refused before any provider call:
    /// `shell` in `tools` fails even though the child opted in and the registry holds `shell`.
    #[tokio::test]
    async fn a_spec_naming_a_tool_outside_the_allow_list_is_refused() {
        let host = Arc::new(FakeHost::unix().with_file("/work/notes.txt", "x"));
        let provider = LoopProvider::new(
            "b",
            vec![LoopTurn::Final("done".to_string())],
            LoopTurn::Final("done".to_string()),
        );
        let (mut pen, provider, _host) = loop_spawner(provider, host, "/work");
        let spec = pen
            .build_spec(&[])
            .expect("draws")
            .with_tools(vec!["shell".to_string()]);
        let st = pen.store.clone();
        let s = session(&st);
        let err = pen
            .run_child(&spec, s.id(), "run a shell")
            .await
            .expect_err("shell is outside the child allow-list");
        assert!(
            err.to_string().contains("allow-list"),
            "the failure names the allow-list: {err}"
        );
        assert_eq!(
            provider.calls(),
            0,
            "the refusal precedes any provider call, so no tool could run"
        );
    }

    /// Default off: a spec straight from `build_spec` names no tools, so `run_child` makes exactly
    /// one provider call even on a spawner with a tool environment — and records no tools used.
    #[tokio::test]
    async fn a_default_spec_on_a_tool_ready_spawner_still_makes_one_call() {
        let host = Arc::new(FakeHost::unix().with_file("/work/notes.txt", "x"));
        let provider = LoopProvider::new(
            "b",
            vec![LoopTurn::Final("done".to_string())],
            LoopTurn::Final("done".to_string()),
        );
        let (mut pen, provider, _host) = loop_spawner(provider, host, "/work");
        let spec = pen.build_spec(&[]).expect("draws");
        assert!(spec.tools.is_empty());
        let st = pen.store.clone();
        let s = session(&st);
        let rec = pen
            .run_child(&spec, s.id(), "hi")
            .await
            .expect("a default child runs");
        assert_eq!(provider.calls(), 1);
        assert!(rec.tools_used.is_empty());
    }
}