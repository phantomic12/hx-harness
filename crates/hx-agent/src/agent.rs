//! The agent loop: one turn at a time, with every tool call gated before it runs.
//!
//! ## The shape of a turn
//!
//! 1. Build a request from the transcript plus the tool specs.
//! 2. Call the model.
//! 3. Append its answer. If it called no tools, the turn is the answer and we are done.
//! 4. For each tool call: **classify, ask, then run**. The classification is the capability token
//!    (may this agent do this at all?) and the approval session (does a human want *this* one?), in
//!    that order — a denied capability is not a prompt someone can approve away.
//! 5. Append every outcome as a tool result, including the refusals, and go to 1.
//!
//! ## What the model is told when something is refused
//!
//! Everything. A refusal the model cannot see is a model that will try the same thing again, or —
//! worse — believe it succeeded. So a denied call, an unknown tool and unparseable arguments all
//! become tool results in the transcript with the reason attached, and the loop carries on.
//!
//! ## What this deliberately does not do yet
//!
//! Streaming (a turn arrives whole and is emitted as one `TextDelta`) and cost accounting (usage
//! is reported in tokens; the price table is the router's business). Each is a visible gap rather
//! than a silent one. Compaction is *not* on that list: a long transcript is handed to
//! [`crate::context::ContextBuilder`] before the request is built, so a session that grows past its
//! configured window stays sendable instead of being refused by the provider.

use crate::approver::{ApprovalDecision, Approver};
use crate::context::{ContextBuilder, ContextFacts};
use crate::model::ModelCall;
use hx_core::approval::{ActionRequest, ApprovalSession, RiskClass, Verdict};
use hx_core::capability::{Action, CapabilityToken, Decision, RequestUsage, Resource};
use hx_core::error::Result;
use hx_core::event::{AgentEvent, StopReason};
use hx_core::ids::{AgentId, ToolCallId};
use hx_core::message::{Message, Part};
use hx_provider::{ToolSpec, Usage};
use hx_tools::{Requirement, ToolContext, ToolError, ToolRegistry};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How far one run may go.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Model turns, not tool calls: a turn may contain several calls.
    pub max_turns: u32,
    /// Wall-clock ceiling for the whole run.
    pub deadline: Option<Duration>,
    /// Output tokens requested per turn.
    pub max_tokens: u32,
    /// Compaction threshold, in estimated tokens. When the transcript the loop hands the model
    /// exceeds this estimate, the middle is elided (head and tail kept) so a long session stays
    /// sendable. `0` disables compaction. This is the loop's copy of `AgentConfig.compact_at_tokens`.
    pub compact_at_tokens: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Enough for real work, few enough that a loop with a bug stops instead of billing.
            max_turns: 24,
            deadline: Some(Duration::from_secs(600)),
            max_tokens: 4096,
            // Matches the config default; a session that grows past ~120k estimated tokens gets
            // its middle elided rather than being refused by the provider.
            compact_at_tokens: 120_000,
        }
    }
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq)]
pub struct RunOutcome {
    pub stop: StopReason,
    pub turns: u32,
    /// Summed over the run.
    pub usage: Usage,
    /// The text of the last assistant turn — the answer, when there was one.
    pub final_text: String,
    /// Tool calls that were executed, for the transcript summary and for the audit log.
    pub tool_calls: u32,
    /// Tool calls a capability or an approval refused.
    pub refusals: u32,
    /// Events the run produced that never reached the event channel.
    ///
    /// WHY counted rather than hidden: in a daemon run the channel's reader is the writer that
    /// persists events to the store, so a dropped event is a hole in the audit trail. Surfacing
    /// the count in the outcome makes that hole visible to the caller instead of silent. A
    /// closed channel is *not* counted: nobody listening is a configured shape (live clients
    /// come and go), not a loss — and the transcript sink remains the durable path regardless.
    /// Zero in the common case, where the writer keeps up.
    pub dropped_events: u32,
}

/// Where the messages of a run go as they are produced.
///
/// The loop owns no storage — a session store does — and this is how that store hears about a message
/// before the run is over. The difference matters most exactly when a tool has already run: a
/// transcript that stops at the last turn boundary loses the only record of what that call did, while
/// a daemon that was killed leaves a session that cannot be resumed honestly.
///
/// Synchronous on purpose. The loop calls it the moment a message exists and stops the run if it
/// fails, because a store that cannot write is a store problem the caller must see rather than
/// something to paper over by finishing a run whose transcript will never be complete.
pub trait TranscriptSink: Send + Sync {
    /// One message, in the order the loop produced it.
    fn appended(&self, message: &Message) -> Result<()>;
}

/// The loop.
pub struct AgentLoop {
    agent: AgentId,
    model: Arc<dyn ModelCall>,
    tools: Arc<ToolRegistry>,
    capability: CapabilityToken,
    /// Approval state for this chat. Behind a mutex because decisions are stateful: a remembered
    /// "allow for this chat", and the unattended counter that a prompt resets.
    approvals: std::sync::Mutex<ApprovalSession>,
    approver: Arc<dyn Approver>,
    limits: Limits,
    events: Option<mpsc::Sender<AgentEvent>>,
    sink: Option<Arc<dyn TranscriptSink>>,
    system: Option<String>,
    /// Events produced but never delivered (channel full *and* the deadline expired while waiting
    /// for capacity). Atomic because `run` takes `&self` while every emit site needs to record a
    /// loss; reset at the start of each run and read into the outcome at its end.
    dropped: AtomicU32,
}

impl AgentLoop {
    pub fn new(
        agent: AgentId,
        model: Arc<dyn ModelCall>,
        tools: Arc<ToolRegistry>,
        capability: CapabilityToken,
        session: ApprovalSession,
        approver: Arc<dyn Approver>,
    ) -> Self {
        Self {
            agent,
            model,
            tools,
            capability,
            approvals: std::sync::Mutex::new(session),
            approver,
            limits: Limits::default(),
            events: None,
            sink: None,
            system: None,
            dropped: AtomicU32::new(0),
        }
    }

    /// Assemble the builder this run uses to turn a transcript into a request.
    ///
    /// Built from the run's own facts rather than passed in, so a caller cannot hand the loop a
    /// builder whose system prompt disagrees with `with_system_prompt` — one source, one answer.
    fn context_builder(&self, tool_specs: Vec<hx_provider::ToolSpec>) -> ContextBuilder {
        ContextBuilder::new(ContextFacts {
            system: self.system.clone(),
            tools: tool_specs,
            max_tokens: self.limits.max_tokens,
            compact_at_tokens: self.limits.compact_at_tokens,
        })
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_system_prompt(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Where the run's events go. A closed channel is not an error: clients come and go, and the
    /// run is the thing that matters.
    pub fn with_events(mut self, events: mpsc::Sender<AgentEvent>) -> Self {
        self.events = Some(events);
        self
    }

    /// Where a produced message goes before the run ends.
    ///
    /// A session store passes one so that a killed run leaves a transcript of what actually happened.
    /// Without it the transcript lives only in memory until the run returns, and the run that a
    /// client most needs to resume is the one that never returned.
    pub fn with_transcript_sink(mut self, sink: Arc<dyn TranscriptSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn tools(&self) -> &Arc<ToolRegistry> {
        &self.tools
    }

    /// Append a produced message, in the one order that is safe.
    ///
    /// The sink first: a message that reached the transcript but not the store is one a killed run
    /// loses *after* its tool has already run — the transcript would then be unable to say what the
    /// tool did, which is the single most important thing for it to say.
    fn append(&self, transcript: &mut Vec<Message>, message: Message) -> Result<()> {
        if let Some(sink) = &self.sink {
            sink.appended(&message)?;
        }
        transcript.push(message);
        Ok(())
    }

    /// Send an event to the writer, waiting (backpressure) if the channel is full so a
    /// persisted event is never silently dropped. `send().await` only errors when the receiver has
    /// closed, which is a configured shape (nobody listening), not a loss.
    async fn emit(&self, event: AgentEvent) {
        if let Some(sender) = &self.events {
            let _ = sender.send(event).await;
        }
    }

    /// Run to completion (or to a stopping condition), appending to `transcript` as it goes.
    ///
    /// The transcript is the caller's: a session store owns it, this borrows it. That is what makes
    /// "killing the TUI and reconnecting resumes the session mid-flight" possible later.
    pub async fn run(
        &self,
        transcript: &mut Vec<Message>,
        ctx: &ToolContext,
    ) -> Result<RunOutcome> {
        let started = Instant::now();
        let mut usage = Usage::default();
        let mut tool_calls = 0u32;
        let mut refusals = 0u32;
        let specs = self.tool_specs();
        // -- turn assembly: fixed facts once, the transcript per turn.
        let context = self.context_builder(specs.clone());

        for turn in 1..=self.limits.max_turns {
            if let Some(deadline) = self.limits.deadline {
                if started.elapsed() >= deadline {
                    self.emit(AgentEvent::TurnFinished {
                        agent: self.agent.clone(),
                        turn,
                        stop: StopReason::BudgetExhausted,
                    })
                    .await;
                    return Ok(RunOutcome {
                        stop: StopReason::BudgetExhausted,
                        turns: turn.saturating_sub(1),
                        usage,
                        final_text: last_assistant_text(transcript),
                        tool_calls,
                        refusals,
                        dropped_events: self.dropped.load(Ordering::SeqCst),
                    });
                }
            }

            // The capability spend ceiling: once the run's settled model spend passes the token's
            // provider budget, no further model call goes out. Priced from reconciled cost, not
            // the pessimistic reservation — and only when the token expresses a budget at all
            // (see `provider_budget_usd`: no provider grants, or an uncapped one, means no stop).
            if let Some(limit) = self.capability.provider_budget_usd() {
                let spent = self.model.spent_usd();
                if spent > limit {
                    self.emit(AgentEvent::TurnFinished {
                        agent: self.agent.clone(),
                        turn,
                        stop: StopReason::BudgetExhausted,
                    })
                    .await;
                    return Ok(RunOutcome {
                        stop: StopReason::BudgetExhausted,
                        turns: turn.saturating_sub(1),
                        usage,
                        final_text: last_assistant_text(transcript),
                        tool_calls,
                        refusals,
                        dropped_events: self.dropped.load(Ordering::SeqCst),
                    });
                }
            }

            self.emit(AgentEvent::TurnStarted {
                agent: self.agent.clone(),
                turn,
            })
            .await;

            // What goes on the wire is `ContextBuilder`'s decision, not the loop's: which transcript
            // (the audit trail is never shrunk here — a compacted *view* may be sent), whether tools
            // are offered, and whether a system prompt exists at all. See `crate::context`.
            let request = context.request(&self.model.model(), transcript);

            // The wall-clock deadline must hold across an in-flight provider call, not just between turns:
            // a stalled upstream must not hold the session past its bound (GH #26). We wrap the call in
            // the remaining budget rather than trusting the client's own timeout, which is about a single
            // request and not this run's bound.
            let complete = async { self.model.complete(request).await };
            let response = match self.limits.deadline {
                None => complete.await,
                Some(deadline) => {
                    let left = deadline.saturating_sub(started.elapsed());
                    match tokio::time::timeout(left, complete).await {
                        Ok(result) => result,
                        Err(_) => {
                            self.emit(AgentEvent::TurnFinished {
                                agent: self.agent.clone(),
                                turn,
                                stop: StopReason::BudgetExhausted,
                            })
                            .await;
                            return Ok(RunOutcome {
                                stop: StopReason::BudgetExhausted,
                                turns: turn.saturating_sub(1),
                                usage,
                                final_text: last_assistant_text(transcript),
                                tool_calls,
                                refusals,
                                dropped_events: self.dropped.load(Ordering::SeqCst),
                            });
                        }
                    }
                }
            };
            let response = match response {
                Ok(response) => response,
                Err(err) => {
                    self.emit(AgentEvent::Error {
                        agent: self.agent.clone(),
                        message: err.to_string(),
                    })
                    .await;
                    return Err(err);
                }
            };

            usage.input_tokens += response.usage.input_tokens;
            usage.output_tokens += response.usage.output_tokens;
            usage.cached_input_tokens += response.usage.cached_input_tokens;
            usage.reasoning_tokens += response.usage.reasoning_tokens;

            self.emit(AgentEvent::Usage {
                agent: self.agent.clone(),
                provider: self.model.provider_id(),
                credential: self.model.credential_id(),
                model: response.model.clone(),
                input_tokens: response.usage.input_tokens,
                output_tokens: response.usage.output_tokens,
                // Cost needs a price table, which belongs to the router rather than the loop.
                cost_usd: 0.0,
            })
            .await;

            // One delta for the whole turn: there is no streaming yet, and pretending otherwise by
            // slicing the text would make the TUI's progress indicator a lie.
            let text = response.message.text();
            if !text.is_empty() {
                self.emit(AgentEvent::TextDelta {
                    agent: self.agent.clone(),
                    text: text.clone(),
                })
                .await;
            }

            let calls: Vec<(ToolCallId, String, serde_json::Value)> = response
                .message
                .tool_calls()
                .filter_map(|part| match part {
                    Part::ToolCall {
                        id,
                        name,
                        arguments,
                    } => Some((id.clone(), name.clone(), arguments.clone())),
                    _ => None,
                })
                .collect();

            self.append(transcript, response.message.clone())?;

            if calls.is_empty() {
                self.emit(AgentEvent::TurnFinished {
                    agent: self.agent.clone(),
                    turn,
                    stop: StopReason::Completed,
                })
                .await;
                return Ok(RunOutcome {
                    stop: StopReason::Completed,
                    turns: turn,
                    usage,
                    final_text: text,
                    tool_calls,
                    refusals,
                    dropped_events: self.dropped.load(Ordering::SeqCst),
                });
            }

            for (id, name, arguments) in calls {
                self.emit(AgentEvent::ToolCallStarted {
                    agent: self.agent.clone(),
                    call: id.clone(),
                    name: name.clone(),
                    arguments: arguments.clone(),
                })
                .await;

                let began = Instant::now();
                let outcome = self.handle_call(&id, &name, arguments, ctx).await;

                // Counted here rather than inside `handle_call`: whether a call *ran* is the run's
                // business. A command that ran and exited non-zero was still executed — the tool is
                // what decides `ok`, and only a refusal means nothing happened.
                let (ok, summary) = match outcome {
                    CallOutcome::Ran { ok, content } => {
                        tool_calls += 1;
                        (ok, content)
                    }
                    CallOutcome::Refused { content } => {
                        refusals += 1;
                        (false, content)
                    }
                };

                self.append(
                    transcript,
                    Message::tool_result(id.clone(), ok, summary.clone()),
                )?;

                self.emit(AgentEvent::ToolCallFinished {
                    agent: self.agent.clone(),
                    call: id,
                    ok,
                    summary,
                    duration_ms: began.elapsed().as_millis() as u64,
                })
                .await;
            }
        }

        self.emit(AgentEvent::TurnFinished {
            agent: self.agent.clone(),
            turn: self.limits.max_turns,
            stop: StopReason::MaxTurns,
        })
        .await;

        Ok(RunOutcome {
            stop: StopReason::MaxTurns,
            turns: self.limits.max_turns,
            usage,
            final_text: last_assistant_text(transcript),
            tool_calls,
            refusals,
            dropped_events: self.dropped.load(Ordering::SeqCst),
        })
    }

    /// Gate one call, then run it. The result is the text the model will read next turn.
    async fn handle_call(
        &self,
        id: &ToolCallId,
        name: &str,
        arguments: serde_json::Value,
        ctx: &ToolContext,
    ) -> CallOutcome {
        // Phase 1: parse and ask the tool what it would need. `prepare` also rejects an unknown
        // tool or unusable arguments, which is a result the model can act on.
        let mut prepared = match self.tools.prepare(name, arguments, ctx) {
            Ok(prepared) => prepared,
            Err(err) => {
                return CallOutcome::refused(format!("could not run {name}: {err}"));
            }
        };

        // The resource the post-run byte check enforces against: the lexical requirement, replaced
        // by the canonical path when the re-check below resolves one. A read through a link that
        // lands under a *different* grant must be measured against that grant's bound, not the
        // lexical one's — otherwise a wide grant at the target still trips a tight grant at the name.
        let mut enforced_resource: Option<(Resource, Action)> = None;

        // Phase 2: the capability. A denial here is auditable and not something a prompt can
        // approve away — that is the whole distinction between a capability and an approval.
        if let Some(requirement) = prepared.requirement().cloned() {
            let now = chrono::Utc::now();
            let usage = requirement
                .bytes
                .map(RequestUsage::bytes)
                .unwrap_or_default();
            let decision = self.capability.check_with_usage(
                &requirement.resource,
                requirement.action,
                now,
                usage,
            );
            if let Decision::Allow = decision {
                enforced_resource = Some((requirement.resource.clone(), requirement.action));

                // Phase 2b: the symlink re-check. The lexical check above compares strings; the
                // host resolves what it would actually open, and the token is asked again about
                // that. A path that reads as inside the grant but opens as outside it is refused
                // here — closing the escape lexical containment leaves open.
                //
                // Residual risks, stated rather than hidden: a host that cannot resolve at all
                // keeps the lexical decision (see `Host::canonicalize`), and a link swapped
                // between this re-check and the open still wins its race. The tool opens the
                // resolved path (`set_path`), so at least the checked and the opened path are the
                // same string.
                if let Resource::FsPath { path } = &requirement.resource {
                    if let Ok(canonical) = ctx.host.canonicalize(path).await {
                        let canonical_resource = Resource::FsPath {
                            path: canonical.clone(),
                        };
                        let recheck = self.capability.check_with_usage(
                            &canonical_resource,
                            requirement.action,
                            now,
                            usage,
                        );
                        if let Decision::Allow = recheck {
                            if canonical != *path {
                                prepared.set_path(&canonical);
                                enforced_resource = Some((canonical_resource, requirement.action));
                            }
                        } else {
                            return CallOutcome::refused(format!(
                                "refused: {path} resolves to {canonical}, outside the agent's \
                                 filesystem grants (symlink escape). This is not something you \
                                 can retry — ask the operator to widen the grant."
                            ));
                        }
                    }
                }
            } else {
                let Decision::Deny(reason) = decision else {
                    unreachable!("checked above")
                };
                return CallOutcome::refused(format!(
                    "refused: the agent's capability does not cover this ({reason}). This is not \
                     something you can retry — ask the operator to widen the grant."
                ));
            }
        }

        // Phase 3: approval, only for tools with an external effect.
        if let Some(requirement) = prepared.requirement() {
            // What the call will touch, measured *now* — after the capability check, because a call
            // this agent is not allowed to make is not worth a directory walk, and before the prompt,
            // because §3 requires the question to name what will be gone. A measurement that fails
            // does not fail the call: the classification stands, and the prompt is a prompt with less
            // detail rather than no question at all.
            let targets = prepared.targets(ctx).await.unwrap_or_default();

            let action = self
                .action_request(&prepared, requirement)
                .with_targets(targets)
                .with_undo_opt(prepared.undo(ctx))
                // Where the call will run is part of the request *before* the decision, because a rule
                // may match on it (`docs/approvals.md` §4) — and it comes from the tool, which is the only
                // layer that knows whether it was given a boundary to run in. A tool that cannot say
                // honestly says the host.
                .confined_to(prepared.confinement(ctx));

            let verdict = {
                let mut approvals = self.approvals.lock().expect("approval lock");
                approvals.decide(&action, chrono::Utc::now())
            };

            match verdict {
                Verdict::Allow { .. } => {}
                Verdict::Deny { why } => {
                    return CallOutcome::refused(format!("refused by policy: {why}"));
                }
                Verdict::Ask(request) => {
                    let approval_id = request.id.clone();
                    self.emit(AgentEvent::ApprovalRequested {
                        agent: self.agent.clone(),
                        approval: approval_id.clone(),
                        call: id.clone(),
                        reason: request.reason.clone(),
                        // Cloned before the resolution moves on: this is the record of what the person
                        // was actually shown, and the queue drops the question the moment it is answered.
                        targets: action.targets.clone(),
                    })
                    .await;

                    let decision: ApprovalDecision = self.approver.decide(&request, &action).await;

                    let resolved = {
                        let mut approvals = self.approvals.lock().expect("approval lock");
                        approvals.resolve(&approval_id, decision.option, &action)
                    };

                    self.emit(AgentEvent::ApprovalResolved {
                        agent: self.agent.clone(),
                        approval: approval_id,
                        approved: resolved.is_allowed(),
                        by: decision.by.clone(),
                    })
                    .await;

                    match resolved {
                        Verdict::Allow { .. } => {}
                        _ => {
                            return CallOutcome::refused(format!(
                                "refused by {}: {}",
                                decision.by,
                                resolved.why()
                            ));
                        }
                    }
                }
            }
        }

        // Phase 4: run it. A tool that ran and reported failure is still a call that ran: the
        // model gets the error text and decides what to do about it, which is the whole point of
        // a tool result being a result rather than an abort.
        //
        // The byte bound is enforced here when the requirement could not state the size up front
        // (reads, patches): the outcome reports what actually moved, and an over-bound result is
        // replaced with a refusal before the model sees it. For a read nothing left the machine,
        // so the refusal is complete; for a mutation the effect already landed, and the message
        // says so rather than pretending otherwise.
        let byte_gate = match &enforced_resource {
            Some((resource, action)) => {
                let stated = prepared
                    .requirement()
                    .and_then(|requirement| requirement.bytes);
                if stated.is_none() {
                    Some((resource.clone(), *action))
                } else {
                    None
                }
            }
            None => None,
        };
        match prepared.run(ctx).await {
            Ok(outcome) => {
                if outcome.ok {
                    if let (Some((resource, action)), Some(moved)) =
                        (&byte_gate, outcome.bytes_moved)
                    {
                        let now = chrono::Utc::now();
                        if let Some(cap) = self.capability.max_bytes_for(resource, *action, now) {
                            if moved > cap {
                                let landed = if action.is_mutating() {
                                    " The write already landed; nothing about it is shown."
                                } else {
                                    ""
                                };
                                return CallOutcome::refused(format!(
                                    "refused: the call moved {moved} bytes, over the {cap}-byte \
                                     grant bound.{landed} This is not something you can retry — ask \
                                     the operator to widen the grant."
                                ));
                            }
                        }
                    }
                }
                CallOutcome::Ran {
                    ok: outcome.ok,
                    content: if outcome.truncated {
                        format!("{}\n[output truncated]", outcome.content)
                    } else {
                        outcome.content
                    },
                }
            }
            // The tool could not act at all. Still a result: the model needs to know the call went
            // nowhere, not to have the run end under it.
            Err(ToolError::Arguments(message)) => {
                CallOutcome::refused(format!("the arguments were not usable: {message}"))
            }
            Err(ToolError::Unavailable(message)) => CallOutcome::refused(message),
        }
    }

    /// Describe a call for the approval engine.
    fn action_request(
        &self,
        prepared: &hx_tools::PreparedCall,
        requirement: &hx_tools::Requirement,
    ) -> ActionRequest {
        // A shell command has a classifier of its own; everything else is described by what it
        // touches. Reusing `ActionRequest::shell` for commands is what keeps `rm -rf` destructive
        // rather than "a shell tool".
        match requirement.command() {
            Some(command) if prepared.name() == "shell" => ActionRequest::shell(command),
            _ => {
                let (risk, reason) = risk_of(requirement);
                ActionRequest::tool(prepared.name(), requirement.describes.clone(), risk, reason)
            }
        }
    }

    fn tool_specs(&self) -> Vec<ToolSpec> {
        self.tools
            .describe()
            .into_iter()
            .map(|info| ToolSpec {
                name: info.name,
                description: info.description,
                input_schema: info.schema,
            })
            .collect()
    }
}

/// What happened to one tool call.
///
/// The distinction the counters and the audit trail depend on: `Ran` means the tool was reached
/// (whatever it then reported), `Refused` means the gate stopped it and nothing happened. A
/// non-zero exit is a `Ran` with `ok: false` — the run did execute a command.
#[derive(Clone, Debug, PartialEq)]
enum CallOutcome {
    Ran {
        /// The tool's own verdict on what it produced.
        ok: bool,
        /// What the model reads next turn.
        content: String,
    },
    Refused {
        /// The reason, phrased so the model knows whether retrying could ever help.
        content: String,
    },
}

impl CallOutcome {
    fn refused(content: impl Into<String>) -> Self {
        Self::Refused {
            content: content.into(),
        }
    }
}

/// How dangerous a non-shell tool call is.
///
/// Deliberately coarse: the classifier does the fine-grained work for commands, and a capability
/// check has already decided whether the agent may touch this at all.
///
/// **Public, and shared with `hx-mcp`'s server half**, because the alternative is a second table
/// that can drift: a tool call made by a third-party MCP client is classified by exactly this
/// function, so "the same requirement/risk path as a local call" is one implementation rather
/// than two that agree today. It reads a [`Requirement`] — an `hx-tools` type carrying the
/// resource, the action and the third-party fact — and returns the class the approval policy
/// judges, which is why it belongs beside the loop that consults it rather than in the surface
/// that calls it.
///
/// ## The one arm that is not a `(resource, action)` pair
///
/// A [`Resource::Process`] with [`Requirement::third_party`] set is [`RiskClass::ThirdParty`]
/// rather than [`RiskClass::Mutate`], and the guard is first so it wins. The resource is unchanged
/// — the capability token is still asked about `Process` + `Execute`, because that is what a child
/// process *is* — and the flag is a separate fact the tool reported: *this runs a program the
/// operator did not write*. Without it, a stdio MCP server's tools were classified `Mutate`, which
/// the default `balanced` level auto-allows, so an operator who expected a prompt never got one
/// (`ROADMAP.md` M6). With it they are `ThirdParty`, which sits above `External` and therefore
/// above `balanced`'s threshold.
///
/// The table is the **only** place the flag becomes a class. `hx-mcp` reports the fact and nothing
/// else, so a future tool that spawns a third-party binary gets the same answer without a second
/// policy being written for it.
pub fn risk_of(requirement: &Requirement) -> (RiskClass, String) {
    match (&requirement.resource, requirement.action) {
        (Resource::Process, _) if requirement.third_party => (
            RiskClass::ThirdParty,
            "runs a program the operator did not write".to_string(),
        ),
        (Resource::FsPath { path }, Action::Read) => (RiskClass::Read, format!("reads {path}")),
        (Resource::FsPath { path }, Action::Delete) => {
            (RiskClass::Destructive, format!("deletes {path}"))
        }
        (Resource::FsPath { path }, _) => (RiskClass::Mutate, format!("changes {path}")),
        (Resource::NetworkHost { host }, _) => (
            RiskClass::External,
            format!("reaches {host} over the network"),
        ),
        (Resource::Provider { .. }, _) => (RiskClass::External, "spends model budget".to_string()),
        (Resource::Secret { .. }, _) => (RiskClass::Privileged, "touches a secret".to_string()),
        (Resource::Process, _) => (RiskClass::Mutate, "runs a process".to_string()),
        (Resource::Host { .. } | Resource::Sandbox { .. }, Action::Read) => {
            (RiskClass::Read, "reads the host".to_string())
        }
        (Resource::Host { .. } | Resource::Sandbox { .. }, _) => {
            (RiskClass::Mutate, "acts on the host".to_string())
        }
    }
}

fn last_assistant_text(transcript: &[Message]) -> String {
    transcript
        .iter()
        .rev()
        .find(|message| message.role == hx_core::message::Role::Assistant)
        .map(|message| message.text())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::approval::{ApprovalPolicy, AutonomyLevel};

    fn requirement(resource: Resource, action: Action) -> Requirement {
        Requirement::new(resource, action, "a call")
    }

    #[test]
    fn the_table_puts_a_third_party_process_above_the_default_level() {
        // The classification `hx-mcp`'s `requirement_for` feeds in — `Process` + `Execute` with the
        // third-party flag set — and the class it must produce.
        let third_party = requirement(Resource::Process, Action::Execute).third_party();
        let (risk, reason) = risk_of(&third_party);
        assert_eq!(risk, RiskClass::ThirdParty, "{reason}");
        assert!(
            reason.contains("did not write"),
            "the prompt has to say what is wrong with this call: {reason}"
        );

        // The control, and the one that matters: the *same* resource and action without the flag is
        // still `Mutate`. A table that returned `ThirdParty` for every process would be as wrong as
        // one that returned `Mutate` for this one — it would prompt on `ls`.
        let own_code = requirement(Resource::Process, Action::Execute);
        assert_eq!(risk_of(&own_code).0, RiskClass::Mutate);

        // And the guard is not a blanket override: the flag on a resource that is not a process
        // changes nothing, because nothing about it runs a program.
        let flagged_file = requirement(
            Resource::FsPath {
                path: "/tmp/x".to_string(),
            },
            Action::Write,
        )
        .third_party();
        assert_eq!(risk_of(&flagged_file).0, RiskClass::Mutate);
    }

    #[test]
    fn a_third_party_process_is_asked_about_at_the_default_level() {
        // The property item 1 of M6 exists for, end to end through this crate: the requirement an
        // MCP stdio call produces is classified here and decided by `hx-core`'s session — and at
        // the default level the answer is a prompt, not a wave-through.
        let (risk, reason) =
            risk_of(&requirement(Resource::Process, Action::Execute).third_party());
        let request = ActionRequest::tool("files__read_file", "call `read_file`", risk, reason);

        let mut balanced = ApprovalSession::new(ApprovalPolicy::at(AutonomyLevel::Balanced));
        let verdict = balanced.decide(&request, chrono::Utc::now());
        assert!(
            verdict.is_asking(),
            "`balanced` must ask before a third-party binary runs: {verdict:?}"
        );

        // A level that already tolerates an egress runs it without asking: the class is a prompt,
        // not a refusal, so MCP stays usable for an operator who has decided to trust it.
        let mut trusting = ApprovalSession::new(ApprovalPolicy::at(AutonomyLevel::Trusting));
        assert!(trusting.decide(&request, chrono::Utc::now()).is_allowed());
    }

    #[test]
    fn every_other_resource_keeps_the_class_it_had() {
        // The new arm is a guard in front of a match that predates it, so the regression this
        // catches is a reordering: `(Process, _)` moved above the guard, or the guard widened to a
        // wildcard, would change the answer for calls that have nothing to do with third-party code.
        let cases = [
            (
                requirement(
                    Resource::FsPath {
                        path: "/tmp/x".to_string(),
                    },
                    Action::Read,
                ),
                RiskClass::Read,
            ),
            (
                requirement(
                    Resource::FsPath {
                        path: "/tmp/x".to_string(),
                    },
                    Action::Delete,
                ),
                RiskClass::Destructive,
            ),
            (
                requirement(
                    Resource::NetworkHost {
                        host: "example.com".to_string(),
                    },
                    Action::Connect,
                ),
                RiskClass::External,
            ),
            (
                requirement(
                    Resource::Provider {
                        id: hx_core::ids::ProviderId::from("prv_x"),
                    },
                    Action::Connect,
                ),
                RiskClass::External,
            ),
            (
                requirement(
                    Resource::Secret {
                        name: "s".to_string(),
                    },
                    Action::Read,
                ),
                RiskClass::Privileged,
            ),
            (
                requirement(Resource::Process, Action::Execute),
                RiskClass::Mutate,
            ),
            (
                requirement(
                    Resource::Host {
                        id: hx_core::ids::HostId::from("hst_x"),
                    },
                    Action::Read,
                ),
                RiskClass::Read,
            ),
            (
                requirement(
                    Resource::Host {
                        id: hx_core::ids::HostId::from("hst_x"),
                    },
                    Action::Write,
                ),
                RiskClass::Mutate,
            ),
        ];

        for (requirement, expected) in cases {
            assert_eq!(
                risk_of(&requirement).0,
                expected,
                "{:?} / {:?}",
                requirement.resource,
                requirement.action
            );
        }
    }
}
