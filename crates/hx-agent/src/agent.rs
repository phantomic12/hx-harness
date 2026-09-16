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
//! Streaming (a turn arrives whole and is emitted as one `TextDelta`), compaction (a long
//! transcript is sent as-is), and cost accounting (usage is reported in tokens; the price table is
//! the router's business). Each is a visible gap rather than a silent one.

use crate::approver::{ApprovalDecision, Approver};
use crate::model::ModelCall;
use hx_core::approval::{ActionRequest, ApprovalSession, RiskClass, Verdict};
use hx_core::capability::{Action, CapabilityToken, Decision, Resource};
use hx_core::error::Result;
use hx_core::event::{AgentEvent, StopReason};
use hx_core::ids::{AgentId, ToolCallId};
use hx_core::message::{Message, Part};
use hx_provider::{ChatRequest, ToolSpec, Usage};
use hx_tools::{ToolContext, ToolError, ToolRegistry};
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
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Enough for real work, few enough that a loop with a bug stops instead of billing.
            max_turns: 24,
            deadline: Some(Duration::from_secs(600)),
            max_tokens: 4096,
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
    system: Option<String>,
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
            system: None,
        }
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

    pub fn tools(&self) -> &Arc<ToolRegistry> {
        &self.tools
    }

    fn emit(&self, event: AgentEvent) {
        if let Some(sender) = &self.events {
            let _ = sender.try_send(event);
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

        for turn in 1..=self.limits.max_turns {
            if let Some(deadline) = self.limits.deadline {
                if started.elapsed() >= deadline {
                    self.emit(AgentEvent::TurnFinished {
                        agent: self.agent.clone(),
                        turn,
                        stop: StopReason::BudgetExhausted,
                    });
                    return Ok(RunOutcome {
                        stop: StopReason::BudgetExhausted,
                        turns: turn.saturating_sub(1),
                        usage,
                        final_text: last_assistant_text(transcript),
                        tool_calls,
                        refusals,
                    });
                }
            }

            self.emit(AgentEvent::TurnStarted {
                agent: self.agent.clone(),
                turn,
            });

            let mut request = ChatRequest::new(self.model.model(), transcript.clone())
                .with_max_tokens(self.limits.max_tokens);
            if let Some(system) = &self.system {
                request = request.with_system(system.clone());
            }
            if !specs.is_empty() {
                request = request.with_tools(specs.clone());
            }

            let response = match self.model.complete(request).await {
                Ok(response) => response,
                Err(err) => {
                    self.emit(AgentEvent::Error {
                        agent: self.agent.clone(),
                        message: err.to_string(),
                    });
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
            });

            // One delta for the whole turn: there is no streaming yet, and pretending otherwise by
            // slicing the text would make the TUI's progress indicator a lie.
            let text = response.message.text();
            if !text.is_empty() {
                self.emit(AgentEvent::TextDelta {
                    agent: self.agent.clone(),
                    text: text.clone(),
                });
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

            transcript.push(response.message.clone());

            if calls.is_empty() {
                self.emit(AgentEvent::TurnFinished {
                    agent: self.agent.clone(),
                    turn,
                    stop: StopReason::Completed,
                });
                return Ok(RunOutcome {
                    stop: StopReason::Completed,
                    turns: turn,
                    usage,
                    final_text: text,
                    tool_calls,
                    refusals,
                });
            }

            for (id, name, arguments) in calls {
                self.emit(AgentEvent::ToolCallStarted {
                    agent: self.agent.clone(),
                    call: id.clone(),
                    name: name.clone(),
                    arguments: arguments.clone(),
                });

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

                transcript.push(Message::tool_result(id.clone(), ok, summary.clone()));

                self.emit(AgentEvent::ToolCallFinished {
                    agent: self.agent.clone(),
                    call: id,
                    ok,
                    summary,
                    duration_ms: began.elapsed().as_millis() as u64,
                });
            }
        }

        self.emit(AgentEvent::TurnFinished {
            agent: self.agent.clone(),
            turn: self.limits.max_turns,
            stop: StopReason::MaxTurns,
        });

        Ok(RunOutcome {
            stop: StopReason::MaxTurns,
            turns: self.limits.max_turns,
            usage,
            final_text: last_assistant_text(transcript),
            tool_calls,
            refusals,
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
        let prepared = match self.tools.prepare(name, arguments) {
            Ok(prepared) => prepared,
            Err(err) => {
                return CallOutcome::refused(format!("could not run {name}: {err}"));
            }
        };

        // Phase 2: the capability. A denial here is auditable and not something a prompt can
        // approve away — that is the whole distinction between a capability and an approval.
        if let Some(requirement) = prepared.requirement() {
            let decision = self.capability.check(
                &requirement.resource,
                requirement.action,
                chrono::Utc::now(),
            );
            if let Decision::Allow = decision {
                // Allowed by the token; approval still has its say below.
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
            let action = self.action_request(&prepared, requirement);
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
                    });

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
                    });

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
        match prepared.run(ctx).await {
            Ok(outcome) => CallOutcome::Ran {
                ok: outcome.ok,
                content: if outcome.truncated {
                    format!("{}\n[output truncated]", outcome.content)
                } else {
                    outcome.content
                },
            },
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
                let (risk, reason) = risk_of(&requirement.resource, requirement.action);
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
fn risk_of(resource: &Resource, action: Action) -> (RiskClass, String) {
    match (resource, action) {
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
