//! The agent loop, against a scripted model and a fake host.
//!
//! Every test here asserts something about the **gate**, because that is the property the loop
//! exists to hold: nothing a model asks for happens until something has checked it. The fake host
//! is what makes that assertion possible — it records the commands it was asked to run, so "the
//! model asked and was refused" and "nothing happened" are distinguishable.
//!
//! The scripted model is deliberately dumb: it returns queued turns in order and fails the run if
//! the loop asks for more turns than the script has. A test whose script is exhausted is a test
//! that expected fewer turns than it got, and it should see that rather than a plausible answer.

use async_trait::async_trait;
use hx_agent::approver::{AlwaysAllow, AlwaysDeny, ApprovalDecision, Approver, ScriptedApprover};
use hx_agent::{AgentLoop, Limits, ModelCall, TranscriptSink};
use hx_core::approval::{ApprovalPolicy, ApprovalSession, AutonomyLevel, Confinement, Rule};
use hx_core::capability::{Action, Capability, CapabilityToken, Resource};
use hx_core::error::{HxError, Result};
use hx_core::event::{AgentEvent, StopReason};
use hx_core::ids::{AgentId, CredentialId, ProviderId, ToolCallId};
use hx_core::message::{Message, Part};
use hx_provider::{ChatRequest, ChatResponse, FinishReason, Usage};
use hx_tools::testing::{BrokenHost, FakeHost, FakeSandbox};
use hx_tools::{ReadFileTool, ShellTool, Tool, ToolContext, ToolError, ToolOutcome, ToolRegistry};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------------------------

/// A model that answers from a script, in order.
struct ScriptedModel {
    replies: Mutex<VecDeque<Result<ChatResponse>>>,
    /// Every request the loop sent, so a test can assert what the model was *told* — the tool
    /// specs, and the tool results from the previous turn.
    seen: Mutex<Vec<ChatRequest>>,
}

impl ScriptedModel {
    fn new(replies: Vec<Result<ChatResponse>>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(VecDeque::from(replies)),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<ChatRequest> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl ModelCall for ScriptedModel {
    async fn complete(&self, req: ChatRequest) -> Result<ChatResponse> {
        self.seen.lock().unwrap().push(req);
        self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
            Err(HxError::Provider(
                "the scripted model was asked for more turns than it has answers".to_string(),
            ))
        })
    }

    fn model(&self) -> String {
        "scripted".to_string()
    }

    fn provider_id(&self) -> ProviderId {
        ProviderId::from("test")
    }

    fn credential_id(&self) -> CredentialId {
        CredentialId::from("cred_test")
    }
}

/// A tool that touches nothing, and says so by declaring no requirement.
///
/// This is the case the loop is supposed to run without asking anybody — and it is the one that
/// fails loudly if the gate is ever rewritten to check something before consulting
/// `requirement()`, because `requirement()` returning `None` is a *claim*, not an absence.
struct InertTool;

#[async_trait]
impl Tool for InertTool {
    fn name(&self) -> &str {
        "inert"
    }

    fn description(&self) -> &str {
        "does nothing at all; here to prove that nothing external implies no prompt"
    }

    fn schema(&self) -> Value {
        json!({ "type": "object", "properties": {}, "additionalProperties": false })
    }

    fn requirement(
        &self,
        _args: &Value,
        _ctx: &ToolContext,
    ) -> std::result::Result<Option<hx_tools::Requirement>, ToolError> {
        Ok(None)
    }

    async fn call(
        &self,
        _args: Value,
        _ctx: &ToolContext,
    ) -> std::result::Result<ToolOutcome, ToolError> {
        Ok(ToolOutcome::ok("thought about it"))
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn agent() -> AgentId {
    AgentId::from("agt_test")
}

/// A capability token issued *now*.
///
/// The loop checks expiry against the wall clock (`chrono::Utc::now()`), because a run is a real
/// interval of real time and a token that lapsed mid-run must stop being usable. That makes a
/// fixed historical `issued_at` useless in a test — it reads as an expired token, which is
/// exactly how this fixture was first written and what the first test run reported.
fn token(grants: Vec<Capability>) -> CapabilityToken {
    CapabilityToken::issue(agent(), grants, chrono::Utc::now(), 3600)
}

/// A grant of one action on one resource.
fn grant(resource: Resource, action: Action) -> Capability {
    Capability::new(resource, [action])
}

fn process_execute() -> Capability {
    grant(Resource::Process, Action::Execute)
}

fn read_under(path: &str) -> Capability {
    grant(
        Resource::FsPath {
            path: path.to_string(),
        },
        Action::Read,
    )
}

fn tools() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(ShellTool::new()));
    registry.register(Arc::new(ReadFileTool::new()));
    registry.register(Arc::new(InertTool));
    registry
}

fn usage(input: u64, output: u64) -> Usage {
    Usage {
        input_tokens: input,
        output_tokens: output,
        cached_input_tokens: 0,
        reasoning_tokens: 0,
    }
}

fn reply(text: &str) -> ChatResponse {
    ChatResponse {
        message: Message::assistant(text),
        usage: usage(100, 20),
        finish: FinishReason::Stop,
        model: "scripted".to_string(),
        raw: None,
    }
}

/// A turn that calls tools: the text (if any) plus the calls, in one assistant message.
fn reply_with(calls: Vec<(&str, &str, Value)>) -> ChatResponse {
    let mut parts = Vec::new();
    for (id, name, arguments) in calls {
        parts.push(Part::ToolCall {
            id: ToolCallId::from(id),
            name: name.to_string(),
            arguments,
        });
    }
    ChatResponse {
        message: Message::new(hx_core::message::Role::Assistant, parts),
        usage: usage(100, 20),
        finish: FinishReason::ToolUse,
        model: "scripted".to_string(),
        raw: None,
    }
}

struct Harness {
    agent_loop: AgentLoop,
    model: Arc<ScriptedModel>,
    ctx: ToolContext,
    host: Arc<FakeHost>,
}

fn harness(
    replies: Vec<Result<ChatResponse>>,
    grants: Vec<Capability>,
    policy: ApprovalPolicy,
    approver: Arc<dyn Approver>,
) -> Harness {
    harness_on(FakeHost::unix(), replies, grants, policy, approver)
}

fn harness_on(
    host: FakeHost,
    replies: Vec<Result<ChatResponse>>,
    grants: Vec<Capability>,
    policy: ApprovalPolicy,
    approver: Arc<dyn Approver>,
) -> Harness {
    let host = Arc::new(host);
    let model = ScriptedModel::new(replies);
    let agent_loop = AgentLoop::new(
        agent(),
        model.clone(),
        Arc::new(tools()),
        token(grants),
        ApprovalSession::new(policy),
        approver,
    );
    Harness {
        agent_loop,
        model,
        ctx: ToolContext::new(host.clone()),
        host,
    }
}

/// What the transcript says about each tool call, in order.
fn tool_results(transcript: &[Message]) -> Vec<(String, bool, String)> {
    transcript
        .iter()
        .flat_map(|message| message.parts.iter())
        .filter_map(|part| match part {
            Part::ToolResult { id, ok, content } => {
                Some((id.as_str().to_string(), *ok, content.clone()))
            }
            _ => None,
        })
        .collect()
}

fn transcript_start() -> Vec<Message> {
    vec![Message::user("build it")]
}

// ---------------------------------------------------------------------------------------------
// The plain path
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_turn_with_no_tool_calls_is_the_answer() {
    let h = harness(
        vec![Ok(reply("all done"))],
        vec![],
        ApprovalPolicy::paranoid(),
        Arc::new(AlwaysDeny),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.stop, StopReason::Completed);
    assert_eq!(outcome.final_text, "all done");
    assert_eq!(outcome.turns, 1);
    assert_eq!(outcome.tool_calls, 0);
    assert_eq!(outcome.refusals, 0);
    assert_eq!(transcript.len(), 2, "the user's turn and the answer");
    assert_eq!(h.model.seen().len(), 1, "one model call, not a loop");
}

#[tokio::test]
async fn a_tool_result_reaches_the_next_turn_and_the_tools_were_offered() {
    let h = harness(
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "read_file",
                json!({ "path": "/w/notes.txt" }),
            )])),
            Ok(reply("the file says hello")),
        ],
        vec![read_under("/w")],
        ApprovalPolicy::at(AutonomyLevel::Balanced),
        Arc::new(AlwaysDeny),
    );
    h.host
        .files
        .lock()
        .unwrap()
        .insert("/w/notes.txt".to_string(), b"hello".to_vec());

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.stop, StopReason::Completed);
    assert_eq!(outcome.tool_calls, 1);
    assert_eq!(outcome.final_text, "the file says hello");

    let results = tool_results(&transcript);
    assert_eq!(results.len(), 1);
    assert!(results[0].1, "the read succeeded");
    assert_eq!(results[0].2, "hello");

    // What actually matters is that the *model* saw it: a tool result that never reaches the next
    // request is a transcript entry, not a memory.
    let requests = h.model.seen();
    assert_eq!(requests.len(), 2);
    let second = &requests[1].messages;
    let last = second.last().expect("the tool result is the last message");
    assert!(
        matches!(&last.parts[0], Part::ToolResult { content, .. } if content == "hello"),
        "{:?}",
        last.parts
    );
    // And the tools were described to it, or it could not have called one.
    assert_eq!(requests[0].tools.len(), 3);
}

#[tokio::test]
async fn usage_is_summed_across_turns() {
    let h = harness(
        vec![
            Ok(reply_with(vec![("tc_1", "inert", json!({}))])),
            Ok(reply("done")),
        ],
        vec![],
        ApprovalPolicy::at(AutonomyLevel::Balanced),
        Arc::new(AlwaysDeny),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.usage.input_tokens, 200);
    assert_eq!(outcome.usage.output_tokens, 40);
}

// ---------------------------------------------------------------------------------------------
// The capability gate
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_denied_capability_is_a_refusal_the_model_can_read() {
    let h = harness(
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "echo hi" }),
            )])),
            Ok(reply("understood")),
        ],
        // No `Process` grant at all.
        vec![read_under("/w")],
        ApprovalPolicy::at(hx_core::approval::AutonomyLevel::Trusting),
        Arc::new(AlwaysAllow),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.refusals, 1);
    assert_eq!(outcome.tool_calls, 0);
    assert!(
        h.host.commands().is_empty(),
        "a denied capability must not reach the host"
    );

    let results = tool_results(&transcript);
    assert_eq!(results.len(), 1);
    assert!(!results[0].1);
    assert!(
        results[0].2.contains("capability"),
        "the model is told why, and that retrying cannot help: {}",
        results[0].2
    );
    // The run continues: a refusal is not the end of the conversation.
    assert_eq!(outcome.stop, StopReason::Completed);
    assert_eq!(outcome.final_text, "understood");
}

#[tokio::test]
async fn a_capability_denial_cannot_be_approved_away() {
    // The ordering property, stated as a test: an approver that would say yes to anything still
    // does not get asked, because the capability decided first. If this ever fails, "approval
    // cannot widen a grant" has stopped being true.
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalDecision::allow_once()]));
    let h = harness_on(
        FakeHost::unix(),
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "echo hi" }),
            )])),
            Ok(reply("understood")),
        ],
        vec![],
        ApprovalPolicy::paranoid(),
        approver.clone(),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.refusals, 1);
    assert_eq!(outcome.tool_calls, 0);
    assert!(
        approver.seen().is_empty(),
        "no one should be prompted about something the agent may not do at all"
    );
}

#[tokio::test]
async fn a_denied_call_does_not_stop_its_sibling() {
    // Two calls in one turn, the first refused. The second must still run: a model that asks for
    // one bad thing alongside a good one should not lose the good one.
    let h = harness(
        vec![
            Ok(reply_with(vec![
                ("tc_1", "shell", json!({ "cmd": "echo refused" })),
                ("tc_2", "read_file", json!({ "path": "/w/notes.txt" })),
            ])),
            Ok(reply("one of those worked")),
        ],
        vec![read_under("/w")],
        ApprovalPolicy::at(hx_core::approval::AutonomyLevel::Trusting),
        Arc::new(AlwaysAllow),
    );
    h.host
        .files
        .lock()
        .unwrap()
        .insert("/w/notes.txt".to_string(), b"hello".to_vec());

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.refusals, 1);
    assert_eq!(outcome.tool_calls, 1);

    let results = tool_results(&transcript);
    assert_eq!(results.len(), 2, "both calls got an answer");
    assert_eq!(results[0].0, "tc_1");
    assert!(!results[0].1);
    assert_eq!(results[1].0, "tc_2");
    assert_eq!(results[1].2, "hello");
}

// ---------------------------------------------------------------------------------------------
// The approval gate
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_tool_with_no_external_effect_is_never_asked_about() {
    // Paranoid (prompt before *everything*) plus an approver that refuses everything. The inert
    // tool declares no requirement, so both gates are skipped by design — and if this test ever
    // fails, the loop has started asking about calls that cannot touch anything.
    let h = harness(
        vec![
            Ok(reply_with(vec![("tc_1", "inert", json!({}))])),
            Ok(reply("done")),
        ],
        vec![],
        ApprovalPolicy::paranoid(),
        Arc::new(AlwaysDeny),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.tool_calls, 1);
    assert_eq!(outcome.refusals, 0);
    assert_eq!(tool_results(&transcript)[0].2, "thought about it");
}

#[tokio::test]
async fn an_approval_denial_is_reported_and_the_command_never_runs() {
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalDecision::deny("user")]));
    let h = harness_on(
        FakeHost::unix(),
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "rm -rf /tmp/x" }),
            )])),
            Ok(reply("not doing that")),
        ],
        vec![process_execute()],
        ApprovalPolicy::paranoid(),
        approver.clone(),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.refusals, 1);
    assert_eq!(outcome.tool_calls, 0);
    assert!(h.host.commands().is_empty());
    assert_eq!(approver.seen().len(), 1, "the prompt was actually shown");

    let results = tool_results(&transcript);
    assert!(results[0].2.contains("refused by user"), "{}", results[0].2);
    // The prompt carries the classified risk, not the tool name: this is what the user decides on.
    assert_eq!(approver.seen()[0].tool, "shell");
    assert!(
        !approver.seen()[0].reason.is_empty(),
        "a prompt with no reason is a prompt nobody can answer"
    );
}

#[tokio::test]
async fn an_approved_call_runs() {
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalDecision::allow_once()]));
    let h = harness_on(
        FakeHost::unix(),
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "echo hi" }),
            )])),
            Ok(reply("it printed hi")),
        ],
        vec![process_execute()],
        ApprovalPolicy::paranoid(),
        approver,
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.tool_calls, 1);
    assert_eq!(outcome.refusals, 0);
    assert_eq!(h.host.commands(), vec!["echo hi".to_string()]);
}

#[tokio::test]
async fn allow_for_chat_stops_the_second_prompt() {
    // Two turns, the same command twice. One answer should cover both — that is what "remembered
    // decision" means, and it is scoped to the key (`shell|echo hi`), not to the tool.
    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalDecision::allow_for_chat(),
    ]));
    let h = harness_on(
        FakeHost::unix(),
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "echo hi" }),
            )])),
            Ok(reply_with(vec![(
                "tc_2",
                "shell",
                json!({ "cmd": "echo hi" }),
            )])),
            Ok(reply("twice")),
        ],
        vec![process_execute()],
        ApprovalPolicy::paranoid(),
        approver.clone(),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.tool_calls, 2);
    assert_eq!(outcome.refusals, 0);
    assert_eq!(
        approver.seen().len(),
        1,
        "the second identical command was already approved for this chat"
    );
    assert_eq!(h.host.commands().len(), 2);
}

#[tokio::test]
async fn a_remembered_denial_is_not_asked_again() {
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalDecision::deny("user")]));
    let h = harness_on(
        FakeHost::unix(),
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "echo hi" }),
            )])),
            Ok(reply_with(vec![(
                "tc_2",
                "shell",
                json!({ "cmd": "echo hi" }),
            )])),
            Ok(reply("twice refused")),
        ],
        vec![process_execute()],
        ApprovalPolicy::paranoid(),
        approver.clone(),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.refusals, 2);
    assert_eq!(outcome.tool_calls, 0);
    assert_eq!(approver.seen().len(), 1, "asked once, remembered after");
    assert!(h.host.commands().is_empty());
}

#[tokio::test]
async fn policy_alone_can_allow_a_command_without_a_prompt() {
    // `Trusting` runs local edits free but still asks for irreversible things. A benign command
    // under a `Balanced` policy is the path a daily session actually takes: no prompt, no
    // ceremony, still classified and still counted.
    let approver = Arc::new(AlwaysDeny);
    let h = harness_on(
        FakeHost::unix(),
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "ls -la" }),
            )])),
            Ok(reply("listed")),
        ],
        vec![process_execute()],
        ApprovalPolicy::at(AutonomyLevel::Balanced),
        approver,
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.tool_calls, 1);
    assert_eq!(h.host.commands(), vec!["ls -la".to_string()]);
}

// ---------------------------------------------------------------------------------------------
// Bad calls, bad weather
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_tool_becomes_a_result_listing_what_exists() {
    let h = harness(
        vec![
            Ok(reply_with(vec![("tc_1", "teleport", json!({}))])),
            Ok(reply("no teleport then")),
        ],
        vec![],
        ApprovalPolicy::paranoid(),
        Arc::new(AlwaysDeny),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.refusals, 1);
    assert_eq!(outcome.tool_calls, 0);
    let text = &tool_results(&transcript)[0].2;
    assert!(text.contains("no tool named 'teleport'"), "{text}");
    assert!(
        text.contains("shell"),
        "the message lists what it can call: {text}"
    );
    assert_eq!(outcome.stop, StopReason::Completed, "the run goes on");
}

#[tokio::test]
async fn unusable_arguments_come_back_as_the_argument_error() {
    // Empty command: the tool's own `requirement()` refuses to even describe it, so nothing was
    // classified, nothing was approved, and nothing ran.
    let h = harness(
        vec![
            Ok(reply_with(vec![("tc_1", "shell", json!({ "cmd": "   " }))])),
            Ok(reply("trying something else")),
        ],
        vec![process_execute()],
        ApprovalPolicy::paranoid(),
        Arc::new(AlwaysAllow),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.refusals, 1);
    assert!(h.host.commands().is_empty());
    let text = &tool_results(&transcript)[0].2;
    assert!(text.contains("cmd is empty"), "{text}");
}

#[tokio::test]
async fn a_command_that_exits_non_zero_is_a_call_that_ran() {
    // The distinction the counters must not blur: the host *was* reached, and the model gets the
    // failure text. A run that counted this as "did not happen" would understate what it did.
    let h = harness_on(
        FakeHost::unix().with_exec_output("", "boom", Some(2)),
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "make" }),
            )])),
            Ok(reply("the build failed; here is why")),
        ],
        vec![process_execute()],
        ApprovalPolicy::paranoid(),
        Arc::new(AlwaysAllow),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.tool_calls, 1);
    assert_eq!(outcome.refusals, 0);
    let results = tool_results(&transcript);
    assert!(!results[0].1, "the tool reported failure");
    assert!(results[0].2.contains("boom"), "{}", results[0].2);
    assert!(results[0].2.contains("exit 2"), "{}", results[0].2);
}

#[tokio::test]
async fn a_transport_failure_is_a_result_not_an_abort() {
    let host = BrokenHost::new();
    let model = ScriptedModel::new(vec![
        Ok(reply_with(vec![("tc_1", "shell", json!({ "cmd": "ls" }))])),
        Ok(reply("the host is down")),
    ]);
    let agent_loop = AgentLoop::new(
        agent(),
        model,
        Arc::new(tools()),
        token(vec![process_execute()]),
        ApprovalSession::new(ApprovalPolicy::paranoid()),
        Arc::new(AlwaysAllow),
    );
    let ctx = ToolContext::new(Arc::new(host));

    let mut transcript = transcript_start();
    let outcome = agent_loop.run(&mut transcript, &ctx).await.unwrap();

    assert_eq!(outcome.stop, StopReason::Completed);
    assert_eq!(outcome.tool_calls, 1);
    let text = &tool_results(&transcript)[0].2;
    assert!(text.contains("connection reset"), "{text}");
}

#[tokio::test]
async fn a_model_error_ends_the_run_and_says_so() {
    let h = harness(
        vec![Err(HxError::Provider("upstream is down".to_string()))],
        vec![],
        ApprovalPolicy::paranoid(),
        Arc::new(AlwaysDeny),
    );

    let mut transcript = transcript_start();
    let error = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap_err();

    assert!(error.to_string().contains("upstream is down"), "{error}");
}

// ---------------------------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn max_turns_stops_a_model_that_will_not_stop() {
    // Six answers of a tool call each, a limit of three: the run must stop at the limit rather
    // than keep billing, and it must say which limit it hit.
    let replies = (0..6)
        .map(|_| Ok(reply_with(vec![("tc_1", "inert", json!({}))])))
        .collect::<Vec<_>>();
    let h = harness(
        replies,
        vec![],
        ApprovalPolicy::at(AutonomyLevel::Balanced),
        Arc::new(AlwaysDeny),
    );

    let mut transcript = transcript_start();
    let h = Harness {
        agent_loop: h.agent_loop.with_limits(Limits {
            max_turns: 3,
            deadline: None,
            max_tokens: 512,
            ..Limits::default()
        }),
        ..h
    };
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.stop, StopReason::MaxTurns);
    assert_eq!(outcome.turns, 3);
    assert_eq!(outcome.tool_calls, 3);
    assert_eq!(h.model.seen().len(), 3, "three model calls, not six");
}

#[tokio::test]
async fn an_exhausted_deadline_stops_before_the_first_turn() {
    let h = harness(
        vec![Ok(reply("never sent"))],
        vec![],
        ApprovalPolicy::paranoid(),
        Arc::new(AlwaysDeny),
    );

    let h = Harness {
        agent_loop: h.agent_loop.with_limits(Limits {
            max_turns: 4,
            deadline: Some(Duration::ZERO),
            max_tokens: 512,
            ..Limits::default()
        }),
        ..h
    };

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.stop, StopReason::BudgetExhausted);
    assert!(h.model.seen().is_empty(), "no turn was billed");
    assert_eq!(transcript.len(), 1, "nothing was appended");
}

// ---------------------------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_events_tell_the_story_of_a_gated_call() {
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalDecision::deny("user")]));
    let h = harness_on(
        FakeHost::unix(),
        vec![
            Ok(reply_with(vec![(
                "tc_1",
                "shell",
                json!({ "cmd": "rm -rf /tmp/x" }),
            )])),
            Ok(reply("understood")),
        ],
        vec![process_execute()],
        ApprovalPolicy::paranoid(),
        approver,
    );

    let (tx, mut rx) = mpsc::channel(64);
    let agent_loop = h.agent_loop.with_events(tx);

    let mut transcript = transcript_start();
    agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }

    let kinds: Vec<&str> = events.iter().map(kind_of).collect();
    assert_eq!(
        kinds,
        vec![
            // The refused turn.
            "turn_started",
            "usage",
            "tool_call_started",
            "approval_requested",
            "approval_resolved",
            "tool_call_finished",
            // The model's answer to it.
            "turn_started",
            "usage",
            "text_delta",
            "turn_finished",
        ],
        "a client rendering this run needs exactly these, in this order"
    );

    // The approval events carry the identity the UI needs to answer the prompt it just drew.
    let AgentEvent::ApprovalRequested {
        approval,
        call,
        reason,
        targets,
        ..
    } = &events[3]
    else {
        panic!("expected an approval request, got {:?}", events[3]);
    };
    // ...and an empty list is honest: `shell` cannot name what `rm -rf /tmp/x` will touch, so it says
    // nothing rather than guessing. (`delete` fills this in — see the delete tests below.)
    assert!(
        targets.is_empty(),
        "the shell tool has no enumerable target: {targets:?}"
    );
    assert_eq!(call.as_str(), "tc_1");
    assert!(!reason.is_empty());
    let AgentEvent::ApprovalResolved {
        approval: resolved,
        approved,
        by,
        ..
    } = &events[4]
    else {
        panic!("expected a resolution, got {:?}", events[4]);
    };
    assert_eq!(resolved, approval);
    assert!(!approved);
    assert_eq!(by, "user");

    // And the refusal is visible as a finished call that did not succeed.
    let AgentEvent::ToolCallFinished { ok, summary, .. } = &events[5] else {
        panic!("expected a finished call, got {:?}", events[5]);
    };
    assert!(!ok);
    assert!(summary.contains("refused by user"), "{summary}");
}

fn kind_of(event: &AgentEvent) -> &'static str {
    match event {
        AgentEvent::SessionStarted { .. } => "session_started",
        AgentEvent::TurnStarted { .. } => "turn_started",
        AgentEvent::TextDelta { .. } => "text_delta",
        AgentEvent::ReasoningDelta { .. } => "reasoning_delta",
        AgentEvent::ToolCallStarted { .. } => "tool_call_started",
        AgentEvent::ToolCallFinished { .. } => "tool_call_finished",
        AgentEvent::ApprovalRequested { .. } => "approval_requested",
        AgentEvent::ApprovalResolved { .. } => "approval_resolved",
        AgentEvent::Usage { .. } => "usage",
        AgentEvent::TurnFinished { .. } => "turn_finished",
        AgentEvent::Error { .. } => "error",
    }
}

#[tokio::test]
async fn a_run_with_nobody_listening_still_completes() {
    let h = harness(
        vec![Ok(reply("done"))],
        vec![],
        ApprovalPolicy::paranoid(),
        Arc::new(AlwaysDeny),
    );
    let (tx, rx) = mpsc::channel(1);
    drop(rx);

    let agent_loop = h.agent_loop.with_events(tx);
    let mut transcript = transcript_start();
    let outcome = agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.stop, StopReason::Completed);
    assert_eq!(outcome.final_text, "done");
}

// ---------------------------------------------------------------------------------------------
// Where the messages go while the run is still going
// ---------------------------------------------------------------------------------------------

/// A store's stand-in: keeps what it was handed, and can be told to fail at a given message.
#[derive(Default)]
struct RecordingSink {
    seen: Mutex<Vec<Message>>,
    /// Fail when this many messages have already been recorded — one message short of `N`.
    fail_at: Option<usize>,
}

impl RecordingSink {
    fn fail_at(n: usize) -> Arc<Self> {
        Arc::new(Self {
            fail_at: Some(n),
            ..Default::default()
        })
    }

    fn seen(&self) -> Vec<Message> {
        self.seen.lock().unwrap().clone()
    }
}

impl TranscriptSink for RecordingSink {
    fn appended(&self, message: &Message) -> Result<()> {
        let mut seen = self.seen.lock().unwrap();
        if Some(seen.len()) == self.fail_at {
            return Err(HxError::Store("the disk is full".to_string()));
        }
        seen.push(message.clone());
        Ok(())
    }
}

#[tokio::test]
async fn every_message_the_run_produces_reaches_the_sink_as_it_is_produced() {
    // The property a session store depends on: the messages exist *outside* the run as soon as the
    // run makes them. A daemon killed mid-run then has a transcript that says what happened instead
    // of one that stops at the last turn boundary.
    let sink: Arc<RecordingSink> = Arc::default();
    let model = ScriptedModel::new(vec![
        Ok(reply_with(vec![("c1", "shell", json!({"cmd": "echo hi"}))])),
        Ok(reply("done")),
    ]);
    let agent_loop = AgentLoop::new(
        agent(),
        model,
        Arc::new(tools()),
        token(vec![Capability::new(Resource::Process, [Action::Execute])]),
        ApprovalSession::new(ApprovalPolicy::at(AutonomyLevel::Yolo)),
        Arc::new(AlwaysAllow),
    )
    .with_transcript_sink(Arc::clone(&sink) as Arc<dyn TranscriptSink>);

    let ctx = ToolContext::new(Arc::new(FakeHost::unix().with_exec_output(
        "hi\n",
        "",
        Some(0),
    )));
    let mut transcript = vec![Message::user("run echo")];
    let outcome = agent_loop.run(&mut transcript, &ctx).await.unwrap();

    assert_eq!(outcome.stop, StopReason::Completed);
    let recorded = sink.seen();
    assert_eq!(
        recorded.len(),
        transcript.len() - 1,
        "every message the loop appended, and only those"
    );
    assert_eq!(
        recorded,
        transcript[1..].to_vec(),
        "in the same order, with the same content"
    );
    // The tool result is among them, which is the message that matters most: it is the only record
    // of what a call did.
    assert!(
        recorded.iter().any(|m| m.text().contains("hi")),
        "{recorded:#?}"
    );
}

#[tokio::test]
async fn a_long_session_is_compacted_for_the_model_but_never_from_the_audit() {
    // The whole point of the threshold: a transcript that has grown past it is elided *for the
    // model* so the request stays inside the model's window, while the loop's transcript — the audit
    // the store keeps — still holds every message. Dropping one of the two halves would either
    // re-introduce the unbounded-request bug this key exists to fix, or silently edit the record a
    // human audits.
    let model = ScriptedModel::new(vec![Ok(reply("all done"))]);
    let mut transcript = transcript_start();
    // A large middle that pushes the estimate far past any small threshold: each assistant turn is
    // thousands of tokens, so the transcript as a whole is un-sendable.
    for i in 0..40 {
        transcript.push(Message::assistant(format!(
            "step {i}: {}",
            "x".repeat(2000)
        )));
    }
    transcript.push(Message::assistant("the end"));

    let agent_loop = AgentLoop::new(
        agent(),
        model.clone(),
        Arc::new(tools()),
        token(vec![]),
        ApprovalSession::new(ApprovalPolicy::paranoid()),
        Arc::new(AlwaysDeny),
    )
    .with_limits(Limits {
        max_turns: 1,
        compact_at_tokens: 1, // far under the transcript's estimate, so compaction fires
        ..Limits::default()
    });

    let ctx = ToolContext::new(Arc::new(FakeHost::unix()));
    let outcome = agent_loop.run(&mut transcript, &ctx).await.unwrap();
    assert_eq!(outcome.stop, StopReason::Completed);

    let sent = model.seen();
    assert_eq!(sent.len(), 1);
    let sent = &sent[0].messages;

    // The audit trail is whole — every message the run started with, plus the answer the loop appended.
    assert_eq!(transcript.len(), 43, "the record must keep every message");
    assert_eq!(
        transcript[..42].len(),
        42,
        "the original 42 are all present"
    );

    // What the model was handed is a strict subset: head(2) + marker(1) + tail(12) = 15, far
    // smaller than the record, and the marker says the elision happened and names its scale.
    // 42 original messages, 14 kept from the record (head+tail), so 28 were elided.
    assert!(sent.len() < transcript.len(), "the request must be smaller");
    assert_eq!(sent.len(), 15, "head + marker + tail");
    let marker = sent
        .iter()
        .find(|m| m.text().contains("elided"))
        .expect("the request must contain the explicit elision marker");
    assert!(
        marker.text().contains("28"),
        "the marker names how much was elided: {}",
        marker.text()
    );
}

#[tokio::test]
async fn a_sink_that_cannot_write_stops_the_run_rather_than_finishing_a_lie() {
    // A store that fails is a store problem the caller must see. Finishing the run would report
    // success for a transcript that will never be complete.
    let sink = RecordingSink::fail_at(1);
    let model = ScriptedModel::new(vec![
        Ok(reply_with(vec![("c1", "shell", json!({"cmd": "echo hi"}))])),
        Ok(reply("done")),
    ]);
    let agent_loop = AgentLoop::new(
        agent(),
        model,
        Arc::new(tools()),
        token(vec![Capability::new(Resource::Process, [Action::Execute])]),
        ApprovalSession::new(ApprovalPolicy::at(AutonomyLevel::Yolo)),
        Arc::new(AlwaysAllow),
    )
    .with_transcript_sink(sink.clone());

    let ctx = ToolContext::new(Arc::new(FakeHost::unix().with_exec_output(
        "hi\n",
        "",
        Some(0),
    )));
    let mut transcript = vec![Message::user("run echo")];
    let err = agent_loop.run(&mut transcript, &ctx).await.unwrap_err();

    assert!(matches!(err, HxError::Store(_)), "{err:?}");
    // The assistant turn was recorded, the tool ran, and the result could not be — so the run stops
    // with the transcript holding exactly what is durable, and nothing that is not.
    assert_eq!(sink.seen().len(), 1);
    assert!(transcript
        .iter()
        .all(|m| m.role != hx_core::message::Role::Tool));
}

// ---------------------------------------------------------------------------------------------
// What the prompt says will be gone
// ---------------------------------------------------------------------------------------------

/// The registry plus `delete`, for the tests that need a tool able to name its targets.
///
/// Deliberately not folded into [`tools`]: the plain-path tests assert the exact set a model is
/// offered (`requests[0].tools.len()`), and a fixture that drifts under them makes those assertions
/// meaningless.
fn tools_with_delete() -> ToolRegistry {
    let mut registry = tools();
    registry.register(Arc::new(hx_tools::DeleteTool::new()));
    registry
}

#[tokio::test]
async fn a_delete_reaches_the_prompt_with_what_will_be_gone() {
    // `docs/approvals.md` §3, end to end: the question a person is shown names the resolved target,
    // how much of it there is, and whether it comes back. The measurement happens between the
    // capability check and the prompt, which is the only order in which the number is *true* — it
    // describes the tree as it is at the moment of asking, not as the model believed it to be.
    let host = Arc::new(
        FakeHost::unix()
            .with_file("/w/build/a.o", "aaaa")
            .with_file("/w/build/b.o", "bb"),
    );
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalDecision::deny(
        "not now",
    )]));
    let agent_loop = AgentLoop::new(
        agent(),
        ScriptedModel::new(vec![
            Ok(reply_with(vec![(
                "c1",
                "delete",
                json!({ "path": "build", "recursive": true }),
            )])),
            Ok(reply("understood — I will not delete it")),
        ]),
        Arc::new(tools_with_delete()),
        token(vec![grant(
            Resource::FsPath {
                path: "/w/build".to_string(),
            },
            Action::Delete,
        )]),
        ApprovalSession::new(ApprovalPolicy::paranoid()),
        approver.clone(),
    );

    let ctx = ToolContext::new(host.clone()).in_workspace("/w");
    let (tx, mut rx) = mpsc::channel(64);
    let agent_loop = agent_loop.with_events(tx);
    let mut transcript = transcript_start();
    let outcome = agent_loop.run(&mut transcript, &ctx).await.unwrap();

    assert_eq!(
        outcome.refusals, 1,
        "a denial is a refusal, not a call that ran"
    );
    assert_eq!(outcome.tool_calls, 0);

    let asked = approver.seen();
    assert_eq!(asked.len(), 1);
    let question = &asked[0];
    assert_eq!(question.targets.len(), 1, "{question:?}");
    assert_eq!(question.targets[0].path, "/w/build");
    assert_eq!(question.targets[0].entries, Some(2));
    assert_eq!(question.targets[0].bytes, Some(6));

    // The rendered question is the thing a client shows, so it is the thing to assert on: a target
    // the person cannot read is a target they cannot price.
    let rendered = question.render();
    assert!(
        rendered.contains("/w/build — directory, 2 entries, 6 B"),
        "{rendered}"
    );
    assert!(
        rendered.contains("trash"),
        "the way back is named rather than asserted: {rendered}"
    );
    assert!(
        !rendered.contains("This cannot be undone"),
        "a trash delete does not claim to be unrecoverable: {rendered}"
    );

    // And the denial held: nothing moved.
    assert!(host.file("/w/build/a.o").is_some());

    // The audit trail keeps the question, not only the answer. The event that reaches the store
    // carries the same measurement the approver saw, because the queue drops the question the moment
    // it is answered and the rendering is not a thing a store can re-render a year later.
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    let recorded = events
        .iter()
        .find_map(|event| match event {
            AgentEvent::ApprovalRequested { targets, .. } => Some(targets.clone()),
            _ => None,
        })
        .expect("an approval request reached the event stream");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].path, "/w/build");
    assert_eq!(recorded[0].entries, Some(2));
    assert_eq!(recorded[0].bytes, Some(6));
}

// ---------------------------------------------------------------------------------------------
// Where a call runs (`docs/approvals.md` §4)
// ---------------------------------------------------------------------------------------------

/// The policy §4 describes: `npm test` may run unattended *in a box*, and not on the host.
fn confined_only_policy() -> ApprovalPolicy {
    ApprovalPolicy {
        level: AutonomyLevel::Cautious,
        allow: vec![Rule::tool("shell").command("cargo test*").confined(true)],
        ..ApprovalPolicy::default()
    }
}

fn scripted_test_run() -> Vec<Result<ChatResponse>> {
    vec![
        Ok(reply_with(vec![(
            "c1",
            "shell",
            json!({ "cmd": "cargo test", "workdir": "/w" }),
        )])),
        Ok(reply("done")),
    ]
}

#[tokio::test]
async fn a_rule_that_requires_confinement_lets_the_confined_run_through_without_asking() {
    // The whole point of the axis: an unattended agent can be given build steps because they run inside a
    // boundary, and the *same string* is still questioned when it would run on the machine itself. The
    // approver is never asked here, which is what `seen().is_empty()` asserts — a question would be a
    // failure of the rule, not a detail of it.
    let host = Arc::new(FakeHost::unix());
    let sandbox = Arc::new(FakeSandbox::answering("test result: ok\n", 0));
    let approver = Arc::new(ScriptedApprover::new(vec![]));
    let h = harness_on(
        FakeHost::unix(),
        scripted_test_run(),
        vec![process_execute()],
        confined_only_policy(),
        approver.clone(),
    );
    let ctx = ToolContext::new(host)
        .in_workspace("/w")
        .with_sandbox(sandbox.clone());

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &ctx).await.unwrap();

    assert_eq!(outcome.refusals, 0);
    assert_eq!(outcome.tool_calls, 1);
    assert!(
        approver.seen().is_empty(),
        "a confined allowance is not a question: {:?}",
        approver.seen()
    );
    assert_eq!(sandbox.runs().len(), 1, "it ran in the boundary");
    assert!(h.host.commands().is_empty(), "{:?}", h.host.commands());
}

#[tokio::test]
async fn the_same_command_on_the_host_is_still_asked_about() {
    // And the other half, in the same configuration: no boundary, so the allow rule must not match and the
    // cautious level must ask. If this ever stops asking, §4's axis has become a way to launder an
    // unconfined command through a rule written for a confined one.
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalDecision::deny(
        "not on my machine",
    )]));
    let h = harness_on(
        FakeHost::unix(),
        scripted_test_run(),
        vec![process_execute()],
        confined_only_policy(),
        approver.clone(),
    );

    let mut transcript = transcript_start();
    let outcome = h
        .agent_loop
        .run(
            &mut transcript,
            &ToolContext::new(h.host.clone()).in_workspace("/w"),
        )
        .await
        .unwrap();

    assert_eq!(outcome.refusals, 1);
    assert_eq!(outcome.tool_calls, 0);
    let asked = approver.seen();
    assert_eq!(asked.len(), 1, "it was put to a human");
    assert_eq!(asked[0].confined, Confinement::Host);
    assert!(h.host.commands().is_empty(), "{:?}", h.host.commands());
}

#[tokio::test]
async fn the_prompt_says_when_the_call_is_confined() {
    // A person answering a prompt is deciding about their own machine, so "inside a sandbox" has to be in
    // the question rather than inferred from the fact that a rule exists.
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalDecision::allow_once()]));
    let h = harness_on(
        FakeHost::unix(),
        scripted_test_run(),
        vec![process_execute()],
        // Paranoid, so the question is asked whatever the rules say.
        ApprovalPolicy::paranoid(),
        approver.clone(),
    );
    let ctx = ToolContext::new(h.host.clone())
        .in_workspace("/w")
        .with_sandbox(Arc::new(FakeSandbox::answering("", 0)));

    let mut transcript = transcript_start();
    h.agent_loop.run(&mut transcript, &ctx).await.unwrap();

    let asked = approver.seen();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].confined, Confinement::Sandbox);
    assert!(
        asked[0]
            .render()
            .contains("where: inside a sandbox, not on the host"),
        "{}",
        asked[0].render()
    );
}

#[tokio::test]
async fn a_call_the_agent_may_not_make_is_not_measured_either() {
    // A measurement is work — a directory walk on someone's machine — and a capability denial is not
    // a prompt, so there is nothing to measure *for*. The order matters for the same reason it
    // matters everywhere else in this loop: capability first, and a denial is not a question.
    let host = Arc::new(FakeHost::unix().with_file("/w/build/a.o", "aaaa"));
    let approver = Arc::new(ScriptedApprover::new(vec![]));
    let agent_loop = AgentLoop::new(
        agent(),
        ScriptedModel::new(vec![
            Ok(reply_with(vec![(
                "c1",
                "delete",
                json!({ "path": "build", "recursive": true }),
            )])),
            Ok(reply("I am not allowed to do that")),
        ]),
        Arc::new(tools_with_delete()),
        token(vec![]),
        ApprovalSession::new(ApprovalPolicy::paranoid()),
        approver.clone(),
    );

    let ctx = ToolContext::new(host.clone()).in_workspace("/w");
    let mut transcript = transcript_start();
    let outcome = agent_loop.run(&mut transcript, &ctx).await.unwrap();

    assert_eq!(outcome.refusals, 1);
    assert!(approver.seen().is_empty(), "a denial is not a question");
    assert!(
        host.listings().is_empty(),
        "nothing was walked for a call that could never run: {:?}",
        host.listings()
    );
}

#[tokio::test]
async fn a_pattern_deletion_is_refused_rather_than_asked_about() {
    // The other half of §3: `rm -rf build*` covers a set the person answering cannot see, so the
    // honest answer is not "yes" or "no" but "name the files" — and that decision belongs before the
    // prompt, not in it. `deployment_default()` carries the check; a blank policy does not.
    let h = harness(
        vec![
            Ok(reply_with(vec![(
                "c1",
                "shell",
                json!({ "cmd": "rm -rf ./build*" }),
            )])),
            Ok(reply("then I will name them")),
        ],
        vec![process_execute()],
        ApprovalPolicy::deployment_default(),
        Arc::new(ScriptedApprover::new(vec![])),
    );

    let mut transcript = transcript_start();
    let outcome = h.agent_loop.run(&mut transcript, &h.ctx).await.unwrap();

    assert_eq!(outcome.refusals, 1);
    assert_eq!(outcome.tool_calls, 0);
    let results = tool_results(&transcript);
    assert!(results[0].2.contains("refused"), "{}", results[0].2);
    assert!(
        results[0].2.contains("cannot be listed"),
        "the refusal explains itself: {}",
        results[0].2
    );
    assert!(
        results[0].2.contains("./build*"),
        "and names the target it is refusing: {}",
        results[0].2
    );
    assert!(
        h.host.commands().is_empty(),
        "nothing ran: {:?}",
        h.host.commands()
    );
}
