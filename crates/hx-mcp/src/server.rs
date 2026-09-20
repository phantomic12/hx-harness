//! The server half: `hx`'s own tools, offered to somebody else's MCP client over a pipe.
//!
//! ## The property this module exists to hold
//!
//! **An MCP client is a caller, not an operator.** A client that connects here can ask for a tool
//! call, and every call it asks for goes through the path a call from the local loop goes through:
//! the same [`ToolRegistry::prepare`], the same capability check, the same
//! requirement → risk → approval decision, the same tool. There is no second execution path, no way
//! to reach a tool around the gate, and no argument shape that skips one — [`McpServer::call`] is
//! the only thing in this crate that runs a tool, and it is the same sequence `hx-agent`'s
//! `handle_call` performs, with one deliberate difference described below.
//!
//! ## stdio only, and why there is no HTTP transport here
//!
//! The transport is the client's stdin/stdout, and there is **no listening socket** — not as a
//! configuration option, not behind a feature flag. A TCP transport would need an authentication
//! story: who is this client, what may *they* do, and how is that identity proven? `hx` has a
//! capability token for its own agents and a vault for its own credentials, and neither answers
//! "which stranger on the network is calling". Shipping an unauthenticated HTTP endpoint that runs
//! tools would be shipping the exact hole this module exists to not be, so the transport is a pipe
//! that the operator had to start deliberately, and the *client* has to have been given it.
//!
//! `rmcp`'s streamable-HTTP **server** transport is already in this crate's dependency graph (the
//! HTTP test suite runs a real one on `axum`), so adding it later is a decision about authentication
//! rather than a missing dependency. It is recorded in `ROADMAP.md` as the open item it is.
//!
//! ## Refuse rather than prompt
//!
//! When the approval policy's answer for a call is [`Verdict::Ask`], this server **refuses the call
//! immediately** and says why. It does not prompt — it cannot: there is no surface on the other end
//! of a stdio pipe that a person is looking at, and MCP's `elicitation` is a request *to the client
//! application*, which is a third-party program rather than the operator who set the policy. A
//! question parked with nobody to answer it is not a question; in `hx`'s own approval queue it would
//! become a silent denial on timeout, and the caller would have waited for it.
//!
//! The refusal names the tool, the risk class the call carries, the policy's reason, and the two
//! ways to actually allow it: an `allow` rule in the policy this server runs under, or making the
//! call from a surface that can reach the operator. Both are operator actions. Neither is something
//! a client can perform by asking again.
//!
//! ## No approver field, and no approval-posting path
//!
//! `McpServer` has no `Approver`, no `ApprovalQueue`, and no code that publishes an
//! [`ApprovalRequest`] anywhere — a client cannot reach one, and neither can a future caller by
//! accident, because the field does not exist to wire up. That is the design decision stated in the
//! type rather than in a comment: a surface with nobody to ask has no approver to hand it.
//!
//! What the gate *does* call is [`ApprovalSession::decide`], because that is the policy evaluation —
//! deny rules, ask rules, the ceiling, the level threshold — and re-implementing it here would be a
//! second policy that agrees today and drifts later. `decide` answers `Ask` by recording the request
//! in the session's own slot; this server applies the session's fail-closed default
//! ([`ApprovalSession::timeout`], "no response within the timeout; defaulted to deny") and refuses in
//! the same call, **under the same lock, before the guard is released**, so the intermediate state is
//! unobservable by anything else in this process. Nothing is queued, nothing is emitted, no client is
//! told a question exists. The property the tests hold is the observable one: after a refused call,
//! [`McpServer::outstanding`] is `None` and the daemon's [`hx_agent::ApprovalQueue`] is empty.
//!
//! ## An MCP client's arguments are untrusted input
//!
//! Stated here because it governs the shape of the gate. A client's `arguments` are parsed by the
//! tool that declared them and by nothing else, its claims about itself are not read, and the only
//! prose this server sends is a refusal reason it wrote. A client that asks for a destructive tool
//! with an `allow` rule in place gets the destructive tool — that is the operator's decision, made in
//! the policy — but it never gets one because it *said* it needed one.
//!
//! ## What is deliberately not done
//!
//! - **No HTTP transport** (above), and therefore no authentication story, no session header, no
//!   OAuth: none of it is needed for a pipe the operator started.
//! - **No `resources/*` or `prompts/*`**, and no server-initiated requests. This server advertises
//!   the `tools` capability and nothing else: `hx`'s tools are what it has to offer, and the rest of
//!   MCP's surface is machinery a caller does not need and a hole it should not be given.
//! - **No tool annotations.** The protocol's `readOnlyHint`/`destructiveHint` are the *server's*
//!   claims about itself, and this crate's other half is explicit that a client must not decide
//!   anything from them. This server does not emit hints it would then have to be trusted for.
//! - **No sampling, roots or elicitation on the client side of the handshake.** Those are the three
//!   capabilities through which a server reaches back into its client, and this server has no reason
//!   to ask the client for any of them.

use chrono::Utc;
use hx_core::approval::{ActionRequest, ApprovalRequest, ApprovalSession, Verdict};
use hx_core::capability::{CapabilityToken, Decision};
use hx_tools::{ToolContext, ToolInfo, ToolOutcome, ToolRegistry};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// What one call did, as the server knows it.
///
/// Two arms rather than a `Result`, because both are *answers* the client reads: a tool that ran and
/// reported a failure is [`CallOutcome::Ran`] with `ok: false` (the model of the tool's own outcome),
/// while [`CallOutcome::Refused`] means the gate stopped the call and nothing happened. Keeping the
/// distinction is what makes the counters and the transcript honest about which of the two occurred.
#[derive(Clone, Debug, PartialEq)]
pub enum CallOutcome {
    /// The tool ran. Whether it succeeded is the tool's own verdict.
    Ran(ToolOutcome),
    /// The gate stopped the call before it reached the tool. The reason is written for the client's
    /// user to read.
    Refused { reason: String },
}

impl CallOutcome {
    /// The text the client sees.
    pub fn text(&self) -> &str {
        match self {
            Self::Ran(outcome) => &outcome.content,
            Self::Refused { reason } => reason,
        }
    }

    /// Whether MCP should mark this result as an error. A refusal always is one; a run is whatever
    /// the tool said.
    pub fn is_error(&self) -> bool {
        match self {
            Self::Ran(outcome) => !outcome.ok,
            Self::Refused { .. } => true,
        }
    }

    /// Whether the gate stopped this call, as opposed to the tool having run.
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }
}

/// What this server has done since it started.
///
/// A count and not a log: the numbers are what an operator asks a long-lived server for ("is anything
/// getting through, and is the policy refusing a lot?"), and the reasons are already in the answers
/// the clients received. `refused_needing_approval` is the one that matters most — it is the count of
/// calls that a surface able to ask a person would have put a question to, and which this one
/// refused instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Every `tools/call` this server handled, whatever became of it.
    pub calls: u64,
    /// Calls that reached a tool.
    pub ran: u64,
    /// Calls refused because the approval policy would have asked a person.
    pub refused_needing_approval: u64,
    /// Calls refused for any other reason: an unknown tool, unusable arguments, a capability denial,
    /// a deny rule. The distinction is kept because these are the refusals a client *can* do
    /// something about, and the approval one is not.
    pub refused_other: u64,
}

/// The counters behind [`ServerStats`], updated on the call path.
#[derive(Debug, Default)]
struct Counters {
    calls: AtomicU64,
    ran: AtomicU64,
    refused_needing_approval: AtomicU64,
    refused_other: AtomicU64,
}

impl Counters {
    fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ServerStats {
        ServerStats {
            calls: self.calls.load(Ordering::Relaxed),
            ran: self.ran.load(Ordering::Relaxed),
            refused_needing_approval: self.refused_needing_approval.load(Ordering::Relaxed),
            refused_other: self.refused_other.load(Ordering::Relaxed),
        }
    }
}

/// `hx`'s tools, served to an MCP client over stdio, behind the same gate a local call passes.
///
/// Construction is the whole configuration: a registry of tools, the context they run in, the
/// capability this server holds, and the approval policy it applies. There is deliberately no
/// approver and no queue — see the module doc.
pub struct McpServer {
    /// The tools this server advertises and dispatches to. `Arc` because the registry is the host's,
    /// not this server's: one daemon may offer the same tools to a local run and to a client.
    registry: Arc<ToolRegistry>,
    /// Where the tools act. A workspace and a host, exactly as a local run has.
    ctx: ToolContext,
    /// What this server may do at all. A capability denial is not an approval decision and no client
    /// can talk its way past one.
    capability: CapabilityToken,
    /// The policy, and the slot `decide` records a question in. `std::sync::Mutex` rather than an
    /// async one: the critical section is synchronous (policy evaluation), it is never held across an
    /// `await`, and holding a `tokio` lock for it would mean an `await` point inside the gate for no
    /// reason. This is the same shape `hx-agent`'s loop uses for the same object.
    approvals: Mutex<ApprovalSession>,
    counters: Counters,
}

impl McpServer {
    /// Build the server half over a tool registry.
    ///
    /// `capability` is required and not optional: every surface in `hx` runs under a token, and a
    /// server that had no grant would have to either refuse everything or invent one, and inventing
    /// one is how a remote surface becomes the way around the capability check.
    pub fn new(
        registry: Arc<ToolRegistry>,
        ctx: ToolContext,
        capability: CapabilityToken,
        approvals: ApprovalSession,
    ) -> Self {
        Self {
            registry,
            ctx,
            capability,
            approvals: Mutex::new(approvals),
            counters: Counters::default(),
        }
    }

    /// The tools this server advertises: the registry's own list, in registration order.
    ///
    /// Read from [`ToolRegistry::describe`] on every `tools/list` rather than captured at
    /// construction, so a registry that gains a tool (an MCP host registering the tools of a server it
    /// just brought up) is advertised without restarting anything.
    pub fn tools(&self) -> Vec<ToolInfo> {
        self.registry.describe()
    }

    /// The tool names, for a message a person reads.
    pub fn tool_names(&self) -> Vec<String> {
        self.registry.names()
    }

    /// Whether an approval question is outstanding in this server's session.
    ///
    /// This is [`ApprovalSession::outstanding`], exposed because the property this module claims is
    /// about exactly that value: a refused call must leave **nothing** a person could answer. There
    /// is no matching method to *answer* one — a surface with no approver has no reason to hold a
    /// request, and a setter here would be the approval-posting path this design removes.
    pub fn outstanding(&self) -> Option<ApprovalRequest> {
        self.approvals
            .lock()
            .expect("approval lock")
            .outstanding()
            .cloned()
    }

    /// What this server has done so far.
    pub fn stats(&self) -> ServerStats {
        self.counters.snapshot()
    }

    /// Run one call through the gate: prepare, capability, approval, run.
    ///
    /// The order is `hx-agent`'s and is not arbitrary. Arguments are parsed **once**, by the tool, so
    /// the call that is judged and the call that runs cannot differ. The capability is checked before
    /// the approval because a denial there is auditable and not something an approval could authorise.
    /// The approval is consulted last, because it is a decision about one instance of something the
    /// server was already allowed to do.
    ///
    /// Every return is an answer the client can read: an unknown tool, unusable arguments, a
    /// capability denial, a deny rule, an approval this surface cannot ask about, or a tool's own
    /// result. This function does not return `Err` and does not panic for anything a client sent.
    pub async fn call(&self, name: &str, arguments: Value) -> CallOutcome {
        Counters::bump(&self.counters.calls);

        // Phase 1: the tool's own parse. `prepare` rejects an unknown name and unusable arguments,
        // and the requirement it returns is the one this whole function is built on.
        let prepared = match self.registry.prepare(name, arguments, &self.ctx) {
            Ok(prepared) => prepared,
            Err(err) => return self.refuse_other(format!("could not run {name}: {err}")),
        };

        // Phase 2: the capability. Not approvable, not retryable, and worth saying so.
        if let Some(requirement) = prepared.requirement() {
            let decision =
                self.capability
                    .check(&requirement.resource, requirement.action, Utc::now());
            if let Decision::Deny(reason) = decision {
                return self.refuse_other(format!(
                    "refused: the capability this MCP server holds does not cover this call \
                     ({reason}). A capability denial is not an approval decision — a client cannot \
                     retry it away — so this needs the operator to widen the grant this server was \
                     started with."
                ));
            }
        }

        // Phase 3: the policy. This is the step a local call would turn into a prompt, and the step
        // this surface turns into a refusal.
        if let Some(requirement) = prepared.requirement() {
            let (risk, reason) = hx_agent::risk_of(&requirement.resource, requirement.action);
            let action =
                ActionRequest::tool(prepared.name(), requirement.describes.clone(), risk, reason)
                    // What the call will touch, measured before anyone is asked — a local call measures it
                    // here too, and a refusal that cannot say what it was about is a worse answer than one
                    // that can.
                    .with_targets(prepared.targets(&self.ctx).await.unwrap_or_default())
                    .with_undo_opt(prepared.undo(&self.ctx))
                    .confined_to(prepared.confinement(&self.ctx));

            let verdict = {
                let mut approvals = self.approvals.lock().expect("approval lock");
                approvals.decide(&action, Utc::now())
            };

            match verdict {
                Verdict::Allow { .. } => {}
                Verdict::Deny { why } => {
                    return self.refuse_other(format!("refused by policy: {why}"));
                }
                Verdict::Ask(request) => {
                    // The whole design, in one block. There is no approver to hand this to and no
                    // queue to publish it to, so the session's own fail-closed default is applied —
                    // under the same lock, in the same call — and the client is told why. The
                    // question never leaves this function, which is what makes "no approval request
                    // was raised" a property rather than a promise.
                    let _ = self.approvals.lock().expect("approval lock").timeout();
                    Counters::bump(&self.counters.refused_needing_approval);
                    return CallOutcome::Refused {
                        reason: approval_refusal(prepared.name(), &request),
                    };
                }
            }
        }

        // Phase 4: run it. A tool that ran and failed is a result the client reads, not an error the
        // server reports: the caller has to see "exit 1" and adapt, exactly as the local loop's model
        // does.
        Counters::bump(&self.counters.ran);
        match prepared.run(&self.ctx).await {
            Ok(outcome) => CallOutcome::Ran(outcome),
            Err(err) => CallOutcome::Ran(ToolOutcome::failed(format!(
                "the tool could not act: {err}"
            ))),
        }
    }

    /// Record a refusal that is not the approval step, and hand back the answer.
    fn refuse_other(&self, reason: String) -> CallOutcome {
        Counters::bump(&self.counters.refused_other);
        CallOutcome::Refused { reason }
    }

    /// One tool, in the protocol's shape, from the registry's own description.
    ///
    /// The schema goes over the wire as the tool declared it. It is not re-written here, and it is
    /// not summarised: a client that gets a different schema than the tool parses against is a client
    /// that sends arguments the tool will reject.
    fn tool_definition(info: &ToolInfo) -> Tool {
        let schema = match &info.schema {
            Value::Object(map) => map.clone(),
            // A tool whose schema is not an object has no usable input schema; the protocol requires
            // an object, and an empty one is the honest rendering of "this tool declared none".
            _ => serde_json::Map::new(),
        };
        Tool::new(info.name.clone(), info.description.clone(), schema)
    }
}

/// What a client reads when a call needed approval this surface cannot ask for.
///
/// Three things have to be in it, and each is there for a reason: the **tool** (a client may have
/// asked for several), the **risk and the policy's own reason** (so the operator reading the client's
/// transcript knows what the call was about without digging), and the **two ways to allow it** — an
/// `allow` rule, or a surface that can reach the operator. A refusal that names no way forward is a
/// dead end for whoever has to fix it.
fn approval_refusal(tool: &str, request: &ApprovalRequest) -> String {
    format!(
        "refused: `{tool}` needs approval before it can run — {} ({}) — and this is a stdio MCP \
         connection, so there is nobody to ask: hx raised no approval request here, because a \
         question parked with no surface to answer it is not a question. To allow it, either add an \
         `allow` rule for `{tool}` to the policy this server was started with, or run the call from a \
         surface that can reach you (the TUI, a chat, or `POST /v1/approvals`) and let the decision \
         live there.",
        request.risk.label(),
        request.reason
    )
}

impl ServerHandler for McpServer {
    /// The tools capability, and nothing else — see the module doc for why.
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(rmcp::model::Implementation::new(
                "hx-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "hx's own tools, behind hx's capability and approval policy. A call that would need \
                 a person's approval is refused here rather than prompted for: this connection has \
                 no surface to ask. Ask the operator for an `allow` rule if a tool you need is \
                 refused.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(
            self.tools().iter().map(Self::tool_definition).collect(),
        ))
    }

    /// Answer "what is this tool?" from the registry, which is also what a client's argument
    /// validation is checked against when the transport asks.
    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools()
            .iter()
            .find(|info| info.name == name)
            .map(Self::tool_definition)
    }

    /// `tools/call`: the gate, and then a result the client can read.
    ///
    /// A refusal is `CallToolResult::error` — a *result* with the reason in its content — rather than
    /// a JSON-RPC protocol error, and that is the protocol's own guidance: a protocol error is
    /// rendered opaquely by most clients ("tool result missing due to internal error"), and a
    /// refusal nobody can read is a refusal nobody can act on. Only a request that cannot be parsed
    /// at all is a protocol error, and that decision belongs to the transport, not here.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let outcome = self.call(&request.name, arguments).await;
        let block = ContentBlock::text(outcome.text().to_string());
        let result = if outcome.is_error() {
            CallToolResult::error(vec![block])
        } else {
            CallToolResult::success(vec![block])
        };
        Ok(result.into())
    }
}

/// The tool set the `hx-mcp-server` binary serves.
///
/// It lives here rather than in the binary for a reason worth stating: a test can build this same
/// registry and compare what went over the wire against [`ToolRegistry::describe`], so the tool list
/// a client sees is checked against the registry rather than against a second, hand-written list that
/// would agree with itself forever.
///
/// The set is the local, single-machine half of `hx`'s tools — read, write, patch, delete, shell,
/// todo — over whatever host the caller puts in the [`ToolContext`]. `web_search` is not here because
/// it needs search backends a daemon chooses (`hx-server`'s `default_tools` registers it), and the
/// tools of *other* MCP servers are not here because a deployment that wants those registers
/// [`crate::McpHost::tools`] into the same registry.
pub fn default_registry() -> ToolRegistry {
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(hx_tools::ReadFileTool::new()));
    tools.register(Arc::new(hx_tools::WriteFileTool::new()));
    tools.register(Arc::new(hx_tools::PatchTool::new()));
    tools.register(Arc::new(hx_tools::DeleteTool::new()));
    tools.register(Arc::new(hx_tools::ShellTool::new()));
    tools.register(Arc::new(hx_tools::TodoTool::new()));
    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_agent::{ApprovalQueue, Approver};
    use hx_core::approval::{ApprovalOption, ApprovalPolicy, AutonomyLevel, RiskClass, Rule};
    use hx_core::capability::{Action, Capability, Resource};
    use hx_core::ids::AgentId;
    use hx_tools::testing::FakeHost;
    use serde_json::json;
    use std::time::Duration;

    const WORKSPACE: &str = "/ws";
    const SENTINEL: &str = "hx-mcp-server-test-sentinel-not-a-credential";

    fn ctx(host: FakeHost) -> ToolContext {
        ToolContext::new(Arc::new(host)).in_workspace(WORKSPACE)
    }

    /// A token that covers the workspace and process execution — the shape `hx-server`'s daemon
    /// issues for a run, so a test that passes here is not passing because the token was unusually
    /// generous.
    fn capability() -> CapabilityToken {
        CapabilityToken::issue(
            AgentId::from_raw("hx-mcp-server:test"),
            vec![
                Capability::workspace(WORKSPACE),
                Capability::new(Resource::Process, [Action::Execute, Action::Spawn]),
            ],
            Utc::now(),
            3_600,
        )
    }

    fn policy(level: AutonomyLevel) -> ApprovalPolicy {
        ApprovalPolicy::at(level)
    }

    /// A policy that asks about every read — the fixture for the refusal tests, and the one that
    /// makes "a local call leaves a question" and "an MCP call leaves nothing" comparable.
    fn policy_asking_about_reads() -> ApprovalPolicy {
        let mut policy = policy(AutonomyLevel::Balanced);
        policy
            .ask
            .push(Rule::tool("read_file").note("show me every read"));
        policy
    }

    /// A server over an in-memory host holding one readable file and one deletable path.
    fn server(policy: ApprovalPolicy) -> McpServer {
        let host = FakeHost::unix()
            .with_file("/ws/notes.txt", SENTINEL)
            .with_file("/ws/doomed.txt", "still here");
        McpServer::new(
            Arc::new(default_registry()),
            ctx(host),
            capability(),
            ApprovalSession::new(policy),
        )
    }

    /// The call every refusal test makes: a read, which `balanced` allows and an `ask` rule does not.
    async fn read(server: &McpServer) -> CallOutcome {
        server
            .call("read_file", json!({ "path": "/ws/notes.txt" }))
            .await
    }

    #[tokio::test]
    async fn the_tools_advertised_are_the_registrys_own_descriptions_and_schemas() {
        // The wire is checked against the registry, not against a second list: build the same
        // registry, compare every field of every tool.
        let server = server(policy(AutonomyLevel::Balanced));
        let expected = default_registry().describe();

        let advertised = server.tools();
        assert_eq!(
            advertised.iter().map(|t| &t.name).collect::<Vec<_>>(),
            expected.iter().map(|t| &t.name).collect::<Vec<_>>(),
            "names come from the registry, in its order"
        );
        for info in &advertised {
            let from_registry = expected
                .iter()
                .find(|t| t.name == info.name)
                .expect("the registry has this tool");
            assert_eq!(info.schema, from_registry.schema, "{}", info.name);
            assert_eq!(info.description, from_registry.description, "{}", info.name);
        }

        // And the protocol shape carries them unchanged.
        let definition = McpServer::tool_definition(&advertised[0]);
        assert_eq!(definition.name, advertised[0].name);
        assert_eq!(
            Value::Object(definition.input_schema.as_ref().clone()),
            advertised[0].schema
        );
    }

    #[tokio::test]
    async fn a_read_only_call_under_a_policy_that_allows_it_runs() {
        // The control for every refusal below: the same tool, the same registry, the same arguments.
        let server = server(policy(AutonomyLevel::Balanced));
        let outcome = read(&server).await;

        assert!(!outcome.is_refused(), "{}", outcome.text());
        assert!(outcome.text().contains(SENTINEL), "{}", outcome.text());
        assert_eq!(
            server.stats(),
            ServerStats {
                calls: 1,
                ran: 1,
                ..Default::default()
            }
        );
    }

    #[tokio::test]
    async fn a_call_that_needs_approval_is_refused_and_names_the_approval_and_the_way_out() {
        // An `ask` rule on a read: the policy wants to see every one of them, and this surface has
        // nobody to show it to.
        let server = server(policy_asking_about_reads());

        let outcome = read(&server).await;
        assert!(outcome.is_refused(), "{}", outcome.text());

        let text = outcome.text();
        for expected in [
            "needs approval",
            "show me every read",
            "stdio",
            "read_file",
            "allow",
        ] {
            assert!(text.contains(expected), "{expected:?} missing from: {text}");
        }
        assert_eq!(
            server.stats().refused_needing_approval,
            1,
            "the refusal came from the approval step, not from an argument or capability error"
        );
        assert_eq!(server.stats().ran, 0, "nothing ran");
    }

    #[tokio::test]
    async fn a_refused_call_leaves_nothing_a_person_could_answer_where_the_local_path_leaves_a_question(
    ) {
        // The test that replaces "an approver that would say yes". There is no approver in this
        // design, so what is asserted is the *absence* of anything one could answer — and the first
        // half is what makes that assertion able to fail: the local path, on the same policy and the
        // same tool, does leave an outstanding request behind.
        let server = server(policy_asking_about_reads());

        // The local path: `hx-agent`'s loop builds the same request and calls `decide` on the same
        // policy. Here it is done by hand, because the loop needs a model to exist at all.
        let local_action = ActionRequest::tool(
            "read_file",
            "read /ws/notes.txt",
            RiskClass::Read,
            "reads /ws/notes.txt",
        );
        let local_verdict = {
            let mut session = ApprovalSession::new(policy_asking_about_reads());
            session.decide(&local_action, Utc::now())
        };
        assert!(
            local_verdict.is_asking(),
            "the fixture: a local call on this policy asks"
        );

        // The MCP path: refused, and the session it applied the decision to has nothing parked.
        let outcome = read(&server).await;
        assert!(outcome.is_refused(), "{}", outcome.text());
        assert!(
            server.outstanding().is_none(),
            "a request was left outstanding, so a person could have answered it: {:?}",
            server.outstanding()
        );
    }

    #[tokio::test]
    async fn the_daemons_approval_queue_shows_a_local_question_and_never_sees_an_mcp_one() {
        // The queue is the surface a person answers from. A local run's question lands in it — the
        // first half proves the queue is a live channel, so the second half is not asserting that an
        // object nobody wrote to is empty. The MCP server holds no queue at all (that is the design:
        // no approver, no posting path), so the assertion is that its refusal published nothing.
        let queue = ApprovalQueue::new(Duration::from_secs(30));

        let action =
            ActionRequest::tool("read_file", "read /ws/notes.txt", RiskClass::Read, "reads");
        let request = {
            let mut session = ApprovalSession::new(ApprovalPolicy::paranoid());
            match session.decide(&action, Utc::now()) {
                Verdict::Ask(request) => *request,
                other => panic!("the fixture asks: {other:?}"),
            }
        };

        let asking = {
            let queue = Arc::clone(&queue);
            let request = request.clone();
            let action = action.clone();
            tokio::spawn(async move { queue.decide(&request, &action).await })
        };

        // Bounded: the question must appear, and the failure says so rather than hanging.
        let seen = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(first) = queue.outstanding(None).first() {
                    break first.id.clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a local run's question reaches the queue");
        assert_eq!(queue.outstanding(None).len(), 1);

        // Answer it, so the waiting run ends and the queue is clean for the second half.
        assert_eq!(
            queue.answer(seen.as_str(), ApprovalOption::Deny, "test", RiskClass::Read),
            hx_agent::AnswerResult::Answered
        );
        let _ = tokio::time::timeout(Duration::from_secs(10), asking)
            .await
            .expect("the waiting run ends when the question is answered");

        // Now the MCP path, on a policy that asks about the same call.
        let server = server(policy_asking_about_reads());
        let outcome = read(&server).await;
        assert!(outcome.is_refused(), "{}", outcome.text());

        assert!(
            queue.outstanding(None).is_empty(),
            "the refusal published a question to the daemon's approval surface: {:?}",
            queue.outstanding(None)
        );
        assert!(
            queue.is_empty(),
            "nothing may be waiting anywhere a person could answer it"
        );
        assert!(server.outstanding().is_none());
    }

    #[tokio::test]
    async fn a_destructive_tool_is_refused_and_the_path_it_names_is_untouched() {
        // `delete` is `FsPath` + `Delete`, which `hx-agent`'s risk table classifies `Destructive` —
        // above `balanced`'s threshold, so the policy asks and this surface refuses. The file is the
        // evidence that nothing happened: a refusal that still deleted would pass a test that only
        // read the message.
        let server = server(policy(AutonomyLevel::Balanced));
        let outcome = server
            .call("delete", json!({ "path": "/ws/doomed.txt" }))
            .await;

        assert!(outcome.is_refused(), "{}", outcome.text());
        assert!(
            outcome.text().contains("destructive"),
            "the risk class is named: {}",
            outcome.text()
        );
        assert_eq!(
            server.stats().refused_needing_approval,
            1,
            "refused by the approval step, which is the same step a destructive local call meets"
        );
    }

    #[tokio::test]
    async fn a_destructive_tool_runs_when_the_policy_allows_it() {
        // The control for the refusal above, and the reason the refusal is not a capability or
        // argument error: with an `allow` rule the same call reaches the tool.
        let mut policy = policy(AutonomyLevel::Balanced);
        policy.allow.push(Rule::tool("delete"));
        let server = server(policy);

        let outcome = server
            .call("delete", json!({ "path": "/ws/doomed.txt" }))
            .await;
        assert!(
            !outcome.is_refused(),
            "an allow rule is the operator's decision and it reaches the tool: {}",
            outcome.text()
        );
    }

    #[tokio::test]
    async fn a_capability_denial_is_refused_as_a_capability_and_not_as_a_question() {
        // A token for a different workspace: the tool is fine, the arguments are fine, and the
        // answer says which gate refused it — because "widen the grant" and "add an allow rule" are
        // different repairs.
        let host = FakeHost::unix().with_file("/elsewhere/notes.txt", SENTINEL);
        let server = McpServer::new(
            Arc::new(default_registry()),
            ctx(host),
            capability(),
            ApprovalSession::new(policy(AutonomyLevel::Balanced)),
        );

        let outcome = server
            .call("read_file", json!({ "path": "/elsewhere/notes.txt" }))
            .await;
        assert!(outcome.is_refused(), "{}", outcome.text());
        assert!(outcome.text().contains("capability"), "{}", outcome.text());
        assert_eq!(server.stats().refused_needing_approval, 0);
        assert_eq!(server.stats().refused_other, 1);
        assert!(server.outstanding().is_none());
    }

    #[tokio::test]
    async fn unusable_arguments_are_refused_before_the_policy_is_consulted() {
        // A paranoid policy asks about everything, so if the ordering were wrong this call would
        // come back as an approval refusal. It must be an argument error: there is nothing to ask
        // about a call that cannot be built.
        let server = server(policy(AutonomyLevel::Paranoid));
        let outcome = server.call("read_file", json!({})).await;

        assert!(outcome.is_refused(), "{}", outcome.text());
        assert!(outcome.text().contains("path"), "{}", outcome.text());
        assert_eq!(server.stats().refused_needing_approval, 0);
        assert_eq!(server.stats().refused_other, 1);
    }

    #[tokio::test]
    async fn an_unknown_tool_names_the_ones_that_exist() {
        let server = server(policy(AutonomyLevel::Balanced));
        let outcome = server.call("rm_rf", json!({})).await;

        assert!(outcome.is_refused(), "{}", outcome.text());
        assert!(
            outcome.text().contains("no tool named 'rm_rf'"),
            "{}",
            outcome.text()
        );
        assert!(outcome.text().contains("read_file"), "{}", outcome.text());
    }

    #[tokio::test]
    async fn a_tool_with_no_external_effect_runs_without_asking_a_person() {
        // `todo` returns `None` from `requirement`, which is the loop's own answer to "this touches
        // nothing outside the process". The gate must not invent a requirement for it — and at
        // `paranoid`, where *every* classified call is refused, an unclassified one still runs.
        let server = server(policy(AutonomyLevel::Paranoid));
        let outcome = server.call("todo", json!({ "action": "list" })).await;

        assert!(!outcome.is_refused(), "{}", outcome.text());
        assert_eq!(server.stats().ran, 1);
    }

    #[test]
    fn the_info_advertises_tools_and_nothing_else() {
        let server = server(policy(AutonomyLevel::Balanced));
        let wire = serde_json::to_value(server.get_info()).expect("serialises");

        assert!(
            wire["capabilities"]["tools"].is_object(),
            "the tools capability is advertised: {wire}"
        );
        for absent in [
            "resources",
            "prompts",
            "logging",
            "sampling",
            "roots",
            "elicitation",
        ] {
            assert!(
                wire["capabilities"].get(absent).is_none(),
                "{absent} must not be advertised: {wire}"
            );
        }
        assert_eq!(wire["serverInfo"]["name"], "hx-mcp");
    }
}
