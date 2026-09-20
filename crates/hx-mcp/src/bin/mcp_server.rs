//! `hx-mcp-server`: `hx`'s tools, served to somebody else's MCP client over stdio or HTTP.
//!
//! ## What this binary is, and what it deliberately is not
//!
//! It is the transport's entry point and nothing else. Everything it serves is
//! [`hx_mcp::server::McpServer`], so the gate a client's call passes through is the same code a test
//! drives without a pipe, and there is one file to read to know what a call may do.
//!
//! - **stdout is the wire in stdio mode.** Every byte written there is a JSON-RPC message. Nothing in
//!   this program prints to it — not a banner, not a warning, not a help message (`--help` goes to
//!   stderr for exactly this reason). A stray `println!` here would be a protocol error on every
//!   client's first read.
//! - **stderr is not a log sink.** No `tracing` subscriber is installed, so nothing a tool does, a
//!   client sends or a policy decides can reach it: the only lines this program writes are one
//!   startup line and its own fatal errors, neither of which contains a tool's output or an argument.
//! - **stdio is the default.** When `--http` or `--bind` is passed, it serves over streamable HTTP
//!   behind bearer-token authentication. A non-loopback bind without a token configured is refused
//!   at startup.
//! - **There is no approver.** A call the policy would put a question to is refused, immediately,
//!   with a reason naming the two ways an operator can allow it.
//!
//! ## Usage
//!
//! ```text
//! hx-mcp-server [--workspace DIR] [--policy LEVEL] [--ask GLOB]... [--allow GLOB]...
//!               [--report FILE] [--http [BIND]] [--bind ADDR] [--token TOKEN]
//! ```
//!
//! | flag | meaning |
//! |---|---|
//! | `--workspace DIR` | the directory the tools act in (default: the current directory) |
//! | `--policy LEVEL` | `paranoid`, `cautious`, `balanced` (default), `trusting` or `yolo` |
//! | `--ask GLOB` | force a refusal for calls to a matching tool name; repeatable |
//! | `--allow GLOB` | auto-allow a matching tool name, below the level's threshold; repeatable |
//! | `--report FILE` | write the session's state as JSON when the connection ends |
//! | `--http [BIND]` | serve over streamable HTTP instead of stdio (default bind: 127.0.0.1:8787) |
//! | `--bind ADDR` | bind address for HTTP mode (default: 127.0.0.1:8787, or `HX_BIND`) |
//! | `--token TOKEN` | bearer token for HTTP mode (or `HX_API_TOKEN` in environment) |
//!
//! `--report` exists for an operator who wants to know what a long-lived connection did, and for the
//! test suite, which uses it to read the *server's own* approval state after a refused call: the
//! property under test ("a refused call raised no approval request") is about an object inside this
//! process, and the report is how a client-side test can observe it rather than infer it.
//!
//! The policy defaults to [`ApprovalPolicy::deployment_default`] — `balanced` plus the shipped
//! catastrophe denials — because an MCP server is a *deployment*, not a library caller, and the
//! floor is what an operator expects to still be there when they have configured nothing.

use chrono::Utc;
use hx_core::api_auth::{ApiToken, API_TOKEN_ENV};
use hx_core::approval::{ApprovalPolicy, ApprovalSession, AutonomyLevel, Rule};
use hx_core::capability::{Action, Capability, CapabilityToken, Resource};
use hx_core::ids::{AgentId, HostId};
use hx_mcp::server::{default_registry, McpServer};
use hx_remote::LocalHost;
use hx_tools::ToolContext;
use std::path::PathBuf;
use std::sync::Arc;

/// The exit code for a usage error, the same one `hx-mcp-fake-server` uses.
const USAGE_EXIT: i32 = 64;

const USAGE: &str = "\
hx-mcp-server: serve hx's tools to an MCP client over stdio or HTTP

usage: hx-mcp-server [--workspace DIR] [--policy LEVEL] [--ask GLOB]... [--allow GLOB]...
                     [--report FILE] [--http [BIND]] [--bind ADDR] [--token TOKEN]

  --workspace DIR   the directory the tools act in (default: the current directory)
  --policy LEVEL    paranoid | cautious | balanced | trusting | yolo  (default: balanced)
  --ask GLOB        force a refusal for calls to a matching tool name; repeatable
  --allow GLOB      auto-allow a matching tool name below the level's threshold; repeatable
  --report FILE     write the session's approval state as JSON when the connection ends
  --http [BIND]     serve over streamable HTTP instead of stdio (default bind: 127.0.0.1:8787)
  --bind ADDR       bind address for HTTP mode (default: 127.0.0.1:8787, or HX_BIND)
  --token TOKEN     bearer token for HTTP mode (or HX_API_TOKEN in environment)

A call the approval policy would ask a person about is refused here: this connection has no
surface to ask. Add an `allow` rule for a tool you want this connection to be able to call.";

struct Args {
    workspace: PathBuf,
    level: AutonomyLevel,
    ask: Vec<String>,
    allow: Vec<String>,
    report: Option<PathBuf>,
    http: bool,
    bind: Option<String>,
    token: Option<String>,
}

impl Args {
    fn parse(argv: Vec<String>) -> Result<Self, String> {
        let mut workspace: Option<PathBuf> = None;
        let mut level = AutonomyLevel::Balanced;
        let mut ask = Vec::new();
        let mut allow = Vec::new();
        let mut report = None;
        let mut http = false;
        let mut bind = None;
        let mut token = None;

        let mut iter = argv.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--workspace" => {
                    workspace = Some(PathBuf::from(
                        iter.next().ok_or("--workspace needs a value")?,
                    ))
                }
                "--policy" => {
                    let value = iter.next().ok_or("--policy needs a value")?;
                    level = AutonomyLevel::parse(&value).ok_or_else(|| {
                        format!(
                            "unknown policy {value:?}; expected one of {}",
                            AutonomyLevel::NAMES.join(", ")
                        )
                    })?;
                }
                "--ask" => ask.push(iter.next().ok_or("--ask needs a value")?),
                "--allow" => allow.push(iter.next().ok_or("--allow needs a value")?),
                "--report" => {
                    report = Some(PathBuf::from(iter.next().ok_or("--report needs a value")?))
                }
                "--http" => {
                    http = true;
                    if let Some(peek) = iter.as_slice().first() {
                        if !peek.starts_with("--") {
                            bind = Some(iter.next().unwrap());
                        }
                    }
                }
                "--bind" => {
                    http = true;
                    bind = Some(iter.next().ok_or("--bind needs a value")?);
                }
                "--token" => {
                    token = Some(iter.next().ok_or("--token needs a value")?);
                }
                "--help" | "-h" => {
                    // To stderr, because stdout may be the wire — see the module doc.
                    eprintln!("{USAGE}");
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument {other:?}")),
            }
        }

        // A workspace is where the tools act, and a relative one is resolved now rather than after
        // the process has been running for hours: the path in a refusal or a report has to be the one
        // the caller meant.
        let workspace = match workspace {
            Some(path) => path,
            None => {
                std::env::current_dir().map_err(|err| format!("no working directory: {err}"))?
            }
        };

        Ok(Self {
            workspace,
            level,
            ask,
            allow,
            report,
            http,
            bind,
            token,
        })
    }

    fn http_bind(&self) -> Option<String> {
        if self.http || self.bind.is_some() {
            Some(
                self.bind
                    .clone()
                    .or_else(|| std::env::var("HX_BIND").ok())
                    .unwrap_or_else(|| "127.0.0.1:8787".to_string()),
            )
        } else {
            None
        }
    }

    fn resolved_token(&self) -> Option<String> {
        self.token
            .clone()
            .or_else(|| std::env::var(API_TOKEN_ENV).ok())
            .filter(|t| !t.is_empty())
    }

    /// The policy this server runs under.
    ///
    /// The deployment default first — `balanced` and the shipped catastrophe denials — so that
    /// `--policy` moves the *threshold* without dropping the floor, which is the same fold a config
    /// file gets. Then the operator's rules, in the order the policy consults them.
    fn policy(&self) -> ApprovalPolicy {
        let mut policy = ApprovalPolicy::deployment_default();
        policy.level = self.level;
        for pattern in &self.allow {
            policy.allow.push(Rule::tool(pattern.clone()));
        }
        for pattern in &self.ask {
            policy
                .ask
                .push(Rule::tool(pattern.clone()).note("an `ask` rule on this server's policy"));
        }
        policy
    }

    /// The token this server runs under.
    ///
    /// The workspace, and the ability to spawn processes — the same grant `hx-server` issues for a
    /// daemon run, and deliberately not wider: a client that wants a path outside the workspace is
    /// denied by the token, and unlike an approval that is not something anyone can answer away.
    fn capability(&self, now: chrono::DateTime<Utc>) -> CapabilityToken {
        CapabilityToken::issue(
            AgentId::from_raw(format!("hx-mcp-server:{}", self.workspace.display())),
            vec![
                Capability::workspace(self.workspace.to_string_lossy().into_owned()),
                Capability::new(Resource::Process, [Action::Execute, Action::Spawn]),
            ],
            now,
            // Twelve hours. A connection that has been open longer than that is a client that should
            // reconnect, and a grant with no end is a grant nobody revisits.
            12 * 60 * 60,
        )
    }
}

fn main() {
    let args = match Args::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("hx-mcp-server: {message}\n\n{USAGE}");
            std::process::exit(USAGE_EXIT);
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("hx-mcp-server: could not start a runtime: {err}");
            std::process::exit(1);
        }
    };

    if let Err(message) = runtime.block_on(serve(args)) {
        eprintln!("hx-mcp-server: {message}");
        std::process::exit(1);
    }
}

async fn serve(args: Args) -> Result<(), String> {
    if let Some(bind) = args.http_bind() {
        serve_http(args, bind).await
    } else {
        serve_stdio(args).await
    }
}

/// Serve over streamable HTTP until terminated, then write the report.
async fn serve_http(args: Args, bind: String) -> Result<(), String> {
    let host = LocalHost::detect(HostId::from_raw("local"))
        .await
        .map_err(|err| format!("could not probe this machine: {err}"))?;
    let ctx = ToolContext::new(Arc::new(host))
        .in_workspace(args.workspace.to_string_lossy().into_owned());

    let registry = Arc::new(default_registry());
    let server = Arc::new(McpServer::new(
        registry,
        ctx,
        args.capability(Utc::now()),
        ApprovalSession::new(args.policy()),
    ));

    let token = args.resolved_token().map(ApiToken::new);
    let (addr, task) = hx_mcp::server_http::bind_and_serve(
        Arc::clone(&server),
        &bind,
        token,
    )
    .await
    .map_err(|err| err.to_string())?;

    eprintln!(
        "hx-mcp-server: {} tools over HTTP at http://{addr}/mcp, policy {}, workspace {}. A call that needs approval is refused: this connection has no surface to ask.",
        server.tool_names().len(),
        args.level.label(),
        args.workspace.display()
    );

    tokio::select! {
        res = task => {
            if let Err(err) = res {
                return Err(format!("the HTTP service task ended abnormally: {err}"));
            }
        }
        _ = tokio::signal::ctrl_c() => {}
    }

    if let Some(path) = &args.report {
        write_report(path, &args, &server)?;
    }
    Ok(())
}

/// Serve one stdio connection to the end, then write the report.
///
/// One connection per process, and the process is the transport: when the client closes the pipe,
/// `rmcp` sees EOF, the service ends, and this returns. That is the whole lifecycle — there is no
/// accept loop because there is nothing to accept.
async fn serve_stdio(args: Args) -> Result<(), String> {
    let host = LocalHost::detect(HostId::from_raw("local"))
        .await
        .map_err(|err| format!("could not probe this machine: {err}"))?;
    let ctx = ToolContext::new(Arc::new(host))
        .in_workspace(args.workspace.to_string_lossy().into_owned());

    let registry = Arc::new(default_registry());
    let server = Arc::new(McpServer::new(
        registry,
        ctx,
        args.capability(Utc::now()),
        ApprovalSession::new(args.policy()),
    ));

    eprintln!(
        "hx-mcp-server: {} tools over stdio, policy {}, workspace {}. A call that needs approval is \
         refused: this connection has no surface to ask.",
        server.tool_names().len(),
        args.level.label(),
        args.workspace.display()
    );

    // The handler is shared with the service rather than moved into it, so the state read below is
    // the state the calls actually went through.
    let running = rmcp::service::serve_server(Arc::clone(&server), rmcp::transport::io::stdio())
        .await
        .map_err(|err| format!("the MCP handshake failed: {err}"))?;

    let quit = running.waiting().await;
    if let Some(path) = &args.report {
        write_report(path, &args, &server)?;
    }
    quit.map_err(|err| format!("the service task ended abnormally: {err}"))?;
    Ok(())
}

/// Write what the session did, for an operator and for the tests.
///
/// `outstanding_approval` is [`McpServer::outstanding`] — the session's own slot, read at the end of
/// the connection. It is `false` here by construction (a refusal never leaves a request parked), and
/// it is written rather than assumed so that a regression which *did* park one would be visible to
/// whoever reads the file, including a test.
fn write_report(path: &std::path::Path, args: &Args, server: &McpServer) -> Result<(), String> {
    let stats = server.stats();
    let report = serde_json::json!({
        "policy": args.level.label(),
        "workspace": args.workspace.to_string_lossy(),
        "calls": stats.calls,
        "ran": stats.ran,
        "refused_needing_approval": stats.refused_needing_approval,
        "refused_other": stats.refused_other,
        "outstanding_approval": server.outstanding().is_some(),
    });
    let text = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("could not render the report: {err}"))?;
    std::fs::write(path, format!("{text}\n"))
        .map_err(|err| format!("could not write {}: {err}", path.display()))
}
