//! The streamable-HTTP transport: a real MCP server over a real socket, and the endpoints that
//! misbehave.
//!
//! ## What is real here, and what is deliberately not
//!
//! The happy path runs **`rmcp`'s own server** — its streamable-HTTP service on `axum`, on a real
//! loopback socket, answering real JSON-RPC. That is the strongest evidence available for this
//! transport: a client bug in the handshake, the session header, the `Accept` negotiation or the
//! response framing shows up as a failure against an implementation this crate does not own. A
//! hand-rolled stub that agreed with our own reading of the spec would prove nothing about the spec.
//!
//! The *misbehaving* endpoints are hand-rolled on purpose, and they are raw TCP rather than a
//! framework: what is being tested is what happens when a socket accepts and says nothing, or answers
//! 500, and a framework would be in the way of exactly that.
//!
//! ## The credential rule
//!
//! Two tests hold it, and they are a *pair* — either alone is worthless:
//!
//! - a sentinel token is resolved through `hx-secrets`, and the endpoint **records the
//!   `Authorization` header it received**, so the assertion that the token appears in no error and no
//!   log is made about a run that genuinely carried the token. A leak test against a code path that
//!   never had the secret is a no-op that passes forever.
//! - a reference that cannot be resolved fails **without dialling the endpoint**, asserted by an
//!   endpoint that received zero requests. Failing closed is the property; "it returned an error" is
//!   not, because a request that still went out unauthenticated also returns an error.

use hx_core::config::McpServerConfig;
use hx_mcp::{HealthState, McpHost};
use hx_secrets::source::{FixedSecrets, SecretStores};
use indexmap::IndexMap;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The sentinel credential. Distinctive enough that a substring match cannot be an accident, and it
/// is asserted absent from every error and every model-visible string.
const SENTINEL: &str = "hx-mcp-http-token-sentinel-do-not-print";

/// The words the real server uses to describe `echo`, so a test can tell the server's prose from
/// anything `hx` might have written itself.
const ECHO_DESCRIPTION: &str = "the MCP server's own description of echo, which is data";

// ---------------------------------------------------------------------------
// A real MCP server, on a real socket
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct EchoServer;

impl ServerHandler for EchoServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![
            Tool::new("echo", ECHO_DESCRIPTION, serde_json::Map::new()),
            Tool::new("fail", "always reports an error", serde_json::Map::new()),
        ]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let result = match request.name.as_ref() {
            "echo" => {
                let text = request
                    .arguments
                    .as_ref()
                    .and_then(|args| args.get("text"))
                    .and_then(|text| text.as_str())
                    .unwrap_or_default()
                    .to_string();
                CallToolResult::success(vec![ContentBlock::text(text)])
            }
            "fail" => {
                CallToolResult::error(vec![ContentBlock::text("the server refused, on purpose")])
            }
            other => {
                CallToolResult::error(vec![ContentBlock::text(format!("no such tool: {other}"))])
            }
        };
        // `CallToolResponse` is `#[non_exhaustive]`, so it is not constructed here; it implements
        // `From<CallToolResult>`, and `into()` is the one conversion that keeps working when the
        // enum grows a variant. This server only ever completes a call.
        Ok(result.into())
    }
}

/// A running MCP server, stopped when the value is dropped.
struct RealServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RealServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RealServer {
    fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }
}

async fn real_server() -> RealServer {
    let service: StreamableHttpService<EchoServer, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(EchoServer),
            Arc::<LocalSessionManager>::default(),
            StreamableHttpServerConfig::default().with_sse_keep_alive(None),
        );
    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let addr = listener.local_addr().expect("a bound address");
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    RealServer { addr, task }
}

// ---------------------------------------------------------------------------
// Endpoints that misbehave, on raw sockets
// ---------------------------------------------------------------------------

/// What a misbehaving endpoint does with a request that arrives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Misbehaviour {
    /// Accept the connection and never write a byte. The shape that wedges a client.
    Silent,
    /// Record the request head — headers included — and then answer `500 Internal Server Error`.
    ///
    /// The recording is not optional, and there is deliberately no separate "plain 500" mode: an
    /// endpoint that answers `500` *without* recording cannot tell a test apart from a client that
    /// never dialled at all, which is the one distinction every test using this mode depends on. The
    /// head is what makes "the request went out, carrying this `Authorization` header" an assertion
    /// rather than an assumption.
    ServerError,
}

/// An HTTP endpoint on a real socket, in one of the misbehaving modes. Whatever it receives is
/// appended to a log, which is how a test can prove a request was — or was *not* — sent.
struct Endpoint {
    addr: SocketAddr,
    log: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Endpoint {
    fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }

    /// Every request head the endpoint saw, as one string per request.
    fn requests(&self) -> Vec<String> {
        match std::fs::read_to_string(&self.log) {
            Ok(text) => text.lines().map(str::to_string).collect(),
            Err(_) => Vec::new(),
        }
    }
}

async fn misbehaving(behaviour: Misbehaviour) -> Endpoint {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let addr = listener.local_addr().expect("a bound address");
    let dir = tempfile::tempdir().expect("a temp dir");
    let log = dir.path().join("requests");
    let log_for_task = log.clone();

    let task = tokio::spawn(async move {
        // Hold the temp dir alive for as long as the endpoint is serving.
        let _dir = dir;
        loop {
            let Ok((mut socket, _peer)) = listener.accept().await else {
                return;
            };
            let log = log_for_task.clone();
            tokio::spawn(async move {
                match behaviour {
                    Misbehaviour::Silent => {
                        // Accepted, and deliberately never answered. Nothing here will time out for
                        // the client: its own clock is the only thing that ends this.
                        tokio::time::sleep(Duration::from_secs(3_600)).await;
                    }
                    Misbehaviour::ServerError => {
                        let mut buf = vec![0u8; 8_192];
                        let read = tokio::io::AsyncReadExt::read(&mut socket, &mut buf)
                            .await
                            .unwrap_or(0);
                        // Recorded before the response, and unconditionally: the log is what lets a
                        // test assert the request went out at all, and assert what it carried.
                        if read > 0 {
                            let head = String::from_utf8_lossy(&buf[..read]).replace('\r', "");
                            if let Ok(mut file) = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&log)
                            {
                                use std::io::Write;
                                // One line per request: the first line of the request is the request
                                // line, and the rest carries the headers a test wants to read.
                                let _ = writeln!(file, "{}", head.replace('\n', " | "));
                            }
                        }
                        let response =
                            b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\
                                         connection: close\r\n\r\n";
                        let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, response).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
                    }
                }
            });
        }
    });

    Endpoint { addr, log, task }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn config(entries: Vec<(&str, McpServerConfig)>) -> IndexMap<String, McpServerConfig> {
    entries
        .into_iter()
        .map(|(key, cfg)| (key.to_string(), cfg))
        .collect()
}

fn http_server(key: &str, url: &str, token: Option<&str>) -> (String, McpServerConfig) {
    let mut cfg = McpServerConfig::streamable_http(url);
    // Short, so a test that is meant to time out does so in about a second.
    cfg.start_timeout_secs = 2;
    cfg.call_timeout_secs = 2;
    cfg.token = token.map(str::to_string);
    (key.to_string(), cfg)
}

fn stores_with(reference_value: &str) -> Arc<SecretStores> {
    Arc::new(SecretStores::new().with(Arc::new(
        FixedSecrets::vault().set("mcp/test", reference_value),
    )))
}

fn assert_bounded(started: Instant, within: Duration, what: &str) {
    let elapsed = started.elapsed();
    assert!(
        elapsed < within,
        "{what} took {elapsed:?}, past the {within:?} bound — a socket that accepts and says nothing \
         must be cut off by hx's own clock, not waited on"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_streamable_http_server_is_reached_over_a_real_socket_and_its_tools_are_published() {
    let server = real_server().await;
    let (key, cfg) = http_server("remote", &server.url(), None);
    // Held in an `Arc` because `McpHost::tools` hands out `McpTool`s that each hold the host: a tool
    // has to outlive the call that built it, and it resolves the server by name at call time.
    let host = Arc::new(
        McpHost::from_config(&config(vec![(&key, cfg)]), None)
            .await
            .expect("config is fine"),
    );

    let names = host.tool_names();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.contains(&"remote__echo".to_string()), "{names:?}");

    let health = host.status().await;
    assert_eq!(health[0].transport, "streamable_http");
    assert!(
        matches!(&health[0].state, HealthState::Up { .. }),
        "{:?}",
        health[0].state
    );

    // The server's own description arrived, labelled as the server's.
    let echo = host
        .tools()
        .into_iter()
        .find(|tool| tool.name() == "remote__echo")
        .expect("echo is published");
    assert!(
        echo.description().contains(ECHO_DESCRIPTION),
        "{}",
        echo.description()
    );
    assert!(echo.description().contains("passed through as data"));

    host.shutdown().await;
}

#[tokio::test]
async fn a_call_round_trips_over_http_and_a_servers_refusal_is_a_result() {
    let server = real_server().await;
    let (key, cfg) = http_server("remote", &server.url(), None);
    let host = McpHost::from_config(&config(vec![(&key, cfg)]), None)
        .await
        .expect("config is fine");

    let outcome = host
        .call("remote__echo", json!({"text": "over the wire"}))
        .await;
    assert!(outcome.ok, "{}", outcome.content);
    assert_eq!(outcome.content, "over the wire");

    let refused = host.call("remote__fail", json!({})).await;
    assert!(!refused.ok, "{}", refused.content);
    assert!(
        refused.content.contains("refused, on purpose"),
        "{}",
        refused.content
    );

    // Still connected: a refusal is an answer, not a death.
    let after = host
        .call("remote__echo", json!({"text": "still here"}))
        .await;
    assert!(after.ok, "{}", after.content);

    host.shutdown().await;
}

#[tokio::test]
async fn an_endpoint_that_accepts_and_says_nothing_is_cut_off_by_the_handshake_timeout() {
    let endpoint = misbehaving(Misbehaviour::Silent).await;
    let (key, cfg) = http_server("silent", &endpoint.url(), None);

    let started = Instant::now();
    let host = McpHost::from_config(&config(vec![(&key, cfg)]), None)
        .await
        .expect("a connection failure is recorded, not returned");
    assert_bounded(
        started,
        Duration::from_secs(20),
        "startup against a silent endpoint",
    );

    assert!(
        matches!(&host.status().await[0].state, HealthState::Down { .. }),
        "{:?}",
        host.status().await[0].state
    );

    let started = Instant::now();
    let outcome = host.call("silent__echo", json!({})).await;
    assert_bounded(
        started,
        Duration::from_secs(20),
        "a call to a silent endpoint",
    );
    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("silent") && !outcome.content.trim().is_empty(),
        "the failure names the server: {}",
        outcome.content
    );
    host.shutdown().await;
}

#[tokio::test]
async fn an_endpoint_that_answers_with_a_server_error_is_a_readable_failure() {
    let endpoint = misbehaving(Misbehaviour::ServerError).await;
    let (key, cfg) = http_server("broken", &endpoint.url(), None);

    let started = Instant::now();
    let host = McpHost::from_config(&config(vec![(&key, cfg)]), None)
        .await
        .expect("a connection failure is recorded, not returned");
    assert_bounded(started, Duration::from_secs(20), "startup against a 500");

    assert!(
        !endpoint.requests().is_empty(),
        "the endpoint was actually dialled, so this test is about the response and not about a \
         connection that never happened"
    );

    let outcome = host.call("broken__echo", json!({})).await;
    assert!(!outcome.ok, "{}", outcome.content);
    assert!(outcome.content.contains("broken"), "{}", outcome.content);
    host.shutdown().await;
}

#[tokio::test]
async fn a_configured_token_is_sent_as_a_bearer_credential_and_never_appears_in_a_failure() {
    let endpoint = misbehaving(Misbehaviour::ServerError).await;
    let (key, cfg) = http_server("gh", &endpoint.url(), Some("vault:mcp/test"));
    let stores = stores_with(SENTINEL);

    let host = McpHost::from_config(&config(vec![(&key, cfg)]), Some(stores))
        .await
        .expect("a connection failure is recorded, not returned");

    // The tripwire: the run genuinely carried the credential. Without this half the leak assertion
    // below would pass against a code path that never resolved the secret at all.
    let requests = endpoint.requests();
    assert!(
        !requests.is_empty(),
        "the endpoint was dialled, so a token should have been on the request"
    );
    assert!(
        requests
            .iter()
            .any(|head| head.contains(&format!("Bearer {SENTINEL}"))),
        "the resolved secret reached the Authorization header: {requests:?}"
    );

    // And the failure the caller sees does not contain it. The message may name the server, the URL
    // and the reason; it may not carry a value.
    let outcome = host.call("gh__echo", json!({})).await;
    let visible = format!("{}\n{:?}", outcome.content, host.status().await);
    assert!(
        !visible.contains(SENTINEL),
        "a resolved credential must never reach a tool result or a health report: {visible}"
    );
    assert!(
        outcome.content.contains("gh"),
        "while still naming the server that failed: {}",
        outcome.content
    );
    host.shutdown().await;
}

#[tokio::test]
async fn a_credential_that_cannot_be_resolved_fails_without_dialling_the_endpoint() {
    let endpoint = misbehaving(Misbehaviour::ServerError).await;
    let (key, cfg) = http_server("gh", &endpoint.url(), Some("vault:mcp/absent"));
    let stores = stores_with(SENTINEL);

    let host = McpHost::from_config(&config(vec![(&key, cfg)]), Some(stores))
        .await
        .expect("a connection failure is recorded, not returned");

    // Failing closed is the property: a request that still went out — unauthenticated, or with a
    // stale token — would also "return an error", and would have leaked the endpoint's reachability.
    assert!(
        endpoint.requests().is_empty(),
        "nothing may be dialled when the credential cannot be resolved: {:?}",
        endpoint.requests()
    );

    let outcome = host.call("gh__echo", json!({})).await;
    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("vault:mcp/absent"),
        "the operator gets the reference to fix: {}",
        outcome.content
    );
    assert!(
        !outcome.content.contains(SENTINEL),
        "and never a value: {}",
        outcome.content
    );
    host.shutdown().await;
}

#[tokio::test]
async fn a_deployment_with_no_secret_stores_refuses_rather_than_dialling_unauthenticated() {
    let endpoint = misbehaving(Misbehaviour::ServerError).await;
    let (key, cfg) = http_server("gh", &endpoint.url(), Some("vault:mcp/test"));

    let host = McpHost::from_config(&config(vec![(&key, cfg)]), None)
        .await
        .expect("a connection failure is recorded, not returned");

    assert!(
        endpoint.requests().is_empty(),
        "a server with a token and no stores is refused, not dialled without one: {:?}",
        endpoint.requests()
    );
    let outcome = host.call("gh__echo", json!({})).await;
    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("no secret stores"),
        "the message says what is missing: {}",
        outcome.content
    );
    host.shutdown().await;
}
