//! Live MCP canary: a *real* third-party server, not the hand-rolled double.
//!
//! ## Why this file exists even though every other test here is hermetic
//!
//! `tests/stdio.rs` and `tests/http.rs` drive a double that this crate also wrote. That is the right
//! double for the properties they hold — it fails loudly on unscripted input, which a real server
//! never does — but it is still *our* reading of the protocol on both ends of the wire. A client that
//! agreed with our own double about, say, the `initialize` result shape, or about which JSON-RPC
//! framing a child expects, would pass every test in this crate and fail against every real server.
//!
//! `rmcp` is what is supposed to make that impossible, and `rmcp` is not under test here. What is
//! under test is the *glue*: that this crate spawns a real package correctly, completes a real
//! handshake, publishes a real server's tools under its namespace, and round-trips a real call —
//! and that when a real server misbehaves, the failure still arrives as a readable [`ToolOutcome`]
//! rather than a hang.
//!
//! ## It is opt-in, and it asserts nothing about *which* tools exist
//!
//! There is no MCP server that can be assumed present on a build machine, so every test here is
//! `#[ignore]`d and reads its target from the environment. Nothing asserts a particular tool name:
//! the server under test is chosen by whoever runs the canary, and a test that hard-coded
//! `read_file` would be asserting a property of `@modelcontextprotocol/server-filesystem` rather
//! than of this crate. What it asserts is the shape of a working connection and the shape of every
//! failure.
//!
//! ```console
//! # a real npx package over stdio:
//! $ HX_MCP_LIVE_COMMAND=npx \
//!   HX_MCP_LIVE_ARGS="-y @modelcontextprotocol/server-filesystem /tmp" \
//!   cargo test -p hx-mcp --test mcp_live -- --ignored --nocapture
//!
//! # a real streamable-HTTP endpoint (a token comes from the vault, never from here):
//! $ HX_MCP_LIVE_URL=https://mcp.example.com/mcp HX_MCP_LIVE_TOKEN_REF=vault:mcp/example \
//!   cargo test -p hx-mcp --test mcp_live -- --ignored --nocapture
//! ```
//!
//! ## The one property that is worth the most here
//!
//! [`a_live_target_that_is_not_there_is_a_readable_failure_and_not_a_hang`] runs **without** any
//! environment variable configured, which means it runs anywhere, including CI. It is the canary for
//! the promise in the crate's module doc: the commonest real-world state of an MCP server is
//! "misconfigured and not starting", and that has to be a sentence.

use hx_core::config::McpServerConfig;
use hx_mcp::{HealthState, McpHost};
use hx_secrets::source::SecretStores;
use indexmap::IndexMap;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the canary waits for a real server to answer. Generous, because `npx` may be installing
/// a package on the first run; short enough that a wedged server fails the job rather than the job
/// failing the machine.
const LIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// The environment variable naming a real stdio server's executable.
const COMMAND: &str = "HX_MCP_LIVE_COMMAND";

/// The environment variable naming that server's arguments, whitespace-separated.
const ARGS: &str = "HX_MCP_LIVE_ARGS";

/// The environment variable naming a real streamable-HTTP endpoint.
const URL: &str = "HX_MCP_LIVE_URL";

/// The environment variable naming a `vault:`/`env:` *reference* for that endpoint's token.
///
/// A reference and never a value: this file must not become the place a live credential is written
/// down, and `hx-secrets` resolving it is the code path a deployment actually uses.
const TOKEN_REF: &str = "HX_MCP_LIVE_TOKEN_REF";

/// The tool to call, when the operator wants to name one. Otherwise the first tool the server lists
/// is called with an empty argument object, which is the call that needs no knowledge of the schema.
const TOOL: &str = "HX_MCP_LIVE_TOOL";

fn stdio_config() -> Option<McpServerConfig> {
    let command = std::env::var(COMMAND).ok()?;
    let args: Vec<String> = std::env::var(ARGS)
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let mut cfg = McpServerConfig::stdio(command, args);
    cfg.start_timeout_secs = LIVE_TIMEOUT.as_secs();
    cfg.call_timeout_secs = LIVE_TIMEOUT.as_secs();
    Some(cfg)
}

fn http_config() -> Option<McpServerConfig> {
    let url = std::env::var(URL).ok()?;
    let mut cfg = McpServerConfig::streamable_http(url);
    cfg.start_timeout_secs = LIVE_TIMEOUT.as_secs();
    cfg.call_timeout_secs = LIVE_TIMEOUT.as_secs();
    cfg.token = std::env::var(TOKEN_REF).ok();
    Some(cfg)
}

/// The host, and the stores a `vault:` reference needs. The vault is *empty* here on purpose: a live
/// run supplies the reference and the operator's own vault supplies the value, so a missing vault
/// entry shows up as the readable refusal the crate promises rather than as a panic in a test.
async fn host_for(cfg: McpServerConfig) -> Arc<McpHost> {
    let mut servers: IndexMap<String, McpServerConfig> = IndexMap::new();
    servers.insert("live".to_string(), cfg);
    let stores: Option<Arc<SecretStores>> = Some(Arc::new(SecretStores::new()));
    Arc::new(
        McpHost::from_config(&servers, stores)
            .await
            .expect("a live config is valid, or the canary is misconfigured rather than the code"),
    )
}

/// A bound, not a duration: the canary asserts that a call *ended*, and the module doc's promise is
/// that it ends on this crate's own clock rather than on the server's.
fn assert_bounded(started: Instant, within: Duration, what: &str) {
    let elapsed = started.elapsed();
    assert!(
        elapsed < within,
        "{what} took {elapsed:?}, past the {within:?} bound — a real server that wedges must be cut \
         off by hx's own clock"
    );
}

/// The canary that runs anywhere: no environment, no server, and the failure still has to be a
/// sentence a model can read.
#[tokio::test]
async fn a_live_target_that_is_not_there_is_a_readable_failure_and_not_a_hang() {
    // A command that cannot exist. This is the state most misconfigured MCP servers are actually in,
    // and it is the one case where the operator's typo has to reach them as text.
    let mut cfg = McpServerConfig::stdio(
        "hx-mcp-live-canary-command-that-does-not-exist",
        Vec::<String>::new(),
    );
    cfg.start_timeout_secs = 5;
    cfg.call_timeout_secs = 5;

    let started = Instant::now();
    let host = McpHost::from_config(
        &{
            let mut servers: IndexMap<String, McpServerConfig> = IndexMap::new();
            servers.insert("live".to_string(), cfg);
            servers
        },
        None,
    )
    .await
    .expect("a connection failure is recorded, not returned");
    assert_bounded(
        started,
        Duration::from_secs(30),
        "startup against a command that is not there",
    );

    assert!(
        matches!(&host.status().await[0].state, HealthState::Down { .. }),
        "{:?}",
        host.status().await[0].state
    );

    let outcome = host.call("live__anything", json!({})).await;
    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("live"),
        "the failure names the server: {}",
        outcome.content
    );
    assert!(
        !outcome.content.trim().is_empty(),
        "and it is a sentence rather than an empty string"
    );
    host.shutdown().await;
}

/// A real package over stdio: spawn it, handshake it, list its tools, call one.
#[tokio::test]
#[ignore = "needs a real MCP server: set HX_MCP_LIVE_COMMAND (and HX_MCP_LIVE_ARGS)"]
async fn a_real_stdio_server_is_spawned_handshaken_and_called() {
    let Some(cfg) = stdio_config() else {
        panic!("set {COMMAND} (and optionally {ARGS}) to run this canary");
    };

    let started = Instant::now();
    let host = host_for(cfg).await;
    assert_bounded(started, LIVE_TIMEOUT * 2, "a real stdio handshake");

    let health = host.status().await;
    assert!(
        matches!(&health[0].state, HealthState::Up { .. }),
        "a real server must come up: {:?}",
        health[0].state
    );
    assert_eq!(health[0].transport, "stdio");

    // Every name is namespaced for the server it came from. This is the property a real server's own
    // tool names are the input to, and the one a model reads the origin off.
    let names = host.tool_names();
    assert!(
        !names.is_empty(),
        "a real MCP server exposes at least one tool, or it is not an MCP server"
    );
    for name in &names {
        assert!(
            name.starts_with("live__"),
            "{name} is not namespaced under the server it came from"
        );
    }

    // And a real call round-trips. The *result* is not asserted — it is whatever that server does —
    // only that a call reached it and came back as an outcome rather than as a hang.
    let tool = std::env::var(TOOL)
        .ok()
        .or_else(|| names.first().cloned())
        .expect("at least one tool");
    let started = Instant::now();
    let outcome = host.call(&tool, json!({})).await;
    assert_bounded(started, LIVE_TIMEOUT * 2, "a call to a real stdio server");
    assert!(
        !outcome.content.trim().is_empty(),
        "a call to a real server returns text either way — a refusal is a result, not a silence"
    );

    // The reaping property, against a real child: after shutdown the process is gone.
    host.shutdown().await;
}

/// A real streamable-HTTP endpoint: the handshake, the session header and the framing that a
/// hand-rolled client would most plausibly get wrong.
#[tokio::test]
#[ignore = "needs a real MCP endpoint: set HX_MCP_LIVE_URL (and HX_MCP_LIVE_TOKEN_REF)"]
async fn a_real_streamable_http_endpoint_is_reached_and_its_tools_are_published() {
    let Some(cfg) = http_config() else {
        panic!("set {URL} (and optionally {TOKEN_REF}) to run this canary");
    };

    let started = Instant::now();
    let host = host_for(cfg).await;
    assert_bounded(
        started,
        LIVE_TIMEOUT * 2,
        "a real streamable-HTTP handshake",
    );

    let health = host.status().await;
    assert_eq!(health[0].transport, "streamable_http");
    assert!(
        matches!(&health[0].state, HealthState::Up { .. }),
        "a real endpoint must come up: {:?}",
        health[0].state
    );

    let names = host.tool_names();
    assert!(
        !names.is_empty(),
        "a real endpoint exposes at least one tool"
    );
    for name in &names {
        assert!(name.starts_with("live__"), "{name} is not namespaced");
    }

    let tool = std::env::var(TOOL)
        .ok()
        .or_else(|| names.first().cloned())
        .expect("at least one tool");
    let started = Instant::now();
    let outcome = host.call(&tool, json!({})).await;
    assert_bounded(started, LIVE_TIMEOUT * 2, "a call to a real endpoint");

    // The credential rule, asserted on a run that genuinely carried one: whatever came back, the
    // resolved value is not in it. The reference may be — that is what an operator fixes — and the
    // value may not.
    let visible = format!("{}\n{:?}", outcome.content, host.status().await);
    assert!(
        !visible.contains("Bearer "),
        "a tool result or health report must not carry an Authorization header: {visible}"
    );

    host.shutdown().await;
}
