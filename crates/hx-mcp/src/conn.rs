//! Getting to a server: one signature, two transports, and the client identity both announce.
//!
//! ## What the host tells a server about itself, and why it is almost nothing
//!
//! An MCP client's `initialize` request advertises *capabilities* — and the capabilities a client
//! can advertise are the things a server may then ask it to do: `sampling` (run a model for me),
//! `roots` (tell me which directories you can see), `elicitation` (prompt my user for input). Every
//! one of those is a channel from an untrusted server into `hx`, and none of them is needed to
//! *consume* a server's tools, which is the entire job of this crate.
//!
//! So [`client_info`] advertises [`ClientCapabilities::default()`] — all four fields absent — and
//! that is a security decision rather than an oversight. A server that asks `hx` to sample anyway
//! gets `MethodNotFound` from `rmcp`'s default handler, and the property is pinned by a test that
//! serialises what we send rather than by reading the source back to itself.
//!
//! The identity we *do* send is honest: name `hx`, this build's version. A server operator
//! debugging a client is owed the truth about which client it was.
//!
//! ## Why both transports return the same type
//!
//! Because nothing above this module should know which one it is holding. A `RunningService` is a
//! peer: `list_all_tools`, `call_tool`, `is_closed`, `cancel`. The supervisor in [`crate::host`]
//! reasons about health and restarts in those terms, and the transport only appears where the
//! connection is *made* — which is what keeps "a server that dies is detected" one code path
//! instead of two.

use crate::stdio::StderrTail;
use hx_core::config::{McpServerConfig, McpTransport};
use hx_secrets::SecretStores;
use rmcp::model::{ClientCapabilities, ClientConfig, Implementation};
use rmcp::service::RunningService;
use rmcp::RoleClient;
use std::sync::Arc;
use std::time::Duration;

/// A live connection to one MCP server.
pub(crate) type Connection = RunningService<RoleClient, ClientConfig>;

/// Why a server could not be brought up.
///
/// The distinction that matters to the caller is [`Self::HandshakeTimeout`] and [`Self::Spawn`]
/// versus everything else: those three are *this* machine's problem (the command is wrong, the
/// server never answered), while a handshake failure is the server's. The supervisor records the
/// message either way; the distinction exists so an operator reading `hx doctor` output can tell
/// "I configured this wrong" from "that server is broken".
///
/// No variant carries a credential, and none may be extended to: for the HTTP transport the token
/// is resolved inside [`crate::http`] and only ever reaches the `Authorization` header.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConnectError {
    /// The child process could not be started at all.
    #[error("could not start `{command}`: {source}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    /// The server never finished the `initialize` handshake in time.
    #[error("the server did not finish its handshake within {secs}s")]
    HandshakeTimeout { secs: u64 },

    /// The handshake was answered with a refusal or a broken frame.
    #[error("the handshake failed: {0}")]
    Handshake(String),

    /// A credential reference could not be resolved.
    ///
    /// Carries the reference (`vault:mcp/github`), never a value — the whole point of the
    /// reference form is that this message is safe to write down.
    #[error("could not resolve the credential {reference}: {reason}")]
    Credential { reference: String, reason: String },

    /// A block that passed parsing but cannot start a server. `McpServerConfig::validate` catches
    /// most of these; this is the belt for a caller that built a config in code and skipped it.
    #[error("{0}")]
    Config(String),
}

/// The identity `hx` announces to every server it consumes.
///
/// See the module doc: no capabilities, deliberately.
pub(crate) fn client_info() -> ClientConfig {
    ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("hx", env!("CARGO_PKG_VERSION")),
    )
}

/// Bring one server up, whichever transport it is configured for.
///
/// `secrets` is `None` for a deployment with no stores configured, which is a real deployment (a
/// laptop running only stdio servers). An HTTP server with a `token` and no stores is an error that
/// names the reference, not a request that goes out unauthenticated.
///
/// `tail` is the supervisor's stderr sink, threaded through so it can outlive a dead connection: the
/// diagnosis it exists for ("this server wrote 4,000 lines to stderr and exited") is exactly the case
/// where the connection is already gone. The HTTP arm has no child and ignores it.
pub(crate) async fn connect(
    name: &str,
    cfg: &McpServerConfig,
    secrets: Option<&Arc<SecretStores>>,
    handshake_timeout: Duration,
    tail: StderrTail,
) -> Result<Connection, ConnectError> {
    cfg.validate(name)
        .map_err(|err| ConnectError::Config(err.to_string()))?;

    match cfg.transport {
        McpTransport::Stdio => super::stdio::connect(name, cfg, handshake_timeout, tail).await,
        McpTransport::StreamableHttp => {
            super::http::connect(name, cfg, secrets, handshake_timeout).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::config::McpServerConfig;
    use serde_json::json;

    /// The security property, pinned by serialising what actually goes on the wire.
    ///
    /// `sampling`, `roots` and `elicitation` are the three capabilities through which an MCP server
    /// can reach *into* the client. A host that advertised any of them would be offering an
    /// untrusted server a model call, a filesystem view, or the user's attention — none of which is
    /// needed to call a tool.
    #[test]
    fn the_client_announces_no_capability_that_lets_a_server_reach_back() {
        let info = client_info();
        let wire = serde_json::to_value(&info).expect("serialises");

        assert_eq!(
            wire["capabilities"],
            json!({}),
            "an empty capabilities object is the claim; anything in it is a channel back into hx"
        );
        for forbidden in [
            "sampling",
            "roots",
            "elicitation",
            "experimental",
            "extensions",
        ] {
            assert!(
                !wire["capabilities"].to_string().contains(forbidden),
                "{forbidden} must not be advertised"
            );
        }

        // And the identity it does send is truthful, because a server operator debugging a client
        // is owed the truth about which client it was.
        assert_eq!(wire["clientInfo"]["name"], "hx");
        assert_eq!(wire["clientInfo"]["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn a_block_that_cannot_start_a_server_is_refused_before_anything_is_spawned() {
        // The belt for a caller that built a config in code and skipped `validate`: `connect` calls
        // it too, so a missing command is a named error rather than a spawn of the empty string.
        let cfg = McpServerConfig::stdio("", Vec::<String>::new());
        let err = connect(
            "files",
            &cfg,
            None,
            Duration::from_secs(1),
            StderrTail::default(),
        )
        .await
        .expect_err("no command");
        assert!(
            err.to_string().contains("files") && err.to_string().contains("command"),
            "{err}"
        );
    }
}
