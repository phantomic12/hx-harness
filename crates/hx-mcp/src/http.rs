//! A server that is an HTTP endpoint, reached over MCP's streamable-HTTP transport.
//!
//! ## Why the transport is `rmcp`'s and not a `reqwest` POST in a loop
//!
//! Streamable HTTP is not "JSON-RPC over POST". A conformant client has to negotiate a protocol
//! version, carry `mcp-session-id` across a session, decide per response whether the body is
//! `application/json` or an SSE stream, resume a stream from `Last-Event-ID`, and recover a session
//! the server has expired with a fresh `initialize` — and the failure modes of getting any of that
//! subtly wrong are hangs and duplicated tool calls rather than errors. `rmcp` implements the
//! negotiation and the session recovery; reimplementing it here would be a second, worse copy of a
//! specification this crate does not own.
//!
//! ## The credential rule, and the one place it is allowed to exist
//!
//! The token in the config is a *reference*. It is resolved here, at connect time, through
//! `hx-secrets`, and the resolved value goes straight into the `Authorization` header. It is never
//! stored on a type, never logged, and never formatted into an error: the error path names the
//! reference (`vault:mcp/github`) and the reason, which is exactly what an operator needs and
//! exactly what a credential must not be. `tests/http.rs` pins that with a sentinel token and a
//! vault that refuses to answer.
//!
//! Resolution happens *per connect*, not once at startup, so rotating a vault entry takes effect on
//! the next restart of a server without restarting the daemon — and a token that expires is a
//! reconnect rather than a redeploy.

use super::conn::{client_info, ConnectError, Connection};
use hx_core::config::{McpServerConfig, SecretRef};
use hx_secrets::SecretStores;
use rmcp::service::serve_client;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use std::sync::Arc;
use std::time::Duration;

/// Dial the configured endpoint and complete the MCP handshake.
pub(crate) async fn connect(
    name: &str,
    cfg: &McpServerConfig,
    secrets: Option<&Arc<SecretStores>>,
    handshake_timeout: Duration,
) -> Result<Connection, ConnectError> {
    let url = cfg
        .url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .ok_or_else(|| ConnectError::Config(format!("mcp server {name:?}: no url")))?;

    let mut config = StreamableHttpClientTransportConfig::with_uri(url);
    // The handshake is bounded here as well as in the transport, because a TCP connect to a host
    // that accepts and then says nothing is the shape that wedges a run, and `rmcp`'s own timeouts
    // are about session recovery rather than about the first request.
    config = config.session_recovery_timeout(handshake_timeout);

    if let Some(reference) = &cfg.token {
        let secret = resolve(name, reference, secrets)?;
        config = config.auth_header(secret.expose());
    }

    let transport = StreamableHttpClientTransport::from_config(config);
    let handshake = tokio::time::timeout(handshake_timeout, serve_client(client_info(), transport));

    match handshake.await {
        Err(_elapsed) => Err(ConnectError::HandshakeTimeout {
            secs: handshake_timeout.as_secs(),
        }),
        Ok(Ok(connection)) => Ok(connection),
        Ok(Err(err)) => Err(ConnectError::Handshake(err.to_string())),
    }
}

/// Turn a `store:name` reference into a value, naming the reference and never the value.
///
/// Three failures are kept apart because they have three different fixes: the reference is
/// malformed (fix the config), no stores are configured (configure a vault or an `env:` source), or
/// the store does not have the entry (add it). All three name the reference; none of them can name a
/// value, because none of them has one.
fn resolve(
    name: &str,
    reference: &str,
    secrets: Option<&Arc<SecretStores>>,
) -> Result<hx_secrets::Secret, ConnectError> {
    let parsed = SecretRef::parse(reference).map_err(|err| ConnectError::Credential {
        reference: reference.to_string(),
        reason: err.to_string(),
    })?;

    let stores = secrets.ok_or_else(|| ConnectError::Credential {
        reference: parsed.to_string(),
        reason: format!(
            "mcp server {name:?} needs a credential but this deployment has no secret stores \
             configured (`vault:` and `env:` are the usual ones)"
        ),
    })?;

    stores
        .resolve(&parsed)
        .map_err(|err| ConnectError::Credential {
            reference: parsed.to_string(),
            // `err` comes from `hx-secrets`, whose contract is that a value never appears in a
            // message. Nothing here re-renders it.
            reason: err.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::config::McpServerConfig;
    use hx_secrets::source::{EnvSecrets, FixedSecrets};

    const SENTINEL: &str = "hx-mcp-token-sentinel-do-not-print";

    fn stores_with(value: &str) -> Arc<SecretStores> {
        Arc::new(SecretStores::new().with(Arc::new(FixedSecrets::vault().set("mcp/github", value))))
    }

    #[test]
    fn a_reference_is_resolved_through_the_stores_and_the_value_comes_back() {
        // The happy path, asserted on the *value* so the test cannot pass by resolving nothing.
        let stores = stores_with(SENTINEL);
        let secret = resolve("gh", "vault:mcp/github", Some(&stores)).expect("resolves");
        assert_eq!(secret.expose(), SENTINEL);
    }

    #[test]
    fn a_store_that_does_not_have_the_entry_names_the_reference_and_not_the_value() {
        let stores = stores_with(SENTINEL);
        let err = resolve("gh", "vault:mcp/absent", Some(&stores)).expect_err("absent");
        let message = err.to_string();
        assert!(
            message.contains("vault:mcp/absent"),
            "the operator needs the reference: {message}"
        );
        assert!(
            !message.contains(SENTINEL),
            "and must not get a value it never resolved: {message}"
        );
    }

    #[test]
    fn a_deployment_with_no_stores_refuses_rather_than_dialling_unauthenticated() {
        let err = resolve("gh", "vault:mcp/github", None).expect_err("no stores");
        let message = err.to_string();
        assert!(message.contains("vault:mcp/github"), "{message}");
        assert!(
            message.contains("no secret stores"),
            "and says what is missing: {message}"
        );
        assert!(!message.contains(SENTINEL), "{message}");
    }

    #[test]
    fn a_malformed_reference_is_refused_without_the_value_being_read() {
        let stores = stores_with(SENTINEL);
        let err = resolve("gh", "not-a-reference", Some(&stores)).expect_err("malformed");
        let message = err.to_string();
        assert!(message.contains("not-a-reference"), "{message}");
        assert!(!message.contains(SENTINEL), "{message}");
    }

    #[test]
    fn an_env_store_works_the_same_way_so_a_laptop_needs_no_vault() {
        // `env:` is the second store name the config may use, and the reference rule is about the
        // *shape* rather than about the vault specifically.
        std::env::set_var("HX_MCP_TEST_TOKEN", SENTINEL);
        let stores = Arc::new(SecretStores::new().with(Arc::new(EnvSecrets)));
        let secret = resolve("gh", "env:HX_MCP_TEST_TOKEN", Some(&stores)).expect("resolves");
        assert_eq!(secret.expose(), SENTINEL);
        std::env::remove_var("HX_MCP_TEST_TOKEN");
    }

    #[tokio::test]
    async fn a_url_that_is_not_there_fails_with_a_message_rather_than_hanging() {
        // Nothing is listening on this port. The point of the test is the *shape* of the failure:
        // an error naming the server, inside the handshake timeout, rather than a future that never
        // resolves. The port is bound and immediately dropped so it is genuinely free.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let cfg = McpServerConfig::streamable_http(format!("http://{addr}/mcp"));
        let started = std::time::Instant::now();
        let err = connect("gh", &cfg, None, Duration::from_secs(5))
            .await
            .expect_err("nothing is listening");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a refused connection must not wait out the handshake timeout"
        );
        assert!(!err.to_string().is_empty(), "{err}");
    }
}
