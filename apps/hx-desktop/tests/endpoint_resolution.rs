//! Pure tests for daemon endpoint and API token resolution in the desktop shell.
//!
//! ## Why this matters
//!
//! The desktop shell must communicate with either a local `hxd` instance or a remote one.
//! Because `hxd` itself enforces fail-closed authentication on all non-loopback binds, a remote
//! configuration without a token is doomed to fail. Detecting this eagerly at desktop startup
//! provides an actionable error message rather than a confusing HTTP 401 on the first request.
//!
//! Furthermore, token resolution must strictly adhere to the project's precedence rules:
//! `api.token` in the configuration takes precedence over `HX_API_TOKEN` in the environment,
//! and blank/whitespace tokens are treated as absent.

use hx_core::api_auth::{ApiToken, API_TOKEN_ENV};
use hx_core::config::Config;
use hx_desktop::{
    normalize_daemon_url, resolve_daemon_target, resolve_daemon_target_pure, DesktopConfigError,
};
use hx_secrets::{EnvSecrets, SecretStores};
use std::sync::Arc;

#[test]
fn a_loopback_target_without_a_token_is_permitted() {
    // On loopback (127.0.0.1 or localhost), authentication is optional.
    // A developer running `hxd` locally without a token must be able to open the desktop shell
    // without being blocked by an unnecessary credential requirement.
    let target = resolve_daemon_target_pure("127.0.0.1:8787", None, None)
        .expect("local loopback without a token must succeed");

    assert_eq!(target.base_url, "http://127.0.0.1:8787");
    assert!(target.is_local);
    assert!(
        target.token.is_none(),
        "a loopback target needs no credential"
    );

    let target_localhost = resolve_daemon_target_pure("http://localhost:7717", None, None)
        .expect("localhost loopback without a token must succeed");
    assert_eq!(target_localhost.base_url, "http://localhost:7717");
    assert!(target_localhost.is_local);
    assert!(
        target_localhost.token.is_none(),
        "localhost is loopback too, so it needs no credential"
    );
}

#[test]
fn a_remote_target_without_a_token_fails_eagerly_with_actionable_error() {
    // Non-loopback daemons refuse to start without an API token (fail-closed).
    // Attempting to point a desktop shell at a remote daemon without providing a token
    // is a guaranteed failure; catching it before launching the webview gives immediate feedback.
    let err = resolve_daemon_target_pure("192.168.1.50:8787", None, None)
        .expect_err("remote daemon without a token must be rejected");

    match err {
        DesktopConfigError::RemoteMissingToken { url, env_var } => {
            assert_eq!(url, "http://192.168.1.50:8787");
            assert_eq!(env_var, API_TOKEN_ENV);
            let message = err.to_string();
            assert!(
                message.contains("api.token"),
                "error must name the config setting"
            );
            assert!(
                message.contains(API_TOKEN_ENV),
                "error must name the environment variable"
            );
        }
        other => panic!("expected RemoteMissingToken error, got: {other:?}"),
    }
}

#[test]
fn a_remote_target_with_a_token_from_config_succeeds() {
    // When a token is supplied via configuration, a remote target resolves successfully
    // and preserves the token.
    let target =
        resolve_daemon_target_pure("https://hx.example.com", Some("secret-token-123"), None)
            .expect("remote daemon with config token must succeed");

    assert_eq!(target.base_url, "https://hx.example.com");
    assert!(!target.is_local);
    assert_eq!(
        target.token.as_ref().map(ApiToken::expose),
        Some("secret-token-123")
    );
}

#[test]
fn a_remote_target_with_a_token_from_environment_succeeds() {
    // When no configuration token is present, the environment fallback is honoured.
    let target = resolve_daemon_target_pure("10.0.0.5:8787", None, Some("env-token-456"))
        .expect("remote daemon with env token must succeed");

    assert_eq!(target.base_url, "http://10.0.0.5:8787");
    assert!(!target.is_local);
    assert_eq!(
        target.token.as_ref().map(ApiToken::expose),
        Some("env-token-456")
    );
}

#[test]
fn config_token_takes_precedence_over_environment_token() {
    // If both config and environment specify a token, the configuration setting wins.
    let target =
        resolve_daemon_target_pure("10.0.0.5:8787", Some("config-wins"), Some("env-loses"))
            .expect("target resolution must succeed");

    assert_eq!(
        target.token.as_ref().map(ApiToken::expose),
        Some("config-wins")
    );
}

#[test]
fn whitespace_only_tokens_are_treated_as_absent() {
    // A token consisting solely of whitespace is not a valid credential and must not be accepted
    // as satisfying the remote token requirement.
    let err = resolve_daemon_target_pure("10.0.0.5:8787", Some("   "), Some("  \t\n  "))
        .expect_err("whitespace tokens must be treated as absent");

    assert!(matches!(err, DesktopConfigError::RemoteMissingToken { .. }));
}

#[test]
fn url_normalization_handles_schemes_and_trailing_slashes() {
    // Operators may specify bare host:port, http://, https://, or include trailing slashes.
    // All must normalize to a clean URL without a trailing slash.
    let (url1, is_local1) =
        normalize_daemon_url("127.0.0.1:8787/").expect("normalized bare host with slash");
    assert_eq!(url1, "http://127.0.0.1:8787");
    assert!(is_local1);

    let (url2, is_local2) =
        normalize_daemon_url("https://remote.server:9000///").expect("normalized https url");
    assert_eq!(url2, "https://remote.server:9000");
    assert!(!is_local2);
}

#[test]
fn resolve_daemon_target_from_config_model_matches_rules() {
    // Integration test with `hx_core::config::Config`:
    // Tests that `resolve_daemon_target` correctly extracts `daemon.http_addr` and `api.token`.
    let mut config = Config::default();
    config.daemon.http_addr = "192.168.1.100:8787".to_string();
    config.api.token = Some("literal-token".to_string());

    let secrets = SecretStores::new().with(Arc::new(EnvSecrets));
    let target = resolve_daemon_target(&config, None, &secrets)
        .expect("resolution from config struct must succeed");

    assert_eq!(target.base_url, "http://192.168.1.100:8787");
    assert!(!target.is_local);
    assert_eq!(
        target.token.as_ref().map(ApiToken::expose),
        Some("literal-token")
    );
}
