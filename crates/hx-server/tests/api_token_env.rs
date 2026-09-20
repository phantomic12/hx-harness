//! The `HX_API_TOKEN` fallback, in a file of its own.
//!
//! ## Why this is not in `api_auth.rs`
//!
//! `std::env::set_var` is process-global, and a test binary runs its tests on several threads. A test
//! that sets a variable another test reads is a race, and the failure it produces is
//! order-dependent — the worst kind, because it passes on a quiet machine. So this file holds
//! **one** test, and the rest of the suite deliberately clears the variable instead of setting it
//! (see `try_state` in `api_auth.rs`, and `build_state` in `crates/hx-server/src/routes.rs`).
//!
//! ## What it pins
//!
//! The environment fallback is an operator-facing path, not an implementation detail: `DEPLOY.md`
//! tells an operator to export `HX_API_TOKEN` for a container, and `SETUP.md` names it for CI. It
//! was the only part of the auth story with **no** test at all — every other case configures
//! `api.token` — and an untested fallback is a fallback nobody would notice breaking.
//!
//! Both directions are asserted, because either alone is vacuous: with the variable set, the daemon
//! must pick it up *and hold that value*; with it unset, the daemon must hold no token. A build that
//! always produced `Some` would pass the first half, and one that always produced `None` would pass
//! the second.

use std::sync::Arc;

use hx_server::AppState;

/// Deliberately not key-shaped: the read-side redaction that masks key-shaped literals in a file
/// display would hide a key-shaped sentinel from the leak assertions elsewhere in this crate.
const SENTINEL: &str = "hx-api-env-sentinel-9c3f0a72";

/// Removes the variable however the test exits, so a panic cannot leave the fallback armed for
/// whatever runs next in this process.
struct EnvGuard;

impl EnvGuard {
    fn set(value: &str) -> Self {
        std::env::set_var(hx_core::api_auth::API_TOKEN_ENV, value);
        EnvGuard
    }

    fn clear() -> Self {
        std::env::remove_var(hx_core::api_auth::API_TOKEN_ENV);
        EnvGuard
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var(hx_core::api_auth::API_TOKEN_ENV);
    }
}

/// A config that names **no** token, so the only source left is the environment.
fn config_yaml() -> &'static str {
    r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["dead-model"]
    credentials:
      - { id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }

pools:
  interactive: { members: ["local/dead-model"] }

roles:
  builder: interactive

search:
  backends: []
"#
}

/// Build through the real `AppState::build`, so the fallback is exercised on the path the daemon
/// takes rather than on a value injected past it.
async fn build() -> Arc<AppState> {
    let mut config = hx_core::config::Config::from_yaml(config_yaml()).expect("config parses");
    // A test must not write a session database into the developer's home directory.
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.keep().display().to_string();
    let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    AppState::build(config, now).await.expect("state builds")
}

#[tokio::test]
async fn the_daemon_takes_its_token_from_the_environment_only_when_the_config_names_none() {
    // The negative control first: with nothing configured and nothing exported, there is no token.
    // Without this, a build that always produced `Some` would pass the assertion below.
    {
        let _guard = EnvGuard::clear();
        let state = build().await;
        assert!(
            state.api_token.is_none(),
            "a config with no token and no HX_API_TOKEN must produce no token"
        );
    }

    // Now the fallback itself, and the value is checked rather than only its presence: a token that
    // existed but held something else would authenticate nobody, and a bare `is_some` would not say.
    let _guard = EnvGuard::set(SENTINEL);
    let state = build().await;
    let token = state
        .api_token
        .as_ref()
        .expect("HX_API_TOKEN must reach the state when the config names no token");
    assert!(
        token.matches(SENTINEL),
        "the token must be the one the environment carried"
    );
    assert!(
        !token.matches("hx-api-env-sentinel-9c3f0a7"),
        "a correct prefix must not match"
    );
}
