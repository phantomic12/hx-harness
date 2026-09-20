//! The `hx-desktop` Tauri 2 desktop shell.
//!
//! ## Property this crate exists to hold
//!
//! Requirement #3 demands a web UI that can do everything a terminal can, and M7 brings that
//! interface to the desktop. This crate provides a native desktop shell around the **exact same** web
//! client that `hxd` serves, connecting to either a local or remote `hxd` daemon and presenting
//! the API bearer token when one is configured.
//!
//! ## The desktop three (M7)
//!
//! Three desktop features make the shell an *app* rather than a window, each in its own module and each
//! **degrading to a working window with a reported warning** if the desktop session cannot provide it:
//!
//! - [`tray`] — a system tray icon with a menu (toggle the window, open approvals, quit). The menu
//!   item set and id→action mapping are pure and tested; the icon itself needs a live desktop session.
//! - [`hotkey`] — a system-wide shortcut that summons the window, configurable, and **reported** when the
//!   OS refuses the binding (a hotkey that silently fails to register is worse than none). Parsing and
//!   refusal-surfacing are tested behind a [`hotkey::HotkeyBackend`] trait.
//! - [`notification`] — a native notification when an approval is requested. The body is a pure value,
//!   asserted **not** to leak a token or a path outside the workspace.
//!
//! ## Why the web bundle is not forked
//!
//! The desktop shell reuses `crates/hx-server/static/index.html` directly via Tauri's asset
//! configuration (`frontendDist: "../../crates/hx-server/static"`). It does **not** fork, duplicate,
//! or re-implement the frontend. A separate frontend copy would immediately create two UIs that
//! drift out of sync as features are added to one surface and forgotten in the other. By referencing
//! the identical static asset, any enhancement or bugfix to the web interface is instantaneously
//! available in both the browser and the desktop shell with zero maintenance overhead.
//!
//! ## Authentication and endpoint resolution
//!
//! The daemon's HTTP API is authenticated via a bearer token ([`hx_core::api_auth::ApiToken`]; see
//! `crates/hx-core/src/api_auth.rs` and `crates/hx-server/src/auth.rs`). When targeting a local
//! loopback daemon (`127.0.0.1`, `localhost`), authentication is optional: a token is sent if
//! configured, but an unauthenticated loopback connection is permitted.
//!
//! When targeting a **remote** daemon (non-loopback address), the daemon itself refuses to start
//! without an API token configured. Therefore, configuring a remote `hxd` endpoint without an API
//! token is a fatal misconfiguration. Rather than allowing requests to fail cryptically with
//! `401 Unauthorized` at runtime, [`resolve_daemon_target`] detects this condition eagerly and fails
//! with a clear, actionable error advising the operator to set `api.token` in the configuration or
//! `HX_API_TOKEN` in the environment.
//!
//! ## What is deliberately NOT done yet
//!
//! - **Mobile (iOS / Android) is not started:** Mobile requires the Android NDK/SDK and a macOS host
//!   for iOS compilation and signing. Neither is available in this environment. Mobile is explicitly
//!   deferred to subsequent M7 milestones.
//! - **Auto-update and code signing:** Infrastructure for release signing and auto-updating will land
//!   with the release matrix.
//!
//! ## Honest testing limits
//!
//! A GUI window cannot be asserted in CI without an active display server, compositor, and GPU/software
//! rasterizer. We do not pretend otherwise. What is tested:
//! 1. The endpoint and token resolution pure function (local vs remote, config vs environment tokens,
//!    and eager remote misconfiguration detection).
//! 2. The bundle path identity asserting that the frontend asset configured for Tauri resolves to the
//!    exact same file that `hx-server` embeds and serves.
//! 3. The desktop-three testable cores: the tray menu's item set and id→action mapping, the hotkey
//!    string parsing and refusal-surfacing (behind a trait), and the approval-notification body with its
//!    no-leak guarantees. The actual tray icon, a real hotkey binding, and a raised notification all
//!    need a live desktop session and are **not** asserted here — each module's doc says so.

use hx_core::api_auth::{bind_is_loopback, ApiToken, API_TOKEN_ENV};
use hx_core::config::Config;
use hx_secrets::SecretStores;

pub mod hotkey;
pub mod notification;
pub mod tray;

/// Relative path from `apps/hx-desktop` to the shared web UI bundle.
pub const BUNDLE_RELATIVE_PATH: &str = "../../crates/hx-server/static/index.html";

/// Embedded copy of the exact same web UI bundle served by `hx-server`.
pub const BUNDLE_HTML: &str = include_str!("../../../crates/hx-server/static/index.html");

/// A resolved daemon target, verified for connectivity and authentication.
///
/// Deliberately **not** `PartialEq`/`Eq`: this struct holds a credential, and `ApiToken` has no
/// `PartialEq` on purpose — `==` on a secret is a timing-unsafe comparison, which is why the type
/// offers constant-time `matches` instead. Deriving equality here would smuggle that comparison back
/// in through the derive, so a caller that wants to compare tokens calls `matches`, and the tests
/// assert `is_none()` / `expose()` rather than `==`.
#[derive(Clone, Debug)]
pub struct DaemonTarget {
    /// The normalized base URL of the daemon (e.g. `http://127.0.0.1:8787`).
    pub base_url: String,
    /// Whether this target is loopback / local.
    pub is_local: bool,
    /// The bearer token to authenticate with, if one resolved.
    pub token: Option<ApiToken>,
}

/// Errors encountered while resolving or validating the desktop configuration.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DesktopConfigError {
    #[error(
        "remote hxd at '{url}' requires an API token because non-loopback daemons refuse unauthenticated traffic. Set `api.token` in the config or {env_var} in the environment."
    )]
    RemoteMissingToken { url: String, env_var: &'static str },
    #[error("invalid daemon URL '{0}': {1}")]
    InvalidUrl(String, String),
    #[error("token resolution error: {0}")]
    TokenResolution(String),
}

/// Normalize a raw daemon address string into a URL with scheme and determine whether it is loopback.
pub fn normalize_daemon_url(raw: &str) -> Result<(String, bool), DesktopConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(DesktopConfigError::InvalidUrl(
            raw.to_string(),
            "empty URL".to_string(),
        ));
    }
    let with_scheme = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.trim_end_matches('/').to_string()
    } else {
        format!("http://{}", raw.trim_end_matches('/'))
    };

    let parsed = url::Url::parse(&with_scheme)
        .map_err(|e| DesktopConfigError::InvalidUrl(raw.to_string(), e.to_string()))?;

    let host_str = parsed.host_str().unwrap_or("");
    let is_local = bind_is_loopback(host_str);

    Ok((with_scheme, is_local))
}

/// Pure resolution of the daemon target without external I/O.
///
/// Handles:
/// - local vs remote target identification
/// - token precedence: `config_token` wins over `env_token`
/// - eager failure when a remote target has no token
pub fn resolve_daemon_target_pure(
    raw_addr: &str,
    config_token: Option<&str>,
    env_token: Option<&str>,
) -> Result<DaemonTarget, DesktopConfigError> {
    let (base_url, is_local) = normalize_daemon_url(raw_addr)?;

    let token = config_token
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| env_token.map(str::trim).filter(|s| !s.is_empty()))
        .map(ApiToken::new);

    if !is_local && token.is_none() {
        return Err(DesktopConfigError::RemoteMissingToken {
            url: base_url,
            env_var: API_TOKEN_ENV,
        });
    }

    Ok(DaemonTarget {
        base_url,
        is_local,
        token,
    })
}

/// Resolve the daemon target from a loaded [`Config`] and [`SecretStores`].
///
/// Reuses the existing `hx_secrets::resolve_api_token` logic so the desktop app
/// respects `api.token` literal values, `store:name` references, and `HX_API_TOKEN`.
pub fn resolve_daemon_target(
    config: &Config,
    explicit_daemon: Option<&str>,
    secrets: &SecretStores,
) -> Result<DaemonTarget, DesktopConfigError> {
    let raw_addr = explicit_daemon.unwrap_or(&config.daemon.http_addr);
    let (base_url, is_local) = normalize_daemon_url(raw_addr)?;

    let token = hx_secrets::resolve_api_token(config, secrets)
        .map_err(|e| DesktopConfigError::TokenResolution(e.to_string()))?;

    if !is_local && token.is_none() {
        return Err(DesktopConfigError::RemoteMissingToken {
            url: base_url,
            env_var: API_TOKEN_ENV,
        });
    }

    Ok(DaemonTarget {
        base_url,
        is_local,
        token,
    })
}

/// Generate initialization JavaScript to preload the API token into localStorage.
///
/// The web client (`crates/hx-server/static/index.html`) reads `localStorage.getItem("hx.api.token")`.
/// Pre-populating it allows seamless authentication without prompting the user.
pub fn generate_init_script(target: &DaemonTarget) -> String {
    let mut script = String::new();
    if let Some(ref token) = target.token {
        script.push_str(&format!(
            r#"try {{ localStorage.setItem("hx.api.token", "{}"); }} catch (e) {{ console.error("failed to set token", e); }}"#,
            token.expose()
        ));
    }
    script
}

/// Run the Tauri desktop application window targeting the specified daemon.
pub fn run(target: DaemonTarget) -> Result<(), Box<dyn std::error::Error>> {
    let init_script = generate_init_script(&target);
    let target_url = target.base_url.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .setup(move |app| {
            let mut builder = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::External(target_url.parse()?),
            )
            .title("hx")
            .inner_size(1200.0, 800.0);

            if !init_script.is_empty() {
                builder = builder.initialization_script(&init_script);
            }

            builder.build()?;

            // System tray: degrade to a working window if the tray cannot be shown.
            if let Err(e) = crate::tray::build_tray(app.handle()) {
                tracing::warn!("system tray unavailable, continuing without it: {e}");
            }

            // Global hotkey: summon the window. A refused/unparseable binding is **reported**, never
            // swallowed, and never prevents the window from starting.
            let outcome = crate::hotkey::register_plugin_shortcut(app.handle(), "Control+Shift+H");
            match &outcome {
                crate::hotkey::HotkeyOutcome::Registered(spec) => {
                    tracing::info!("registered global hotkey {spec}");
                }
                crate::hotkey::HotkeyOutcome::Refused { spec, reason } => {
                    tracing::warn!("global hotkey {spec} could not be registered: {reason}");
                }
            }

            Ok(())
        })
        .run(tauri::generate_context!())?;

    Ok(())
}
