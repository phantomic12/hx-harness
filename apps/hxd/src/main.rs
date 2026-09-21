//! `hxd` — the hx harness daemon.
//!
//! Owns all state and serves the HTTP API that every front end talks to. One process, one
//! source of truth: that is what makes the CLI, the browser, the desktop app and the chat
//! connectors agree about what is running.
//!
//! What starts today: config validation, the model router (pools, credentials, ceilings), search
//! backends, the sandbox manager, the TTL reaper, and the status API. What does not: the agent
//! loop and the WebSocket event stream — see `ROADMAP.md` M1.

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use hx_core::config::Config;
use hx_core::update::UpdateConfig;
use hx_server::AppState;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How often the sandbox TTL reaper runs.
const REAP_INTERVAL: Duration = Duration::from_secs(60);

/// The command an operator runs to install the new version; shown by the update log line.
const INSTALL_COMMAND: &str =
    "curl -fsSL https://raw.githubusercontent.com/phantomic12/hx-harness/main/install.sh | sh";

#[derive(Debug, Parser)]
#[command(
    name = "hxd",
    version,
    about = "The hx agent harness daemon",
    long_about = "Runs the model router, search backends, sandbox manager and HTTP API.\n\
                  Every front end (CLI, web UI, desktop app, chat connectors) is a client of \
                  this process."
)]
struct Args {
    /// Path to the configuration file.
    #[arg(short, long, env = "HX_CONFIG", default_value = "hx.yaml")]
    config: PathBuf,

    /// Address to bind the HTTP API to.
    #[arg(long, env = "HX_BIND", default_value = "127.0.0.1:7717")]
    bind: String,

    /// Validate the configuration and exit, without serving.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hxd=debug".into()),
        )
        .init();

    let args = Args::parse();

    // An unreadable or unparseable config must fail loudly and early. `Config` denies unknown
    // fields precisely so a typo surfaces here rather than as a silently-ignored setting.
    let raw = std::fs::read_to_string(&args.config).with_context(|| {
        format!(
            "could not read the config file {}. Pass --config, or set HX_CONFIG.",
            args.config.display()
        )
    })?;

    let config = Config::from_yaml(&raw)
        .with_context(|| format!("{} is not a valid hx config", args.config.display()))?;

    tracing::info!(
        providers = config.providers.len(),
        pools = config.pools.len(),
        roles = config.roles.len(),
        hosts = config.hosts.len(),
        "configuration loaded"
    );

    // Building the state validates the routing table: every role must resolve to a real pool,
    // every pool member to a real provider and model. A misconfigured harness fails here rather
    // than at 3am on the first request. It also resolves the API's bearer token, so a `api.token`
    // reference that cannot be resolved fails here rather than leaving the API unprotected.
    let update_cfg = config.update.clone();
    let state = AppState::build(config, Utc::now())
        .await
        .context("could not build the daemon state")?;

    // **Fail closed, before anything is bound.** A bind that is not loopback and a token that was
    // not configured is a refusal to start, not a warning: starting anyway would serve an
    // unauthenticated API — file reads, commands on every configured host, and the approval
    // questions a run is waiting on — to anything that can route to the address. `--check` is
    // behind this on purpose, so validating a deployment that would not be allowed to run says so.
    hx_core::api_auth::require_token_for_bind(&args.bind, state.api_token.is_some())
        .context("the HTTP API would be reachable without authentication")?;

    if args.check {
        let report = state.status(Utc::now()).await;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    spawn_reaper(&state);
    spawn_update_checker(update_cfg, env!("CARGO_PKG_VERSION"));

    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("could not bind {}", args.bind))?;

    tracing::info!(addr = %args.bind, "hxd listening");

    axum::serve(listener, hx_server::app(state))
        .await
        .context("the HTTP server stopped unexpectedly")?;

    Ok(())
}

/// Periodically reap sandboxes past their TTL.
///
/// Without this, a sandbox whose owner forgot about it holds a concurrency slot and its disk
/// forever. The manager also enforces the TTL at query time, so a failed sweep degrades rather
/// than leaks.
fn spawn_reaper(state: &Arc<AppState>) {
    let Some(manager) = state.sandboxes.clone() else {
        tracing::debug!("no sandbox manager; the reaper is not needed");
        return;
    };

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REAP_INTERVAL);
        // The first tick fires immediately; skip it so startup is not delayed.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            match manager.reap(Utc::now()).await {
                Ok(reaped) if !reaped.is_empty() => {
                    tracing::info!(count = reaped.len(), "reaped expired sandboxes");
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "the sandbox reaper failed"),
            }
        }
    });
}

/// Optionally check the configured releases feed for a newer build, on an interval.
///
/// **Off by default.** The caller only reaches here when `update.enabled` is true, so a daemon
/// that says nothing about `update` performs no fetch and spawns no task. When enabled, it is
/// **non-intrusive**: no download, no restart, no startup delay — the first check runs after one
/// interval, and the only behaviour is a single `info!` line when a newer version exists and a
/// single `debug!` line when the fetch fails. A transient failure must not spam the log or take
/// the daemon down; the fetch is one `reqwest` call with a bounded timeout inside the spawned task,
/// never on the startup path.
fn spawn_update_checker(cfg: UpdateConfig, current_version: &str) {
    if !cfg.enabled {
        tracing::debug!("update checking is disabled; no task spawned");
        return;
    }

    let current = current_version.to_string();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
        // Skip the immediate first tick so the first check is not on the startup path.
        ticker.tick().await;

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                tracing::debug!(error = %err, "could not build the update-check HTTP client");
                return;
            }
        };

        loop {
            ticker.tick().await;
            check_once(&client, &cfg, &current).await;
        }
    });
}

/// Perform a single update check: fetch the feed, compare, and log the result.
///
/// Returns nothing and cannot fail upward — by design. Everything is observed, so a broken feed or a
/// bad `tag_name` degrades to a log line rather than taking a spawned task (and with it the
/// daemon's job of just working) down.
async fn check_once(client: &reqwest::Client, cfg: &UpdateConfig, current: &str) {
    let response = match client.get(&cfg.url).send().await {
        Ok(response) => response,
        Err(err) => {
            tracing::debug!(error = %err, url = %cfg.url, "update check failed; will retry next interval");
            return;
        }
    };

    let body = match response.error_for_status() {
        Ok(response) => match response.text().await {
            Ok(body) => body,
            Err(err) => {
                tracing::debug!(error = %err, url = %cfg.url, "update check could not read the release feed");
                return;
            }
        },
        Err(err) => {
            tracing::debug!(error = %err, url = %cfg.url, "update check got a non-success status");
            return;
        }
    };

    let tag_name = match hx_core::update::release_tag_name(&body) {
        Some(tag) => tag,
        None => {
            tracing::debug!(url = %cfg.url, "update check found no usable version in the release feed");
            return;
        }
    };

    match hx_core::update::compare_versions(&tag_name, current) {
        Some(std::cmp::Ordering::Greater) => {
            tracing::info!(
                version = %tag_name,
                current = current,
                url = %cfg.url,
                install = INSTALL_COMMAND,
                "a newer version is available — run the install command to update"
            );
        }
        _ => {
            tracing::debug!(current = current, "already on the latest version");
        }
    }
}
