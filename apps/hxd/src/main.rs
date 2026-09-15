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
use hx_server::AppState;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How often the sandbox TTL reaper runs.
const REAP_INTERVAL: Duration = Duration::from_secs(60);

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
    // than at 3am on the first request.
    let state = AppState::build(config, Utc::now())
        .await
        .context("could not build the daemon state")?;

    if args.check {
        let report = state.status(Utc::now()).await;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    spawn_reaper(&state);

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
