//! The `hx-desktop` application binary.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use clap::Parser;
use hx_core::config::Config;
use hx_desktop::{resolve_daemon_target, run};
use hx_secrets::{EnvSecrets, SecretStores};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(
    name = "hx-desktop",
    version,
    about = "hx desktop shell",
    long_about = "Tauri 2 desktop shell for the hx agent harness.\n\n\
                  Reuses the exact web UI bundle from hxd and connects to a local\n\
                  or remote daemon."
)]
struct Args {
    /// Path to the configuration file.
    #[arg(short, long, env = "HX_CONFIG", default_value = "hx.yaml")]
    config: PathBuf,

    /// Where the daemon is. Defaults to `daemon.http_addr` from the config.
    #[arg(long)]
    daemon: Option<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hx_desktop=debug".into()),
        )
        .init();

    let args = Args::parse();

    let config = if args.config.exists() {
        let raw = std::fs::read_to_string(&args.config).with_context(|| {
            format!(
                "could not read config file {}. Pass --config or set HX_CONFIG.",
                args.config.display()
            )
        })?;
        Config::from_yaml(&raw)
            .with_context(|| format!("{} is not a valid hx config", args.config.display()))?
    } else {
        Config::default()
    };

    let secrets = SecretStores::new().with(Arc::new(EnvSecrets));
    let target = resolve_daemon_target(&config, args.daemon.as_deref(), &secrets)
        .context("failed to resolve daemon target")?;

    tracing::info!(
        target = %target.base_url,
        is_local = target.is_local,
        has_token = target.token.is_some(),
        "starting hx desktop shell"
    );

    run(target).map_err(|e| anyhow::anyhow!("desktop error: {e}"))
}
