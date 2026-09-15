//! `hx` — the hx harness CLI.
//!
//! Runs against the configuration directly rather than over HTTP, so the inspection commands
//! work when the daemon is down — which is exactly when you most want to know why it will not
//! start. `hx doctor` is the first thing to reach for.

mod commands;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use hx_core::config::Config;
use hx_provider::ModelRouter;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "hx",
    version,
    about = "hx — an agent harness",
    long_about = "Inspect and drive the hx harness.\n\n\
                  Most commands read the configuration directly and work with or without the \
                  daemon running."
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, env = "HX_CONFIG", default_value = "hx.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the model pools, their routes, and the role bindings.
    Pools,

    /// Check the configuration and the environment.
    Doctor,

    /// Show the configured hosts.
    Hosts,

    /// Search the web through the configured backends.
    Search {
        /// What to search for.
        query: String,

        /// Maximum number of results.
        #[arg(short, long, default_value_t = 10)]
        limit: usize,
    },

    /// Inspect sandbox profiles.
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SandboxCommand {
    /// List configured sandbox profiles.
    Profiles,

    /// Print the concrete container settings a profile produces.
    ///
    /// This is the answer to "what does L2 actually mean", so it prints the settings that go to
    /// the container engine rather than summarising the profile.
    Spec {
        /// Profile name from `sandbox_profiles:`.
        profile: String,

        /// Host directory to mount as the workspace.
        #[arg(long, default_value = "/workspace-src")]
        workspace: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let raw = std::fs::read_to_string(&cli.config).with_context(|| {
        format!(
            "could not read the config file {}. Pass --config, or set HX_CONFIG.",
            cli.config.display()
        )
    })?;

    let config = Config::from_yaml(&raw)
        .with_context(|| format!("{} is not a valid hx config", cli.config.display()))?;

    match cli.command {
        Command::Pools => {
            let router = ModelRouter::from_config(&config, Utc::now())?;
            print!("{}", commands::render_pools(&router));
        }

        Command::Doctor => {
            let mut checks = commands::static_checks(&config);
            checks.push(commands::docker_check().await);
            print!("{}", commands::render_doctor(&checks));
        }

        Command::Hosts => print!("{}", commands::render_hosts(&config)),

        Command::Search { query, limit } => {
            if config.search.backends.is_empty() {
                anyhow::bail!(
                    "no search backends are configured; add a `search.backends` list to {}",
                    cli.config.display()
                );
            }
            let report = commands::run_search(&config, &query, limit).await?;
            print!("{}", commands::render_search(&report));
        }

        Command::Sandbox { command } => match command {
            SandboxCommand::Profiles => print!("{}", commands::render_profiles(&config)),
            SandboxCommand::Spec { profile, workspace } => {
                let found = config.sandbox_profiles.get(&profile).ok_or_else(|| {
                    anyhow::anyhow!(
                        "no sandbox profile named '{profile}'; configured profiles: {}",
                        if config.sandbox_profiles.is_empty() {
                            "(none)".to_string()
                        } else {
                            config
                                .sandbox_profiles
                                .keys()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        }
                    )
                })?;
                print!(
                    "{}",
                    commands::render_sandbox_spec(&profile, found, &workspace)
                );
            }
        },
    }

    Ok(())
}
