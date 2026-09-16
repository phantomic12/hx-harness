//! `hx` — the hx harness CLI.
//!
//! The inspection commands read the configuration directly, so they work when the daemon is down —
//! which is exactly when you most want to know why it will not start. `hx doctor` is the first thing
//! to reach for.
//!
//! A *run* is different, and the difference is deliberate: `hx chat` is a client of the daemon, like
//! the TUI and the browser will be. The process that owns the routing table, the limits and the
//! session store is the one that runs the loop, so the terminal asks it rather than racing it.

mod commands;
mod daemon;

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

    /// Where the daemon is. Defaults to `daemon.http_addr` from the config.
    #[arg(long)]
    daemon: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Send a prompt to the running daemon and print what the run did.
    Chat {
        /// What to ask for.
        prompt: String,

        /// Continue an existing session instead of starting one.
        #[arg(long)]
        session: Option<String>,

        /// Which role (and therefore which pool) to run as.
        #[arg(long)]
        role: Option<String>,

        /// The directory the run may read and write. Defaults to the daemon's own.
        #[arg(long)]
        workspace: Option<String>,

        /// `paranoid`, `cautious`, `balanced`, `trusting` or `yolo`.
        ///
        /// This is what decides whether a risky call can be answered at all: over HTTP nobody is
        /// attached to answer a prompt, so anything above the level's threshold is refused unless the
        /// level is `yolo`.
        #[arg(long)]
        autonomy: Option<String>,

        /// Stop after this many turns.
        #[arg(long, default_value_t = 12)]
        max_turns: u32,

        /// Print the daemon's reply as JSON instead of a summary.
        #[arg(long)]
        json: bool,
    },

    /// List the daemon's sessions.
    Sessions {
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },

    /// Show one session, or export it.
    Session {
        id: String,

        /// `json`, `md`, or `none` for just the record and totals.
        #[arg(long, default_value = "none")]
        export: String,
    },

    /// Show the approval questions a run is waiting on.
    Approvals {
        /// Only the questions belonging to this session.
        #[arg(long)]
        session: Option<String>,

        /// Print the daemon's reply as JSON instead of a rendering.
        #[arg(long)]
        json: bool,
    },

    /// Answer a waiting approval question.
    Approve {
        /// The id printed by `hx approvals`.
        id: String,

        /// `once`, `chat`, `always` or `deny`.
        #[arg(long, default_value = "once")]
        option: String,

        /// Who is answering. Recorded in the audit trail, so a terminal and a phone do not look
        /// alike afterwards.
        #[arg(long, default_value = "terminal")]
        by: String,
    },

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
        Command::Chat {
            prompt,
            session,
            role,
            workspace,
            autonomy,
            max_turns,
            json,
        } => {
            let base = daemon::base_url(&config, cli.daemon.as_deref());
            let mut body = serde_json::json!({ "prompt": prompt, "max_turns": max_turns });
            // Only the fields the caller actually set: the daemon's defaults are its own to decide,
            // and sending `null`s would make this command's defaults look like the daemon's.
            if let Some(session) = session {
                body["session"] = serde_json::json!(session);
            }
            if let Some(role) = role {
                body["role"] = serde_json::json!(role);
            }
            if let Some(workspace) = workspace {
                body["workspace"] = serde_json::json!(workspace);
            }
            if let Some(autonomy) = autonomy {
                body["autonomy"] = serde_json::json!(autonomy);
            }

            let client = reqwest::Client::new();
            let reply = daemon::chat(&client, &base, &body).await?;
            print!("{}", commands::render_chat(&reply, json));

            // A run that did not complete is not a success: `stop` says whether the text above is an
            // answer or the beginning of one, and a script needs to be able to tell.
            if reply["stop"].as_str() != Some("completed") {
                std::process::exit(2);
            }
        }

        Command::Sessions { limit } => {
            let base = daemon::base_url(&config, cli.daemon.as_deref());
            let list = daemon::sessions(&reqwest::Client::new(), &base, limit).await?;
            print!("{}", commands::render_sessions(&list));
        }

        Command::Session { id, export } => {
            let base = daemon::base_url(&config, cli.daemon.as_deref());
            let client = reqwest::Client::new();

            match export.as_str() {
                "none" => {
                    let value = daemon::session(&client, &base, &id, false).await?;
                    print!("{}", commands::render_session(&value));
                }
                "json" | "md" | "markdown" => {
                    let format = if export == "json" { "json" } else { "markdown" };
                    print!("{}", daemon::export(&client, &base, &id, format).await?);
                }
                other => anyhow::bail!("unknown export format '{other}'; known: json, md, none"),
            }
        }

        Command::Pools => {
            let router = ModelRouter::from_config(&config, Utc::now())?;
            print!("{}", commands::render_pools(&router));
        }

        Command::Approvals { session, json } => {
            let base = daemon::base_url(&config, cli.daemon.as_deref());
            let list =
                daemon::approvals(&reqwest::Client::new(), &base, session.as_deref()).await?;
            print!("{}", commands::render_approvals(&list, json));
        }

        Command::Approve { id, option, by } => {
            let base = daemon::base_url(&config, cli.daemon.as_deref());
            let reply = daemon::approve(&reqwest::Client::new(), &base, &id, &option, &by).await?;
            // Echoed, not assumed: the daemon is the one that knows whether a question was still
            // waiting, and an answer that arrived after the run gave up is not an answer.
            println!("{}", serde_json::to_string(&reply).unwrap_or_default());
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
