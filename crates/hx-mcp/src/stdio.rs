//! A server that is a child process, spoken to over its own stdin and stdout.
//!
//! ## Why the host spawns `npx` and does not reimplement it
//!
//! `ARCHITECTURE.md` §3.10: "existing MCP servers and CLIs — Python/Node/Go. Run them *inside* the
//! sandbox. Rewriting `npx` servers in Rust is pure cost." The MCP ecosystem's servers are
//! overwhelmingly published as `npx`/`uvx` packages, and the value `hx` adds is not a filesystem
//! server — it is *supervision*: a bounded restart budget, a handshake timeout, a readable failure,
//! and a child that gets reaped. So this module spawns one and treats it as what it is: a program
//! whose output is data.
//!
//! ## Framing
//!
//! MCP's stdio transport is newline-delimited JSON-RPC: one JSON object per line, on stdin and on
//! stdout. `rmcp`'s `AsyncRwTransport` implements exactly that, which is why this module's own code
//! is about process hygiene rather than about parsing.
//!
//! ## The child inherits an allowlist, not the daemon's environment
//!
//! `env:` in the config *adds* variables for the child, and the set the child *inherits* is an
//! **allowlist**: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `LANG`, `LC_ALL` and `TERM`,
//! plus the Windows-only set (`SYSTEMROOT`, `TEMP`, `TMP`, `PATHEXT`, `COMSPEC`, `USERPROFILE`,
//! `APPDATA`, `LOCALAPPDATA`, `PROGRAMFILES`, `NUMBER_OF_PROCESSORS`). Everything else the daemon
//! holds is **not** passed, so a credential exported into the daemon's shell does not reach the
//! children it spawns.
//!
//! This replaced plain inheritance. Inheritance was the honest reading of what `npx` needs — `PATH`
//! resolves Node, `HOME` is where it caches — and it was also a real exposure: `OPENAI_API_KEY`
//! exported into the shell that started the daemon reached every MCP child, including servers
//! written by somebody else. The list is short on purpose, and a tool that genuinely needs something
//! else names it in the server's `env_passthrough:`. That opt-in is **per server**, never global:
//! the operator writing the name is the review, and a variable nobody names cannot leak.
//!
//! `Command::env_clear()` is what makes this fail closed. `env()` alone *adds* to whatever the parent
//! already has, so an allowlist written as a filter over `env()` calls is an allowlist a later
//! `env()` can undo — and one that silently stops applying the day a caller sets a variable before
//! spawning.
//!
//! What this does not do: it bounds *inheritance*, not access. The child runs as the daemon's user
//! and can read what that user can read. `hx`'s answer to a credential a server genuinely needs is
//! still the vault (`vault:` references, resolved per call, never placed in an environment) or an
//! explicit `env:` literal for that one server.
//!
//! ## stderr is captured, never forwarded
//!
//! A server's stderr can contain anything — a token it logged, a filesystem path, a prompt-injection
//! payload aimed at the model. It is therefore piped rather than inherited, drained so the child
//! cannot block on a full pipe, and kept in a bounded tail that only ever reaches a `tracing` line
//! at debug level. Nothing on the model-visible path reads it: not a tool result, not a health
//! report, not a `Debug` rendering. `tests/stdio.rs` pins that with a sentinel written to the
//! child's stderr.

use super::conn::{client_info, ConnectError, Connection};
use hx_core::config::McpServerConfig;
use rmcp::service::serve_client;
use rmcp::transport::TokioChildProcess;
use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

/// How many lines of a child's stderr are kept for a debug log.
const STDERR_TAIL_LINES: usize = 8;

/// How much of one stderr line is kept. A server that prints a megabyte on one line must not be able
/// to grow this process's memory through a channel nobody is reading for content.
const STDERR_LINE_CHARS: usize = 200;

/// A bounded tail of a child's stderr, and a count of everything it wrote.
///
/// The count is the useful part: "this server wrote 4,000 lines to stderr and exited" is a diagnosis,
/// and it is a diagnosis that cannot leak anything. The tail exists for `tracing::debug!` and is
/// reachable only through [`Self::log_tail`], which is the single place that reads it.
#[derive(Clone, Default)]
pub(crate) struct StderrTail {
    lines: Arc<Mutex<VecDeque<String>>>,
    total: Arc<AtomicU64>,
}

impl StderrTail {
    /// How many lines the child has written to stderr. Safe to put in a message: it is a number.
    pub(crate) fn lines_seen(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Write the tail to the debug log, and nowhere else.
    ///
    /// A method rather than a getter on purpose: `fn tail(&self) -> Vec<String>` is a value any
    /// caller could interpolate into a tool result, and this is the channel that must not carry a
    /// server's arbitrary output to a model. There is no getter.
    pub(crate) fn log_tail(&self, server: &str) {
        let lines = match self.lines.lock() {
            Ok(lines) => lines,
            Err(poisoned) => poisoned.into_inner(),
        };
        for line in lines.iter() {
            tracing::debug!(server, "mcp server stderr: {line}");
        }
    }

    fn record(&self, line: String) {
        self.total.fetch_add(1, Ordering::Relaxed);
        let mut lines = match self.lines.lock() {
            Ok(lines) => lines,
            Err(poisoned) => poisoned.into_inner(),
        };
        if lines.len() == STDERR_TAIL_LINES {
            lines.pop_front();
        }
        let line: String = line.chars().take(STDERR_LINE_CHARS).collect();
        lines.push_back(line);
    }
}

/// The variables an MCP child inherits from the daemon's environment, on every platform.
///
/// Short on purpose, and the shortness is the security property. Every entry is here because a
/// program this crate spawns cannot start without it:
///
/// - `PATH` — how `npx`/`uvx`/`node` are resolved at all. Without it nothing spawns.
/// - `HOME`, `USER`, `LOGNAME` — where `npx` and `uvx` keep their caches, and what a server reports
///   about who is running it. `SHELL` for the same reason `HOME` is here: a `npx` shim may run one.
/// - `TMPDIR` — where a package manager stages an install; the default is wrong often enough on a
///   container that omitting it breaks real servers.
/// - `LANG`, `LC_ALL`, `TERM` — locale and terminal, which a server that prints anything reads.
///
/// What is deliberately **absent** is anything credential-shaped, and the reason this is a list
/// rather than a scrubber: a scrubber has to *recognise* a secret, and `OPENAI_API_KEY`,
/// `AWS_SECRET_ACCESS_KEY`, `GH_TOKEN` and `MY_COMPANY_DEPLOY_KEY` do not share a shape. An
/// allowlist does not have to recognise anything.
const INHERITED_ALWAYS: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "TERM",
];

/// The extra variables a Windows child needs to start at all.
///
/// `SYSTEMROOT` is not optional there — a process cannot load its own DLLs without it — and `TEMP`
/// is `TMPDIR`'s counterpart. The rest are what `cmd`, `npm`'s `.cmd` shims and `PATHEXT`-driven
/// resolution read: a Windows child without `PATHEXT` cannot run `npx.cmd`.
#[cfg(windows)]
const INHERITED_WINDOWS: &[&str] = &[
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "PATHEXT",
    "COMSPEC",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMFILES",
    "NUMBER_OF_PROCESSORS",
];

/// The counterpart on every other platform, so the filter is one expression rather than a `cfg` at
/// each use site. Empty filters nothing, and [`INHERITED_ALWAYS`] is then the whole allowlist.
#[cfg(not(windows))]
const INHERITED_WINDOWS: &[&str] = &[];

/// Is this variable inherited — on the built-in allowlist, or named by the server's
/// `env_passthrough`?
///
/// The comparison is case-insensitive on Windows and exact everywhere else, because that is what the
/// platform does: `Path` and `PATH` are one variable there, and two variables here. Getting this
/// wrong on Windows fails *open* in the one direction that matters — the allowlist entry `PATH`
/// would not match the `Path` the OS actually exports, and the child would not start — so it is a
/// `cfg` rather than a normalisation applied everywhere.
fn is_inherited(name: &str, passthrough: &[String]) -> bool {
    let listed = |allowed: &str| -> bool {
        #[cfg(windows)]
        {
            allowed.eq_ignore_ascii_case(name)
        }
        #[cfg(not(windows))]
        {
            allowed == name
        }
    };

    INHERITED_ALWAYS
        .iter()
        .chain(INHERITED_WINDOWS)
        .any(|allowed| listed(allowed))
        || passthrough.iter().any(|opted_in| listed(opted_in))
}

/// The environment an MCP child is given: the daemon's own, filtered down to the allowlist, plus
/// whatever the server's config says.
///
/// Fail-closed by construction — the caller pairs this with [`Command::env_clear`], so a variable
/// that reaches the child is one that was *put* there. See the module doc for the exposure this
/// closes and [`INHERITED_ALWAYS`] for the list.
///
/// `env:` is applied last and is not filtered: a value written in a server's config was written for
/// that server, by the operator, on purpose — which is the same review `env_passthrough` gets. A
/// name in both places takes the config's value, because the config is the more specific statement.
fn child_environment(cfg: &McpServerConfig) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(name, _)| is_inherited(name, &cfg.env_passthrough))
        .collect();

    for (key, value) in &cfg.env {
        match env.iter_mut().find(|(name, _)| name == key) {
            Some(slot) => slot.1 = value.clone(),
            None => env.push((key.clone(), value.clone())),
        }
    }

    env
}

/// Spawn the configured command and complete the MCP handshake over its pipes.
///
/// `tail` is the server's stderr sink, owned by the supervisor rather than by the connection: the
/// tail has to outlive a dead connection to be worth anything, and the diagnosis it exists for
/// ("this server wrote 4,000 lines to stderr and exited") is exactly the case where the connection
/// is already gone.
pub(crate) async fn connect(
    name: &str,
    cfg: &McpServerConfig,
    handshake_timeout: Duration,
    tail: StderrTail,
) -> Result<Connection, ConnectError> {
    let command = cfg
        .command
        .as_deref()
        .ok_or_else(|| ConnectError::Config(format!("mcp server {name:?}: no command")))?;

    let mut cmd = tokio::process::Command::new(command);
    cmd.args(&cfg.args);
    // Fail closed. `env()` alone *adds* to the inherited environment, so an allowlist written as a
    // filter over `env()` calls is one a later `env()` — or a variable the daemon happens to have —
    // can undo. `env_clear()` first, then exactly what the allowlist and the config say. See
    // `child_environment`.
    cmd.env_clear();
    cmd.envs(child_environment(cfg));
    if let Some(cwd) = &cfg.cwd {
        cmd.current_dir(cwd);
    }
    // The backstop against an orphan. `TokioChildProcess` reaps the child on an orderly close and
    // `RunningService` closes on drop, so this only matters for the path where the whole runtime
    // goes away mid-flight — which is exactly the path an operator's `Ctrl-C` takes.
    cmd.kill_on_drop(true);

    // stderr is *piped*, overriding `rmcp`'s `Stdio::inherit()` default: inheriting would put a
    // server's arbitrary output on the daemon's stderr, which is a log file the model's context can
    // be assembled from. See the module doc.
    let (transport, stderr) = TokioChildProcess::builder(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ConnectError::Spawn {
            command: command.to_string(),
            source,
        })?;

    if let Some(stderr) = stderr {
        drain_stderr(stderr, tail);
    }

    let handshake = tokio::time::timeout(handshake_timeout, serve_client(client_info(), transport));
    match handshake.await {
        // The timeout drops the `serve_client` future, which drops the transport, which kills the
        // child. A server that never answers `initialize` therefore cannot leave a process behind.
        Err(_elapsed) => Err(ConnectError::HandshakeTimeout {
            secs: handshake_timeout.as_secs(),
        }),
        Ok(Ok(connection)) => Ok(connection),
        Ok(Err(err)) => Err(ConnectError::Handshake(err.to_string())),
    }
}

/// Read a child's stderr to end-of-file, keeping a bounded tail.
///
/// Draining is not optional: a piped stderr that nobody reads fills its buffer and then blocks the
/// child on its next write, which presents as "the server hung" and is one of the classic ways a
/// supervised process appears wedged when it is not.
fn drain_stderr(stderr: tokio::process::ChildStderr, tail: StderrTail) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tail.record(line);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The predicate, unit-tested where the child-process test can only show it end to end. The
    /// integration test proves the filter is *used*; this proves it is the right filter.
    #[test]
    fn the_allowlist_lets_a_toolchain_start_and_nothing_else_through() {
        let nothing = Vec::new();

        // The positive controls: without these the child does not start at all.
        for name in ["PATH", "HOME", "TMPDIR", "LANG"] {
            assert!(is_inherited(name, &nothing), "{name} must be inherited");
        }

        // The negatives, chosen to be the shapes a real daemon holds: two API keys, a cloud secret,
        // a token, and a company-specific deploy key. None shares a pattern with another, which is
        // exactly why this is a list and not a scrubber.
        for name in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "GH_TOKEN",
            "MY_COMPANY_DEPLOY_KEY",
            "HTTPS_PROXY",
        ] {
            assert!(
                !is_inherited(name, &nothing),
                "{name} must not be inherited by default"
            );
        }

        // A near-miss, so a prefix or case-insensitive match on Unix cannot pass this by accident.
        assert!(
            !is_inherited("path", &nothing),
            "Unix names are case-sensitive"
        );
        assert!(!is_inherited("PATHEXTRA", &nothing));
    }

    #[test]
    fn an_opted_in_name_is_inherited_and_only_for_the_server_that_named_it() {
        let opted_in = vec!["HTTPS_PROXY".to_string()];

        assert!(is_inherited("HTTPS_PROXY", &opted_in));
        assert!(
            !is_inherited("HTTP_PROXY", &opted_in),
            "one name does not bring its family: the opt-in is exact"
        );
        assert!(
            !is_inherited("OPENAI_API_KEY", &opted_in),
            "and it does not widen the list it was added to"
        );
        assert!(
            is_inherited("PATH", &opted_in),
            "opting in does not remove what was already there"
        );
    }

    #[test]
    fn the_config_env_is_applied_and_overrides_what_was_inherited() {
        // `env:` is the operator's own literal for one server, so it is not filtered — and a name it
        // repeats takes the config's value, because the config is the more specific statement.
        let mut cfg = McpServerConfig::stdio("npx", Vec::<String>::new());
        cfg.env
            .insert("HTTPS_PROXY".into(), "http://127.0.0.1:9".into());
        cfg.env
            .insert("SENTINEL_FOR_THIS_SERVER".into(), "on".into());
        cfg.env_passthrough = vec!["HTTPS_PROXY".to_string()];

        // Only assert on what the *config* contributed: the inherited half depends on the machine
        // this runs on, and a test that hard-coded `PATH` would be asserting the CI environment.
        let env = child_environment(&cfg);
        let value = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("SENTINEL_FOR_THIS_SERVER"), Some("on"));
        assert_eq!(value("HTTPS_PROXY"), Some("http://127.0.0.1:9"));
        assert_eq!(
            env.iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case("HTTPS_PROXY"))
                .count(),
            1,
            "the config's value replaces the inherited one rather than appearing twice"
        );
    }
}
