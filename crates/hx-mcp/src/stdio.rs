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
//! ## The child inherits the daemon's environment, knowingly
//!
//! `env:` in the config *adds* variables; it does not replace the inherited set. That is deliberate
//! — `npx` resolves Node through `PATH`, and servers read `HOME` for caches — and it is also a real
//! exposure: a credential exported into the daemon's environment reaches every MCP child it spawns.
//! `hx`'s own answer to this is the vault (`vault:` references, resolved per call, never placed in
//! an environment) and the rule that a server needing a token is configured with one, but a daemon
//! started from a shell with `OPENAI_API_KEY` exported does hand that to its children. It is called
//! out here, in `ROADMAP.md`, and in `TESTING.md` rather than papered over with a half-scrubbed
//! environment that would break the servers this feature exists to run.
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
    for (key, value) in &cfg.env {
        cmd.env(key, value);
    }
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
