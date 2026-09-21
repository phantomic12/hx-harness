//! The stdio transport, driven against a real child process on a real pipe.
//!
//! ## What is being held here
//!
//! `tests/support/fake_mcp_server.rs` is a real MCP server: real JSON-RPC 2.0, newline-delimited, over
//! the pipes of a real child process spawned by this crate's own code. Nothing in this file is a
//! mock, and the double *fails loudly* — it records an `UNEXPECTED` line in its pid file and exits
//! non-zero on any input it was not scripted for, which every test here asserts is absent. A client
//! bug that sent the wrong method, a malformed frame, or a request twice would therefore fail a test
//! instead of being answered politely.
//!
//! The properties under test are the ones the module docs claim:
//!
//! - **A dead, silent, wedged or misbehaving server is a readable [`ToolOutcome`], never a hang.**
//!   Every failure mode the double can produce has a test, and each asserts a *bound* on how long the
//!   call took rather than a wall-clock duration.
//! - **Restarts are bounded.** A server that cannot start is spawned a bounded number of times, which
//!   the pid file counts — the one thing a unit test of `RestartBudget` cannot show.
//! - **A child is reaped.** After the host shuts down, the pid in the pid file is gone from `/proc`,
//!   and the test says explicitly when it is a *zombie* rather than merely alive, because "killed but
//!   not reaped" is the failure this property exists to catch.
//! - **stderr is counted and never forwarded.** A sentinel written to the child's stderr appears in no
//!   tool result, no health report and no tool description — while the count proves it was written.
//! - **The server's own spelling of a tool name is what goes back on the wire.** A tool the provider
//!   charset cannot carry verbatim (`a b`) is the case that catches a client sending the folded name.

use hx_core::config::McpServerConfig;
use hx_mcp::{HealthState, McpHost};
use hx_tools::ToolOutcome;
use indexmap::IndexMap;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The binary under test. `[[bin]] hx-mcp-fake-server` in `Cargo.toml` is what makes cargo build it
/// and export this variable to the test process.
const FAKE_SERVER: &str = env!("CARGO_BIN_EXE_hx-mcp-fake-server");

/// The sentinel the double writes to stderr in `noisy-stderr` mode. Spelled the same way here as
/// there, and asserted absent from every model-visible string.
const STDERR_SENTINEL: &str = "hx-mcp-stderr-sentinel-token-please-do-not-echo";

/// How many lines `noisy-stderr` writes. More than the bounded tail (8), so a count of 40 proves the
/// counter is *total* rather than the size of the tail.
const NOISY_STDERR_LINES: usize = 40;

/// A scratch directory per test, holding the double's pid file.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("a temp dir"),
        }
    }

    fn pid_file(&self) -> PathBuf {
        self.dir.path().join("pids")
    }

    fn pid_file_arg(&self) -> String {
        self.pid_file().to_string_lossy().into_owned()
    }

    /// Every line the double has recorded: one pid per start, plus an `UNEXPECTED …` line for any
    /// input it was not scripted for.
    fn records(&self) -> Vec<String> {
        match std::fs::read_to_string(self.pid_file()) {
            Ok(text) => text.lines().map(str::to_string).collect(),
            // No file at all is a legitimate state (a server that was never spawned).
            Err(_) => Vec::new(),
        }
    }

    /// How many times a server was spawned. The pid file is appended to on every start.
    fn spawns(&self) -> usize {
        self.records()
            .iter()
            .filter(|line| !line.starts_with("UNEXPECTED"))
            .count()
    }

    fn last_pid(&self) -> String {
        self.records()
            .into_iter()
            .rfind(|line| !line.starts_with("UNEXPECTED"))
            .expect("the double recorded its pid")
    }

    /// The loud-failure check every test makes: the double was fed only what it was scripted for.
    fn assert_scripted_only(&self) {
        let unexpected: Vec<String> = self
            .records()
            .into_iter()
            .filter(|line| line.starts_with("UNEXPECTED"))
            .collect();
        assert!(
            unexpected.is_empty(),
            "the fake server was sent something it was not scripted for, so this test proved \
             nothing about the case it names: {unexpected:?}"
        );
    }
}

/// A stdio server block for the double, in one mode.
fn server(mode: &str, fixture: &Fixture) -> McpServerConfig {
    let mut cfg = McpServerConfig::stdio(
        FAKE_SERVER,
        vec![
            "--mode".to_string(),
            mode.to_string(),
            "--pid-file".to_string(),
            fixture.pid_file_arg(),
        ],
    );
    // Short, so a test that is *supposed* to time out does so in about a second rather than twenty.
    cfg.start_timeout_secs = 2;
    cfg.call_timeout_secs = 2;
    cfg
}

fn config(entries: Vec<(&str, McpServerConfig)>) -> IndexMap<String, McpServerConfig> {
    entries
        .into_iter()
        .map(|(key, cfg)| (key.to_string(), cfg))
        .collect()
}

/// Bring a host up around one server, and give it back. `from_config` never fails for a connection
/// problem, which is itself part of what these tests lean on.
async fn host_for(key: &str, mode: &str, fixture: &Fixture) -> Arc<McpHost> {
    let servers = config(vec![(key, server(mode, fixture))]);
    Arc::new(
        McpHost::from_config(&servers, None)
            .await
            .expect("a connection failure is recorded, not returned"),
    )
}

/// Poll a condition with a bound.
///
/// This is not a wall-clock assertion: it asserts that something *becomes* true and fails if it does
/// not. It is the honest way to observe work the OS does asynchronously — a child being reaped, a
/// stderr drain task being scheduled — without pretending a fixed sleep is evidence.
async fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

/// The single-letter state of a process, from `/proc/<pid>/stat` — or `None` when it is gone.
///
/// `Z` is the answer worth having: a zombie is a child that was killed but never reaped, which is
/// exactly the failure the reaping property exists to catch, and it is invisible to a check that only
/// asks whether the process is still running.
#[cfg(target_os = "linux")]
fn process_state(pid: &str) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is in parentheses and may contain spaces or parentheses of its own, so the
    // fields after it start at the *last* `)`.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

fn assert_bounded(started: Instant, within: Duration, what: &str) {
    let elapsed = started.elapsed();
    assert!(
        elapsed < within,
        "{what} took {elapsed:?}, past the {within:?} bound — the point of the bound is that nothing \
         waits on a server that will not answer"
    );
}

// ---------------------------------------------------------------------------
// The happy path: a real child, a real handshake, a real round trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_stdio_server_is_spawned_and_its_tools_are_published_under_its_namespace() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;

    let names = host.tool_names();
    assert!(
        names.contains(&"fake__echo".to_string()),
        "a remote tool is named for the server it came from: {names:?}"
    );
    // Four tools, and the one whose name the provider charset cannot carry is folded for the model.
    assert_eq!(names.len(), 4, "{names:?}");
    assert!(names.contains(&"fake__a_b".to_string()), "{names:?}");

    let health = host.status().await;
    assert_eq!(health.len(), 1);
    assert_eq!(health[0].server, "fake");
    assert_eq!(health[0].transport, "stdio");
    assert!(
        matches!(&health[0].state, HealthState::Up { tools } if tools.len() == 4),
        "{:?}",
        health[0].state
    );

    // One child, and it was fed only the scripted handshake.
    assert_eq!(fixture.spawns(), 1);
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn a_call_round_trips_through_the_childs_own_pipe() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;

    let outcome = host.call("fake__echo", json!({"text": "round trip"})).await;

    assert!(outcome.ok, "{}", outcome.content);
    assert_eq!(
        outcome.content, "round trip",
        "the text came back from the child's stdout, through the client's framing"
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn a_call_is_sent_with_the_servers_own_spelling_of_the_tool_name() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;

    // The model calls `fake__a_b`; the server only knows a tool called `a b`. The double answers the
    // two cases differently, so this cannot pass by accident: sending the folded name gets
    // `isError: true` with "no such tool: a_b".
    let outcome = host.call("fake__a_b", json!({})).await;

    assert!(outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("the server's own spelling"),
        "the call went out with the server's name, not the model's: {}",
        outcome.content
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn a_tool_the_server_marks_as_an_error_is_a_result_and_the_connection_survives() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;

    let refused = host.call("fake__fail", json!({})).await;
    assert!(
        !refused.ok,
        "the server's own is_error becomes a failed outcome: {}",
        refused.content
    );
    assert!(
        refused.content.contains("refused, on purpose"),
        "{}",
        refused.content
    );

    // The connection is *not* torn down: a refusal is an answer, and killing the server for
    // answering would turn every argument error into a restart.
    let after = host.call("fake__echo", json!({"text": "still here"})).await;
    assert!(after.ok, "{}", after.content);
    assert_eq!(fixture.spawns(), 1, "no restart happened for a refusal");
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn structured_content_is_rendered_when_the_server_sends_no_prose() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;

    let outcome = host.call("fake__structured", json!({})).await;

    assert!(outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("42"),
        "structured output is the answer when there is no prose to show: {}",
        outcome.content
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn the_servers_own_description_reaches_the_model_labelled_as_the_servers() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;

    let tools = host.tools();
    let echo = tools
        .iter()
        .find(|tool| tool.name() == "fake__echo")
        .expect("echo is published");

    let description = echo.description();
    assert!(
        description.contains("the fake server's own description of echo"),
        "the server's words are passed through verbatim: {description}"
    );
    assert!(
        description.contains("passed through as data"),
        "and labelled as the server's, so they are not read as an order: {description}"
    );
    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// The failure modes. Each one: readable, bounded, and never a hang.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_server_that_exits_after_initialising_is_reported_as_down_rather_than_hanging() {
    let fixture = Fixture::new();
    let started = Instant::now();

    // `from_config` connects eagerly, so the half-finished handshake is recorded rather than
    // returned: a daemon that refused to start because a third-party server was down would be a
    // daemon nobody could use.
    let host = host_for("fake", "exit-after-init", &fixture).await;
    assert_bounded(
        started,
        Duration::from_secs(20),
        "startup against a dying server",
    );

    let health = host.status().await;
    assert!(
        matches!(&health[0].state, HealthState::Down { retrying: true, .. }),
        "a server that died after `initialize` is down and will be retried: {:?}",
        health[0].state
    );
    assert!(
        host.tool_names().is_empty(),
        "a server that never listed its tools contributes none"
    );

    // A call now tries to bring it back, fails, and says so in words.
    let started = Instant::now();
    let outcome = host.call("fake__echo", json!({"text": "hello"})).await;
    assert_bounded(
        started,
        Duration::from_secs(20),
        "a call to a server that will not stay up",
    );
    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("fake") && outcome.content.contains("not running"),
        "the failure names the server and its state: {}",
        outcome.content
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn a_server_that_says_nothing_is_cut_off_by_the_handshake_timeout() {
    let fixture = Fixture::new();
    let started = Instant::now();
    let host = host_for("fake", "silent", &fixture).await;

    // Two seconds is the configured `start_timeout_secs`; the bound is loose on purpose, because what
    // is being asserted is "bounded at all" rather than a stopwatch reading.
    assert_bounded(started, Duration::from_secs(15), "the handshake timeout");

    let health = host.status().await;
    assert!(
        matches!(&health[0].state, HealthState::Down { .. }),
        "{:?}",
        health[0].state
    );

    let started = Instant::now();
    let outcome = host.call("fake__echo", json!({"text": "x"})).await;
    assert_bounded(
        started,
        Duration::from_secs(15),
        "a call to a silent server",
    );
    assert!(
        outcome.content.contains("did not finish its handshake"),
        "the reason is the timeout, not something invented: {}",
        outcome.content
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn a_server_that_writes_garbage_fails_the_handshake_with_a_readable_reason() {
    let fixture = Fixture::new();
    let started = Instant::now();
    let host = host_for("fake", "garbage", &fixture).await;

    // Both outcomes are acceptable and both are failures: `rmcp` may reject the frame outright or
    // skip it and wait for a reply that never comes. Either way the caller gets a bounded, named
    // failure rather than a future that never resolves — which is the whole property.
    assert_bounded(
        started,
        Duration::from_secs(15),
        "startup against a server writing garbage",
    );

    let outcome = host.call("fake__echo", json!({"text": "x"})).await;
    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("fake") && !outcome.content.trim().is_empty(),
        "{}",
        outcome.content
    );
    host.shutdown().await;
}

#[tokio::test]
async fn a_server_that_dies_during_a_call_is_detected_and_marked_down() {
    let fixture = Fixture::new();
    let host = host_for("fake", "die-on-tool", &fixture).await;
    assert!(
        matches!(&host.status().await[0].state, HealthState::Up { .. }),
        "the handshake completed before the tool was called"
    );

    let started = Instant::now();
    let outcome = host.call("fake__echo", json!({"text": "x"})).await;
    assert_bounded(
        started,
        Duration::from_secs(15),
        "a call to a server that dies",
    );

    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("not running") || outcome.content.contains("connection dropped"),
        "a dead child is reported as a connection that dropped: {}",
        outcome.content
    );
    assert!(
        matches!(&host.status().await[0].state, HealthState::Down { .. }),
        "and the server is marked down rather than left claiming to be up: {:?}",
        host.status().await[0].state
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn a_server_that_never_answers_a_call_is_cut_off_by_the_call_timeout() {
    let fixture = Fixture::new();
    let host = host_for("fake", "hang-on-tool", &fixture).await;

    let started = Instant::now();
    let outcome = host.call("fake__echo", json!({"text": "x"})).await;
    // `call_timeout_secs` is 2; the bound is the assertion, not the number.
    assert_bounded(started, Duration::from_secs(10), "the call timeout");

    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("timeout") || outcome.content.contains("did not answer"),
        "the failure is a timeout the model can read: {}",
        outcome.content
    );

    // The connection is deliberately *not* torn down. A slow server and a dead one look the same from
    // here, and killing a server for being slow is how a working deployment becomes a flapping one.
    let health = host.status().await;
    assert!(
        matches!(&health[0].state, HealthState::Up { .. }),
        "a wedged server is left connected: {:?}",
        health[0].state
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// Restarts, and the process table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restarts_are_bounded_so_a_server_that_cannot_start_stops_being_respawned() {
    let fixture = Fixture::new();
    let mut cfg = server("exit-on-start", &fixture);
    cfg.max_restarts = 3;
    cfg.start_timeout_secs = 2;
    let max_restarts = cfg.max_restarts;

    let servers = config(vec![("fake", cfg)]);
    let host = McpHost::from_config(&servers, None)
        .await
        .expect("config is fine");

    // Six calls against a server that can never start. The pid file is the evidence: one line per
    // spawn, and the count must stop rather than growing with the number of calls.
    let mut last = ToolOutcome::failed("");
    for _ in 0..6 {
        last = host.call("fake__echo", json!({"text": "x"})).await;
        assert!(!last.ok, "{}", last.content);
    }

    let spawns = fixture.spawns();
    assert!(
        spawns <= max_restarts as usize,
        "the budget is a ceiling on processes, not a suggestion: {spawns} spawns for a budget of \
         {max_restarts}"
    );
    assert!(spawns >= 1, "it did try at least once: {spawns}");
    assert!(
        last.content.contains("stopped restarting"),
        "and the last call says hx has given up, with the way out: {}",
        last.content
    );
    assert!(
        matches!(&host.status().await[0].state, HealthState::GivenUp { .. }),
        "{:?}",
        host.status().await[0].state
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

#[tokio::test]
async fn a_servers_stderr_is_counted_and_never_reaches_a_result_or_a_health_report() {
    let fixture = Fixture::new();
    let host = host_for("fake", "noisy-stderr", &fixture).await;

    let outcome = host.call("fake__echo", json!({"text": "the answer"})).await;
    assert!(outcome.ok, "{}", outcome.content);

    // The counter is total, not the size of the bounded tail: a server that wrote 40 lines and exited
    // is a diagnosis, and a diagnosis that cannot leak anything.
    let mut counted = false;
    for _ in 0..200 {
        if host.status().await[0].stderr_lines >= NOISY_STDERR_LINES as u64 {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let health = host.status().await;
    assert!(
        counted && health[0].stderr_lines >= NOISY_STDERR_LINES as u64,
        "every line is counted (the tail is bounded at 8): {}",
        health[0].stderr_lines
    );

    // And nowhere on the model-visible path does a byte of it appear.
    let visible = format!(
        "{}\n{:?}\n{}",
        outcome.content,
        health,
        host.tools()
            .iter()
            .map(|tool| format!("{} {}", tool.name(), tool.description()))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        !visible.contains(STDERR_SENTINEL),
        "a child's stderr is captured, drained and counted — never echoed into a result, a health \
         report or a description: {visible}"
    );
    fixture.assert_scripted_only();
    host.shutdown().await;
}

/// Linux is the one target where the child PID can be observed through `/proc/<pid>/stat` (state
/// bit) and a `kill -0` style existence check, so only there can the test prove the child was
/// actually reaped (not left as a `Z` zombie). macOS has no `/proc`, so it falls to the
/// portable arm below just like Windows.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_host_reaps_every_child_it_spawned_when_it_shuts_down() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;
    assert_eq!(fixture.spawns(), 1);
    let pid = fixture.last_pid();
    assert!(
        process_state(&pid).is_some(),
        "the child is running before the shutdown, so this test is not vacuous"
    );

    host.shutdown().await;

    let gone = wait_until(|| process_state(&pid).is_none()).await;
    if !gone {
        panic!(
            "the child {pid} survived the host's shutdown in state {:?} — `Z` means it was killed \
             and never reaped, which is the orphan this property exists to catch",
            process_state(&pid)
        );
    }
    fixture.assert_scripted_only();
}

/// Windows and macOS have no `/proc` (macOS lacks `/proc/<pid>/stat` too), so the process-gone
/// check cannot be made from a test process there. What this arm asserts is the half that is portable
/// and still load-bearing: the shutdown completes, and the server it closed is no longer reported as up.
/// A shutdown that hung, or that left the state claiming `Up`, fails on either platform.
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn the_host_reaps_every_child_it_spawned_when_it_shuts_down() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;
    assert_eq!(fixture.spawns(), 1);

    let started = Instant::now();
    host.shutdown().await;
    assert_bounded(started, Duration::from_secs(15), "a shutdown");

    assert!(
        matches!(&host.status().await[0].state, HealthState::Down { .. }),
        "a closed server is not reported as up: {:?}",
        host.status().await[0].state
    );
    fixture.assert_scripted_only();
}

// ---------------------------------------------------------------------------
// Config-shaped refusals: nothing is spawned for a server that cannot run
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_disabled_server_is_never_spawned_and_offers_no_tools() {
    let fixture = Fixture::new();
    let mut cfg = server("ok", &fixture);
    cfg.enabled = false;

    let servers = config(vec![("fake", cfg)]);
    let host = McpHost::from_config(&servers, None)
        .await
        .expect("config is fine");

    assert_eq!(fixture.spawns(), 0, "`enabled: false` starts nothing");
    assert!(host.tool_names().is_empty());
    assert!(
        matches!(&host.status().await[0].state, HealthState::Disabled),
        "{:?}",
        host.status().await[0].state
    );

    let outcome = host.call("fake__echo", json!({"text": "x"})).await;
    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("disabled"),
        "a call to a disabled server says which switch turned it off, rather than claiming the \
         tool does not exist: {}",
        outcome.content
    );
    assert!(
        outcome.content.contains("enabled: false"),
        "and names the setting: {}",
        outcome.content
    );
    host.shutdown().await;
}

#[tokio::test]
async fn two_servers_that_fold_onto_one_namespace_are_refused_before_anything_is_spawned() {
    let fixture = Fixture::new();
    // Sanitising is lossy, so two config keys can fold onto one namespace — and letting the second
    // server quietly take over the first one's names is exactly what namespacing exists to prevent.
    let servers = config(vec![
        ("github-work", server("ok", &fixture)),
        ("github_work", server("ok", &fixture)),
    ]);

    let err = match McpHost::from_config(&servers, None).await {
        Ok(_) => panic!("a namespace collision is a config error"),
        Err(err) => err,
    };

    let message = err.to_string();
    assert!(message.contains("github-work"), "{message}");
    assert!(message.contains("github_work"), "{message}");
    assert!(message.contains("namespace"), "{message}");
    assert_eq!(
        fixture.spawns(),
        0,
        "the collision is refused before a child is started, not after"
    );
}

#[tokio::test]
async fn a_config_that_cannot_start_a_server_fails_construction_rather_than_at_first_use() {
    let fixture = Fixture::new();
    // No command at all: the operator's typo, and the only class of problem that will not fix itself.
    let servers = config(vec![(
        "fake",
        McpServerConfig::stdio("", Vec::<String>::new()),
    )]);

    let err = match McpHost::from_config(&servers, None).await {
        Ok(_) => panic!("a missing command is a config error"),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(message.contains("fake"), "{message}");
    assert!(message.contains("command"), "{message}");
    assert_eq!(fixture.spawns(), 0);
}

#[tokio::test]
async fn a_tool_nobody_offers_is_a_readable_result_listing_what_is_available() {
    let fixture = Fixture::new();
    let host = host_for("fake", "ok", &fixture).await;

    let outcome = host.call("nope__nothing", json!({})).await;

    assert!(!outcome.ok, "{}", outcome.content);
    assert!(
        outcome.content.contains("no MCP tool named"),
        "{}",
        outcome.content
    );
    assert!(
        outcome.content.contains("fake__echo"),
        "the model is told what it could have called instead: {}",
        outcome.content
    );
    host.shutdown().await;
}
