//! What an MCP child actually inherits — asked of a real child process, not of a filter function.
//!
//! ## Why this is its own test binary
//!
//! The property is about the *parent's* environment, so the test has to put a secret in it, and
//! `std::env::set_var` is not safe to call while another thread is reading the environment. Cargo
//! runs each integration-test file as its own process, so a file that mutates its own environment and
//! has one test in it cannot race anything. That is the whole reason this is not another case in
//! `tests/stdio.rs`.
//!
//! ## What is asserted, and why a child rather than `is_inherited`
//!
//! `hx-mcp`'s own unit tests pin the predicate (`is_inherited`) and the map it builds
//! (`child_environment`). Those can both be right while `connect` forgets to *use* them — which is
//! exactly the shape the old code had, where `Command::env` silently added to an inherited
//! environment. So this test spawns the real double over a real pipe, through the real
//! `McpHost::from_config`, and reads the environment the child actually holds, dumped by the child
//! itself (`--env-file`, see `tests/support/fake_mcp_server.rs`).
//!
//! The assertions are deliberately *complete* rather than spot checks. A negative ("the sentinel is
//! absent") passes trivially if the child inherits nothing at all — a child that could not start, or
//! one whose dump was empty. So:
//!
//! - **The positive control is the sentinel's twin**: `LOGNAME` is on the allowlist and the test sets
//!   its *value*, so its arrival proves the child read the parent's environment rather than its own
//!   defaults. `PATH` is checked too, because without it no `npx`/`uvx` server starts at all.
//! - **The negative is a whole set, not a name**: every variable in the child's environment must be
//!   on the allowlist, opted in for that server, or written in that server's `env:`. A leak of any
//!   name — one nobody thought to check — fails the test.
//! - **The opt-in is per server**: the same variable is present for the server that named it and
//!   absent for the one that did not, in one run.
//!
//! The expected allowlist is written out here **on purpose**. It is the specification, so a change to
//! the crate's list has to change this test too, and that edit is the review. Reading the list back
//! out of the crate would make the test agree with whatever the code does.

use hx_core::config::McpServerConfig;
use hx_mcp::{HealthState, McpHost};
use indexmap::IndexMap;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The binary under test — the same hand-rolled MCP server `tests/stdio.rs` drives.
const FAKE_SERVER: &str = env!("CARGO_BIN_EXE_hx-mcp-fake-server");

/// The secret. Its name is deliberately the shape a real daemon's environment holds — this is the
/// `OPENAI_API_KEY` in the ROADMAP's example, with a value distinctive enough to grep for.
const SECRET: &str = "HX_MCP_ENV_SENTINEL_SECRET";
const SECRET_VALUE: &str = "sk-do-not-give-this-to-a-third-party-server";

/// A variable that is *not* on the allowlist and *not* opted in. Distinct from [`SECRET`] so a
/// failure says which property broke: "a credential leaked" is a different bug from "an ordinary
/// variable leaked", and only the second would be caught by a scrubber that recognised secrets.
const ORDINARY: &str = "HX_MCP_ENV_ORDINARY";
const ORDINARY_VALUE: &str = "not-a-secret-but-not-the-childs-business-either";

/// The variable one server opts into, and the other does not.
const OPTED_IN: &str = "HX_MCP_ENV_OPTED_IN";
const OPTED_IN_VALUE: &str = "this-one-was-named-in-the-config";

/// The variable the child is given *by* its own config, which is not inheritance at all.
const FROM_CONFIG: &str = "HX_MCP_ENV_FROM_CONFIG";
const FROM_CONFIG_VALUE: &str = "written-for-this-server";

/// On the allowlist, and set to a value the test controls: the positive control. Nothing in this
/// process reads `LOGNAME`, so overwriting it cannot change what the test is measuring.
const ALLOWLISTED_CONTROL: &str = "LOGNAME";
const ALLOWLISTED_CONTROL_VALUE: &str = "hx-env-test-control";

/// The allowlist, as the specification. See the module doc for why this is not read from the crate.
#[cfg(windows)]
const ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "TERM",
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

#[cfg(not(windows))]
const ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "TERM",
];

/// How long the spawn-and-handshake may take before this test calls it wedged. A *bound* with a
/// message, not a duration to sleep for: `from_config` returns as soon as the handshake is done.
const BOUND: Duration = Duration::from_secs(30);

fn server(fixture: &Fixture, env_file: &Path, passthrough: &[&str]) -> McpServerConfig {
    let mut cfg = McpServerConfig::stdio(
        FAKE_SERVER,
        vec![
            "--mode".to_string(),
            "ok".to_string(),
            "--pid-file".to_string(),
            fixture.pid_file_arg(),
            "--env-file".to_string(),
            env_file.to_string_lossy().into_owned(),
        ],
    );
    cfg.start_timeout_secs = 10;
    cfg.call_timeout_secs = 10;
    cfg.env_passthrough = passthrough.iter().map(|name| name.to_string()).collect();
    cfg
}

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

    fn env_file(&self, server: &str) -> PathBuf {
        self.dir.path().join(format!("env-{server}"))
    }
}

/// The environment a child actually held, as the child wrote it down.
///
/// Read only after the host reported the server *up*: the dump happens before the handshake, so a
/// completed handshake is what makes the file complete. No sleep, and no polling.
fn child_environment(path: &PathBuf, server: &str) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| {
        panic!(
            "the {server} child did not write its environment to {} ({err}) — it was never spawned, \
             or it died before writing",
            path.display()
        )
    });

    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| match line.split_once('=') {
            Some((key, value)) => (key.to_string(), value.to_string()),
            None => panic!("a line with no `=` in the environment dump: {line:?}"),
        })
        .collect()
}

/// Case-insensitive lookup, because that is what Windows does: `Path` and `PATH` are one variable
/// there. On Unix this is still exact for every name this test uses.
fn get<'a>(env: &'a BTreeMap<String, String>, name: &str) -> Option<&'a String> {
    env.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn on_allowlist(name: &str) -> bool {
    ALLOWLIST
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(name))
}

/// The whole property, in one test, because it needs one environment: a secret in the daemon's
/// shell, an ordinary variable beside it, an opt-in that one server names and another does not, and
/// a positive control whose arrival proves the child read the parent.
#[tokio::test]
async fn an_mcp_child_gets_the_allowlist_the_opt_in_and_its_own_config_and_nothing_else() {
    // `set_var` before anything is spawned, in a binary whose only test this is.
    std::env::set_var(SECRET, SECRET_VALUE);
    std::env::set_var(ORDINARY, ORDINARY_VALUE);
    std::env::set_var(OPTED_IN, OPTED_IN_VALUE);
    std::env::set_var(ALLOWLISTED_CONTROL, ALLOWLISTED_CONTROL_VALUE);

    // And read them back before spawning, so the absences asserted below cannot be vacuous: if the
    // parent does not hold the secret, "the child does not hold the secret" is true for a reason
    // that has nothing to do with `hx-mcp`. `set_var` cannot fail, but this is the assertion that
    // says so.
    for (name, value) in [
        (SECRET, SECRET_VALUE),
        (ORDINARY, ORDINARY_VALUE),
        (OPTED_IN, OPTED_IN_VALUE),
        (ALLOWLISTED_CONTROL, ALLOWLISTED_CONTROL_VALUE),
    ] {
        assert_eq!(
            std::env::var(name).ok().as_deref(),
            Some(value),
            "the fixture is the parent's environment: {name} must be set before the child is spawned"
        );
    }

    let fixture = Fixture::new();
    let opted_in_env = fixture.env_file("optedin");
    let opted_out_env = fixture.env_file("optedout");

    // Two servers, one host: the opt-in is per server, so the same variable must be present for one
    // and absent for the other *in the same run*. A single-server test could not tell a per-server
    // opt-in from a global one.
    let mut opted_in = server(&fixture, &opted_in_env, &[OPTED_IN]);
    opted_in
        .env
        .insert(FROM_CONFIG.into(), FROM_CONFIG_VALUE.into());
    let opted_out = server(&fixture, &opted_out_env, &[]);

    let servers: IndexMap<String, McpServerConfig> = [
        ("optedin".to_string(), opted_in),
        ("optedout".to_string(), opted_out),
    ]
    .into_iter()
    .collect();

    let started = Instant::now();
    let host = Arc::new(
        McpHost::from_config(&servers, None)
            .await
            .expect("a spawn failure is recorded as health, not returned as an error"),
    );
    assert!(
        started.elapsed() < BOUND,
        "spawn and handshake took {:?}, past the {BOUND:?} bound — a child that cannot be reached \
         must be cut off by hx's own clock",
        started.elapsed()
    );

    let health = host.status().await;
    for entry in &health {
        assert!(
            matches!(&entry.state, HealthState::Up { .. }),
            "the {} child must come up, or nothing below is about inheritance: {:?}",
            entry.server,
            entry.state
        );
    }

    // -- the positive controls, first --------------------------------------------------------
    //
    // Before any absence is asserted, the child must be shown to have read the parent's
    // environment at all. Otherwise every `!contains` below would pass on a child that inherited
    // nothing — including a child that never started.
    let opted_in_child = child_environment(&opted_in_env, "optedin");
    let opted_out_child = child_environment(&opted_out_env, "optedout");

    for (name, child) in [("optedin", &opted_in_child), ("optedout", &opted_out_child)] {
        assert_eq!(
            get(child, ALLOWLISTED_CONTROL).map(String::as_str),
            Some(ALLOWLISTED_CONTROL_VALUE),
            "the {name} child must have inherited the parent's `{ALLOWLISTED_CONTROL}` — without \
             this, the absences below prove nothing: {child:?}"
        );
        assert!(
            get(child, "PATH").is_some_and(|path| !path.trim().is_empty()),
            "`PATH` is what resolves `npx` and `uvx`; a child without it cannot run a real MCP \
             server at all: {child:?}"
        );
    }

    // -- the exposure this closes -------------------------------------------------------------
    for (name, child) in [("optedin", &opted_in_child), ("optedout", &opted_out_child)] {
        assert!(
            get(child, SECRET).is_none(),
            "a secret exported into the daemon's shell must not reach a child the operator did not \
             write: the {name} child holds `{SECRET}`"
        );
        assert!(
            get(child, ORDINARY).is_none(),
            "and the rule is the allowlist, not a guess at what looks like a secret — `{ORDINARY}` \
             is not credential-shaped and must not arrive either: the {name} child holds it"
        );
    }

    // -- the opt-in, which is per server ------------------------------------------------------
    assert_eq!(
        get(&opted_in_child, OPTED_IN).map(String::as_str),
        Some(OPTED_IN_VALUE),
        "the server that named `{OPTED_IN}` in `env_passthrough` must receive it"
    );
    assert!(
        get(&opted_out_child, OPTED_IN).is_none(),
        "and the server that did not must not — an opt-in that leaked to a sibling would be a \
         global one wearing a per-server spelling"
    );

    // -- `env:` is still the operator's own literal -------------------------------------------
    assert_eq!(
        get(&opted_in_child, FROM_CONFIG).map(String::as_str),
        Some(FROM_CONFIG_VALUE),
        "a value written in a server's config is written for that server and is not filtered"
    );

    // -- the complete statement ----------------------------------------------------------------
    //
    // Every variable the child holds, by name, must be accounted for. This is the assertion a
    // scrubber-shaped test cannot make: it fails on a *name* nobody thought to check.
    //
    // It is also what makes the two negatives above non-vacuous, in a way that needs no run against
    // broken code to be convincing: the *parent* holds names that are not on the allowlist — asserted
    // here, because otherwise "the child holds none" would be true of a parent that had none either —
    // and the child holds none. Those two facts together are the filter doing something.
    let parent_unlisted: Vec<String> = std::env::vars()
        .map(|(name, _)| name)
        .filter(|name| !on_allowlist(name))
        .collect();
    assert!(
        parent_unlisted.len() > 2,
        "the fixture must give the parent names the allowlist does not cover, or nothing below is \
         being filtered: {parent_unlisted:?}"
    );

    for (name, child, opted_in_names) in [
        ("optedin", &opted_in_child, vec![OPTED_IN]),
        ("optedout", &opted_out_child, vec![]),
    ] {
        let config_names: Vec<&str> = if name == "optedin" {
            vec![FROM_CONFIG]
        } else {
            vec![]
        };

        let unaccounted: Vec<&String> = child
            .keys()
            .filter(|key| {
                !on_allowlist(key)
                    && !opted_in_names.iter().any(|n| n.eq_ignore_ascii_case(key))
                    && !config_names.iter().any(|n| n.eq_ignore_ascii_case(key))
            })
            .collect();

        assert!(
            unaccounted.is_empty(),
            "the {name} child holds variables that are neither on the allowlist, nor opted in, nor \
             written in its config: {unaccounted:?}. The environment is an allowlist, so this list \
             must be empty — a name nobody checked is exactly the leak this test exists to catch"
        );
    }

    host.shutdown().await;
}
