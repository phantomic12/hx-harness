//! What a stealth browser child process actually inherits — asked of a real process, not a filter function.
//!
//! ## Why this is its own test binary
//!
//! The property is about the *parent's* environment, so the test has to put a sentinel variable in it,
//! and `std::env::set_var` is not thread-safe when called concurrently with other threads reading
//! the environment. Cargo runs each integration-test file as its own separate process, so a file
//! that mutates its own environment and has one test in it cannot race another test.
//!
//! ## What is asserted
//!
//! A real `StealthRung` is configured with `/usr/bin/env` as its command and dispatched through
//! `Fetcher::fetch`. `/usr/bin/env` ignores the four-line stdin protocol payload, dumps its own
//! process environment to stdout, and exits 0 (which the rung reads as `EXIT_BODY`).
//!
//! The assertions:
//! - **Sentinel absence**: `HX_ENV_SENTINEL_STEALTH_TEST` is set in the parent and asserted ABSENT
//!   from the child's output. The name is non-key-shaped so secret redaction cannot hide it.
//! - **Ordinary variable absence**: `HX_BROWSER_ORDINARY_VAR` is set in the parent and asserted
//!   ABSENT from the child's output, proving the rule is an allowlist and not a heuristic secret-recognizer.
//! - **Positive control**: `PATH` is asserted PRESENT and non-empty in the child's output. Without this,
//!   a child that inherited nothing at all (or failed to start) would trivially pass the absence checks.
//! - **Controlled allowlist variable**: `LOGNAME` is set in the parent to a test-controlled value and
//!   asserted present with that exact value in the child's output.
//! - **Allowlist completeness**: Every variable present in the child's output is checked against the
//!   specification allowlist. Any unaccounted-for variable fails the test.
//! - **Parent non-vacuity**: Before spawning, the parent environment is verified to contain variables
//!   NOT on the allowlist, proving the filter actually excluded entries.

#![cfg(unix)]

use hx_browser::profile::PoolRoot;
use hx_browser::rung::{FetchRequest, Fetcher};
use hx_browser::rungs::StealthRung;
use hx_browser::target::{Admission, TargetUrl};
use hx_core::ids::SessionId;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// The sentinel variable set on the parent.
/// Non-key-shaped so secret redaction in logging/display cannot hide or mutate it.
const SENTINEL: &str = "HX_ENV_SENTINEL_STEALTH_TEST";
const SENTINEL_VALUE: &str = "sentinel-value-asserted-absent-from-child";

/// An ordinary unlisted variable set on the parent.
/// Proves the filter is an allowlist, not a secret scanner.
const ORDINARY: &str = "HX_BROWSER_ORDINARY_VAR";
const ORDINARY_VALUE: &str = "ordinary-non-credential-value";

/// Allowed control variable. On the allowlist, with a value controlled by the test.
const ALLOWLISTED_CONTROL: &str = "LOGNAME";
const ALLOWLISTED_CONTROL_VALUE: &str = "hx-stealth-env-control";

/// The allowlist specification on Unix.
/// Defined in the test rather than imported from the crate so the test cannot agree with itself.
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
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
];

fn on_allowlist(name: &str) -> bool {
    ALLOWLIST.contains(&name)
}

fn parse_env_output(stdout: &str) -> BTreeMap<String, String> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| match line.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => panic!("unexpected line without '=' in /usr/bin/env output: {line:?}"),
        })
        .collect()
}

#[tokio::test]
async fn a_stealth_browser_child_inherits_only_the_allowlist_and_never_the_daemon_environment() {
    let env_bin = Path::new("/usr/bin/env");
    if !env_bin.exists() {
        return;
    }

    // Mutate parent environment before spawning.
    std::env::set_var(SENTINEL, SENTINEL_VALUE);
    std::env::set_var(ORDINARY, ORDINARY_VALUE);
    std::env::set_var(ALLOWLISTED_CONTROL, ALLOWLISTED_CONTROL_VALUE);

    // Verify parent has them, and has unlisted variables so the test is non-vacuous.
    assert_eq!(
        std::env::var(SENTINEL).ok().as_deref(),
        Some(SENTINEL_VALUE)
    );
    assert_eq!(
        std::env::var(ORDINARY).ok().as_deref(),
        Some(ORDINARY_VALUE)
    );
    assert_eq!(
        std::env::var(ALLOWLISTED_CONTROL).ok().as_deref(),
        Some(ALLOWLISTED_CONTROL_VALUE)
    );

    let parent_unlisted: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|name| !on_allowlist(name))
        .collect();
    assert!(
        parent_unlisted.len() >= 2,
        "the parent environment must contain unlisted variables to prove filtering is active: {parent_unlisted:?}"
    );

    let temp = tempfile::tempdir().expect("a temp directory");
    let root = PoolRoot::new(temp.path().join("pool")).expect("a pool root");
    let session = root
        .session(&SessionId::from_raw("stealth-env-test"))
        .expect("a session profile");

    let rung = StealthRung::new(env_bin);
    let request = FetchRequest {
        target: TargetUrl::parse_with(Admission::AllowLocal, "https://example.test/page?q=1")
            .expect("an admitted target"),
        profile: Arc::new(session),
        timeout: Duration::from_secs(5),
    };

    let page = rung
        .fetch(&request)
        .await
        .expect("env exited 0 so rung must return UntrustedPage");

    let child_env = parse_env_output(page.body_untrusted());

    // Clean up parent environment regardless of assertions below.
    std::env::remove_var(SENTINEL);
    std::env::remove_var(ORDINARY);
    std::env::remove_var(ALLOWLISTED_CONTROL);

    // 1. Positive controls: PATH and LOGNAME must be present.
    // Without positive controls, an empty environment would trivially pass absence checks.
    assert!(
        child_env.get("PATH").is_some_and(|p| !p.trim().is_empty()),
        "`PATH` must be present and non-empty in child environment: {child_env:?}"
    );
    assert_eq!(
        child_env.get(ALLOWLISTED_CONTROL).map(String::as_str),
        Some(ALLOWLISTED_CONTROL_VALUE),
        "the child must inherit the controlled allowlisted variable `{ALLOWLISTED_CONTROL}`: {child_env:?}"
    );

    // 2. Absence checks: the sentinel and unlisted variables must NOT be present.
    assert!(
        !child_env.contains_key(SENTINEL),
        "sentinel `{SENTINEL}` must be absent from child environment: child holds {child_env:?}"
    );
    assert!(
        !child_env.contains_key(ORDINARY),
        "ordinary unlisted variable `{ORDINARY}` must be absent from child: child holds {child_env:?}"
    );

    // 3. Completeness check: EVERY variable in the child must be on the specification allowlist.
    let unaccounted: Vec<&String> = child_env.keys().filter(|key| !on_allowlist(key)).collect();
    assert!(
        unaccounted.is_empty(),
        "the stealth child holds variables not on the allowlist: {unaccounted:?}. \
         The child environment is an allowlist, fail-closed."
    );
}
