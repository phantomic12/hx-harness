//! The second rung: a real browser, launched as a subprocess, spoken to over a pipe.
//!
//! ## Why a subprocess
//!
//! A stealth browser is a large, single-purpose binary with its own process model, its own sandbox and
//! its own release cadence. Linking one into this crate would put that cadence inside the daemon's
//! dependency graph, and a browser crash would be a daemon crash. So this rung launches a configured
//! tool and speaks to it over a pipe: the tool owns the browser, this crate owns the policy.
//!
//! ## The protocol
//!
//! **stdin** — four lines, always, in this order:
//!
//! ```text
//! 1. the URL to fetch
//! 2. the session's profile directory, for the tool's own user-data directory
//! 3. the `Cookie:` header value from that profile, or an empty line
//! 4. the budget in seconds
//! ```
//!
//! **exit code** — the verdict:
//!
//! ```text
//! 0   the body is on stdout
//! 3   a wall: the tool saw a challenge or a refusal
//! any other non-zero   a transport failure
//! killed by a signal   a transport failure
//! ```
//!
//! **stdout** — the body, on exit 0, and nothing else. **stderr** — the tool's own diagnostics; this
//! rung does not read them (see below).
//!
//! ## The URL goes on stdin, never in argv
//!
//! A process's arguments are readable by every other process on the machine through
//! `/proc/<pid>/cmdline`, and a URL can carry a token in its query string. The session's cookies are a
//! credential too. Both travel on stdin, which is private to the pair, and the arguments this rung
//! passes are exactly the ones the operator configured.
//!
//! ## What this rung deliberately does not do
//!
//! - **It does not inherit the daemon's environment.** Inheriting the parent environment is the
//!   convenient default and what this rung initially did, but a third-party browser process
//!   would then inherit every secret and API key exported in the daemon's shell. Instead,
//!   `Command::env_clear()` is called and only an explicit allowlist is passed back.
//! - **It does not quote the tool's stderr into an error.** The stderr of a third-party process is
//!   unbounded, is written by something this crate does not control, and can contain the URL it was
//!   handed — and therefore a token. The exit code is the protocol's report; a reason that quoted the
//!   tool's own output would be the leak this crate spends most of its comments preventing.
//! - **It does not report an HTTP status or a real content type.** The protocol carries neither. See
//!   [`BODY_STATUS`] and [`BODY_CONTENT_TYPE`]; extending the protocol to carry headers would make
//!   stdout a second, weaker wire format to keep in step with the exit codes.
//! - **It does not detect a missing browser.** Whether the configured tool is installed is the tool's
//!   business; a command that cannot be spawned is [`FetchError::Unavailable`], which escalates, so a
//!   deployment without a stealth browser degrades to the interactive rung rather than failing.

use crate::error::{FetchError, RefusalReason};
use crate::rung::{FetchRequest, Fetcher, RungKind, UntrustedPage};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

/// The exit code that means "the body is on stdout".
pub const EXIT_BODY: i32 = 0;

/// The exit code that means "the tool saw a wall".
///
/// Three, not one: one is the conventional generic failure, and a tool that fails to start must not be
/// mistaken for a tool that saw a challenge — the first is a transport failure that stops the ladder,
/// the second escalates.
pub const EXIT_WALL: i32 = 3;

/// The status reported for a body the tool handed back.
///
/// The exit-code protocol carries no HTTP status: the tool read the page, and what it saw is the body.
/// 200 is the conventional answer for "a page came back". **A caller must not read this field as the
/// site's own status on this rung** — [`crate::rungs::http::HttpRung`] is where a real status lives.
pub const BODY_STATUS: u16 = 200;

/// The content type reported for a body the tool handed back.
///
/// The protocol has no header channel, so this is this rung's own label for "text the tool retrieved"
/// rather than the site's claim — unlike [`UntrustedPage::content_type`], which on the HTTP rung is the
/// site's word. A tool that wants a different label needs the protocol extended, which is deliberately
/// not done.
pub const BODY_CONTENT_TYPE: &str = "text/html";

/// A browser this crate launches and speaks to over a pipe.
#[derive(Clone)]
pub struct StealthRung {
    command: PathBuf,
    args: Vec<String>,
    name: String,
}

impl StealthRung {
    /// The rung, launching `command` with no arguments.
    pub fn new(command: impl Into<PathBuf>) -> Self {
        let command = command.into();
        let name = Self::name_for(&command);
        Self {
            command,
            args: Vec::new(),
            name,
        }
    }

    /// The rung with the operator's arguments.
    ///
    /// **Replaces** any arguments already set rather than appending to them. A builder that silently
    /// accumulated would make the configured set depend on call order — `with_args(["-c", script])`
    /// followed by `with_args(["--flag"])` would leave a tool with arguments nobody wrote together.
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// The configured command.
    pub fn command(&self) -> &Path {
        &self.command
    }

    /// The rung's name, `stealth-<tool>`.
    ///
    /// The tool's *file stem* rather than the configured path: `name()` reaches a model, and a path is
    /// both a disclosure and noise. A command whose file stem cannot be read is named plain `stealth`.
    fn name_for(command: &Path) -> String {
        match command.file_stem().and_then(|stem| stem.to_str()) {
            Some(stem) if !stem.is_empty() => format!("stealth-{stem}"),
            _ => "stealth".to_string(),
        }
    }

    /// The four lines the tool reads, in the order the module documents.
    fn stdin_payload(&self, request: &FetchRequest) -> String {
        let cookies = request.profile.read_cookies().unwrap_or_default();
        format!(
            "{}\n{}\n{}\n{}\n",
            request.target.request_url(),
            request.profile.dir().display(),
            cookies,
            request.timeout.as_secs(),
        )
    }
}

impl std::fmt::Debug for StealthRung {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The arguments are deliberately absent: they are the operator's, and an operator is entitled
        // to put a token in them. A derived `Debug` would put it in whatever log line or panic message
        // happened to format this rung.
        f.debug_struct("StealthRung")
            .field("name", &self.name)
            .field("arg_count", &self.args.len())
            .finish()
    }
}

/// The variables a stealth browser child inherits from the daemon's environment, on every platform.
///
/// This is a mirror of `hx-mcp`'s allowlist discipline (`crates/hx-mcp/src/stdio.rs`). It is mirrored
/// here rather than shared because `hx-browser` does not depend on `hx-mcp` (they are sibling crates
/// with disjoint concerns), and factoring a shared allowlist into `hx-core` would widen that crate's
/// scope for a two-site pattern. In addition to the base process environment (`PATH`, `HOME`, `USER`,
/// `LOGNAME`, `SHELL`, `TMPDIR`, `LANG`, `LC_ALL`, `TERM`), a browser on Linux may need display and session
/// sockets (`DISPLAY`, `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`).
///
/// What is deliberately absent is anything credential-shaped: `OPENAI_API_KEY`, cloud keys, tokens,
/// and daemon settings. An allowlist fail-closed approach means unlisted names cannot leak.
const INHERITED_ALWAYS: &[&str] = &[
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

/// The extra variables a Windows child needs to start at all.
///
/// Mirrored from `crates/hx-mcp/src/stdio.rs`. `SYSTEMROOT` is needed for loading DLLs, `TEMP`/`TMP`
/// for staging, and `PATHEXT`/`COMSPEC` for executable resolution.
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

/// The counterpart on every other platform so the check is a single expression without `cfg` at each site.
#[cfg(not(windows))]
const INHERITED_WINDOWS: &[&str] = &[];

/// Is this variable inherited on the allowlist?
///
/// Case-insensitive on Windows and exact on Unix, matching platform environment semantics.
fn is_inherited(name: &str) -> bool {
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
}

/// The environment passed to the child process: the daemon's own environment filtered to the allowlist.
///
/// Paired with `Command::env_clear()`, this ensures fail-closed environment inheritance.
fn child_environment() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(name, _)| is_inherited(name))
        .collect()
}

#[async_trait]
impl Fetcher for StealthRung {
    fn kind(&self) -> RungKind {
        RungKind::Stealth
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn fetch(&self, request: &FetchRequest) -> Result<UntrustedPage, FetchError> {
        let rung = RungKind::Stealth;

        let mut child = tokio::process::Command::new(&self.command)
            .args(&self.args)
            .env_clear()
            .envs(child_environment())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // A tool that outlives this rung is a browser nobody is watching. The request timeout is
            // the bound; this is the backstop for a future dropped for any other reason.
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| FetchError::Unavailable {
                rung,
                reason: match err.kind() {
                    std::io::ErrorKind::NotFound => format!("{} is not installed", self.name),
                    _ => format!("{} could not be started: {err}", self.name),
                },
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            // A tool that answers without reading its input closes the pipe under this write, so an
            // EPIPE here is a legitimate thing for a tool to do rather than this rung's failure — the
            // exit status is the report. The error is dropped deliberately, and the payload is never
            // echoed: it holds the URL and the session's cookies.
            let _ = stdin
                .write_all(self.stdin_payload(request).as_bytes())
                .await;
            let _ = stdin.shutdown().await;
        }

        let output = match tokio::time::timeout(request.timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(err)) => {
                return Err(FetchError::Transport {
                    rung,
                    reason: format!("{} could not be waited on: {err}", self.name),
                })
            }
            // The future is dropped here, which drops the child, which `kill_on_drop` turns into a
            // kill: a tool that ignored its own deadline does not get to outlive the attempt.
            Err(_) => {
                return Err(FetchError::Transport {
                    rung,
                    reason: format!(
                        "{} did not answer within {}s",
                        self.name,
                        request.timeout.as_secs()
                    ),
                })
            }
        };

        match output.status.code() {
            Some(EXIT_BODY) => {}
            Some(EXIT_WALL) => {
                return Err(FetchError::Refused {
                    rung,
                    reason: RefusalReason::Challenge {
                        // The tool reports a wall by exit code and never by status, so the marker says
                        // who is reporting rather than inventing an HTTP status nobody observed.
                        marker: format!("{} reported a wall", self.name),
                    },
                });
            }
            Some(code) => {
                return Err(FetchError::Transport {
                    rung,
                    reason: format!(
                        "{} exited {code}, which is neither a body nor a wall",
                        self.name
                    ),
                })
            }
            None => {
                return Err(FetchError::Transport {
                    rung,
                    reason: format!("{} was killed by a signal before it answered", self.name),
                })
            }
        }

        Ok(UntrustedPage::new(
            request.target.clone(),
            BODY_STATUS,
            BODY_CONTENT_TYPE,
            rung,
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{PoolRoot, SessionProfile};
    use crate::target::{Admission, TargetUrl};
    use hx_core::ids::SessionId;
    use std::sync::Arc;
    use std::time::Duration;

    fn profile() -> (tempfile::TempDir, Arc<SessionProfile>) {
        let temp = tempfile::tempdir().expect("a temp directory");
        let root = PoolRoot::new(temp.path().join("pool")).expect("a pool root");
        let session = root
            .session(&SessionId::from_raw("stealth-test"))
            .expect("a session profile");
        (temp, Arc::new(session))
    }

    fn request(profile: Arc<SessionProfile>, timeout: Duration) -> FetchRequest {
        FetchRequest {
            target: TargetUrl::parse_with(Admission::AllowLocal, "https://example.test/page?q=1")
                .expect("an admitted target"),
            profile,
            timeout,
        }
    }

    fn shell(script: &str) -> StealthRung {
        StealthRung::new("/bin/sh").with_args(["-c", script])
    }

    #[test]
    fn the_rung_is_named_after_the_tool_and_not_after_its_path() {
        // `name()` reaches a model: a path is a disclosure and noise.
        let rung = StealthRung::new("/opt/very/secret/place/camoufox");
        assert_eq!(rung.name(), "stealth-camoufox");
        assert!(!rung.name().contains('/'), "{}", rung.name());

        // A command with no usable file stem still names itself, rather than being empty.
        assert_eq!(StealthRung::new("/").name(), "stealth");
    }

    #[test]
    fn the_arguments_are_absent_from_debug_because_an_operator_may_put_a_token_in_them() {
        // One call: `with_args` replaces, so two calls would leave only the second set — which is
        // exactly the footgun its doc comment names.
        let rung = StealthRung::new("/bin/sh").with_args([
            "-c",
            "true",
            "--api-key",
            "SENTINEL-TOKEN-VALUE",
        ]);
        let rendered = format!("{rung:?}");

        assert!(!rendered.contains("SENTINEL-TOKEN-VALUE"), "{rendered}");
        assert!(rendered.contains("arg_count"), "{rendered}");
        // The count is there so a mismatch is still debuggable.
        assert!(rendered.contains("4"), "{rendered}");
    }

    #[test]
    fn the_payload_is_four_lines_in_the_documented_order() {
        let (_temp, profile) = profile();
        profile
            .write_cookies("cf_clearance=SENTINEL-COOKIE")
            .expect("the jar is writable");

        let rung = shell("true");
        let payload = rung.stdin_payload(&request(profile.clone(), Duration::from_secs(7)));
        let lines: Vec<&str> = payload.lines().collect();

        assert_eq!(lines.len(), 4, "{payload:?}");
        assert_eq!(lines[0], "https://example.test/page?q=1");
        assert_eq!(lines[1], profile.dir().display().to_string());
        assert_eq!(lines[2], "cf_clearance=SENTINEL-COOKIE");
        assert_eq!(lines[3], "7");
    }

    #[tokio::test]
    async fn a_tool_that_is_not_installed_reports_unavailable_so_the_climb_continues() {
        // A deployment without a stealth browser must degrade to the next rung, not fail the fetch.
        let (_temp, profile) = profile();
        let rung = StealthRung::new("/nonexistent/hx-stealth-tool-that-is-not-installed");

        let err = rung
            .fetch(&request(profile, Duration::from_secs(5)))
            .await
            .expect_err("a missing tool is not a page");

        assert!(matches!(err, FetchError::Unavailable { .. }), "{err:?}");
        assert_eq!(err.rung(), Some(RungKind::Stealth));
        assert!(err.is_refusal(), "an unavailable rung escalates: {err}");
        // The reason names the rung, not the path it was configured with.
        assert!(!format!("{err}").contains("/nonexistent"), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_tool_that_exits_zero_hands_back_its_stdout_as_the_page() {
        // The tool does not read its input here, which also exercises the EPIPE path: a tool that
        // answers without draining stdin is legitimate, and the exit status is the report.
        let (_temp, profile) = profile();
        let rung = shell("printf '<h1>the page the tool retrieved</h1>'");

        let page = rung
            .fetch(&request(profile, Duration::from_secs(5)))
            .await
            .expect("a page");

        assert_eq!(page.rung, RungKind::Stealth);
        assert_eq!(page.status, BODY_STATUS);
        assert!(page
            .body_untrusted()
            .contains("the page the tool retrieved"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_url_and_the_sessions_cookies_travel_on_stdin_and_never_in_the_arguments() {
        // A process's argv is readable by every other process on the machine via /proc, and both the
        // URL and the cookie jar are things that must not be there. This asserts the payload arrived
        // AND that argv stayed empty.
        let (_temp, profile) = profile();
        profile
            .write_cookies("cf_clearance=SENTINEL-COOKIE-VALUE")
            .expect("the jar is writable");

        let rung = shell(
            "read -r url; read -r dir; read -r cookie; read -r budget; \
             printf 'url=%s|dir=%s|cookie=%s|budget=%s|argv=[%s]' \"$url\" \"$dir\" \"$cookie\" \"$budget\" \"$*\"",
        );

        let page = rung
            .fetch(&request(profile.clone(), Duration::from_secs(9)))
            .await
            .expect("a page");
        let body = page.body_untrusted();

        assert!(body.contains("url=https://example.test/page?q=1"), "{body}");
        assert!(
            body.contains(&format!("dir={}", profile.dir().display())),
            "{body}"
        );
        assert!(
            body.contains("cookie=cf_clearance=SENTINEL-COOKIE-VALUE"),
            "{body}"
        );
        assert!(body.contains("budget=9"), "{body}");
        assert!(body.contains("argv=[]"), "the URL reached argv: {body}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_tool_that_reports_a_wall_escalates_rather_than_reporting_a_page() {
        // Exit 3 is the one failure that escalates: the tool saw a challenge, so a different
        // fingerprint — a person — is what it is asking for.
        let (_temp, profile) = profile();
        let rung = shell("cat > /dev/null; exit 3");

        let err = rung
            .fetch(&request(profile, Duration::from_secs(5)))
            .await
            .expect_err("a wall is not a page");

        assert!(matches!(err, FetchError::Refused { .. }), "{err:?}");
        assert!(err.is_refusal(), "a wall escalates: {err}");
        assert_eq!(err.rung(), Some(RungKind::Stealth));
        // The marker says who reported the wall rather than inventing a status nobody observed.
        assert!(format!("{err}").contains("reported a wall"), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn any_other_exit_code_is_a_transport_failure_and_the_ladder_stops() {
        // Escalating on a broken tool would spend a person on a machine fault.
        let (_temp, profile) = profile();
        let rung = shell("exit 7");

        let err = rung
            .fetch(&request(profile, Duration::from_secs(5)))
            .await
            .expect_err("a broken tool is not a page");

        assert!(matches!(err, FetchError::Transport { .. }), "{err:?}");
        assert!(!err.is_refusal(), "a transport failure stops: {err}");
        assert!(format!("{err}").contains("exited 7"), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_tool_that_ignores_its_deadline_is_bounded_by_the_request_timeout() {
        // A tool that never finishes must not hold the attempt open. The outer timeout is *longer*
        // than the rung's, so a rung that ignored its budget fails this test rather than hanging it.
        let (_temp, profile) = profile();
        let rung = shell("sleep 30");

        let bounded = tokio::time::timeout(
            Duration::from_secs(20),
            rung.fetch(&request(profile, Duration::from_millis(300))),
        )
        .await
        .expect("the rung must return on its own budget, not the outer one")
        .expect_err("a tool that never answers is not a page");

        assert!(
            matches!(bounded, FetchError::Transport { .. }),
            "{bounded:?}"
        );
        assert!(!bounded.is_refusal(), "{bounded}");
        assert!(format!("{bounded}").contains("did not answer"), "{bounded}");
    }

    #[test]
    fn the_allowlist_covers_what_a_browser_needs_and_nothing_credential_shaped() {
        for name in [
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
        ] {
            assert!(is_inherited(name), "{name} must be inherited");
        }

        for name in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "GH_TOKEN",
            "MY_COMPANY_DEPLOY_KEY",
            "HX_API_TOKEN",
        ] {
            assert!(
                !is_inherited(name),
                "{name} must not be inherited by default"
            );
        }

        #[cfg(not(windows))]
        {
            assert!(!is_inherited("path"), "Unix names are case-sensitive");
        }
        assert!(!is_inherited("PATHEXTRA"));
    }
}
