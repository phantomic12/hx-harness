//! Shell execution.

use crate::tool::{parse_args, Requirement, Tool, ToolContext, ToolError, ToolOutcome};
use async_trait::async_trait;
use hx_core::approval::Confinement;
use hx_core::capability::{Action, Resource};
use hx_remote::host::ShellKind;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

/// The default deadline for one command. Long enough for a real build step, short enough that a
/// hung command does not hold the loop forever.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// The ceiling a model cannot raise: an agent that can ask for a 24-hour command will eventually
/// ask for one.
pub const MAX_TIMEOUT_SECS: u64 = 900;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    cmd: String,
    #[serde(default)]
    workdir: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// Run a command line on the host.
pub struct ShellTool;

impl ShellTool {
    pub fn new() -> Self {
        Self
    }

    /// Build the command line actually sent: `cd` first when a working directory was given.
    ///
    /// Quoted through the host's own shell quoting, so a path with a space (or a `;`) cannot become
    /// a second command. The transport quotes again for its own shell; doing it here is what makes
    /// the `cd` unambiguous.
    ///
    /// The run's workspace is the default directory, because the alternative is real and was once
    /// expensive: `git push` with no `workdir` runs wherever the *daemon* happens to be, which is not
    /// the checkout the model was asked about. A command that acts on the wrong repository is worse
    /// than one that fails.
    fn command_line<F: Fn(&str) -> String>(
        args: &Args,
        workspace: Option<&str>,
        shell: ShellKind,
        quote: F,
    ) -> String {
        let dir = match &args.workdir {
            Some(dir) if !dir.trim().is_empty() => Some(dir.clone()),
            _ => workspace
                .map(str::trim)
                .filter(|root| !root.is_empty())
                .map(str::to_string),
        };

        match dir {
            // The join is the shell's, not `&&`: PowerShell 5.1 rejects `&&`, so a line built that
            // way failed on Windows before the command ran — for every `workdir`-qualified call.
            Some(dir) => shell.chain(&format!("cd {}", quote(&dir)), &args.cmd),
            None => args.cmd.clone(),
        }
    }
}

impl Default for ShellTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn description(&self) -> &str {
        "Run a shell command on the host and return its output. Use `workdir` to run somewhere \
         other than the default directory, and `timeout_secs` (max 900) for long builds. A \
         non-zero exit code is returned as output, not as a failure of the call."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "cmd": { "type": "string", "description": "the command line to run" },
                "workdir": { "type": "string", "description": "directory to run it in" },
                "timeout_secs": {
                    "type": "integer",
                    "description": "deadline in seconds (default 120, max 900)"
                }
            },
            "required": ["cmd"]
        })
    }

    fn requirement(
        &self,
        args: &Value,
        _ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError> {
        let parsed: Args = parse_args(args)?;
        if parsed.cmd.trim().is_empty() {
            return Err(ToolError::Arguments("cmd is empty".to_string()));
        }
        // `Process` rather than a host-scoped read/execute: running a command line is the blunt
        // capability, and the approval engine's command classifier is what decides how dangerous
        // this particular line is. Naming a resource here would invite a tool that quietly avoids
        // the check by choosing a friendlier-looking one.
        Ok(Some(Requirement::new(
            Resource::Process,
            Action::Execute,
            parsed.cmd.clone(),
        )))
    }

    /// `shell` is the one tool that can run either way, so it answers from the context: a run was given
    /// a boundary or it was not, and the approval that has already happened was based on exactly this
    /// fact (`docs/approvals.md` §4).
    fn confinement(&self, _args: &Value, ctx: &ToolContext) -> Confinement {
        ctx.confinement()
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        let parsed: Args = parse_args(&args)?;
        let shell = ctx.host.caps().shell;

        let timeout = Duration::from_secs(
            parsed
                .timeout_secs
                .unwrap_or(DEFAULT_TIMEOUT_SECS)
                .clamp(1, MAX_TIMEOUT_SECS),
        );

        // Which of the two places this runs in is decided by the context, not here: the capability check
        // and the approval both already happened against `Tool::confinement`, and running on the host
        // anyway would make the answer to that question false after the fact. Only host execution
        // embeds a quoted `cd`; the sandbox receives its working directory as a separate argument.
        let (output, where_it_ran) = match &ctx.sandbox {
            Some(sandbox) => {
                // Pass the command without a host-side `cd`: the sandbox adapter translates the
                // separate workdir into its mount. An embedded host path does not exist inside it.
                let workdir = parsed
                    .workdir
                    .as_deref()
                    .filter(|dir| !dir.trim().is_empty())
                    .map(|dir| crate::resolve_path(dir, ctx.workspace.as_deref()));
                let workdir = workdir.as_deref().or(ctx.workspace.as_deref());
                let result =
                    match tokio::time::timeout(timeout, sandbox.exec(&parsed.cmd, workdir)).await {
                        Ok(output) => output,
                        Err(_) => Err(hx_core::error::HxError::Sandbox(
                            "command timed out; it may still be running inside the sandbox".into(),
                        )),
                    };
                let output = match result {
                    Ok(output) => output,
                    Err(err) => {
                        // A boundary that cannot be entered is the failure that matters most for an
                        // unattended run: do *not* fall back to the host, say so.
                        return Ok(ToolOutcome::failed(format!(
                            "could not run the command in {}: {err}. It was not run on the host instead.",
                            sandbox.describe()
                        )));
                    }
                };
                (output, Some(sandbox.describe()))
            }
            None => {
                let line = Self::command_line(&parsed, ctx.workspace.as_deref(), shell, |arg| {
                    shell.quote(arg)
                });
                let output = match ctx.host.exec(&line, timeout).await {
                    Ok(output) => output,
                    Err(err) => {
                        // A transport failure is a result the model should read: it can retry, or work
                        // around a host that has gone away, but only if it is told.
                        return Ok(ToolOutcome::failed(format!(
                            "could not run the command: {err}"
                        )));
                    }
                };
                (output, None)
            }
        };

        let mut report = String::new();
        if !output.stdout.is_empty() {
            report.push_str(&output.stdout);
        }
        if !output.stderr.is_empty() {
            if !report.is_empty() {
                report.push('\n');
            }
            report.push_str("stderr:\n");
            report.push_str(&output.stderr);
        }
        if report.is_empty() {
            report.push_str("(no output)");
        }
        match output.exit_code {
            Some(0) | None => {}
            Some(code) => {
                report.push_str(&format!("\n[exit {code}]"));
            }
        }

        // The model is told where its command ran, because the two answers differ in ways it can act on
        // — paths inside a sandbox are not the host's paths, and a file written there is not on the host.
        if let Some(boundary) = where_it_ran {
            report.push_str(&format!("\n[ran in {boundary}]"));
        }

        let ok = output.exit_code.unwrap_or(0) == 0;
        // `bound` keeps both ends and says how much it dropped. One bounding path, not two: an
        // earlier version also called `ExecOutput::bounded`, which produced a different shape,
        // dropped stderr's label, and never reported that it had truncated anything.
        let (content, truncated) = crate::tool::bound(report);

        // Shell output is unbounded by nature and never a file transfer: no byte count is stated,
        // so `max_bytes` does not apply to it. A shell that needs a byte bound is a different tool.
        Ok(ToolOutcome {
            content,
            ok,
            truncated,
            bytes_moved: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{BrokenHost, FakeHost, FakeSandbox};
    use crate::tool::MAX_TOOL_OUTPUT_CHARS;
    use hx_remote::host::shell_quote;
    use std::sync::Arc;

    fn ctx(host: Arc<dyn hx_remote::Host>) -> ToolContext {
        ToolContext::new(host)
    }

    // ---- where the command runs (`docs/approvals.md` §4) ---------------------

    #[tokio::test]
    async fn a_run_with_a_boundary_runs_the_command_inside_it() {
        // The point of the axis: the same string, sent elsewhere. A host that was not touched is the
        // assertion that matters — a fallback would be invisible in the output and would silently
        // unconfine every server whose container engine hiccuped.
        let host = Arc::new(FakeHost::unix());
        let sandbox = Arc::new(FakeSandbox::answering("ok from inside\n", 0));
        let ctx = ToolContext::new(host.clone())
            .in_workspace("/w")
            .with_sandbox(sandbox.clone());

        let outcome = ShellTool
            .call(json!({ "cmd": "cargo test" }), &ctx)
            .await
            .unwrap();

        assert!(outcome.ok, "{}", outcome.content);
        assert_eq!(sandbox.runs().len(), 1);
        assert_eq!(sandbox.runs()[0].0, "cargo test");
        assert_eq!(sandbox.runs()[0].1.as_deref(), Some("/w"));
        assert!(
            host.commands().is_empty(),
            "the host was not touched: {:?}",
            host.commands()
        );
        assert!(
            outcome.content.contains("ran in sandbox fake"),
            "the model is told where its command ran, because paths inside a box are not the host's: {}",
            outcome.content
        );
        assert_eq!(
            ShellTool.confinement(&json!({}), &ctx),
            Confinement::Sandbox
        );
    }

    #[tokio::test]
    async fn a_confined_workdir_is_resolved_separately_from_the_command() {
        // The adapter owns mount translation; shell must not bury a host path in shell source.
        let host = Arc::new(FakeHost::unix());
        let sandbox = Arc::new(FakeSandbox::answering("ok", 0));
        let ctx = ToolContext::new(host.clone())
            .in_workspace("/w")
            .with_sandbox(sandbox.clone());
        let output = ShellTool
            .call(json!({"cmd": "pwd", "workdir": "sub dir"}), &ctx)
            .await
            .unwrap();
        assert!(output.ok);
        assert_eq!(
            sandbox.runs(),
            vec![("pwd".into(), Some("/w/sub dir".into()))]
        );
        assert!(host.commands().is_empty());
    }

    #[tokio::test]
    async fn a_boundary_that_cannot_be_entered_does_not_quietly_become_the_host() {
        // The failure that would matter most: an unattended run whose sandbox is gone, deciding that the
        // host will do. It is reported as a failed call, and the host sees nothing.
        let host = Arc::new(FakeHost::unix());
        let sandbox = Arc::new(FakeSandbox::unavailable("engine is not running"));
        let ctx = ToolContext::new(host.clone())
            .in_workspace("/w")
            .with_sandbox(sandbox);

        let outcome = ShellTool
            .call(json!({ "cmd": "cargo test" }), &ctx)
            .await
            .unwrap();

        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("engine is not running"),
            "{}",
            outcome.content
        );
        assert!(
            outcome.content.contains("not run on the host instead"),
            "and says what it did not do: {}",
            outcome.content
        );
        assert!(host.commands().is_empty(), "{:?}", host.commands());
    }

    #[tokio::test]
    async fn without_a_boundary_the_command_runs_on_the_host_and_says_so() {
        // The other half, and the reason the default is the host rather than the context: a tool that has
        // not been given a boundary must not report one.
        let host = Arc::new(FakeHost::unix());
        let ctx = ctx(host.clone()).in_workspace("/w");

        assert_eq!(ShellTool.confinement(&json!({}), &ctx), Confinement::Host);

        let outcome = ShellTool
            .call(json!({ "cmd": "cargo test" }), &ctx)
            .await
            .unwrap();
        assert_eq!(host.commands(), vec!["cd '/w' && cargo test"]);
        assert!(
            !outcome.content.contains("ran in"),
            "no boundary, no claim about one: {}",
            outcome.content
        );
    }

    #[test]
    fn the_schema_requires_a_command() {
        let schema = ShellTool.schema();
        assert_eq!(schema["required"][0], "cmd");
        assert!(schema["properties"]["timeout_secs"].is_object());
    }

    #[test]
    fn an_empty_command_is_refused_before_anything_runs() {
        let err = ShellTool
            .requirement(&json!({"cmd": "   "}), &ctx(Arc::new(FakeHost::unix())))
            .unwrap_err();
        assert!(err.to_string().contains("cmd is empty"), "{err}");
    }

    #[test]
    fn the_requirement_is_a_process_execution_carrying_the_command() {
        // The command line is what the risk classifier sees, so it must travel with the request.
        let requirement = ShellTool
            .requirement(
                &json!({"cmd": "rm -rf /"}),
                &ctx(Arc::new(FakeHost::unix())),
            )
            .unwrap()
            .expect("running a command has an external effect");
        assert_eq!(requirement.action, Action::Execute);
        assert_eq!(requirement.command(), Some("rm -rf /"));
    }

    #[test]
    fn the_workspace_is_the_default_directory_for_a_command() {
        // No `workdir` in the arguments, so the run's workspace decides. Without this the command
        // runs wherever the daemon happens to be — which is how a test `git push` reached the real
        // repository instead of a temporary directory.
        let args = Args {
            cmd: "git status".to_string(),
            workdir: None,
            timeout_secs: None,
        };
        let line = ShellTool::command_line(&args, Some("/ws"), ShellKind::Posix, shell_quote);
        // `shell_quote` quotes unconditionally, so the expected line carries the quotes too.
        assert_eq!(line, "cd '/ws' && git status");
    }

    #[test]
    fn an_explicit_workdir_beats_the_workspace() {
        let args = Args {
            cmd: "ls".to_string(),
            workdir: Some("/elsewhere".to_string()),
            timeout_secs: None,
        };
        let line = ShellTool::command_line(&args, Some("/ws"), ShellKind::Posix, shell_quote);
        assert_eq!(line, "cd '/elsewhere' && ls");
    }

    #[test]
    fn a_workdir_is_prepended_and_quoted() {
        let args = Args {
            cmd: "ls -la".to_string(),
            workdir: Some("/tmp/it's here".to_string()),
            timeout_secs: None,
        };
        let line = ShellTool::command_line(&args, None, ShellKind::Posix, shell_quote);
        assert!(line.starts_with("cd '/tmp/it'\\''s here' && "), "{line}");
        assert!(line.ends_with("ls -la"));
    }

    #[test]
    fn an_absolute_command_does_not_get_a_cd() {
        let args = Args {
            cmd: "pwd".to_string(),
            workdir: None,
            timeout_secs: None,
        };
        assert_eq!(
            ShellTool::command_line(&args, None, ShellKind::Posix, shell_quote),
            "pwd"
        );
    }

    #[test]
    fn a_workdir_under_powershell_does_not_use_an_ampersand() {
        // Regression test. `&&` is not a statement separator in Windows PowerShell 5.1, which is what
        // `powershell` resolves to on a stock Windows host. A `cd <dir> && <cmd>` line therefore died
        // with `The token '&&' is not a valid statement separator in this version` before the command
        // ran — every `workdir`-qualified call on Windows, which is what the `api` tests caught.
        let args = Args {
            cmd: "git push".to_string(),
            workdir: Some(r"C:\work".to_string()),
            timeout_secs: None,
        };
        let line = ShellTool::command_line(&args, Some(r"C:\ws"), ShellKind::PowerShell, |arg| {
            ShellKind::PowerShell.quote(arg)
        });

        assert!(
            !line.contains("&&"),
            "PowerShell 5.1 rejects `&&`, so the line must not contain one: {line}"
        );
        // It still has to gate the second statement on the first, or a failed `cd` would run the
        // command in whatever directory the daemon happens to be in.
        assert!(
            line.contains("if ($?") || line.contains("if ("),
            "the command must still run only when the `cd` succeeded: {line}"
        );
        assert!(
            line.contains("git push"),
            "the command must survive: {line}"
        );
    }

    #[test]
    fn a_workdir_under_cmd_still_uses_an_ampersand() {
        // `cmd.exe` does support `&&`, so this must not be changed for the sake of the PowerShell
        // case: the fix is per-shell, not a global switch away from `&&`.
        let args = Args {
            cmd: "dir".to_string(),
            workdir: Some(r"C:\work".to_string()),
            timeout_secs: None,
        };
        let line =
            ShellTool::command_line(&args, None, ShellKind::Cmd, |arg| ShellKind::Cmd.quote(arg));
        assert!(line.contains("&&"), "cmd.exe supports `&&`: {line}");
    }

    #[tokio::test]
    async fn output_and_exit_code_come_back_together() {
        let host = Arc::new(FakeHost::unix().with_exec_output("hello\n", "a warning\n", Some(0)));
        let outcome = ShellTool
            .call(json!({"cmd": "echo hello"}), &ctx(host.clone()))
            .await
            .unwrap();

        assert!(outcome.ok);
        assert!(outcome.content.contains("hello"));
        assert!(outcome.content.contains("stderr:"));
        assert!(outcome.content.contains("a warning"));
        assert_eq!(host.commands(), vec!["echo hello".to_string()]);
    }

    #[tokio::test]
    async fn a_failing_command_is_a_result_not_an_error() {
        // The distinction matters: the model has to see `exit 2` and decide what to do.
        let host = Arc::new(FakeHost::unix().with_exec_output("", "boom", Some(2)));
        let outcome = ShellTool
            .call(json!({"cmd": "false"}), &ctx(host))
            .await
            .unwrap();

        assert!(!outcome.ok);
        assert!(outcome.content.contains("[exit 2]"), "{}", outcome.content);
        assert!(outcome.content.contains("boom"));
    }

    #[tokio::test]
    async fn silence_says_it_was_silent() {
        let host = Arc::new(FakeHost::unix().with_exec_output("", "", Some(0)));
        let outcome = ShellTool
            .call(json!({"cmd": "true"}), &ctx(host))
            .await
            .unwrap();
        assert_eq!(outcome.content, "(no output)");
    }

    #[tokio::test]
    async fn a_host_that_cannot_be_reached_is_reported_as_such() {
        let outcome = ShellTool
            .call(json!({"cmd": "ls"}), &ctx(Arc::new(BrokenHost::new())))
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("could not run"),
            "{}",
            outcome.content
        );
    }

    #[tokio::test]
    async fn a_huge_output_is_truncated_in_the_middle() {
        let body = "x".repeat(200_000);
        let host = Arc::new(FakeHost::unix().with_exec_output(&body, "", Some(0)));
        let outcome = ShellTool
            .call(json!({"cmd": "cat big.log"}), &ctx(host))
            .await
            .unwrap();

        assert!(outcome.truncated);
        assert!(
            outcome.content.chars().count() <= MAX_TOOL_OUTPUT_CHARS + 80,
            "{}",
            outcome.content.chars().count()
        );
        assert!(outcome.content.contains("characters omitted"));
    }

    #[tokio::test]
    async fn the_timeout_is_clamped_to_the_ceiling() {
        // A model that asks for a day gets the maximum, not a day.
        let host = Arc::new(FakeHost::unix());
        let outcome = ShellTool
            .call(
                json!({"cmd": "sleep 1", "timeout_secs": 999_999}),
                &ctx(host),
            )
            .await
            .unwrap();
        assert!(outcome.ok);

        let args: Args =
            serde_json::from_value(json!({"cmd": "x", "timeout_secs": 999_999})).unwrap();
        let requested = args.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        assert_eq!(requested.clamp(1, MAX_TIMEOUT_SECS), MAX_TIMEOUT_SECS);
    }

    #[tokio::test]
    async fn a_misnamed_argument_is_refused_rather_than_ignored() {
        // The dangerous shape of this bug: `cwd` instead of `workdir`. Without `deny_unknown_fields`
        // serde drops the unknown key, the command runs *somewhere else* — and a shell command that
        // silently executes in the wrong directory is worse than one that fails. (It pushed a real
        // branch once.)
        let err = ShellTool
            .requirement(
                &serde_json::json!({ "cmd": "pwd", "cwd": "/tmp" }),
                &ctx(Arc::new(FakeHost::unix())),
            )
            .expect_err("a misnamed argument must not be ignored");

        let message = format!("{err}");
        assert!(
            message.contains("cwd") || message.contains("unknown field"),
            "the error must name the offending key: {message}"
        );
    }

    #[tokio::test]
    async fn a_missing_command_argument_is_an_argument_error() {
        let err = ShellTool
            .call(json!({"command": "ls"}), &ctx(Arc::new(FakeHost::unix())))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Arguments(_)), "{err}");
    }
}
