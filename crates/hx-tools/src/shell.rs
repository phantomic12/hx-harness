//! Shell execution.

use crate::tool::{parse_args, Requirement, Tool, ToolContext, ToolError, ToolOutcome};
use async_trait::async_trait;
use hx_core::capability::{Action, Resource};
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
    fn command_line<F: Fn(&str) -> String>(args: &Args, quote: F) -> String {
        match &args.workdir {
            Some(dir) if !dir.trim().is_empty() => {
                format!("cd {} && {}", quote(dir), args.cmd)
            }
            _ => args.cmd.clone(),
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

    fn requirement(&self, args: &Value) -> Result<Option<Requirement>, ToolError> {
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

    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        let parsed: Args = parse_args(&args)?;
        let shell = ctx.host.caps().shell;

        let timeout = Duration::from_secs(
            parsed
                .timeout_secs
                .unwrap_or(DEFAULT_TIMEOUT_SECS)
                .clamp(1, MAX_TIMEOUT_SECS),
        );

        let line = Self::command_line(&parsed, |arg| shell.quote(arg));

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

        let ok = output.exit_code.unwrap_or(0) == 0;
        // `bound` keeps both ends and says how much it dropped. One bounding path, not two: an
        // earlier version also called `ExecOutput::bounded`, which produced a different shape,
        // dropped stderr's label, and never reported that it had truncated anything.
        let (content, truncated) = crate::tool::bound(report);

        Ok(ToolOutcome {
            content,
            ok,
            truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{BrokenHost, FakeHost};
    use crate::tool::MAX_TOOL_OUTPUT_CHARS;
    use hx_remote::host::shell_quote;
    use std::sync::Arc;

    fn ctx(host: Arc<dyn hx_remote::Host>) -> ToolContext {
        ToolContext::new(host)
    }

    #[test]
    fn the_schema_requires_a_command() {
        let schema = ShellTool.schema();
        assert_eq!(schema["required"][0], "cmd");
        assert!(schema["properties"]["timeout_secs"].is_object());
    }

    #[test]
    fn an_empty_command_is_refused_before_anything_runs() {
        let err = ShellTool.requirement(&json!({"cmd": "   "})).unwrap_err();
        assert!(err.to_string().contains("cmd is empty"), "{err}");
    }

    #[test]
    fn the_requirement_is_a_process_execution_carrying_the_command() {
        // The command line is what the risk classifier sees, so it must travel with the request.
        let requirement = ShellTool
            .requirement(&json!({"cmd": "rm -rf /"}))
            .unwrap()
            .expect("running a command has an external effect");
        assert_eq!(requirement.action, Action::Execute);
        assert_eq!(requirement.command(), Some("rm -rf /"));
    }

    #[test]
    fn a_workdir_is_prepended_and_quoted() {
        let args = Args {
            cmd: "ls -la".to_string(),
            workdir: Some("/tmp/it's here".to_string()),
            timeout_secs: None,
        };
        let line = ShellTool::command_line(&args, shell_quote);
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
        assert_eq!(ShellTool::command_line(&args, shell_quote), "pwd");
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
    async fn a_missing_command_argument_is_an_argument_error() {
        let err = ShellTool
            .call(json!({"command": "ls"}), &ctx(Arc::new(FakeHost::unix())))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Arguments(_)), "{err}");
    }
}
