//! The tool contract.

use async_trait::async_trait;
use hx_core::approval::{Confinement, Target};
use hx_core::capability::{Action, Resource};
use hx_core::error::HxError;
use hx_remote::{ExecOutput, Host};
use serde_json::Value;
use std::sync::Arc;

/// How much of a tool's output is kept. Beyond this, the middle is dropped and the omission is
/// stated.
///
/// Sized for a context window rather than for a terminal: ~24k characters is roughly 6k tokens of
/// estimate, which a model can hold alongside a task's earlier turns. A tool result that silently
/// exceeds this is how a long agent run dies of context exhaustion instead of doing work.
pub const MAX_TOOL_OUTPUT_CHARS: usize = 24_000;

/// What a tool produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolOutcome {
    /// The text the model sees. Bounded.
    pub content: String,
    /// Whether the tool considers this a success. A failed command is still a *result* — the model
    /// needs to see the error and adapt, not have the loop abort.
    pub ok: bool,
    /// Set when the content was truncated, so the model (and the transcript) can say so.
    pub truncated: bool,
}

impl ToolOutcome {
    pub fn ok(content: impl Into<String>) -> Self {
        let (content, truncated) = bound(content.into());
        Self {
            content,
            ok: true,
            truncated,
        }
    }

    /// A failure the model should read, not an error that stops the loop.
    pub fn failed(content: impl Into<String>) -> Self {
        let (content, truncated) = bound(content.into());
        Self {
            content,
            ok: false,
            truncated,
        }
    }
}

/// What the caller must be allowed to do before [`Tool::call`] may run.
///
/// The loop checks this against the capability token (is it legal?) and the approval policy (must
/// a human say yes?). Both, not either: a capability says what the agent *may* do, approval says
/// whether this particular instance is wanted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub resource: Resource,
    pub action: Action,
    /// A short phrase for the approval prompt — "run a command", "write /etc/hosts".
    pub describes: String,
}

impl Requirement {
    pub fn new(resource: Resource, action: Action, describes: impl Into<String>) -> Self {
        Self {
            resource,
            action,
            describes: describes.into(),
        }
    }

    /// The command line a shell approval decision turns on, when there is one.
    ///
    /// The command risk classifier works on a command string; a filesystem write has nothing for it
    /// to classify, which is why this is optional rather than a required field.
    pub fn command(&self) -> Option<&str> {
        match &self.resource {
            Resource::Process => Some(self.describes.as_str()),
            _ => None,
        }
    }
}

/// A tool that could not even be *prepared* — an argument that is missing, the wrong type, or a
/// path that cannot be expressed as a capability.
///
/// This is deliberately not the same as a failed *call*: a command that exits non-zero is a
/// [`ToolOutcome`] the model reads, while unusable arguments are a programming-level problem the
/// loop reports back as a tool result without executing anything.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ToolError {
    #[error("argument error: {0}")]
    Arguments(String),

    #[error("{0}")]
    Unavailable(String),
}

/// What a tool needs in order to act.
///
/// A borrowed context rather than a `&self` field: tools hold configuration (their backend set,
/// their todo list), not connections, so one registry can serve several hosts.
/// A boundary a command can be run inside, when a run was given one.
///
/// The daemon implements this over `hx_sandbox::SandboxManager`; the *trait* lives here and the
/// dependency does not, because a tool layer that linked a container engine in order to say "run this in
/// a box" would make every embedder link one. Returning [`ExecOutput`] rather than a type of its own is
/// the same idea from the other side: `shell` treats a sandbox exactly as it treats an SSH host — a place
/// with its own shell, its own paths and its own exit codes — so both paths share one output type and one
/// reporter.
#[async_trait]
pub trait SandboxExec: Send + Sync {
    /// Run a command line inside the boundary.
    ///
    /// `workdir` is a path as the *host* knows it, because that is what the model's arguments and the
    /// capability token are expressed in; mapping it into the boundary is the implementation's job, since
    /// the implementation is the side that created the mount. A path that is not visible inside must be
    /// an error rather than a silent fallback to some other directory — a command that runs in the wrong
    /// place is worse than one that fails.
    async fn exec(&self, command: &str, workdir: Option<&str>) -> Result<ExecOutput, HxError>;

    /// One line naming the boundary, for a transcript: `sandbox dev (l2, ubuntu:24.04)`.
    fn describe(&self) -> String;
}

pub struct ToolContext {
    pub host: Arc<dyn Host>,
    /// The directory this run may act in.
    ///
    /// Relative paths from a model are resolved against it, and that matters more than it sounds: a
    /// model asked to "read Cargo.toml in this workspace" writes `Cargo.toml`, and a capability token
    /// holds an absolute workspace path. Without the join, the token denies every call the model
    /// naturally makes — which is exactly what happened the first time a real model was pointed at
    /// this harness. `shell` also runs here when the model names no directory of its own, because a
    /// command that runs wherever the daemon happens to be is a command that can act on the wrong
    /// checkout.
    pub workspace: Option<String>,
    /// A boundary this run may use, when it was given one. See [`SandboxExec`].
    ///
    /// `None` is the default and the honest one: a tool that claimed confinement without a boundary to
    /// run in would be claiming the single fact an approval can rest on, which is why nothing here is
    /// inferred and why [`Tool::confinement`] defaults to the host rather than to this field.
    pub sandbox: Option<Arc<dyn SandboxExec>>,
}

impl ToolContext {
    pub fn new(host: Arc<dyn Host>) -> Self {
        Self {
            host,
            workspace: None,
            sandbox: None,
        }
    }

    /// The context a run has: a host and the directory it may act in.
    pub fn in_workspace(mut self, workspace: impl Into<String>) -> Self {
        self.workspace = Some(workspace.into());
        self
    }

    /// Give this run a boundary to run commands in — `docs/approvals.md` §4's other half.
    pub fn with_sandbox(mut self, sandbox: Arc<dyn SandboxExec>) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    /// Whether a command run through this context would end up inside a boundary.
    pub fn confinement(&self) -> Confinement {
        match self.sandbox {
            Some(_) => Confinement::Sandbox,
            None => Confinement::Host,
        }
    }

    /// Resolve a path as the model wrote it: absolute stays as it is, relative joins the workspace.
    ///
    /// `..` is deliberately *not* collapsed. The capability token refuses any path containing a
    /// parent component before it consults a grant, and normalising it away here would hide the one
    /// shape of path that cannot be safely evaluated for containment.
    pub fn resolve(&self, path: &str) -> String {
        resolve_path(path, self.workspace.as_deref())
    }
}

/// Join a relative path onto a workspace. See [`ToolContext::resolve`] for why `..` survives.
pub fn resolve_path(path: &str, workspace: Option<&str>) -> String {
    if is_absolute_path(path) {
        return path.to_string();
    }
    match workspace.map(str::trim).filter(|root| !root.is_empty()) {
        Some(root) => format!("{}/{}", root.trim_end_matches('/'), path),
        // No workspace: the path stays relative, the host resolves it against its own directory, and
        // the capability token refuses it for not being absolute. Failing closed beats guessing.
        None => path.to_string(),
    }
}

/// Absolute on the daemon's platform *or* on a host it might be driving.
///
/// A Linux daemon managing a Windows box sees `C:\Users\...`, which `Path::is_absolute` calls
/// relative; joining that onto a workspace would produce a path that is wrong on both machines.
fn is_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if matches!(bytes.first(), Some(b'/') | Some(b'\\')) {
        return true;
    }
    // A drive letter: `C:`, `d:/`.
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[async_trait]
pub trait Tool: Send + Sync {
    /// The name the model calls. Stable: it appears in transcripts and in approval rules.
    fn name(&self) -> &str;

    /// What the model reads to decide whether to use it. Written for a model, not for a changelog.
    fn description(&self) -> &str;

    /// JSON Schema for the arguments object.
    fn schema(&self) -> Value;

    /// What this call implies, or `None` when it has no external effect at all.
    ///
    /// Called before anything runs, with the raw arguments *and the run's context*, because what a
    /// call implies can depend on it: `read_file { path: "Cargo.toml" }` is a different resource
    /// depending on which workspace the run is in, and the resource named here is the one the
    /// capability token is asked about — and the one the tool must then act on, or the check and the
    /// effect disagree. `None` is a real claim — "this touches nothing outside the process" — and the
    /// loop acts on it by running the tool without asking a capability token or a human. Anything
    /// that reads or writes a file, spawns a process, or opens a connection must return `Some`, which
    /// is why the todo list is the only tool in this crate that returns `None`.
    fn requirement(
        &self,
        args: &Value,
        ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError>;

    /// What this call will touch, measured *before* anyone is asked about it.
    ///
    /// `docs/approvals.md` §3 is the requirement this answers: the prompt for a deletion has to say
    /// what will be gone, and that is a fact about the filesystem rather than about the arguments.
    /// It is therefore measured here — after the capability check (a call the agent is not allowed to
    /// make is not worth a directory walk) and before the prompt — and it is a **lower bound**: empty
    /// by default, because a tool that cannot name its targets is not asked to invent them, and the
    /// prompt is better with no target section than with a wrong one.
    async fn targets(&self, _args: &Value, _ctx: &ToolContext) -> Result<Vec<Target>, ToolError> {
        Ok(Vec::new())
    }

    /// How this call can be taken back, in a sentence the prompt shows, when it can be.
    ///
    /// The fact only the tool knows: moving a file into the trash and unlinking it are the same
    /// [`Action::Delete`] on the same path, and which one it was is the difference between a
    /// recoverable mistake and a lost file. `None` — the default — means *assume not*, so a tool that
    /// says nothing gets the conservative prompt, and the one that answers has to describe the way
    /// back rather than assert a boolean.
    fn undo(&self, _args: &Value, _ctx: &ToolContext) -> Option<String> {
        None
    }

    /// Where this call will run. See [`Confinement`] and `docs/approvals.md` §4.
    ///
    /// The default is the *host*, and deliberately not "whatever the context says": a read through a
    /// filesystem tool touches the real filesystem even in a run whose `shell` has a sandbox under it,
    /// so a tool that has not thought about it must not claim a boundary. `shell` is the one tool that
    /// answers from the context, because it is the one that can run either way.
    fn confinement(&self, _args: &Value, _ctx: &ToolContext) -> Confinement {
        Confinement::Host
    }

    /// Do it.
    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutcome, ToolError>;
}

/// Parse a tool's arguments, reporting what was wrong in the model's terms.
pub fn parse_args<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T, ToolError> {
    serde_json::from_value(args.clone())
        .map_err(|err| ToolError::Arguments(format!("{err} (got: {})", brief(args))))
}

/// A compact rendering of the arguments for an error message: enough to see the mistake, short
/// enough that a 200 KB blob cannot flood the transcript through an error path.
pub fn brief(args: &Value) -> String {
    let text = args.to_string();
    if text.chars().count() <= 200 {
        return text;
    }
    let head: String = text.chars().take(200).collect();
    format!("{head}…")
}

/// Bound a tool's output, reporting whether anything was dropped.
pub fn bound(text: String) -> (String, bool) {
    if text.chars().count() <= MAX_TOOL_OUTPUT_CHARS {
        return (text, false);
    }
    (
        hx_remote::host::truncate_middle(&text, MAX_TOOL_OUTPUT_CHARS),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)] // read through `Deserialize`, never directly
    struct Args {
        cmd: String,
    }

    #[test]
    fn a_missing_argument_names_the_field_and_shows_what_arrived() {
        let err = parse_args::<Args>(&serde_json::json!({"command": "ls"})).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("missing field `cmd`"), "{message}");
        assert!(
            message.contains("command"),
            "the received arguments help: {message}"
        );
    }

    #[test]
    fn a_wrong_type_is_reported_the_same_way() {
        let err = parse_args::<Args>(&serde_json::json!({"cmd": 42})).unwrap_err();
        assert!(err.to_string().contains("invalid type"), "{err}");
    }

    #[test]
    fn huge_arguments_are_summarised_in_errors() {
        let args = serde_json::json!({ "cmd": "x".repeat(5000) });
        let message = brief(&args);
        assert!(message.chars().count() < 300, "{}", message.chars().count());
        assert!(message.ends_with('…'), "{message}");
    }

    #[test]
    fn short_output_is_untouched() {
        let (text, truncated) = bound("hello".to_string());
        assert_eq!(text, "hello");
        assert!(!truncated);
    }

    #[test]
    fn long_output_keeps_both_ends_and_says_what_it_dropped() {
        let long = "a".repeat(40_000) + &"b".repeat(40_000);
        let (text, truncated) = bound(long);
        assert!(truncated);
        assert!(text.chars().count() <= MAX_TOOL_OUTPUT_CHARS + 64);
        assert!(
            text.contains("characters omitted"),
            "the model must know: {text}"
        );
        assert!(text.starts_with('a'));
        assert!(
            text.ends_with('b'),
            "the tail is usually where the error is"
        );
    }

    #[test]
    fn an_outcome_carries_the_truncation_flag() {
        let outcome = ToolOutcome::ok("z".repeat(MAX_TOOL_OUTPUT_CHARS + 100));
        assert!(outcome.ok);
        assert!(outcome.truncated);
        assert!(outcome.content.contains("characters omitted"));
    }

    #[test]
    fn a_failed_outcome_is_still_a_result() {
        // Not an error: the model has to see `exit 1` and adapt.
        let outcome = ToolOutcome::failed("exit 1");
        assert!(!outcome.ok);
        assert_eq!(outcome.content, "exit 1");
    }

    #[test]
    fn a_requirement_only_offers_a_command_when_there_is_one() {
        let process = Requirement::new(Resource::Process, Action::Execute, "ls -la");
        assert_eq!(process.command(), Some("ls -la"));

        let write = Requirement::new(
            Resource::FsPath {
                path: "/tmp/x".to_string(),
            },
            Action::Write,
            "write /tmp/x",
        );
        assert_eq!(
            write.command(),
            None,
            "there is no command line to classify"
        );
    }
}
