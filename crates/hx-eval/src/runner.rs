//! One eval trial: sandbox, staged task, agent run, verifier, score.
//!
//! A trial is five steps, in order:
//!
//! 1. **Spawn** a sandbox from the task's spec ([`to_sandbox_spec`]).
//! 2. **Stage** `instruction.md` and `tests/` into the sandbox workspace with `upload_dir`.
//! 3. **Run** the agent loop against the instruction, under a capability token scoped to the
//!    sandbox workspace and bounded by `Limits { max_turns, deadline }`.
//! 4. **Verify** by running the task's verifier command inside the sandbox; exit code 0 passes.
//! 5. **Persist** the trial (and its parent job row) through the store.
//!
//! ## The agent seam
//!
//! [`AgentDriver`] is the one piece of a trial that needs a model. Production runs use
//! [`RealDriver`] (a real [`AgentLoop`]); tests use a scripted fake. The seam covers *only*
//! the agent phase — sandbox spawn/stage/verify and store persistence run identically in
//! both paths, because those are what the tests are for.
//!
//! ## Tool construction, and what hx-eval cannot reach
//!
//! `hx-server` builds its run tools with `default_tools` (file tools, shell, todo, *plus* web
//! search over `hx-search` backends). `hx-eval` cannot reuse that construction: it has no
//! `hx-search` dependency, and eval sandboxes run default-deny network, so a web tool would
//! only fail closed. [`RealDriver`] therefore registers the smallest set that lets an agent
//! do file work — read, write, patch, delete, shell, todo — all from `hx-tools`, which *is* a
//! dependency. The `ToolContext` host is `hx-remote`'s `LocalHost` (added as a dependency for
//! exactly this); commands reach the sandbox through the [`SandboxExec`] boundary below,
//! which delegates to `SandboxManager::exec`, the same path the verifier uses.
//!
//! ## What is deliberately not crash-safe
//!
//! The daemon wires a transcript sink so a killed run leaves its partial transcript on disk.
//! A trial does not: `run_trial` persists the transcript to the session *after* the agent
//! phase returns. If the harness process dies mid-trial, no trial row is recorded either,
//! so there is no resumable state to be inconsistent about — the trial simply never happened.

use crate::task::{to_sandbox_spec, TaskSpec};
use async_trait::async_trait;
use chrono::Utc;
use hx_agent::{AgentLoop, AlwaysAllow, Limits, ModelCall};
use hx_core::approval::{ApprovalPolicy, ApprovalSession, AutonomyLevel};
use hx_core::capability::{Action, Capability, CapabilityToken, Resource};
use hx_core::error::{HxError, Result};
use hx_core::ids::{AgentId, EvalJobId, EvalTrialId, HostId, SessionId};
use hx_core::message::Message;
use hx_sandbox::SandboxManager;
use hx_store::{NewEvalJob, NewEvalTrial, NewSession, Store};
use hx_tools::WriteFileTool;
use hx_tools::{
    DeleteTool, PatchTool, ReadFileTool, ShellTool, TodoTool, ToolContext, ToolRegistry,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a verifier may run when the task names no timeout.
const DEFAULT_VERIFIER_TIMEOUT: Duration = Duration::from_secs(300);
/// Upper bound on a trial reason stored in the trial row.
const MAX_REASON_CHARS: usize = 4000;
/// How much verifier output the reason keeps (the tail — failures explain themselves at the end).
const MAX_VERIFIER_TAIL_CHARS: usize = 2000;

/// Everything one trial needs.
pub struct TrialConfig<'a> {
    /// Who the trial runs as (capability subject, session owner).
    pub agent: AgentId,
    /// The parsed task: instruction, verifier, resource requirements.
    pub task: TaskSpec,
    /// Dataset name for the parent job row (e.g. the directory the task came from).
    pub dataset: String,
    /// Model role for the parent job row (resolved to a [`ModelCall`] by the caller).
    pub role: String,
    /// The model the agent loop drives.
    pub model: Arc<dyn ModelCall>,
    /// Where the job, trial, session and transcript are recorded.
    pub store: &'a Store,
    /// Where the trial sandbox is spawned. Borrowed: spawn/stage/verify only need `&`.
    pub sandboxes: &'a SandboxManager,
    /// Sandbox policy the task's resource *request* is checked against.
    pub profile: hx_core::config::SandboxProfile,
    /// Model turns before the loop stops with `MaxTurns`.
    pub max_turns: u32,
    /// Wall-clock ceiling for the agent phase, enforced by the loop.
    pub deadline: Duration,
    /// The agent phase. [`RealDriver`] in production (it owns its own `Arc<SandboxManager>`
    /// for the tool boundary — see its docs); a scripted fake in tests.
    pub driver: Arc<dyn AgentDriver>,
}

/// What one trial produced.
pub struct TrialOutcome {
    pub job_id: EvalJobId,
    pub trial_id: EvalTrialId,
    pub session_id: SessionId,
    pub passed: bool,
    pub reason: String,
}

/// What the driver is asked to do. Owned: the real driver moves it across awaits.
pub struct AgentInput {
    pub agent: AgentId,
    pub model: Arc<dyn ModelCall>,
    /// Scoped to the sandbox workspace (plus process spawn); built by `run_trial`, never by
    /// the driver, so a test fake cannot widen what the production path grants.
    pub capability: CapabilityToken,
    /// Carries `max_turns` and `deadline` from the trial config.
    pub limits: Limits,
    /// Sandbox the tool boundary in the driver's `ToolContext` executes through.
    pub sandbox_id: String,
    /// Sandbox workspace path (e.g. `/workspace`), also the capability's filesystem grant.
    pub workspace: String,
}

/// What the driver reports back. The transcript itself travels on the `&mut Vec<Message>`
/// `drive` takes, so a failed run still leaves whatever the loop produced.
pub struct AgentSummary {
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd: f64,
    pub final_text: String,
}

/// The agent phase, behind a seam so tests need no model.
///
/// Implementations append to `transcript` (starting with the instruction as the user message)
/// and return the run's accounting. They must not persist anything: `run_trial` owns all
/// store writes, which is what keeps the test path honest about verification + persistence.
#[async_trait]
pub trait AgentDriver: Send + Sync {
    async fn drive(&self, transcript: &mut Vec<Message>, input: AgentInput)
        -> Result<AgentSummary>;
}

/// The production driver: a real [`AgentLoop`] with [`AlwaysAllow`].
///
/// The `Arc<SandboxManager>` is shared ownership rather than a borrow because the tool
/// boundary (`ToolContext.sandbox: Arc<dyn SandboxExec>`) is `'static`: a borrowed manager
/// cannot back it. The caller that owns the manager hands one `Arc` here and lends `&` to
/// `TrialConfig.sandboxes` for spawn/stage/verify — both point at the same manager.
pub struct RealDriver {
    sandboxes: Arc<SandboxManager>,
}

impl RealDriver {
    pub fn new(sandboxes: Arc<SandboxManager>) -> Self {
        Self { sandboxes }
    }
}

/// A `ToolContext` boundary that runs commands in the trial sandbox.
struct ManagerBoundary {
    sandboxes: Arc<SandboxManager>,
    sandbox_id: String,
    label: String,
}

#[async_trait]
impl hx_tools::tool::SandboxExec for ManagerBoundary {
    async fn exec(
        &self,
        command: &str,
        workdir: Option<&str>,
    ) -> std::result::Result<hx_remote::ExecOutput, HxError> {
        let out = self
            .sandboxes
            .exec(&self.sandbox_id, command, workdir)
            .await?;
        Ok(hx_remote::ExecOutput {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: Some(out.exit_code as i32),
            duration_ms: 0,
            truncated: false,
        })
    }

    fn describe(&self) -> String {
        self.label.clone()
    }
}

#[async_trait]
impl AgentDriver for RealDriver {
    async fn drive(
        &self,
        transcript: &mut Vec<Message>,
        input: AgentInput,
    ) -> Result<AgentSummary> {
        let host = Arc::new(hx_remote::LocalHost::detect(HostId::from("hxd-eval")).await?);
        let mut tools = ToolRegistry::new();
        tools.register(Arc::new(ReadFileTool::new()));
        tools.register(Arc::new(WriteFileTool::new()));
        tools.register(Arc::new(PatchTool::new()));
        tools.register(Arc::new(DeleteTool::new()));
        tools.register(Arc::new(ShellTool::new()));
        tools.register(Arc::new(TodoTool::new()));
        let boundary = Arc::new(ManagerBoundary {
            sandboxes: Arc::clone(&self.sandboxes),
            sandbox_id: input.sandbox_id.clone(),
            label: format!("eval sandbox {}", input.sandbox_id),
        });
        let ctx = ToolContext::new(host)
            .in_workspace(input.workspace.clone())
            .with_sandbox(boundary);
        // Unattended by definition: no client polls for approvals, so an eval trial runs at
        // the yolo level with an approver that allows what the policy still asks about —
        // exactly the daemon's `autonomy: "yolo"` path. The capability token remains the
        // boundary: yolo never widens what the agent may touch, only whether a human is asked.
        let approvals = ApprovalSession::new(ApprovalPolicy::at(AutonomyLevel::Yolo));
        let loop_ = AgentLoop::new(
            input.agent.clone(),
            Arc::clone(&input.model),
            Arc::new(tools),
            input.capability.clone(),
            approvals,
            Arc::new(AlwaysAllow),
        )
        .with_limits(input.limits);
        let outcome = loop_.run(transcript, &ctx).await?;
        Ok(AgentSummary {
            tokens_in: outcome.usage.input_tokens,
            tokens_out: outcome.usage.output_tokens,
            // The loop reports token counts; dollars come from the callable's settled spend
            // (`RouterModel` prices every call it made, a test double reports 0.0).
            cost_usd: input.model.spent_usd(),
            final_text: outcome.final_text,
        })
    }
}

/// Run one trial: spawn, stage, drive the agent, verify, persist.
///
/// The job row is created first, so even a trial that never starts a sandbox counts — the
/// same rule as the store's own ("a setup failure still counts as a trial"). Infrastructure
/// failures (spawn, staging, agent error) are recorded as *failed trials* with the error as
/// the reason and returned as `Ok`; only store failures are `Err`, because then nothing
/// could be recorded at all.
pub async fn run_trial(cfg: TrialConfig<'_>) -> Result<TrialOutcome> {
    let started = Instant::now();
    let task_name = if cfg.task.config.task.name.trim().is_empty() {
        cfg.task
            .root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unnamed-task".to_string())
    } else {
        cfg.task.config.task.name.clone()
    };
    let job = cfg.store.insert_eval_job(&NewEvalJob {
        dataset: cfg.dataset.clone(),
        role: cfg.role.clone(),
        task: task_name.clone(),
    })?;
    let session = cfg.store.create(
        NewSession::new()
            .titled(format!("eval: {task_name}"))
            .run_by(cfg.agent.clone())
            .in_workspace(cfg.task.root.to_string_lossy().into_owned()),
        Utc::now(),
    )?;

    let interim = execute_trial(&cfg, &session.id).await;

    let reason = bound_reason(&interim.reason);
    let trial = cfg.store.insert_eval_trial(&NewEvalTrial {
        job_id: job.id.clone(),
        session_id: Some(session.id.as_str().to_string()),
        task: task_name,
        passed: interim.passed,
        reason: reason.clone(),
        duration_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
        tokens_in: interim.tokens_in.min(i64::MAX as u64) as i64,
        tokens_out: interim.tokens_out.min(i64::MAX as u64) as i64,
        cost_usd: interim.cost_usd,
    })?;

    Ok(TrialOutcome {
        job_id: job.id,
        trial_id: trial.id,
        session_id: session.id,
        passed: interim.passed,
        reason,
    })
}

/// The trial's score and accounting. Never `Err`: every failure becomes `passed: false`.
struct Interim {
    passed: bool,
    reason: String,
    tokens_in: u64,
    tokens_out: u64,
    cost_usd: f64,
}

impl Interim {
    fn fail(reason: String) -> Self {
        Self {
            passed: false,
            reason,
            tokens_in: 0,
            tokens_out: 0,
            cost_usd: 0.0,
        }
    }
}

async fn execute_trial(cfg: &TrialConfig<'_>, session: &SessionId) -> Interim {
    let name = cfg.task.config.task.name.clone();

    // The verifier command first: a task that cannot be scored must fail before it spends
    // model budget, not after.
    let verify_cmd = match verifier_command(&cfg.task) {
        Ok(cmd) => cmd,
        Err(err) => return Interim::fail(format!("task '{name}' cannot be scored: {err}")),
    };

    let mut spec = match to_sandbox_spec(&cfg.task, &cfg.profile) {
        Ok(spec) => spec,
        Err(err) => return Interim::fail(format!("task '{name}' has no runnable sandbox: {err}")),
    };
    // The host path is bind-mounted by the engine backend, so it must exist and be valid —
    // but it carries nothing: task content reaches the sandbox through `upload_dir`, never
    // through the mount. A fresh empty directory per trial keeps one trial's residue out of
    // the next and keeps the task's `solution/` (if any) out of the sandbox entirely.
    let stage_dir = trial_stage_dir();
    if let Err(err) = std::fs::create_dir_all(&stage_dir) {
        return Interim::fail(format!("could not create the sandbox staging dir: {err}"));
    }
    spec.workspace_host_path = stage_dir.to_string_lossy().into_owned();
    let workspace = spec.workspace_path.clone();

    let handle = match cfg.sandboxes.spawn(&spec, Utc::now()).await {
        Ok(handle) => handle,
        Err(err) => {
            let _ = std::fs::remove_dir_all(&stage_dir);
            return Interim::fail(format!("sandbox spawn failed: {err}"));
        }
    };
    let sandbox_id = handle.id.as_str().to_string();

    let interim = execute_guarded(cfg, session, &sandbox_id, &workspace, &verify_cmd).await;

    // Best-effort cleanup, after the outcome is decided: a failed destroy must not fail the
    // trial, and the TTL reaper remains the backstop. Prompt destroy matters most for the
    // concurrency cap — a trial that holds its slot starves the next one.
    let _ = cfg.sandboxes.destroy(&sandbox_id).await;
    let _ = std::fs::remove_dir_all(&stage_dir);
    interim
}

async fn execute_guarded(
    cfg: &TrialConfig<'_>,
    session: &SessionId,
    sandbox_id: &str,
    workspace: &str,
    verify_cmd: &str,
) -> Interim {
    let tar = match build_stage_tar(&cfg.task) {
        Ok(tar) => tar,
        Err(err) => return Interim::fail(format!("could not stage the task files: {err}")),
    };
    if let Err(err) = cfg.sandboxes.upload_dir(sandbox_id, workspace, tar).await {
        return Interim::fail(format!("staging the task into the sandbox failed: {err}"));
    }

    // Workspace read/write plus process spawn, mirroring the daemon's default capability
    // minus the web-search grant (no web tool is registered, and eval sandboxes have no
    // egress to search through). Nothing outside the workspace is reachable, and no
    // approval can widen that — a denied capability is not something `AlwaysAllow` can
    // approve away.
    let capability = CapabilityToken::issue(
        cfg.agent.clone(),
        vec![
            Capability::workspace(workspace),
            Capability::new(Resource::Process, [Action::Execute, Action::Spawn]),
        ],
        Utc::now(),
        cfg.deadline.as_secs() as i64 + 300,
    );
    let limits = Limits {
        max_turns: cfg.max_turns,
        deadline: Some(cfg.deadline),
        ..Default::default()
    };

    let mut transcript = vec![Message::user(cfg.task.instruction.clone())];
    let input = AgentInput {
        agent: cfg.agent.clone(),
        model: Arc::clone(&cfg.model),
        capability,
        limits,
        sandbox_id: sandbox_id.to_string(),
        workspace: workspace.to_string(),
    };
    let summary = match cfg.driver.drive(&mut transcript, input).await {
        Ok(summary) => summary,
        Err(err) => {
            let _ = persist_transcript(cfg.store, session, &transcript);
            return Interim::fail(format!("agent run failed: {err}"));
        }
    };
    if let Err(err) = persist_transcript(cfg.store, session, &transcript) {
        return Interim {
            passed: false,
            reason: format!("the agent ran but its transcript could not be stored: {err}"),
            tokens_in: summary.tokens_in,
            tokens_out: summary.tokens_out,
            cost_usd: summary.cost_usd,
        };
    }

    let timeout = verifier_timeout(&cfg.task);
    let exec = cfg.sandboxes.exec(sandbox_id, verify_cmd, Some(workspace));
    let out = match tokio::time::timeout(timeout, exec).await {
        Ok(Ok(out)) => out,
        Ok(Err(err)) => {
            return Interim {
                passed: false,
                reason: format!("verifier '{verify_cmd}' could not run: {err}"),
                tokens_in: summary.tokens_in,
                tokens_out: summary.tokens_out,
                cost_usd: summary.cost_usd,
            };
        }
        Err(_) => {
            return Interim {
                passed: false,
                reason: format!(
                    "verifier '{verify_cmd}' timed out after {}s",
                    timeout.as_secs()
                ),
                tokens_in: summary.tokens_in,
                tokens_out: summary.tokens_out,
                cost_usd: summary.cost_usd,
            };
        }
    };

    let tail = tail_chars(
        &format!("{}{}", stdout_block(&out.stdout), out.stderr),
        MAX_VERIFIER_TAIL_CHARS,
    );
    if out.exit_code == 0 {
        Interim {
            passed: true,
            reason: if tail.trim().is_empty() {
                "verifier exited 0".to_string()
            } else {
                format!("verifier exited 0:\n{tail}")
            },
            tokens_in: summary.tokens_in,
            tokens_out: summary.tokens_out,
            cost_usd: summary.cost_usd,
        }
    } else {
        Interim {
            passed: false,
            reason: format!("verifier exited {}:\n{tail}", out.exit_code),
            tokens_in: summary.tokens_in,
            tokens_out: summary.tokens_out,
            cost_usd: summary.cost_usd,
        }
    }
}

fn stdout_block(stdout: &str) -> String {
    if stdout.trim().is_empty() {
        String::new()
    } else {
        format!("{stdout}\n")
    }
}

fn persist_transcript(store: &Store, session: &SessionId, transcript: &[Message]) -> Result<()> {
    for message in transcript {
        store.append(session, message, Utc::now())?;
    }
    Ok(())
}

/// The command that scores a trial, run in the sandbox workspace.
///
/// An explicit `[verifier] command` wins (the task embeds its scorer). Otherwise every file
/// under `tests/` runs under `sh`, sorted, short-circuiting on the first failure. A task
/// with neither is unscorable — failing here, before any model budget is spent.
pub fn verifier_command(task: &TaskSpec) -> Result<String> {
    if let Some(cmd) = task.config.verifier.command.as_deref() {
        if !cmd.trim().is_empty() {
            return Ok(cmd.trim().to_string());
        }
    }
    if task.tests.is_empty() {
        return Err(HxError::Config(format!(
            "task '{}' sets no [verifier] command and ships no tests/",
            task.config.task.name
        )));
    }
    let mut names: Vec<String> = task
        .tests
        .iter()
        .map(|p| staged_name(&task.root, p))
        .collect();
    names.sort();
    Ok(names
        .iter()
        .map(|n| format!("sh {n}"))
        .collect::<Vec<_>>()
        .join(" && "))
}

fn staged_name(root: &Path, path: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(root) {
        return rel.to_string_lossy().replace('\\', "/");
    }
    path.file_name()
        .map(|n| format!("tests/{}", n.to_string_lossy()))
        .unwrap_or_else(|| "tests/test.sh".to_string())
}

fn verifier_timeout(task: &TaskSpec) -> Duration {
    match task.config.verifier.timeout_sec {
        Some(secs) if secs.is_finite() && secs > 0.0 => Duration::from_secs_f64(secs),
        _ => DEFAULT_VERIFIER_TIMEOUT,
    }
}

fn trial_stage_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("hx-eval-{}-{nanos}", std::process::id()))
}

/// Tar `instruction.md` plus every file under `tests/` for `upload_dir`.
///
/// Hand-rolled ustar rather than the `tar` crate: nothing else in the workspace produces
/// tar bytes, so `tar` is not in the lockfile and cannot be added under `--offline`. The
/// writer covers exactly what staging needs — regular files and one directory entry — with
/// `ustar` magic so the engine backend extracts it like any other archive.
fn build_stage_tar(task: &TaskSpec) -> Result<Vec<u8>> {
    let mut tar = Vec::new();
    if !task.tests.is_empty() {
        append_entry(&mut tar, "tests/", 0o755, b'5', &[]);
    }
    append_entry(
        &mut tar,
        "instruction.md",
        0o644,
        b'0',
        task.instruction.as_bytes(),
    );
    let mut tests: Vec<(String, PathBuf)> = task
        .tests
        .iter()
        .map(|p| (staged_name(&task.root, p), p.clone()))
        .collect();
    tests.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, path) in tests {
        let bytes = std::fs::read(&path).map_err(|err| {
            HxError::Config(format!(
                "could not read test file {}: {err}",
                path.display()
            ))
        })?;
        append_entry(&mut tar, &name, 0o644, b'0', &bytes);
    }
    // End-of-archive: two zero blocks.
    tar.extend_from_slice(&[0u8; 1024]);
    Ok(tar)
}

fn append_entry(out: &mut Vec<u8>, name: &str, mode: u32, kind: u8, data: &[u8]) {
    let mut hdr = [0u8; 512];
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(100);
    hdr[..name_len].copy_from_slice(&name_bytes[..name_len]);
    write_octal(&mut hdr[100..108], mode as u64);
    write_octal(&mut hdr[108..116], 0); // uid
    write_octal(&mut hdr[116..124], 0); // gid
    write_octal(&mut hdr[124..136], data.len() as u64); // size
    write_octal(&mut hdr[136..148], 0); // mtime
    hdr[148..156].fill(b' '); // checksum field reads as spaces while summing
    hdr[156] = kind;
    hdr[257..262].copy_from_slice(b"ustar");
    hdr[263] = b'0';
    hdr[264] = b'0';
    let sum: u64 = hdr.iter().map(|b| *b as u64).sum();
    write_octal(&mut hdr[148..156], sum);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// Octal number, zero-padded, NUL-terminated. A checksum field pre-filled with spaces keeps
/// its trailing space, which ustar readers accept as a terminator.
fn write_octal(dst: &mut [u8], val: u64) {
    let digits = format!("{val:o}");
    let start = dst.len().saturating_sub(digits.len() + 1);
    for (i, b) in digits.bytes().enumerate() {
        dst[start + i] = b;
    }
}

fn tail_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let skip = s.chars().count() - max;
    s.chars().skip(skip).collect()
}

fn bound_reason(reason: &str) -> String {
    if reason.chars().count() <= MAX_REASON_CHARS {
        return reason.to_string();
    }
    format!(
        "{}…[truncated]",
        reason.chars().take(MAX_REASON_CHARS).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::ids::{CredentialId, ProviderId};
    use hx_provider::{ChatRequest, ChatResponse};
    use hx_sandbox::{SandboxExecOutput, SandboxRuntime, SandboxSpec};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/trivial-task");

    /// Scripted agent phase: records what it was given, appends one assistant message.
    struct FakeDriver {
        limits: Mutex<Option<Limits>>,
        capability: Mutex<Option<CapabilityToken>>,
        transcripts: Mutex<usize>,
        tokens_in: u64,
        tokens_out: u64,
        cost_usd: f64,
        fail_with: Mutex<Option<String>>,
    }

    impl FakeDriver {
        fn passing() -> Self {
            Self {
                limits: Mutex::new(None),
                capability: Mutex::new(None),
                transcripts: Mutex::new(0),
                tokens_in: 120,
                tokens_out: 60,
                cost_usd: 0.001,
                fail_with: Mutex::new(None),
            }
        }

        fn failing_agent() -> Self {
            Self {
                fail_with: Mutex::new(Some("the model is unreachable".to_string())),
                ..Self::passing()
            }
        }
    }

    #[async_trait]
    impl AgentDriver for FakeDriver {
        async fn drive(
            &self,
            transcript: &mut Vec<Message>,
            input: AgentInput,
        ) -> Result<AgentSummary> {
            *self.limits.lock().unwrap() = Some(input.limits);
            *self.capability.lock().unwrap() = Some(input.capability.clone());
            if let Some(err) = self.fail_with.lock().unwrap().clone() {
                return Err(HxError::Config(err));
            }
            transcript.push(Message::assistant("did the thing"));
            *self.transcripts.lock().unwrap() = transcript.len();
            Ok(AgentSummary {
                tokens_in: self.tokens_in,
                tokens_out: self.tokens_out,
                cost_usd: self.cost_usd,
                final_text: "did the thing".to_string(),
            })
        }
    }

    /// Never called by the fake driver; exists because the trial config carries a model.
    struct FakeModel;

    #[async_trait]
    impl ModelCall for FakeModel {
        async fn complete(&self, _req: ChatRequest) -> Result<ChatResponse> {
            unreachable!("the fake driver never calls the model")
        }

        fn model(&self) -> String {
            "fake-model".to_string()
        }

        fn provider_id(&self) -> ProviderId {
            ProviderId::new()
        }

        fn credential_id(&self) -> CredentialId {
            CredentialId::new()
        }
    }

    /// Scripted engine: no Docker, no network. `exit_code` is the verdict every `exec`
    /// returns, so one fake covers the passing and the failing verifier.
    struct FakeRuntime {
        exit_code: i64,
        commands: Mutex<Vec<(String, Option<String>)>>,
        uploads: Mutex<Vec<(String, Vec<u8>)>>,
        counter: AtomicUsize,
    }

    impl FakeRuntime {
        fn with_exit(exit_code: i64) -> Self {
            Self {
                exit_code,
                commands: Mutex::new(Vec::new()),
                uploads: Mutex::new(Vec::new()),
                counter: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl SandboxRuntime for FakeRuntime {
        fn name(&self) -> &str {
            "fake"
        }

        async fn available(&self) -> bool {
            true
        }

        async fn create(
            &self,
            _id: &hx_core::ids::SandboxId,
            _spec: &SandboxSpec,
            _settings: &hx_sandbox::HostSettings,
        ) -> Result<String> {
            Ok(format!(
                "hx-fake-{}",
                self.counter.fetch_add(1, Ordering::SeqCst)
            ))
        }

        async fn start(&self, _runtime_id: &str) -> Result<()> {
            Ok(())
        }

        async fn stop(&self, _runtime_id: &str, _grace_secs: i64) -> Result<()> {
            Ok(())
        }

        async fn remove(&self, _runtime_id: &str) -> Result<()> {
            Ok(())
        }

        async fn exec(
            &self,
            _runtime_id: &str,
            command: &str,
            workdir: Option<&str>,
        ) -> Result<SandboxExecOutput> {
            self.commands
                .lock()
                .unwrap()
                .push((command.to_string(), workdir.map(str::to_string)));
            Ok(SandboxExecOutput {
                stdout: format!("fake ran: {command}"),
                stderr: String::new(),
                exit_code: self.exit_code,
            })
        }

        async fn upload(&self, _runtime_id: &str, path: &str, tar: Vec<u8>) -> Result<()> {
            self.uploads.lock().unwrap().push((path.to_string(), tar));
            Ok(())
        }
    }

    fn harness(exit_code: i64) -> (Store, SandboxManager, Arc<FakeRuntime>) {
        let store = Store::in_memory().expect("in-memory store");
        let runtime = Arc::new(FakeRuntime::with_exit(exit_code));
        let manager = SandboxManager::new(Arc::clone(&runtime) as Arc<dyn SandboxRuntime>, 4);
        (store, manager, runtime)
    }

    fn trial_config<'a>(
        store: &'a Store,
        sandboxes: &'a SandboxManager,
        driver: Arc<FakeDriver>,
    ) -> TrialConfig<'a> {
        TrialConfig {
            agent: AgentId::new(),
            task: crate::task::load_task(FIXTURE).expect("fixture loads"),
            dataset: "canary".to_string(),
            role: "builder".to_string(),
            model: Arc::new(FakeModel),
            store,
            sandboxes,
            profile: hx_core::config::SandboxProfile::default(),
            max_turns: 7,
            deadline: Duration::from_secs(60),
            driver,
        }
    }

    #[tokio::test]
    async fn a_passing_verifier_records_a_pass_and_counts_it() {
        let (store, sandboxes, runtime) = harness(0);
        let driver = Arc::new(FakeDriver::passing());
        let outcome = run_trial(trial_config(&store, &sandboxes, Arc::clone(&driver)))
            .await
            .expect("trial runs");

        assert!(outcome.passed);
        assert!(outcome.reason.contains("exited 0"), "{}", outcome.reason);

        // The trial row is readable back, and the job counted it.
        let trials = store.trials_for_job(&outcome.job_id).expect("trials read");
        assert_eq!(trials.len(), 1);
        assert!(trials[0].passed);
        assert_eq!(trials[0].id, outcome.trial_id);
        assert_eq!(
            trials[0].session_id.as_deref(),
            Some(outcome.session_id.as_str())
        );
        assert_eq!(trials[0].tokens_in, 120);
        assert_eq!(trials[0].tokens_out, 60);
        let jobs = store.list_eval_jobs().expect("jobs read");
        assert_eq!(jobs.len(), 1);
        assert_eq!((jobs[0].trials, jobs[0].passed), (1, 1));

        // The transcript reached the session: instruction first, agent reply after.
        let messages = store
            .messages(&outcome.session_id)
            .expect("transcript reads");
        assert!(messages.len() >= 2);
        assert!(messages[0].text().contains("Do nothing"));

        // Staging reached the sandbox workspace as one tar archive.
        let (dest, tar) = {
            let uploads = runtime.uploads.lock().unwrap();
            assert_eq!(uploads.len(), 1);
            uploads[0].clone()
        };
        assert_eq!(dest, "/workspace");
        assert!(tar
            .windows(b"instruction.md".len())
            .any(|w| w == b"instruction.md"));
        assert!(tar
            .windows(b"tests/check.sh".len())
            .any(|w| w == b"tests/check.sh"));

        // The verifier ran in the workspace with the task's command.
        let (command, workdir) = {
            let commands = runtime.commands.lock().unwrap();
            assert_eq!(commands.len(), 1);
            commands[0].clone()
        };
        assert_eq!(command, "sh tests/check.sh");
        assert_eq!(workdir.as_deref(), Some("/workspace"));

        // The sandbox was destroyed again, freeing its slot.
        assert_eq!(sandboxes.list().await.len(), 0);
    }

    #[tokio::test]
    async fn a_failing_verifier_records_a_fail_with_the_exit() {
        let (store, sandboxes, _runtime) = harness(1);
        let driver = Arc::new(FakeDriver::passing());
        let outcome = run_trial(trial_config(&store, &sandboxes, Arc::clone(&driver)))
            .await
            .expect("trial runs");

        assert!(!outcome.passed);
        assert!(outcome.reason.contains("exited 1"), "{}", outcome.reason);

        let trials = store.trials_for_job(&outcome.job_id).expect("trials read");
        assert_eq!(trials.len(), 1);
        assert!(!trials[0].passed);
        // The agent phase still ran and was still persisted before the verdict.
        assert_eq!(trials[0].tokens_in, 120);
        let jobs = store.list_eval_jobs().expect("jobs read");
        assert_eq!((jobs[0].trials, jobs[0].passed), (1, 0));
        assert!(
            store
                .messages(&outcome.session_id)
                .expect("transcript")
                .len()
                >= 2
        );
    }

    #[tokio::test]
    async fn an_agent_failure_is_a_failed_trial_not_a_lost_one() {
        let (store, sandboxes, _runtime) = harness(0);
        let driver = Arc::new(FakeDriver::failing_agent());
        let outcome = run_trial(trial_config(&store, &sandboxes, Arc::clone(&driver)))
            .await
            .expect("trial runs");

        assert!(!outcome.passed);
        assert!(
            outcome.reason.contains("agent run failed"),
            "{}",
            outcome.reason
        );
        let trials = store.trials_for_job(&outcome.job_id).expect("trials read");
        assert_eq!(trials.len(), 1, "the failure is recorded, not swallowed");
        assert!(!trials[0].passed);
    }

    #[tokio::test]
    async fn the_capability_and_limits_bound_actually_reach_the_agent() {
        let (store, sandboxes, _runtime) = harness(0);
        let driver = Arc::new(FakeDriver::passing());
        run_trial(trial_config(&store, &sandboxes, Arc::clone(&driver)))
            .await
            .expect("trial runs");

        let limits = driver.limits.lock().unwrap().expect("driver saw limits");
        assert_eq!(limits.max_turns, 7);
        assert_eq!(limits.deadline, Some(Duration::from_secs(60)));

        let token = driver
            .capability
            .lock()
            .unwrap()
            .clone()
            .expect("driver saw a token");
        let now = Utc::now();
        assert!(
            token
                .check(
                    &Resource::FsPath {
                        path: "/workspace/work".to_string()
                    },
                    Action::Write,
                    now
                )
                .is_allowed(),
            "the workspace grant covers the sandbox workspace"
        );
        assert!(
            !token
                .check(
                    &Resource::FsPath {
                        path: "/etc/passwd".to_string()
                    },
                    Action::Read,
                    now
                )
                .is_allowed(),
            "nothing outside the workspace is reachable"
        );
        assert!(
            token
                .grants
                .iter()
                .all(|g| !matches!(g.resource, Resource::NetworkHost { .. })),
            "no network grant: no web tool is registered and eval sandboxes have no egress"
        );
    }

    #[test]
    fn an_explicit_verifier_command_wins_verbatim() {
        let task = crate::task::load_task(FIXTURE).expect("fixture loads");
        assert_eq!(
            verifier_command(&task).expect("command"),
            "sh tests/check.sh"
        );
    }

    #[test]
    fn without_a_command_every_test_file_runs_under_sh() {
        let root = PathBuf::from("/tmp/hx-eval-test-task");
        let task = TaskSpec {
            root: root.clone(),
            instruction: "x".to_string(),
            config: crate::task::TaskConfig {
                task: crate::task::TaskMeta::default(),
                environment: crate::task::EnvironmentConfig::default(),
                agent: crate::task::AgentConfig::default(),
                verifier: crate::task::VerifierSpec::default(),
            },
            environment: None,
            tests: vec![root.join("tests/b.sh"), root.join("tests/a.sh")],
            solution: Vec::new(),
        };
        assert_eq!(
            verifier_command(&task).expect("default"),
            "sh tests/a.sh && sh tests/b.sh"
        );
    }

    #[test]
    fn without_a_command_and_without_tests_the_task_is_unscorable() {
        let root = PathBuf::from("/tmp/hx-eval-test-task");
        let task = TaskSpec {
            root,
            instruction: "x".to_string(),
            config: crate::task::TaskConfig {
                task: crate::task::TaskMeta::default(),
                environment: crate::task::EnvironmentConfig::default(),
                agent: crate::task::AgentConfig::default(),
                verifier: crate::task::VerifierSpec::default(),
            },
            environment: None,
            tests: Vec::new(),
            solution: Vec::new(),
        };
        assert!(verifier_command(&task).is_err());
    }

    #[test]
    fn the_stage_archive_is_a_parseable_tar() {
        let task = crate::task::load_task(FIXTURE).expect("fixture loads");
        let tar = build_stage_tar(&task).expect("tar builds");
        assert_eq!(tar.len() % 512, 0, "entries are 512-block aligned");
        assert!(tar.len() >= 1024);
        assert!(
            tar[tar.len() - 1024..].iter().all(|b| *b == 0),
            "archive ends with two zero blocks"
        );
        // ustar magic on the first header, and the member names inline.
        assert_eq!(&tar[257..262], b"ustar");
        for name in ["instruction.md", "tests/", "tests/check.sh"] {
            assert!(
                tar.windows(name.len()).any(|w| w == name.as_bytes()),
                "{name} is a member"
            );
        }
    }
}
