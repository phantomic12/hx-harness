//! The Harbor task format, parsed.
//!
//! A task directory contains:
//!
//! ```text
//! instruction.md      — what the agent is asked to do
//! task.toml           — metadata, resource requirements, timeouts
//! environment/        — Dockerfile or docker-compose.yaml (optional if docker_image is set)
//! solution/           — reference solution, for debugging (optional)
//! tests/              — verifier scripts (optional; the task may embed a verifier command)
//! ```
//!
//! The parser is deliberately lenient about unknown fields: Harbor's schema evolves, and a task
//! that uses a newer field should still load — the field is ignored, not an error. What is *not*
//! lenient is the required structure: no `instruction.md` or no `task.toml` means it is not a
//! task directory, and the error says which file is missing.

use hx_core::config::IsolationLevel;
use hx_core::error::{HxError, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// A parsed Harbor task, ready to be mapped onto a `SandboxSpec`.
#[derive(Clone, Debug)]
pub struct TaskSpec {
    /// The directory this was loaded from.
    pub root: PathBuf,
    /// `instruction.md`, verbatim.
    pub instruction: String,
    /// `task.toml` — the parts hx uses.
    pub config: TaskConfig,
    /// Files under `environment/`, if present.
    pub environment: Option<EnvironmentSpec>,
    /// Files under `tests/`, if present.
    pub tests: Vec<PathBuf>,
    /// Files under `solution/`, if present.
    pub solution: Vec<PathBuf>,
}

/// The `[task]` metadata and the `[environment]` resource requirements.
#[derive(Clone, Debug, Deserialize)]
pub struct TaskConfig {
    #[serde(default)]
    pub task: TaskMeta,
    #[serde(default)]
    pub environment: EnvironmentConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub verifier: VerifierSpec,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct TaskMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
}

/// What the task's environment needs, mapped onto sandbox resources.
#[derive(Clone, Debug, Deserialize)]
pub struct EnvironmentConfig {
    /// A prebuilt image to use instead of building `environment/Dockerfile`.
    #[serde(default)]
    pub docker_image: Option<String>,
    /// `public`, `no-network`, or an allowlist. Maps to `SandboxSpec::network`.
    #[serde(default)]
    pub network_mode: Option<String>,
    #[serde(default)]
    pub cpus: Option<f64>,
    #[serde(default)]
    pub memory_mb: Option<u64>,
    #[serde(default)]
    pub storage_mb: Option<u64>,
    /// OS target: `linux` (default) or `windows`. Windows containers are not supported by the
    /// sandbox ladder yet; a task that asks for one is refused at load time.
    #[serde(default)]
    pub os: Option<String>,
    /// Environment variables to pass through. Values may reference `${VAR}` for host lookup.
    #[serde(default)]
    pub env: toml::value::Table,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            docker_image: None,
            network_mode: None,
            cpus: None,
            memory_mb: None,
            storage_mb: None,
            os: None,
            env: toml::value::Table::new(),
        }
    }
}

/// Agent-side timeouts and constraints from `task.toml`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AgentConfig {
    /// Seconds the agent may run before the trial is scored as a timeout.
    #[serde(default)]
    pub timeout_sec: Option<f64>,
    /// The OS user the agent runs as inside the environment.
    #[serde(default)]
    pub user: Option<String>,
}

/// How the task is scored.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VerifierSpec {
    /// The command that scores a trial, run in the sandbox workspace (e.g.
    /// `"sh tests/check.sh"`). hx's extension to the Harbor format: the task may embed its
    /// scorer, and when it does the runner uses it verbatim. Absent, the runner falls back
    /// to running every file under `tests/` with `sh`.
    #[serde(default)]
    pub command: Option<String>,
    /// Seconds the verifier may run.
    #[serde(default)]
    pub timeout_sec: Option<f64>,
    /// Environment for the verifier.
    #[serde(default)]
    pub env: toml::value::Table,
    /// The OS user the verifier runs as.
    #[serde(default)]
    pub user: Option<String>,
}

/// The `environment/` directory's contents, when present.
#[derive(Clone, Debug)]
pub struct EnvironmentSpec {
    /// `environment/Dockerfile`, if present.
    pub dockerfile: Option<PathBuf>,
    /// `environment/docker-compose.yaml`, if present.
    pub compose: Option<PathBuf>,
    /// Every other file under `environment/`, for build context.
    pub files: Vec<PathBuf>,
}

/// Errors specific to loading a task.
#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    #[error("not a Harbor task directory: {0}")]
    NotATask(String),
    #[error("task.toml is invalid: {0}")]
    InvalidToml(#[from] toml::de::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<TaskError> for HxError {
    fn from(err: TaskError) -> Self {
        HxError::Config(err.to_string())
    }
}

/// Load a task from a directory.
///
/// The directory must contain `task.toml` and `instruction.md`. Everything else is optional:
/// `environment/` supplies the build context, `tests/` the verifier scripts, `solution/` the
/// reference. A missing `environment/` is fine when `docker_image` is set — Harbor tasks may
/// reference a prebuilt image and ship no build context at all.
pub fn load_task(root: impl AsRef<Path>) -> Result<TaskSpec> {
    let root = root.as_ref().to_path_buf();

    let task_toml = root.join("task.toml");
    if !task_toml.exists() {
        return Err(TaskError::NotATask(format!("{} has no task.toml", root.display())).into());
    }
    let config: TaskConfig =
        toml::from_str(&std::fs::read_to_string(&task_toml)?).map_err(TaskError::InvalidToml)?;

    let instruction_path = root.join("instruction.md");
    if !instruction_path.exists() {
        return Err(
            TaskError::NotATask(format!("{} has no instruction.md", root.display())).into(),
        );
    }
    let instruction = std::fs::read_to_string(&instruction_path)?;

    // Windows containers are not part of the sandbox ladder; refuse early rather than fail
    // at spawn time with a confusing engine error.
    if let Some(os) = &config.environment.os {
        if os.eq_ignore_ascii_case("windows") {
            return Err(TaskError::NotATask(format!(
                "{} targets Windows containers, which the sandbox ladder does not support",
                root.display()
            ))
            .into());
        }
    }

    let environment = load_environment(&root)?;
    let tests = collect_files(&root.join("tests"))?;
    let solution = collect_files(&root.join("solution"))?;

    Ok(TaskSpec {
        root,
        instruction,
        config,
        environment,
        tests,
        solution,
    })
}

fn load_environment(root: &Path) -> Result<Option<EnvironmentSpec>> {
    let dir = root.join("environment");
    if !dir.is_dir() {
        return Ok(None);
    }

    let dockerfile = dir.join("Dockerfile");
    let compose = dir.join("docker-compose.yaml");
    let mut files = Vec::new();
    collect_into(&dir, &mut files)?;

    Ok(Some(EnvironmentSpec {
        dockerfile: dockerfile.exists().then_some(dockerfile),
        compose: compose.exists().then_some(compose),
        files,
    }))
}

fn collect_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if dir.is_dir() {
        collect_into(dir, &mut out)?;
    }
    Ok(out)
}

fn collect_into(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_into(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Map a loaded task onto a `SandboxSpec`.
///
/// The mapping is deliberate: a Harbor task's `[environment]` section is a *request*, and the
/// sandbox profile is the *policy*. The task says how much CPU and memory it needs; the profile
/// says what isolation it runs under. A task that asks for more than the profile allows is
/// refused rather than silently capped — a benchmark that runs under different constraints than
/// it declared is not measuring what it claims to.
pub fn to_sandbox_spec(
    task: &TaskSpec,
    profile: &hx_core::config::SandboxProfile,
) -> Result<hx_sandbox::SandboxSpec> {
    let mut spec = hx_sandbox::SandboxSpec::from_profile(&task.config.task.name, profile);

    // Image: the task's prebuilt image wins over the profile's default, because the task's
    // environment is part of what is being measured.
    if let Some(image) = &task.config.environment.docker_image {
        spec.image = image.clone();
    }

    // Resources: the task's declared needs override the profile's defaults, but only upward —
    // a task that asks for 8 CPUs on a 2-CPU profile is refused, not throttled.
    if let Some(cpus) = task.config.environment.cpus {
        if cpus > spec.cpus {
            return Err(HxError::Config(format!(
                "task '{}' asks for {} cpus but profile '{}' allows {}",
                task.config.task.name, cpus, spec.profile, spec.cpus
            )));
        }
        spec.cpus = cpus;
    }
    if let Some(memory_mb) = task.config.environment.memory_mb {
        if memory_mb > spec.memory_mb {
            return Err(HxError::Config(format!(
                "task '{}' asks for {} MiB but profile '{}' allows {}",
                task.config.task.name, memory_mb, spec.profile, spec.memory_mb
            )));
        }
        spec.memory_mb = memory_mb;
    }
    if let Some(storage_mb) = task.config.environment.storage_mb {
        if storage_mb > spec.workspace_mb {
            return Err(HxError::Config(format!(
                "task '{}' asks for {} MiB of storage but profile '{}' allows {}",
                task.config.task.name, storage_mb, spec.profile, spec.workspace_mb
            )));
        }
        spec.workspace_mb = storage_mb;
    }

    // Network: `no-network` maps to `network: false`. Anything else (`public`, an allowlist,
    // or omitted) keeps the profile's setting — which is `false` for the default `untrusted`
    // profile, so a task that does not declare a network need gets none.
    if let Some(mode) = &task.config.environment.network_mode {
        match mode.as_str() {
            "no-network" | "none" => spec.network = false,
            "public" => spec.network = true,
            other => {
                return Err(HxError::Config(format!(
                    "task '{}' declares unknown network_mode '{other}'; known: no-network, public",
                    task.config.task.name
                )));
            }
        }
    }

    // Environment variables from the task, resolved against the host's environment where the
    // value is a `${VAR}` reference.
    for (key, value) in &task.config.environment.env {
        let resolved = match value.as_str() {
            Some(s) if s.starts_with("${") && s.ends_with('}') => {
                let var = &s[2..s.len() - 1];
                std::env::var(var).map_err(|_| {
                    HxError::Config(format!(
                        "task '{}' references environment variable {var} which is not set",
                        task.config.task.name
                    ))
                })?
            }
            Some(s) => s.to_string(),
            None => {
                return Err(HxError::Config(format!(
                    "task '{}' environment variable '{key}' is not a string",
                    task.config.task.name
                )));
            }
        };
        spec.env.push((key.clone(), resolved));
    }

    // The agent's user, if the task names one.
    if let Some(user) = &task.config.agent.user {
        spec.user = Some(user.clone());
    }

    Ok(spec)
}

/// The isolation level a task should run under.
///
/// Default is L2 (gVisor): the task's environment is code the harness did not write, and the
/// verifier may run arbitrary commands. L1 is for tasks the operator has reviewed; L3 is for
/// tasks that are actively hostile.
pub fn default_isolation() -> IsolationLevel {
    IsolationLevel::L2
}
