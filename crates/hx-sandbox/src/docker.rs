//! Docker-backed sandbox runtime, via `bollard`.
//!
//! [`to_host_config`] is kept as a pure function and tested directly: it is the join between the
//! reviewed isolation policy in [`crate::spec`] and the settings the container engine actually
//! applies. A field dropped in translation is a security setting silently not enforced, so the
//! mapping is asserted field by field.

use crate::runtime::{SandboxExecOutput, SandboxRuntime};
use crate::spec::{HostSettings, SandboxSpec};
use async_trait::async_trait;
// `bollard` 0.19 deprecated the hand-written `container::*Options` structs in favour of the
// OpenAPI-generated `query_parameters` ones. The fields are the same names, so this is a
// rename — but the deprecated versions emit one warning *per field*, which is exactly the kind
// of noise that hides a real warning.
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::Docker;
use futures::StreamExt;
use hx_core::error::{HxError, Result};
use hx_core::ids::SandboxId;
use std::collections::HashMap;
use std::time::Duration;

/// How long to wait for a container to stop before killing it.
const STOP_GRACE_SECS: i64 = 10;

/// Sandboxes backed by containers.
pub struct DockerRuntime {
    docker: Docker,
    prefix: String,
}

impl DockerRuntime {
    /// Connect to the local engine using its default socket.
    pub async fn connect() -> Result<Self> {
        let docker = Docker::connect_with_local_defaults().map_err(|e| {
            HxError::Sandbox(format!(
                "could not create a Docker client (is the socket mounted and readable?): {e}"
            ))
        })?;
        Ok(Self {
            docker,
            prefix: "hx".to_string(),
        })
    }

    pub fn from_client(docker: Docker) -> Self {
        Self {
            docker,
            prefix: "hx".to_string(),
        }
    }

    fn container_name(&self, id: &SandboxId) -> String {
        format!("{}-{}", self.prefix, id.as_str())
    }
}

/// Translate reviewed sandbox settings into engine settings.
///
/// Every security-relevant field is mapped explicitly rather than relying on the engine's
/// defaults, because the engine's defaults are chosen for convenience and ours are not.
pub fn to_host_config(settings: &HostSettings) -> HostConfig {
    HostConfig {
        privileged: Some(settings.privileged),
        readonly_rootfs: Some(settings.readonly_rootfs),
        cap_drop: Some(settings.cap_drop.clone()),
        cap_add: if settings.cap_add.is_empty() {
            None
        } else {
            Some(settings.cap_add.clone())
        },
        security_opt: Some(settings.security_opt.clone()),
        network_mode: Some(settings.network_mode.clone()),
        pids_limit: Some(settings.pids_limit),
        nano_cpus: Some(settings.nano_cpus),
        memory: Some(settings.memory_bytes),
        memory_swap: Some(settings.memory_swap_bytes),
        runtime: settings.runtime.clone(),
        auto_remove: Some(settings.auto_remove),
        init: Some(settings.init),
        // Note: the sandbox user is set on the container body, not here — `HostConfig` has no
        // `user` field in the current API, and setting it in the wrong place would silently
        // leave the sandbox running as root.
        tmpfs: Some(
            settings
                .tmpfs
                .iter()
                .cloned()
                .collect::<HashMap<String, String>>(),
        ),
        binds: if settings.binds.is_empty() {
            None
        } else {
            Some(settings.binds.clone())
        },
        ..Default::default()
    }
}

/// Build the container body from a spec and its derived settings.
pub fn to_container_config(spec: &SandboxSpec, settings: &HostSettings) -> ContainerCreateBody {
    ContainerCreateBody {
        image: Some(spec.image.clone()),
        // The container's only job is to exist and be exec'd into. `sleep infinity` keeps it
        // alive without burning CPU, and gives the agent a shell when it wants one.
        cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
        env: if spec.env.is_empty() {
            None
        } else {
            Some(
                spec.env
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>(),
            )
        },
        // The sandbox user lives on the body, not in HostConfig, which has no such field.
        // Putting it in the wrong place leaves the sandbox running as root.
        user: Some(settings.user.clone()),
        // A TTY allocates a pty per container and makes output ordering non-deterministic;
        // neither is wanted for a batch tool.
        tty: Some(false),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        working_dir: Some(spec.workspace_path.clone()),
        host_config: Some(to_host_config(settings)),
        ..Default::default()
    }
}

#[async_trait]
impl SandboxRuntime for DockerRuntime {
    fn name(&self) -> &str {
        "docker"
    }

    async fn available(&self) -> bool {
        self.docker.ping().await.is_ok()
    }

    async fn create(
        &self,
        id: &SandboxId,
        spec: &SandboxSpec,
        settings: &HostSettings,
    ) -> Result<String> {
        let name = self.container_name(id);
        let body = to_container_config(spec, settings);

        let response = self
            .docker
            .create_container(
                // In the generated API `name` is `Option<String>` and `platform` is a plain
                // `String` where empty means "let the daemon decide".
                Some(CreateContainerOptions {
                    name: Some(name.clone()),
                    ..Default::default()
                }),
                body,
            )
            .await
            .map_err(|e| {
                HxError::Sandbox(format!(
                    "could not create sandbox '{name}' from image '{}': {e}",
                    spec.image
                ))
            })?;

        // The runtime handle is the container *name*, not `response.id`. The name is stable
        // across restarts, greppable in `docker ps`, and is what `start`/`stop`/`inspect` and the
        // label-based sweep all match on. The container id changes whenever the sandbox is
        // recreated, so keying on it would quietly break resume.
        //
        // A successful create always returns an id, so the original
        // `if response.id.is_empty() { name } else { name }` was dead code — both arms returned
        // the name. Assert the invariant rather than branching on it.
        debug_assert!(
            !response.id.is_empty(),
            "docker returned a created container with an empty id"
        );
        Ok(name)
    }

    async fn start(&self, runtime_id: &str) -> Result<()> {
        self.docker
            .start_container(runtime_id, None::<StartContainerOptions>)
            .await
            .map_err(|e| HxError::Sandbox(format!("could not start {runtime_id}: {e}")))
    }

    async fn stop(&self, runtime_id: &str, grace_secs: i64) -> Result<()> {
        let grace = if grace_secs > 0 {
            grace_secs
        } else {
            STOP_GRACE_SECS
        };
        // `t` is `Option<i32>` in the generated API, so "no explicit signal, just wait" is
        // `None` rather than a sentinel value.
        let options = StopContainerOptions {
            t: Some(grace as i32),
            ..Default::default()
        };
        self.docker
            .stop_container(runtime_id, Some(options))
            .await
            .map_err(|e| HxError::Sandbox(format!("could not stop {runtime_id}: {e}")))
    }

    async fn remove(&self, runtime_id: &str) -> Result<()> {
        self.docker
            .remove_container(
                runtime_id,
                Some(RemoveContainerOptions {
                    force: true,
                    v: true,
                    link: false,
                }),
            )
            .await
            .map_err(|e| HxError::Sandbox(format!("could not remove {runtime_id}: {e}")))
    }

    async fn exec(
        &self,
        runtime_id: &str,
        command: &str,
        workdir: Option<&str>,
    ) -> Result<SandboxExecOutput> {
        let exec = self
            .docker
            .create_exec(
                runtime_id,
                CreateExecOptions::<String> {
                    cmd: Some(vec![
                        "sh".to_string(),
                        "-c".to_string(),
                        command.to_string(),
                    ]),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    working_dir: workdir.map(str::to_string),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| {
                HxError::Sandbox(format!("could not create an exec in {runtime_id}: {e}"))
            })?;

        let mut stream = match self
            .docker
            .start_exec(
                &exec.id,
                Some(StartExecOptions {
                    detach: false,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| HxError::Sandbox(format!("could not start the exec: {e}")))?
        {
            StartExecResults::Attached { output, .. } => output,
            StartExecResults::Detached => {
                return Err(HxError::Sandbox(
                    "the engine detached the exec; output cannot be captured".to_string(),
                ))
            }
        };

        let mut stdout = String::new();
        let mut stderr = String::new();
        while let Some(chunk) = stream.next().await {
            match chunk.map_err(|e| HxError::Sandbox(format!("stream error: {e}")))? {
                LogOutput::StdOut { message } | LogOutput::Console { message } => {
                    stdout.push_str(&String::from_utf8_lossy(&message))
                }
                LogOutput::StdErr { message } => {
                    stderr.push_str(&String::from_utf8_lossy(&message))
                }
                LogOutput::StdIn { .. } => {}
            }
        }

        let inspected = self
            .docker
            .inspect_exec(&exec.id)
            .await
            .map_err(|e| HxError::Sandbox(format!("could not read the exec status: {e}")))?;

        Ok(SandboxExecOutput {
            stdout,
            stderr,
            exit_code: inspected.exit_code.unwrap_or(-1),
        })
    }
}

/// Convenience for the daemon: stream a container's logs.
pub async fn logs(docker: &Docker, runtime_id: &str, tail: &str) -> Result<Vec<String>> {
    let mut stream = docker.logs(
        runtime_id,
        Some(LogsOptions {
            stdout: true,
            stderr: true,
            tail: tail.to_string(),
            ..Default::default()
        }),
    );

    let mut lines = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| HxError::Sandbox(format!("log stream error: {e}")))?;
        lines.push(chunk.to_string());
    }
    Ok(lines)
}

/// Poll until the engine is responsive, or give up.
pub async fn wait_for_engine(timeout: Duration) -> Result<()> {
    let runtime = DockerRuntime::connect().await?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if runtime.available().await {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(HxError::Sandbox(format!(
                "the container engine did not respond within {}s",
                timeout.as_secs()
            )));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{SandboxSpec, DEFAULT_WORKSPACE_PATH};
    use hx_core::config::IsolationLevel;

    fn spec(isolation: IsolationLevel) -> SandboxSpec {
        SandboxSpec {
            profile: "dev".into(),
            image: "ubuntu:24.04".into(),
            isolation,
            cpus: 2.0,
            memory_mb: 4096,
            pids_max: 1024,
            workspace_mb: 8192,
            ttl_secs: 3600,
            egress_allow: Vec::new(),
            network: false,
            readonly_rootfs: true,
            workspace_host_path: "/tmp/hx/ws".into(),
            workspace_path: DEFAULT_WORKSPACE_PATH.into(),
            env: vec![("RUST_LOG".into(), "info".into())],
        }
    }

    #[test]
    fn engine_settings_carry_every_security_field_across() {
        // Field-by-field, because a silent drop here is a policy that is not enforced.
        let s = spec(IsolationLevel::L2);
        let engine = to_host_config(&s.host_settings());

        assert_eq!(engine.privileged, Some(false));
        assert_eq!(engine.readonly_rootfs, Some(true));
        assert_eq!(engine.cap_drop, Some(vec!["ALL".to_string()]));
        assert!(
            engine
                .security_opt
                .as_ref()
                .unwrap()
                .iter()
                .any(|o| o.starts_with("no-new-privileges")),
            "{:?}",
            engine.security_opt
        );
        assert_eq!(engine.network_mode.as_deref(), Some("none"));
        assert_eq!(engine.pids_limit, Some(1024));
        assert_eq!(engine.nano_cpus, Some(2_000_000_000));
        assert_eq!(engine.memory, Some(4096 * 1024 * 1024));
        assert_eq!(engine.init, Some(true));
    }

    #[test]
    fn engine_settings_never_leave_memory_unbounded_or_swappable() {
        let engine = to_host_config(&spec(IsolationLevel::L1).host_settings());
        assert!(
            engine.memory.is_some(),
            "an unbounded sandbox is not a sandbox"
        );
        assert_eq!(
            engine.memory_swap, engine.memory,
            "swap above the memory limit makes the limit advisory"
        );
    }

    #[test]
    fn l3_runtime_is_passed_to_the_engine() {
        let engine = to_host_config(&spec(IsolationLevel::L3).host_settings());
        assert_eq!(engine.runtime.as_deref(), Some("runsc"));
    }

    #[test]
    fn l1_capabilities_reach_the_engine_and_l2_adds_none() {
        let l1 = to_host_config(&spec(IsolationLevel::L1).host_settings());
        assert!(
            l1.cap_add
                .as_ref()
                .is_some_and(|c| c.contains(&"CHOWN".to_string())),
            "L1 must be able to build"
        );

        let l2 = to_host_config(&spec(IsolationLevel::L2).host_settings());
        assert_eq!(l2.cap_add, None, "L2 grants nothing back");
    }

    #[test]
    fn tmpfs_entries_become_the_map_the_engine_expects() {
        let engine = to_host_config(&spec(IsolationLevel::L1).host_settings());
        let tmpfs = engine.tmpfs.expect("tmpfs must be set");
        assert!(tmpfs.contains_key("/tmp"));
        assert!(tmpfs["/tmp"].contains("noexec"));
    }

    #[test]
    fn the_workspace_bind_reaches_the_engine() {
        let engine = to_host_config(&spec(IsolationLevel::L1).host_settings());
        assert_eq!(
            engine.binds,
            Some(vec!["/tmp/hx/ws:/workspace:rw".to_string()])
        );
    }

    #[test]
    fn a_spec_with_no_binds_does_not_send_an_empty_list() {
        let mut s = spec(IsolationLevel::L1);
        s.workspace_host_path = String::new();
        assert_eq!(to_host_config(&s.host_settings()).binds, None);
    }

    #[test]
    fn the_container_body_uses_the_image_and_a_non_burning_command() {
        let s = spec(IsolationLevel::L1);
        let body = to_container_config(&s, &s.host_settings());

        assert_eq!(body.image.as_deref(), Some("ubuntu:24.04"));
        let cmd = body
            .cmd
            .expect("a sandbox needs a command that keeps it alive");
        assert!(cmd.join(" ").contains("infinity"), "{cmd:?}");
        assert_eq!(body.working_dir.as_deref(), Some("/workspace"));
        assert_eq!(
            body.user.as_deref(),
            Some("1000:1000"),
            "the sandbox must not run as root; the user lives on the body, not in HostConfig"
        );
        assert_eq!(
            body.tty,
            Some(false),
            "a pty makes output ordering nondeterministic"
        );
    }

    #[test]
    fn environment_variables_are_rendered_as_key_equals_value() {
        let s = spec(IsolationLevel::L1);
        let body = to_container_config(&s, &s.host_settings());
        assert_eq!(body.env, Some(vec!["RUST_LOG=info".to_string()]));
    }

    #[test]
    fn an_empty_environment_is_not_sent_as_an_empty_list() {
        let mut s = spec(IsolationLevel::L1);
        s.env.clear();
        let body = to_container_config(&s, &s.host_settings());
        assert_eq!(body.env, None);
    }

    #[test]
    fn container_names_are_namespaced_and_greppable() {
        let runtime = DockerRuntime::from_client(Docker::connect_with_local_defaults().unwrap());
        let name = runtime.container_name(&SandboxId::from_raw("sbx_abc123"));
        assert_eq!(name, "hx-sbx_abc123");
        assert!(name.starts_with("hx-"), "so `docker ps` can find ours");
    }
}
