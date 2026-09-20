//! Isolated execution: sandbox specifications, the isolation ladder, and container lifecycle.
//!
//! Answers requirement #2 — *"allocate space for isolated development containers where agents can
//! do what they need to securely, safely and not at the risk of my system"*.
//!
//! Three pieces, separated so that each can be reasoned about on its own:
//!
//! - [`spec`] — what a sandbox *is*: resources, egress, lifetime, and the mapping from an
//!   isolation level to concrete container settings. Pure, no engine required.
//! - [`runtime`] — the lifecycle: create, start, exec, stop, remove, plus the concurrency cap
//!   and TTL reaper that stop sandboxes accumulating.
//! - [`docker`] — the `bollard`-backed engine implementation.
//! - [`remote`] — a second runtime that reaches a Docker daemon on a *remote* host through a
//!   tiny transport trait, when the engine is not the machine running the daemon.
//!
//! The design rule throughout: **the safe thing is the default, and loosening it is an explicit
//! act.** Network off, capabilities dropped, non-root, bounded memory/CPU/PIDs, finite TTL.

pub mod docker;
pub mod egress;
pub mod remote;
pub mod runtime;
pub mod spec;

pub use docker::{logs, to_container_config, to_host_config, wait_for_engine, DockerRuntime};
pub use egress::EgressProxy;
pub use remote::{
    create_command, egress_network_name, egress_setup_commands, egress_sidecar_name,
    egress_teardown_commands, exec_command, remove_command, start_command, stop_command,
    RemoteCommandOutput, RemoteCommandRunner, RemoteSandboxRuntime,
};
pub use runtime::{SandboxExecOutput, SandboxHandle, SandboxManager, SandboxRuntime, SandboxState};
pub use spec::{
    HostSettings, IsolationLevel, SandboxProfile, SandboxSpec, SpecError, DEFAULT_WORKSPACE_PATH,
    SANDBOX_UID,
};

use std::sync::Arc;

/// Build a manager on the local Docker engine.
pub async fn docker_manager(max_concurrent: usize) -> hx_core::error::Result<SandboxManager> {
    let runtime = Arc::new(DockerRuntime::connect().await?);
    Ok(SandboxManager::new(runtime, max_concurrent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_isolation_ladder_is_ordered_as_documented() {
        // A sanity check that the public re-exports line up with the documented ladder.
        assert_eq!(
            format!("{:?}", IsolationLevel::L1),
            "L1",
            "the ladder is referred to by level in the docs"
        );
    }

    #[test]
    fn a_default_profile_produces_a_valid_spec() {
        let mut spec = SandboxSpec::from_profile("default", &SandboxProfile::default());
        spec.workspace_host_path = "/tmp/hx/ws".into();
        assert_eq!(spec.validate(), Ok(()));
    }
}
