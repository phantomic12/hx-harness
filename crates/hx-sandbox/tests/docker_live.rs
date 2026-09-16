//! Integration tests against a **real** container engine.
//!
//! Everything else about the isolation ladder is a mapping function: `SandboxSpec -> HostConfig`
//! asserted field by field. That proves the *intent* is translated, not that the engine accepts it
//! or that the kernel enforces it. This file is where the ladder meets a daemon.
//!
//! It was written because of a defect the unit tests could not see: `userns=keep-id` was passed as
//! a `security_opt`, which a Docker daemon refuses at create time
//! (`invalid --security-opt 2: "userns=keep-id"`). Every L2 and L3 sandbox — the levels meant for
//! hostile code — could not be created at all, and the whole suite was green.
//!
//! Run them explicitly:
//!
//! ```console
//! $ cargo test -p hx-sandbox --test docker_live -- --ignored --test-threads=1
//! ```
//!
//! Optional: `HX_DOCKER_TEST_IMAGE` (default `ubuntu:24.04`). The image must be pullable by the
//! daemon; the tests do not pull, so a missing image fails a test rather than hanging on a network.

use bollard::query_parameters::{InspectContainerOptions, ListContainersOptions};
use bollard::Docker;
use chrono::Utc;
use hx_core::config::IsolationLevel;
use hx_sandbox::docker::DockerRuntime;
use hx_sandbox::runtime::{SandboxExecOutput, SandboxManager};
use hx_sandbox::spec::{SandboxSpec, DEFAULT_WORKSPACE_PATH};
use std::sync::Arc;

/// The image to build sandboxes from. Ubuntu is the default everywhere else in the repo.
fn image() -> String {
    std::env::var("HX_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "ubuntu:24.04".to_string())
}

struct Live {
    manager: SandboxManager,
    docker: Docker,
    /// Held so the directory outlives the container that bind-mounts it.
    _workspace: tempfile::TempDir,
    workspace_path: String,
}

/// Connect to the daemon, or return `None` when there is no engine to talk to.
///
/// A missing engine is a skip, not a failure: these tests are `#[ignore]`d, so running them means
/// asking for them, but "asked for" is not the same as "this machine has Docker".
async fn live(cap: usize) -> Option<Live> {
    let runtime = match DockerRuntime::connect().await {
        Ok(runtime) => Arc::new(runtime),
        Err(err) => {
            eprintln!("skipped: could not create a Docker client: {err}");
            return None;
        }
    };

    use hx_sandbox::runtime::SandboxRuntime as _;
    if !runtime.available().await {
        eprintln!("skipped: no reachable Docker daemon");
        return None;
    }

    let docker = Docker::connect_with_local_defaults().ok()?;
    let workspace = tempfile::tempdir().expect("a temp workspace");
    let workspace_path = workspace.path().to_string_lossy().into_owned();

    Some(Live {
        manager: SandboxManager::new(runtime, cap),
        docker,
        _workspace: workspace,
        workspace_path,
    })
}

fn spec(live: &Live, isolation: IsolationLevel, ttl_secs: u64, pids_max: i64) -> SandboxSpec {
    SandboxSpec {
        profile: format!("live-{isolation:?}").to_lowercase(),
        image: image(),
        isolation,
        cpus: 1.0,
        memory_mb: 512,
        pids_max,
        workspace_mb: 1024,
        ttl_secs,
        egress_allow: Vec::new(),
        network: false,
        // Deliberately false for L1/L2: both must still end up read-only, L2 because it forces it
        // and L1 because... it does not. See the level-specific assertions below.
        readonly_rootfs: false,
        workspace_host_path: live.workspace_path.clone(),
        workspace_path: DEFAULT_WORKSPACE_PATH.to_string(),
        // Left as `None` here; `spec()`'s caller adopts the workspace owner, which is what makes
        // the write below work on a host whose uid is not 1000 (a CI runner, for one).
        user: None,
        env: Vec::new(),
    }
}

/// A spec that will actually be able to write its workspace.
fn writable_spec(
    live: &Live,
    isolation: IsolationLevel,
    ttl_secs: u64,
    pids_max: i64,
) -> SandboxSpec {
    let mut spec = spec(live, isolation, ttl_secs, pids_max);
    spec.adopt_workspace_owner()
        .expect("the temp workspace is statable");
    spec
}

/// Whether the engine still has this container.
async fn container_exists(docker: &Docker, name: &str) -> bool {
    docker
        .inspect_container(name, None::<InspectContainerOptions>)
        .await
        .is_ok()
}

/// Every `hx-` container on the daemon, by name.
async fn hx_containers(docker: &Docker) -> Vec<String> {
    docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            ..Default::default()
        }))
        .await
        .expect("the daemon listed containers")
        .into_iter()
        .flat_map(|c| c.names.unwrap_or_default())
        .filter(|name| name.starts_with("/hx-"))
        .collect()
}

async fn exec(manager: &SandboxManager, id: &str, command: &str) -> SandboxExecOutput {
    manager
        .exec(id, command, None)
        .await
        .unwrap_or_else(|err| panic!("exec {command:?} failed: {err}"))
}

// ---------------------------------------------------------------------------------------------
// The level the unit tests could not reach
// ---------------------------------------------------------------------------------------------

#[ignore = "requires a docker daemon"]
#[tokio::test]
async fn an_l2_sandbox_is_created_by_a_real_daemon_and_carries_its_settings() {
    let Some(live) = live(4).await else { return };

    let spec = writable_spec(&live, IsolationLevel::L2, 3600, 128);
    // This is the assertion that would have failed before: the create call itself.
    let handle = live
        .manager
        .spawn(&spec, Utc::now())
        .await
        .expect("the daemon accepts an L2 sandbox");

    // What the daemon actually stored, not what we asked for.
    let inspected = live
        .docker
        .inspect_container(&handle.runtime_id, None::<InspectContainerOptions>)
        .await
        .expect("the container exists");

    let host = inspected.host_config.expect("a host config");
    assert_eq!(host.network_mode.as_deref(), Some("none"));
    assert_eq!(
        host.readonly_rootfs,
        Some(true),
        "L2 forces a read-only root"
    );
    assert_eq!(host.pids_limit, Some(128));
    assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
    assert_eq!(host.privileged, Some(false));
    assert!(
        host.userns_mode.as_deref() == Some("private"),
        "remapping is requested through the field the engine has for it: {:?}",
        host.userns_mode
    );
    assert!(
        !host
            .security_opt
            .unwrap_or_default()
            .iter()
            .any(|o| o.starts_with("userns=")),
        "the security-option spelling is rejected by the daemon"
    );
    assert_eq!(
        host.memory, host.memory_swap,
        "swap above the limit makes the limit advisory"
    );

    let config = inspected.config.expect("a container config");
    // Whoever owns the workspace, and never root: on a host whose user is not uid 1000 the
    // hardcoded default left every write into the mount failing with `Permission denied`.
    let expected_user = spec.user.clone().expect("the workspace owner was adopted");
    assert_eq!(
        config.user.as_deref(),
        Some(expected_user.as_str()),
        "the sandbox must run as the workspace owner, not as root"
    );
    assert_ne!(expected_user, "0:0");

    // And it is a working container, not just an accepted one. The uid is the workspace's owner —
    // on CI's runner that is 1001, not the 1000 the spec used to hardcode, which is why the
    // workspace was unwritable there.
    let out = exec(&live.manager, handle.id.as_str(), "id -u; echo alive").await;
    assert!(out.success(), "{out:?}");
    let uid = expected_user.split(':').next().expect("uid:gid");
    assert_eq!(
        out.stdout.trim(),
        format!("{uid}\nalive"),
        "the container has to run as the owner of the mount, or the workspace is read-only"
    );

    live.manager.destroy(handle.id.as_str()).await.unwrap();
    assert!(
        !container_exists(&live.docker, &handle.runtime_id).await,
        "a destroyed sandbox must be gone from the engine"
    );
}

#[ignore = "requires a docker daemon"]
#[tokio::test]
async fn network_none_really_blocks_egress() {
    let Some(live) = live(4).await else { return };
    let handle = live
        .manager
        .spawn(
            &writable_spec(&live, IsolationLevel::L2, 3600, 128),
            Utc::now(),
        )
        .await
        .expect("spawn");

    // A TCP connection attempt. `network=none` gives the container a loopback interface and
    // nothing else, so this must fail rather than merely be discouraged.
    let out = exec(
        &live.manager,
        handle.id.as_str(),
        "timeout 3 bash -c 'echo > /dev/tcp/1.1.1.1/80' && echo REACHED || echo BLOCKED",
    )
    .await;
    assert!(
        out.stdout.contains("BLOCKED"),
        "egress was not blocked: {out:?}"
    );

    // DNS too, which is the other half of "no network".
    let dns = exec(
        &live.manager,
        handle.id.as_str(),
        "timeout 3 getent hosts example.com || echo NO_DNS",
    )
    .await;
    assert!(dns.stdout.contains("NO_DNS"), "DNS resolved: {dns:?}");

    // The interface list is the explanation, and it is worth having in the log.
    let ifaces = exec(
        &live.manager,
        handle.id.as_str(),
        "ip -o link 2>/dev/null | wc -l",
    )
    .await;
    eprintln!(
        "egress probe: {} | dns: {} | interfaces: {}",
        out.stdout.trim(),
        dns.stdout.trim(),
        ifaces.stdout.trim()
    );

    live.manager.destroy(handle.id.as_str()).await.unwrap();
}

#[ignore = "requires a docker daemon"]
#[tokio::test]
async fn a_read_only_root_rejects_writes_while_the_workspace_stays_writable() {
    let Some(live) = live(4).await else { return };
    let handle = live
        .manager
        .spawn(
            &writable_spec(&live, IsolationLevel::L2, 3600, 128),
            Utc::now(),
        )
        .await
        .expect("spawn");

    let root_write = exec(
        &live.manager,
        handle.id.as_str(),
        "touch /definitely-not-allowed",
    )
    .await;
    assert!(
        !root_write.success(),
        "a read-only root accepted a write: {root_write:?}"
    );

    let tmp_write = exec(
        &live.manager,
        handle.id.as_str(),
        "touch /tmp/ok && echo TMP_WRITABLE",
    )
    .await;
    assert!(
        tmp_write.stdout.contains("TMP_WRITABLE"),
        "the scratch area is what makes a read-only root usable: {tmp_write:?}"
    );

    // `noexec` on the scratch area: a dropped binary there must not run.
    let dropped = exec(
        &live.manager,
        handle.id.as_str(),
        "cp /bin/true /tmp/dropped 2>/dev/null; /tmp/dropped 2>&1; echo exit=$?",
    )
    .await;
    assert!(
        !dropped.stdout.contains("exit=0"),
        "a binary executed from a noexec scratch mount: {dropped:?}"
    );

    let workspace_write = exec(
        &live.manager,
        handle.id.as_str(),
        "touch /workspace/from-inside && echo WORKSPACE_WRITABLE",
    )
    .await;
    assert!(
        workspace_write.stdout.contains("WORKSPACE_WRITABLE"),
        "the workspace is where the agent's work happens: {workspace_write:?}"
    );

    // The write really landed on the host, which is what "the workspace survives the sandbox"
    // means in practice.
    assert!(
        live._workspace.path().join("from-inside").exists(),
        "the bind mount did not reach the host directory"
    );

    live.manager.destroy(handle.id.as_str()).await.unwrap();
}

#[ignore = "requires a docker daemon"]
#[tokio::test]
async fn the_pid_ceiling_is_applied_by_the_kernel_and_stops_a_fork_bomb() {
    let Some(live) = live(4).await else { return };
    // A ceiling low enough that 200 processes cannot fit, high enough for the container's own init.
    let handle = live
        .manager
        .spawn(
            &writable_spec(&live, IsolationLevel::L2, 3600, 64),
            Utc::now(),
        )
        .await
        .expect("spawn");

    // What the kernel was told, read from *inside* the container so it is the sandbox's own cgroup
    // and not the host's.
    let ceiling = exec(
        &live.manager,
        handle.id.as_str(),
        "cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max 2>/dev/null",
    )
    .await;
    assert_eq!(
        ceiling.stdout.trim(),
        "64",
        "the process ceiling is not applied to the sandbox's cgroup: {ceiling:?}"
    );

    // And that the kernel enforces it. Two hundred processes cannot fit under a ceiling of 64, and
    // the shell reports the refusal rather than hanging. `sleep 2`, not `sleep 60`: the slots have
    // to come back, or the assertions below could not fork either.
    let bomb = exec(
        &live.manager,
        handle.id.as_str(),
        "sh -c 'for i in $(seq 1 200); do sleep 2 & done; echo attempted-all-200'",
    )
    .await;
    let refused = bomb.stderr.to_lowercase().contains("fork") || !bomb.success();
    assert!(
        refused,
        "200 processes were all allowed under a ceiling of 64: {bomb:?}"
    );
    assert!(
        !bomb.stdout.contains("attempted-all-200"),
        "the loop ran to completion, so nothing was refused: {bomb:?}"
    );

    // The sandbox survives its own fork bomb, which is the point of a ceiling.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let after = exec(&live.manager, handle.id.as_str(), "echo still-alive").await;
    assert!(after.stdout.contains("still-alive"), "{after:?}");

    eprintln!(
        "pid ceiling 64 enforced by the kernel: {}",
        bomb.stderr.trim()
    );

    live.manager.destroy(handle.id.as_str()).await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Lifecycle: the leak-prevention invariants, against a real engine
// ---------------------------------------------------------------------------------------------

#[ignore = "requires a docker daemon"]
#[tokio::test]
async fn the_ttl_reaper_actually_removes_the_container() {
    let Some(live) = live(4).await else { return };
    let handle = live
        .manager
        .spawn(&writable_spec(&live, IsolationLevel::L2, 1, 64), Utc::now())
        .await
        .expect("spawn");

    assert!(container_exists(&live.docker, &handle.runtime_id).await);

    // Let the TTL pass, then sweep. The bookkeeping is unit-tested; the removal is what needs a
    // daemon, because a reaper that only forgets is a disk-eating bug with a clean test suite.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let reaped = live.manager.reap(Utc::now()).await.expect("reap");

    assert_eq!(reaped, vec![handle.id.clone()]);
    assert!(
        !container_exists(&live.docker, &handle.runtime_id).await,
        "the reaper deregistered the sandbox but left the container behind"
    );
    assert!(live.manager.list().await.is_empty());
}

#[ignore = "requires a docker daemon"]
#[tokio::test]
async fn destroying_a_sandbox_stops_and_removes_it_and_is_idempotent() {
    let Some(live) = live(4).await else { return };
    let handle = live
        .manager
        .spawn(
            &writable_spec(&live, IsolationLevel::L2, 3600, 64),
            Utc::now(),
        )
        .await
        .expect("spawn");

    live.manager.destroy(handle.id.as_str()).await.unwrap();
    assert!(!container_exists(&live.docker, &handle.runtime_id).await);
    assert_eq!(live.manager.free_slots().await, 4, "the slot is released");

    // "Make sure this is gone" is the meaning, so a second call must not fail a cleanup path.
    live.manager.destroy(handle.id.as_str()).await.unwrap();
}

#[ignore = "requires a docker daemon"]
#[tokio::test]
async fn the_concurrency_cap_refuses_the_n_plus_first_container() {
    let Some(live) = live(1).await else { return };
    let before = hx_containers(&live.docker).await.len();

    let first = live
        .manager
        .spawn(
            &writable_spec(&live, IsolationLevel::L2, 3600, 64),
            Utc::now(),
        )
        .await
        .expect("the first sandbox fits");

    let err = live
        .manager
        .spawn(
            &writable_spec(&live, IsolationLevel::L2, 3600, 64),
            Utc::now(),
        )
        .await
        .expect_err("the second must be refused");
    assert!(err.to_string().contains("1 of 1"), "{err}");

    // Refused means nothing was created, not "created and then cleaned up".
    assert_eq!(
        hx_containers(&live.docker).await.len(),
        before + 1,
        "the cap was enforced after the engine had already been asked"
    );

    live.manager.destroy(first.id.as_str()).await.unwrap();
}

#[ignore = "requires a docker daemon"]
#[tokio::test]
async fn a_missing_image_fails_without_leaving_a_container_behind() {
    let Some(live) = live(4).await else { return };
    let before = hx_containers(&live.docker).await.len();

    let mut spec = writable_spec(&live, IsolationLevel::L2, 3600, 64);
    spec.image = "hx-does-not-exist:never".to_string();

    let err = live
        .manager
        .spawn(&spec, Utc::now())
        .await
        .expect_err("the daemon cannot build a container from an image it does not have");
    assert!(
        err.to_string().contains("hx-does-not-exist"),
        "the error must name the image: {err}"
    );

    assert!(
        live.manager.list().await.is_empty(),
        "nothing may be tracked after a failed spawn"
    );
    assert_eq!(
        live.manager.free_slots().await,
        4,
        "a failed spawn must not consume a slot"
    );
    assert_eq!(
        hx_containers(&live.docker).await.len(),
        before,
        "a failed spawn left a container behind"
    );
}
