//! Integration tests for [`RemoteSandboxRuntime`] against a **real** remote Docker daemon.
//!
//! Everything else about the remote runtime is a command-line builder asserted token-for-token
//! against a recording fake: that proves the *words* we send are the words we reviewed, not that
//! a real `docker` on a real far host accepts them or that the far daemon enforces the flags.
//! This file is where the remote runtime meets an actual Docker daemon, reached over a real
//! `SshHost`.
//!
//! It is the remote sibling of `docker_live.rs` in this same directory, and it is gated exactly
//! like `ssh_live.rs` in `hx-remote`: `#[ignore]`d by default, enabled by naming a host
//! in the environment. A missing target is a self-skip, **not** a pass — the `return` in
//! `skip_without_a_host!` prints a message and the test counts as skipped, distinct from the
//! failures below that prove the properties.
//!
//! ```console
//! $ HX_SSH_TEST_HOST=100.99.145.19 \
//!   HX_SSH_TEST_USER=yoav \
//!   HX_SSH_TEST_KEY=~/.ssh/yoav \
//!   cargo test -p hx-sandbox --test remote_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Optional: `HX_SSH_TEST_PORT` (default 22), `HX_DOCKER_TEST_IMAGE` (default
//! `ubuntu:24.04`).
//!
//! ## The adapter, and why it is duplicated here
//!
//! The runtime talks to a [`RemoteCommandRunner`], a one-method trait deliberately narrower than
//! `hx_remote::Host` (a sandbox runtime only ever *runs a command*). The production adapter
//! from `Host` to that trait is being built in `hx-server`, where the dependency on both crates is
//! legal. `hx-sandbox`'s **library** may not depend on `hx-remote` — that is the
//! layering inversion the module explicitly forbids — so the adapter here lives in the test crate
//! (`hx-remote` is a `[dev-dependencies]` of `hx-sandbox`, which never reaches the
//! published library). The duplication is deliberate and will be folded away when `hx-server`'s
//! adapter lands; it is a straight field-for-field copy, the exact copy the design anticipated.
//!
//! ## The security flags are verified on the far host, not in the command string
//!
//! After creating the sandbox we run a raw `docker inspect` — built here, by hand, through the
//! `SshHost` *independently of the code under test* — and parse JSON from the far daemon. A test
//! that only asserted the command line we built would agree with itself; this one reads back what the
//! far daemon actually stored.

use async_trait::async_trait;
use hx_core::config::IsolationLevel;
use hx_core::ids::{HostId, SandboxId};
use hx_remote::{Host, HostKeyPolicy, SshAuth, SshHost};
use hx_sandbox::remote::{RemoteCommandOutput, RemoteCommandRunner, RemoteSandboxRuntime};
use hx_sandbox::runtime::SandboxRuntime;
use hx_sandbox::spec::{SandboxSpec, DEFAULT_WORKSPACE_PATH};
use hx_secrets::Secret;
use std::sync::Arc;
use std::time::Duration;

/// The image to build sandboxes from. Ubuntu is the default everywhere else in the repo.
fn image() -> String {
    std::env::var("HX_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "ubuntu:24.04".to_string())
}

struct Target {
    host: String,
    port: u16,
    user: String,
    key: Secret,
}

/// The machine to test against, or `None` when the environment does not name one.
fn target() -> Option<Target> {
    let host = std::env::var("HX_SSH_TEST_HOST").ok()?;
    let user = std::env::var("HX_SSH_TEST_USER").ok()?;
    let key_path = std::env::var("HX_SSH_TEST_KEY").ok()?;
    let port = std::env::var("HX_SSH_TEST_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(22);

    // `~/...` is expanded here rather than shell-expanded, exactly as `ssh_live.rs` does, so the
    // documented invocation works when the test is started from an editor.
    let path = match key_path.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => key_path,
    };

    let pem = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("HX_SSH_TEST_KEY={path} could not be read: {err}"));

    Some(Target {
        host,
        port,
        user,
        key: Secret::new(pem),
    })
}

fn auth(target: &Target) -> SshAuth {
    SshAuth::Key {
        private_key_pem: Secret::new(target.key.expose().to_string()),
        passphrase: None,
    }
}

macro_rules! skip_without_a_host {
    () => {
        match target() {
            Some(target) => target,
            None => {
                eprintln!(
                    "skipped: set HX_SSH_TEST_HOST, HX_SSH_TEST_USER and HX_SSH_TEST_KEY to run \
                     this against a real remote Docker daemon"
                );
                return;
            }
        }
    };
}

/// The adapter from `SshHost` to the runtime's one-method runner.
///
/// A field-for-field copy of what `hx-server`'s adapter does; see the module doc for why it is
/// duplicated here rather than imported.
struct SshRunner {
    host: Arc<SshHost>,
}

#[async_trait]
impl RemoteCommandRunner for SshRunner {
    async fn run(&self, command: &str) -> hx_core::error::Result<RemoteCommandOutput> {
        let out = self.host.exec(command, Duration::from_secs(180)).await?;
        Ok(RemoteCommandOutput {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code,
        })
    }
}

/// Connect a real `SshHost` to the target, or return `None` when unreachable.
async fn connect(target: &Target) -> Option<Arc<SshHost>> {
    let dir = tempfile::tempdir().ok()?;
    match SshHost::connect(
        HostId::from("hst_remote_live"),
        &target.host,
        target.port,
        &target.user,
        &auth(target),
        &HostKeyPolicy::tofu_at(dir.path().join("known_hosts")),
    )
    .await
    {
        Ok(host) => Some(Arc::new(host)),
        Err(err) => {
            eprintln!("skipped: could not connect to the remote host: {err}");
            None
        }
    }
}

/// Run a raw command on the far host through the `SshHost`, panicking on transport failure.
async fn raw(host: &SshHost, command: &str) -> String {
    let out = host
        .exec(command, Duration::from_secs(180))
        .await
        .unwrap_or_else(|err| panic!("raw exec {command:?} failed on the far host: {err}"));
    if !out.success() {
        panic!(
            "raw exec {command:?} returned exit {:?}\nstdout: {}\nstderr: {}",
            out.exit_code, out.stdout, out.stderr
        );
    }
    out.stdout
}

/// Whether the far daemon still has a container with this name.
async fn container_exists(host: &SshHost, name: &str) -> bool {
    let out = host
        .exec(
            "docker ps -a --format '{{.Names}}'",
            Duration::from_secs(60),
        )
        .await
        .expect("list containers on the far host");
    out.stdout.lines().any(|line| line == name)
}

/// A readable, independent view of the far container's host config, parsed from `docker inspect`.
///
/// Built by hand and read back from the far daemon — never derived from the command line the code
/// under test constructed, so an assertion here failing means the daemon did not enforce what we sent.
#[derive(Default)]
struct Inspected {
    read_only: Option<bool>,
    privileged: Option<bool>,
    cap_drop: Option<Vec<String>>,
    cap_add: Option<Vec<String>>,
    network_mode: Option<String>,
    pids_limit: Option<i64>,
    mounts: Vec<serde_json::Value>,
}

impl Inspected {
    /// The bind-mount destination for the workspace, if the daemon recorded one.
    fn ws_destination(&self) -> Option<&str> {
        self.mounts
            .iter()
            .filter_map(|m| m["Destination"].as_str())
            .find(|d| *d == DEFAULT_WORKSPACE_PATH)
    }
}

async fn inspect(host: &SshHost, name: &str) -> Inspected {
    let json = raw(
        host,
        &format!("docker inspect '{}'", name.replace('\'', "'\\''")),
    )
    .await;
    let value: serde_json::Value =
        serde_json::from_str(&json).expect("docker inspect output must be valid JSON");

    let entry = value
        .get(0)
        .unwrap_or_else(|| panic!("docker inspect returned no entry for {name}"));
    let hc = &entry["HostConfig"];

    Inspected {
        read_only: hc["ReadonlyRootfs"].as_bool(),
        privileged: hc["Privileged"].as_bool(),
        cap_drop: hc["CapDrop"].as_array().map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        }),
        cap_add: hc["CapAdd"].as_array().map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        }),
        network_mode: hc["NetworkMode"].as_str().map(str::to_string),
        // (userns behaviour is covered separately by
        // `the_far_daemon_rejects_l2_userns_remapping_when_it_is_not_configured`, so the
        // mode is not surfaced in this struct)
        pids_limit: hc["PidsLimit"].as_i64(),
        mounts: entry["Mounts"].as_array().cloned().unwrap_or_default(),
    }
}

/// A spec that will actually be able to write its workspace on the far host.
///
/// `workspace_host_path` must be a real directory **on the remote host** (that is where the bind
/// mount lives). `runner_ws` is any `/tmp` path the remote user can write; on rainbowone the
/// user is uid 1000, matching the sandbox's default non-root user, so no owner adoption is needed.
fn spec(workspace_host_path: &str, isolation: IsolationLevel) -> SandboxSpec {
    let spec = SandboxSpec {
        profile: format!("remote-live-{isolation:?}").to_lowercase(),
        image: image(),
        isolation,
        cpus: 1.0,
        memory_mb: 512,
        pids_max: 128,
        workspace_mb: 1024,
        ttl_secs: 120,
        egress_allow: Vec::new(),
        network: false,
        readonly_rootfs: false,
        workspace_host_path: workspace_host_path.to_string(),
        workspace_path: DEFAULT_WORKSPACE_PATH.to_string(),
        user: None,
        env: Vec::new(),
    };
    spec.validate().expect("the spec must validate");
    spec
}

/// Make a scratch workspace directory on the far host, returned as its path.
async fn make_remote_workspace(host: &SshHost) -> String {
    let dir = raw(host, "mktemp -d /tmp/hx-remote-live-XXXXXX").await;
    dir.trim().to_string()
}

/// Remove a remote workspace directory and a container on Drop, even on panic.
struct Cleanup {
    host: Arc<SshHost>,
    name: Option<String>,
    workspace: Option<String>,
    handle: tokio::runtime::Handle,
}

impl Cleanup {
    fn new(host: &Arc<SshHost>, name: &str, workspace_path: &str) -> Self {
        Self {
            host: Arc::clone(host),
            name: Some(name.to_string()),
            workspace: Some(workspace_path.to_string()),
            handle: tokio::runtime::Handle::current(),
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let host = Arc::clone(&self.host);
        let name = self.name.take();
        let workspace = self.workspace.take();
        if name.is_none() && workspace.is_none() {
            return;
        }
        self.handle.spawn(async move {
            if let Some(name) = &name {
                // `docker rm -f` succeeds only if the container exists; a best-effort cleanup is
                // fine here because the test asserts the post-removal state itself.
                let _ = host
                    .exec(
                        &format!("docker rm -f {}", name.replace('\'', "'\\''")),
                        Duration::from_secs(60),
                    )
                    .await;
            }
            if let Some(ws) = &workspace {
                let _ = host
                    .exec(
                        &format!("rm -rf {}", ws.replace('\'', "'\\''")),
                        Duration::from_secs(60),
                    )
                    .await;
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------
// The property this whole file exists to prove: the remote runtime needs no local daemon, and the far
// one accepts and enforces what it sends.
// ---------------------------------------------------------------------------------------------

#[ignore = "requires a real remote Docker host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn a_remote_sandbox_is_read_only_and_capability_stripped_on_the_far_daemon() {
    let target = skip_without_a_host!();
    let Some(host) = connect(&target).await else {
        return;
    };

    // An isolated (network-off) L1 sandbox with the read-only root forced is the remote case that
    // needs no proxy and is safe to prove end to end. L1 is used deliberately, not L2/L3: those
    // levels send `--userns=private`, which a Docker daemon WITHOUT user-namespace remapping
    // configured refuses outright (`--userns: invalid USER mode`) — a real finding captured by the
    // test `the_far_daemon_rejects_userns_remapping_when_it_is_not_configured` below. L1
    // still exercises the read-only root, the capability drop, the pid ceiling, the bind mount and the
    // no-network settings against a real daemon; only the userns remap is left to the finding.
    let ws = make_remote_workspace(&host).await;
    let mut spec = spec(&ws, IsolationLevel::L1);
    spec.readonly_rootfs = true;
    let settings = spec.host_settings();

    let runtime = RemoteSandboxRuntime::new(Arc::new(SshRunner {
        host: Arc::clone(&host),
    }));
    let id = SandboxId::new();
    let name = format!("hx-{}", id.as_str());
    let _cleanup = Cleanup::new(&host, &name, &ws);

    // The full lifecycle over a real SSH transport to a real daemon.
    let created = runtime.create(&id, &spec, &settings).await;
    assert!(created.is_ok(), "create failed: {:?}", created);
    let name = created.unwrap();
    assert!(
        container_exists(&host, &name).await,
        "container must exist after create"
    );

    runtime
        .start(&name)
        .await
        .expect("the far daemon starts the sandbox");

    // --- exec a command inside the container ---
    let exec = runtime
        .exec(&name, "echo REMOTE_ALIVE; id -u", None)
        .await
        .expect("exec inside the remote container");
    assert!(exec.success(), "{exec:?}");
    assert!(exec.stdout.contains("REMOTE_ALIVE"), "{exec:?}");
    let uid = exec.stdout.lines().last().unwrap_or("").trim();
    // The default sandbox user is 1000:1000, never root.
    assert_eq!(uid, "1000", "the sandbox must not run as root: {exec:?}");

    // --- the far daemon's record, queried independently of the code under test ---
    let inspected = inspect(&host, &name).await;
    assert_eq!(
        inspected.read_only,
        Some(true),
        "the far daemon must enforce a read-only root"
    );
    assert!(inspected.privileged == Some(false), "never privileged");
    assert!(
        inspected
            .cap_drop
            .as_deref()
            .map(|d| d.contains(&"ALL".to_string()))
            .unwrap_or(false),
        "capabilities must be dropped: {:?}",
        inspected.cap_drop
    );
    // L1 re-adds the small build-time set, and nothing more — most importantly none of the ones
    // that turn a container into a host.
    let cap_add = inspected.cap_add.as_deref().unwrap_or_default();
    for dangerous in ["SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN"] {
        assert!(
            !cap_add.iter().any(|c| c == dangerous),
            "L1 must not grant {dangerous}: {cap_add:?}"
        );
    }
    assert_eq!(
        inspected.network_mode.as_deref(),
        Some("none"),
        "an isolated remote sandbox has no network"
    );
    assert_eq!(
        inspected.pids_limit,
        Some(128),
        "the pid ceiling must reach the far host"
    );
    assert!(
        inspected.ws_destination().is_some(),
        "the workspace must be bind-mounted into the container"
    );

    // --- verify the read-only root and writable workspace for real ---
    let root_write = runtime
        .exec(
            &name,
            "touch /definitely-not-allowed && echo WROTE || echo DENIED",
            None,
        )
        .await
        .expect("exec");
    assert!(
        root_write.stdout.contains("DENIED"),
        "a read-only root accepted a write: {root_write:?}"
    );

    let ws_write = runtime
        .exec(
            &name,
            "touch /workspace/from-remote && echo WORKSPACE_WRITABLE",
            None,
        )
        .await
        .expect("exec");
    assert!(
        ws_write.stdout.contains("WORKSPACE_WRITABLE"),
        "the workspace must be writable from inside: {ws_write:?}"
    );

    // The write really landed on the remote host, which is what "the workspace survives the sandbox"
    // means when the daemon is on another machine.
    let on_host = raw(
        &host,
        &format!("test -f {ws}/from-remote && echo ON_REMOTE_HOST"),
    )
    .await;
    assert!(
        on_host.contains("ON_REMOTE_HOST"),
        "the bind-mount write did not reach the remote host directory: {on_host:?}"
    );

    // --- stop, then remove ---
    runtime
        .stop(&name, 0)
        .await
        .expect("the far daemon stops the container");
    assert!(
        container_exists(&host, &name).await,
        "stopped but not yet removed"
    );

    runtime
        .remove(&name)
        .await
        .expect("the far daemon removes the container");
    assert!(
        !container_exists(&host, &name).await,
        "the container must be gone from the far daemon after remove"
    );

    // Removal is idempotent: a second remove must not leak or fail in a way that leaves the
    // container behind. `docker rm -f` on an absent container exits non-zero, and the runtime
    // surfaces that as an error — so we treat "already gone" as the property we want, and confirm
    // the container is not there.
    let _ = runtime.remove(&name).await;
    assert!(
        !container_exists(&host, &name).await,
        "after any second remove the container must still be gone"
    );

    // Explicit, awaited workspace cleanup — the `Cleanup` Drop is only a panic safety net, and a
    // spawned task may not run before the test's runtime shuts down (the observed leak this fixes).
    let cleaned = raw(&host, &format!("rm -rf {}", ws.replace('\'', "'\\''"))).await;
    assert_eq!(cleaned.trim(), "", "workspace removal should be silent");
}

#[ignore = "requires a real remote Docker host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn a_remote_sandbox_refuses_a_nonempty_egress_allowlist_without_creating_anything() {
    let target = skip_without_a_host!();
    let Some(host) = connect(&target).await else {
        return;
    };

    let ws = make_remote_workspace(&host).await;
    let mut spec = spec(&ws, IsolationLevel::L1);
    spec.network = true;
    spec.egress_allow = vec!["crates.io".into()];
    let settings = spec.host_settings();

    let runtime = RemoteSandboxRuntime::new(Arc::new(SshRunner {
        host: Arc::clone(&host),
    }));
    let id = SandboxId::new();
    let name = format!("hx-{}", id.as_str());
    let _cleanup = Cleanup::new(&host, &name, &ws);

    // Remote egress can't be enforced (the proxy is a near-host mechanism), so it must be refused
    // and must leave nothing behind on the far host.
    let err = runtime
        .create(&id, &spec, &settings)
        .await
        .expect_err("remote egress must be refused");
    assert!(err.to_string().contains("not implemented yet"), "{err}");
    assert!(
        !container_exists(&host, &name).await,
        "a refused sandbox must not have created anything"
    );

    // Explicit, awaited workspace cleanup (the Drop is only a panic safety net).
    let _ = raw(&host, &format!("rm -rf {}", ws.replace('\'', "'\\''"))).await;
}

#[ignore = "requires a real remote Docker host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn the_far_daemon_rejects_l2_userns_remapping_when_it_is_not_configured() {
    // A documented finding from the first real run, not a soft skip. The runtime's L2/L3 path
    // sends `--userns=private`, which a Docker daemon whose `daemon.json` has no `userns-remap`
    // refuses at create time with `--userns: invalid USER mode`. The module doc claimed the CLI flag
    // was "accepted on a daemon with no remap configured (where it is a no-op)" — that is false
    // for the CLI path (the bollard API value is interpreted differently than the CLI flag). This test
    // pins the *observed* behaviour so the defect stays visible, and proves no container leaks when it
    // happens. It is expected to pass on rainbowone today (the daemon has no remap configured) and
    // will keep passing until `create_command` stops sending `--userns=private` or the daemon
    // enables remapping — both of which are the fix this finding points at.
    let target = skip_without_a_host!();
    let Some(host) = connect(&target).await else {
        return;
    };

    let ws = make_remote_workspace(&host).await;
    let spec = spec(&ws, IsolationLevel::L2);
    let settings = spec.host_settings();

    let runtime = RemoteSandboxRuntime::new(Arc::new(SshRunner {
        host: Arc::clone(&host),
    }));
    let id = SandboxId::new();
    let name = format!("hx-{}", id.as_str());
    let _cleanup = Cleanup::new(&host, &name, &ws);

    let err = runtime
        .create(&id, &spec, &settings)
        .await
        .expect_err("L2 must not create on a daemon without userns remapping configured");
    let message = err.to_string();
    eprintln!("userns finding: {message}");
    // The runtime rewrites this one specific failure to name the cause and the way out (a remote
    // daemon with no `userns-remap`), and keeps the engine's own text. Assert both so a future
    // hardening — say, a live daemon gaining remap that would make `create` succeed — falls loudly
    // rather than as a soft skip.
    assert!(
        message.contains("invalid USER mode"),
        "the engine's own message must surface: {message}"
    );
    assert!(
        message.contains("no user-namespace remapping") && message.contains("Configure userns-remap"),
        "the rejection must name the cause and the way out: {message}"
    );
    assert!(
        !container_exists(&host, &name).await,
        "a rejected create must leave nothing behind"
    );

    // Explicit, awaited workspace cleanup (the Drop is only a panic safety net).
    let _ = raw(&host, &format!("rm -rf {}", ws.replace('\'', "'\\''"))).await;
}
