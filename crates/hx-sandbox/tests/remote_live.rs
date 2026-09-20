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

/// Remove the far host's copy of a sandbox — its container, its egress sidecar and network, its
/// workspace, and any proxy binary the test placed — on Drop, even on panic.
///
/// A sandbox with an allowlist owns three things on the far host: the sandbox container, its
/// `-egress-proxy` sidecar, and the internal `-egress` network. The sidecar is the one that matters —
/// it holds a foot on the bridge by design, so a leaked sidecar is a **live proxy on the far host**,
/// not a harmless leftover. `remove()` tears all three down on the happy path; this guard covers the
/// panic *before* `remove`, which this suite actually hit and which previously leaked a running
/// sidecar and a network. Names are derived from the sandbox name exactly as `create` derives them.
///
/// The sweep runs as a **blocking `ssh` child process**, deliberately not by spawning a task on the
/// runtime handle. A spawned task is not guaranteed to run — the runtime is torn down while the panic
/// unwinds, and the leak was observed precisely because that spawn never completed. A child process
/// has no such dependency, so the removal finishes before `drop` returns.
struct Cleanup {
    name: Option<String>,
    workspace: Option<String>,
    /// The proxy binary placed on the far host for the sidecar to bind-mount, when one was placed.
    binary: Option<String>,
}

impl Cleanup {
    fn new(name: &str, workspace_path: &str) -> Self {
        Self {
            name: Some(name.to_string()),
            workspace: Some(workspace_path.to_string()),
            binary: None,
        }
    }

    /// Also remove a proxy binary this test placed on the far host.
    fn with_binary(mut self, path: impl Into<String>) -> Self {
        self.binary = Some(path.into());
        self
    }
}

/// The `ssh` prefix for a best-effort sweep, read from the same variables `target()` uses. `None` when
/// no remote host is configured, in which case there is nothing to sweep.
fn ssh_prefix() -> Option<Vec<String>> {
    let host = std::env::var("HX_SSH_TEST_HOST").ok()?;
    let user = std::env::var("HX_SSH_TEST_USER").ok()?;
    let key = std::env::var("HX_SSH_TEST_KEY").ok()?;
    let key = match key.strip_prefix("~/") {
        Some(rest) => format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest),
        None => key,
    };
    let port = std::env::var("HX_SSH_TEST_PORT").unwrap_or_else(|_| "22".to_string());
    Some(vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-p".to_string(),
        port,
        "-i".to_string(),
        key,
        format!("{user}@{host}"),
    ])
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let mut commands: Vec<String> = Vec::new();
        if let Some(name) = self.name.take() {
            // `docker rm -f` succeeds only if the container exists, hence best-effort: the happy path
            // asserts the post-removal state itself.
            commands.push(format!("docker rm -f {}", name.replace('\'', "'\\''")));
            // The sidecar first, so it lets go of both networks — `network rm` refuses while anything
            // is still attached to the internal one.
            commands.push(format!(
                "docker rm -f {}",
                format!("{name}-egress-proxy").replace('\'', "'\\''")
            ));
            commands.push(format!(
                "docker network rm {}",
                format!("{name}-egress").replace('\'', "'\\''")
            ));
        }
        if let Some(ws) = self.workspace.take() {
            commands.push(format!("rm -rf {}", ws.replace('\'', "'\\''")));
        }
        if let Some(bin) = self.binary.take() {
            commands.push(format!("rm -f {}", bin.replace('\'', "'\\''")));
        }
        if commands.is_empty() {
            return;
        }
        let Some(prefix) = ssh_prefix() else {
            return;
        };
        let _ = std::process::Command::new("ssh")
            .args(prefix)
            .arg(commands.join("; "))
            .output();
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
    let _cleanup = Cleanup::new(&name, &ws);

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
async fn a_remote_sandbox_with_an_allowlist_reaches_its_allowed_host_and_not_a_denied_one() {
    // The property this milestone exists to hold, proven the only way that counts — by observation
    // on the real far daemon (rainbowone), not by re-reading the command this code built. The pair
    // of probes is what distinguishes *enforcement* (the proxy admits the allowed host and refuses the
    // denied one) from a blanket block (which would fail the allowed half). The sandbox must reach
    // exactly the allowlist's host and no other, and have no route out except the proxy.
    let target = skip_without_a_host!();
    let Some(host) = connect(&target).await else {
        return;
    };

    let ws = make_remote_workspace(&host).await;
    let mut spec = spec(&ws, IsolationLevel::L1);
    spec.network = true;
    spec.egress_allow = vec!["example.com".into()];
    let settings = spec.host_settings();

    // Place the compiled proxy binary on the far host, exactly as the deployment must, so the sidecar
    // can bind-mount it. It must be executable.
    let proxy_bin = std::env::var("HX_DOCKER_TEST_PROXY_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_hx-egress-proxy").to_string());
    let proxy_bytes = std::fs::read(&proxy_bin).unwrap_or_else(|err| {
        panic!("could not read the egress proxy binary at {proxy_bin}: {err}")
    });
    let remote_bin = format!("/tmp/hx-egress-proxy-{}", SandboxId::new().as_str());
    host.write_file(&remote_bin, &proxy_bytes)
        .await
        .unwrap_or_else(|err| panic!("placing the proxy binary on the far host failed: {err}"));
    raw(
        &host,
        &format!("chmod +x {}", remote_bin.replace('\'', "'\\''")),
    )
    .await;

    let runtime = RemoteSandboxRuntime::new(Arc::new(SshRunner {
        host: Arc::clone(&host),
    }))
    .with_proxy_bin(Some(remote_bin.clone()));
    let id = SandboxId::new();
    let name = format!("hx-{}", id.as_str());
    let network = format!("{name}-egress");
    let sidecar = format!("{name}-egress-proxy");
    let _cleanup = Cleanup::new(&name, &ws).with_binary(remote_bin.clone());

    // The full enforcement lifecycle: create (which also creates the internal network + sidecar on the
    // far daemon), start, probe, then remove (which must tear the sidecar and network down).
    let created = runtime.create(&id, &spec, &settings).await;
    assert!(
        created.is_ok(),
        "create with an allowlist failed: {:?}",
        created
    );
    let name = created.unwrap();
    runtime
        .start(&name)
        .await
        .expect("the far daemon starts the egress sandbox");

    // Probe *through the proxy* with a hand-written CONNECT line — what a real tool inside the sandbox
    // does, since `HTTP_PROXY` points it at the sidecar. A raw direct connect would test the route the
    // design deliberately does not use (the internal network has no gateway), so it cannot distinguish a
    // deny from a routing failure. The reply's status line is the verdict: 200 = the proxy relayed,
    // 403 = the allowlist refused.
    let conn = |h: &str| {
        format!(
            "timeout 15 bash -c 'exec 3<>/dev/tcp/hxproxy/3128; \
             printf \"CONNECT {h}:443 HTTP/1.1\\r\\nHost: {h}:443\\r\\n\\r\\n\" >&3; \
             head -c 12 <&3' || echo BLOCKED"
        )
    };
    // Check the proxy sidecar is alive first, so an expired-sleep probe is not mistaken for a routing or
    // DNS symptom — a running sidecar is what a real probe presupposes.
    // `grep -q` prints nothing even on a match, so a quiet grep cannot be read back as "it is up":
    // the assertion compares the NAME, which is what makes a missing sidecar legible instead of
    // looking like an empty string either way.
    let sidecar_up = raw(
        &host,
        &format!(
            "docker ps --format '{{{{.Names}}}}' | grep -x {} || true",
            sidecar.replace('\'', "'\\''")
        ),
    )
    .await;
    assert_eq!(
        sidecar_up.trim(),
        sidecar,
        "the egress sidecar must be running before probing"
    );

    let allowed = runtime
        .exec(&name, &conn("example.com"), None)
        .await
        .expect("exec inside the egress sandbox");
    assert!(
        allowed.stdout.contains("200"),
        "an allowed host must be relayed by the far-host proxy: {allowed:?}"
    );

    let denied = runtime
        .exec(&name, &conn("malware.test"), None)
        .await
        .expect("exec inside the egress sandbox");
    assert!(
        !denied.stdout.contains("200"),
        "a denied host must not be relayed: {denied:?}"
    );
    assert!(
        denied.stdout.contains("403") || denied.stdout.contains("BLOCKED"),
        "the refusal must be the allowlist's, not a blanket block: {denied:?}"
    );

    // The sandbox has no *internet* route except the proxy: the internal network carries no default
    // route, so a *direct* (non-proxy) connection attempts the route the design removes. This is the
    // half that a sandbox merely told about a proxy would violate — it would connect directly and skip
    // the allowlist entirely. (It is not unreachability in every direction: the far host's own bridge
    // address stays reachable on-link, which is the known hole pinned by
    // `a_sandbox_reaches_the_far_hosts_own_bridge_address_and_that_is_a_known_hole` below and filed in
    // ROADMAP.md.)
    let direct = runtime
        .exec(
            &name,
            "timeout 8 bash -c 'exec 5<>/dev/tcp/93.184.216.34/443 && echo DIRECT_OK || echo NO_ROUTE' \
             || echo NO_ROUTE",
            None,
        )
        .await
        .expect("exec inside the egress sandbox");
    assert!(
        direct.stdout.contains("NO_ROUTE"),
        "without the proxy the sandbox must have no route out: {direct:?}"
    );

    // --- teardown leaves the far host clean: the sandbox, its sidecar and its network are gone ---
    runtime
        .remove(&name)
        .await
        .expect("the far daemon removes the egress sandbox");
    assert!(
        !container_exists(&host, &name).await,
        "the sandbox must be gone"
    );
    let net = raw(
        &host,
        &format!(
            "docker network ls --format '{{{{.Name}}}}' | grep -qx {}; echo $?",
            network.replace('\'', "'\\''")
        ),
    )
    .await;
    assert!(
        net.trim() == "1",
        "the egress network must be torn down with its sandbox"
    );
    let side = raw(
        &host,
        &format!(
            "docker ps -a --format '{{{{.Names}}}}' | grep -qx {}; echo $?",
            sidecar.replace('\'', "'\\''")
        ),
    )
    .await;
    assert!(
        side.trim() == "1",
        "the egress sidecar must be torn down with its sandbox"
    );

    // Explicit, awaited binary + workspace cleanup (the Drop is only a panic safety net).
    let _ = raw(
        &host,
        &format!("rm -f {}", remote_bin.replace('\'', "'\\''")),
    )
    .await;
    let _ = raw(&host, &format!("rm -rf {}", ws.replace('\'', "'\\''"))).await;
}

#[ignore = "requires a real remote Docker host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn a_sandbox_reaches_the_far_hosts_own_bridge_address_and_that_is_a_known_hole() {
    // THIS TEST PINS A KNOWN HOLE. It asserts a property we do *not* want, deliberately, so the hole
    // stays measured rather than assumed — and so no doc comment can quietly grow a stronger claim
    // than the code supports. `crates/hx-sandbox/src/egress.rs` used to say a sandbox on the internal
    // egress network "cannot bypass" the proxy because there is "literally no route" off the network.
    // That was false. The network carries no *default* route, but its IPAM gateway is the far host's
    // own bridge interface sitting on the **same on-link subnet** as the sandbox, and on-link delivery
    // needs no route at all: the container ARPs for the address and the packet is delivered. Measured
    // on rainbowone, the host's own sshd answered on that address from inside the sandbox.
    //
    // The probe is deterministic by construction: it targets the SSH port the suite already requires
    // to be listening on the host (`HX_SSH_TEST_PORT`, default 22), read from inside the sandbox.
    // There is no wall-clock assertion and no reliance on the internet.
    let target = skip_without_a_host!();
    let Some(host) = connect(&target).await else {
        return;
    };

    let ws = make_remote_workspace(&host).await;
    let mut spec = spec(&ws, IsolationLevel::L1);
    spec.network = true;
    spec.egress_allow = vec!["example.com".into()];
    let settings = spec.host_settings();

    let proxy_bin = std::env::var("HX_DOCKER_TEST_PROXY_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_hx-egress-proxy").to_string());
    let proxy_bytes = std::fs::read(&proxy_bin).unwrap_or_else(|err| {
        panic!("could not read the egress proxy binary at {proxy_bin}: {err}")
    });
    let remote_bin = format!("/tmp/hx-egress-proxy-{}", SandboxId::new().as_str());
    host.write_file(&remote_bin, &proxy_bytes)
        .await
        .unwrap_or_else(|err| panic!("placing the proxy binary on the far host failed: {err}"));
    raw(
        &host,
        &format!("chmod +x {}", remote_bin.replace('\'', "'\\''")),
    )
    .await;

    let runtime = RemoteSandboxRuntime::new(Arc::new(SshRunner {
        host: Arc::clone(&host),
    }))
    .with_proxy_bin(Some(remote_bin.clone()));
    let id = SandboxId::new();
    let name = format!("hx-{}", id.as_str());
    let network = format!("{name}-egress");
    let _cleanup = Cleanup::new(&name, &ws).with_binary(remote_bin.clone());

    let name = runtime
        .create(&id, &spec, &settings)
        .await
        .expect("create with an allowlist");
    runtime
        .start(&name)
        .await
        .expect("the far daemon starts the egress sandbox");

    // The address the sandbox can actually reach: the internal network's own IPAM gateway. Asked of
    // the far daemon rather than hard-coded, so the probe follows whatever pool the host is on.
    let quoted_network = network.replace('\'', "'\\''");
    let gateway = raw(
        &host,
        &format!(
            "docker network inspect {quoted_network} \
             --format '{{{{(index .IPAM.Config 0).Gateway}}}}'"
        ),
    )
    .await;
    let gateway = gateway.trim().to_string();
    assert!(
        !gateway.is_empty(),
        "the internal network must report a gateway address, or this probe proves nothing"
    );

    // THE HOLE. If this assertion ever fails the hole has been closed, which is good news: the right
    // response is to delete this test *and* the ROADMAP item together, not to weaken the probe.
    let port = std::env::var("HX_SSH_TEST_PORT").unwrap_or_else(|_| "22".to_string());
    let bridge = runtime
        .exec(
            &name,
            &format!(
                "timeout 8 bash -c 'exec 4<>/dev/tcp/{gateway}/{port} && echo BRIDGE_REACHABLE' \
                 || echo BRIDGE_UNREACHABLE"
            ),
            None,
        )
        .await
        .expect("exec inside the egress sandbox");
    assert!(
        bridge.stdout.contains("BRIDGE_REACHABLE"),
        "the far host's bridge address {gateway}:{port} is a known reachable hole from inside the \
         sandbox and must stay measured rather than assumed: {bridge:?}"
    );

    // The half of the old claim that *is* true and must stay true: no default route, so no internet.
    // `/proc/net/route` rather than `ip route` — the image has no `ip`, and the default route is the
    // line whose Destination field is the hex `00000000`.
    let routes = runtime
        .exec(&name, "cat /proc/net/route", None)
        .await
        .expect("exec inside the egress sandbox");
    let has_default_route = routes
        .stdout
        .lines()
        .any(|line| line.split_whitespace().nth(1) == Some("00000000"));
    assert!(
        !has_default_route,
        "the internal network must still carry no default route: {routes:?}"
    );
    let internet = runtime
        .exec(
            &name,
            "timeout 8 bash -c 'exec 5<>/dev/tcp/1.1.1.1/443 && echo INTERNET_OK' \
             || echo NO_INTERNET_ROUTE",
            None,
        )
        .await
        .expect("exec inside the egress sandbox");
    assert!(
        internet.stdout.contains("NO_INTERNET_ROUTE"),
        "there must still be no internet route without the proxy: {internet:?}"
    );

    // --- teardown leaves the far host exactly as it was found ---
    runtime
        .remove(&name)
        .await
        .expect("the far daemon removes the egress sandbox");
    assert!(
        !container_exists(&host, &name).await,
        "the sandbox must be gone"
    );
    let net = raw(
        &host,
        &format!("docker network ls --format '{{{{.Name}}}}' | grep -qx {quoted_network}; echo $?"),
    )
    .await;
    assert!(
        net.trim() == "1",
        "the egress network must be torn down with its sandbox"
    );
    let _ = raw(
        &host,
        &format!("rm -f {}", remote_bin.replace('\'', "'\\''")),
    )
    .await;
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
    let _cleanup = Cleanup::new(&name, &ws);

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
        message.contains("no user-namespace remapping")
            && message.contains("Configure userns-remap"),
        "the rejection must name the cause and the way out: {message}"
    );
    assert!(
        !container_exists(&host, &name).await,
        "a rejected create must leave nothing behind"
    );

    // Explicit, awaited workspace cleanup (the Drop is only a panic safety net).
    let _ = raw(&host, &format!("rm -rf {}", ws.replace('\'', "'\\''"))).await;
}
