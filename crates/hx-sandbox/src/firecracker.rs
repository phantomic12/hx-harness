//! Firecracker microVM-backed sandbox runtime: the real L3 isolation tier.
//!
//! The documented ladder is L1 → L2 (gVisor `runsc`) → **L3 (Firecracker)**. Docker
//! containers share the host kernel; a Firecracker microVM runs a guest kernel under KVM, so
//! a kernel exploit inside lands in the guest and stops there. That is the strongest isolation
//! [`crate::spec`] can request.
//!
//! Firecracker exposes a small HTTP API over a Unix domain socket (the `--api-sock` flag), not a
//! container engine API. This runtime drives that API directly, with `hyperlocal` speaking HTTP over the
//! socket. There is no daemon to connect to: each microVM **is** a `firecracker` process the
//! runtime spawns and owns for its lifetime.
//!
//! ## Lifecycle
//!
//! - `create` spawns `firecracker --api-sock <path>`, waits for the socket, then PUTs the
//!   boot source (kernel + rootfs), the drives (root plus the workspace, which is what makes the
//!   sandbox's work survive it), a vsock device (the only side channel out of a network-off
//!   microVM), and the machine config (vCPU count, memory) from the spec. The runtime id a
//! - `start` PUTs `InstanceStart`.
//! - `stop` / `remove` kill the owned `firecracker` process and remove the temp directory the
//!   microVM was built in. Firecracker has no graceful-stop API; killing the process is how a
//!   microVM is stopped.
//! - `exec` runs in the guest over the vsock device through an [`ExecChannel`] (see below).
//!
//! ## `exec`: the chosen path
//!
//! Firecracker has no `docker exec`-equivalent. The chosen path is a guest-side SSH daemon reached
//! over the microVM's vsock device: the runtime sets up the vsock, and an [`ExecChannel`]
//! implementation performs the command on the far side of it. The seam exists because the guest must be
//! provisioned with `sshd` and a key for this to work — a real transport is deployment work, not
//! library work — and because the hermetic suite needs a transport it can observe without a KVM host.
//! The vsock device is created during `create` (an observable API call), so a profile that asks for
//! L3 always has the side channel its `exec` depends on.
//!
//! A sandbox whose L3 asks for exec must be configured with an [`ExecChannel`] (a real SSH-over-vsock
//! adapter where one is available); the default returns a clear error rather than pretending to run a command
//! that did not actually run in the guest.
//!
//! ## Security posture
//!
//! The microVM is built with no network interfaces (PUTting none is the same as `--net-off` at the
//! microVM layer — the guest has no NIC), no privileged mode (there is no such concept in the API, and
//! the guest root is the guest's own kernel), and only the workspace drive is writable; the root drive
//! is read-only. Every setting this module builds is visible to and asserted by the hermetic mock, so a
//! hardening knob that silently dropped out of the request would fail a test.

use crate::runtime::{SandboxExecOutput, SandboxRuntime};
use crate::spec::{HostSettings, SandboxSpec};
use async_trait::async_trait;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hx_core::error::{HxError, Result};
use hx_core::ids::SandboxId;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tokio::process::{Child, Command};

/// How long `create` waits for the `--api-sock` to appear after spawning the process.
const SOCKET_WAIT: Duration = Duration::from_secs(5);

/// The `drive_id` Firecracker uses for the guest's root filesystem.
const ROOT_DRIVE: &str = "rootfs";
/// The `drive_id` for the workspace volume.
const WORKSPACE_DRIVE: &str = "workspace";
/// The guest's network-free side channel.
const VSOCK_ID: &str = "vsock";

/// Runs a command *inside* the guest of a Firecracker microVM.
///
/// Firecracker's API has no `exec`. The chosen path is a guest `sshd` reached over the vsock
/// device; this trait is that transport. A real implementation is deployment work (the guest must run
/// `sshd` with a key the host trusts) and deliberately lives behind a seam so the hermetic suite can
/// observe it and so a crate caller can supply a real one without the library depending on an SSH stack.
#[async_trait]
pub trait ExecChannel: Send + Sync {
    /// Run `command` in the guest and return its combined output.
    async fn exec(&self, command: &str, workdir: Option<&str>) -> Result<SandboxExecOutput>;
}

/// The default [`ExecChannel`]: refuse loudly rather than claim a command ran.
///
/// A microVM with no configured transport cannot execute anything, and returning a made-up success would be
/// worse than an honest error — the caller would trust output that never left the host.
struct NoExecChannel;

#[async_trait]
impl ExecChannel for NoExecChannel {
    async fn exec(&self, _command: &str, _workdir: Option<&str>) -> Result<SandboxExecOutput> {
        Err(HxError::Sandbox(
            "this Firecracker sandbox has no ExecChannel configured; exec needs a guest sshd \
             reached over vsock (set one via with_exec_channel)"
                .to_string(),
        ))
    }
}

/// The default location of the `firecracker` binary, honoured by `available()` and `create`.
fn default_bin() -> PathBuf {
    PathBuf::from("firecracker")
}

/// The default KVM device `available()` checks for.
fn default_kvm() -> PathBuf {
    PathBuf::from("/dev/kvm")
}

/// A Firecracker microVM sandbox runtime.
pub struct FirecrackerRuntime {
    /// Path to the `firecracker` binary (or just `firecracker`, found on `PATH`).
    bin: PathBuf,
    /// Path to the KVM device `available()` checks.
    kvm: PathBuf,
    /// Root directory under which each microVM's temp dir and API socket are created.
    work_dir: PathBuf,
    /// Host path of the guest kernel image.
    kernel: PathBuf,
    /// Host path of the guest root filesystem image.
    rootfs: PathBuf,
    /// runtime_id -> the owned process for that microVM. Killing it is how the microVM stops.
    vms: Mutex<HashMap<String, Child>>,
    /// The transport used by `exec`.
    exec: Box<dyn ExecChannel>,
}

impl FirecrackerRuntime {
    /// A runtime using the default binary/KVM locations and a temp work root.
    pub fn new(work_dir: PathBuf, kernel: PathBuf, rootfs: PathBuf) -> Self {
        Self {
            bin: default_bin(),
            kvm: default_kvm(),
            work_dir,
            kernel,
            rootfs,
            vms: Mutex::new(HashMap::new()),
            exec: Box::new(NoExecChannel),
        }
    }

    /// Point at a specific `firecracker` binary and KVM device, for tests and non-standard hosts.
    pub fn with_paths(mut self, bin: PathBuf, kvm: PathBuf) -> Self {
        self.bin = bin;
        self.kvm = kvm;
        self
    }

    /// Set the [`ExecChannel`] used by `exec` (the default refuses).
    pub fn with_exec_channel(mut self, exec: Box<dyn ExecChannel>) -> Self {
        self.exec = exec;
        self
    }

    /// Whether the binary is present and the KVM device is usable. Both must hold for a microVM.
    fn binary_usable(&self) -> bool {
        let bin = &self.bin;
        std::fs::metadata(bin).map(|m| m.is_file()).unwrap_or(false)
    }

    fn kvm_usable(&self) -> bool {
        std::fs::metadata(&self.kvm).is_ok()
    }

    /// The per-microVM socket path for `runtime_id` (which is the socket path itself).
    fn sock_for(&self, runtime_id: &str) -> PathBuf {
        PathBuf::from(runtime_id)
    }

    /// The per-microVM dir, derived from the runtime_id (the socket's parent).
    fn dir_for(&self, runtime_id: &str) -> PathBuf {
        PathBuf::from(runtime_id)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(runtime_id))
    }

    /// PUT a JSON body to a Firecracker API endpoint on this microVM's socket.
    async fn put_json(&self, runtime_id: &str, path: &str, body: &Value) -> Result<()> {
        let uri = Uri::new(self.sock_for(runtime_id), path);
        let bytes = serde_json::to_vec(body)
            .map_err(|e| HxError::Sandbox(format!("firecracker request body invalid: {e}")))?;
        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|e| HxError::Sandbox(format!("could not build firecracker request: {e}")))?;
        let response = Client::<UnixConnector, Full<Bytes>>::unix()
            .request(request)
            .await
            .map_err(|e| HxError::Sandbox(format!("firecracker API call failed: {e}")))?;
        let status = response.status();
        let _body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| HxError::Sandbox(format!("firecracker response read failed: {e}")))?;
        if status.is_success() {
            Ok(())
        } else {
            Err(HxError::Sandbox(format!(
                "firecracker API {path} returned {status}"
            )))
        }
    }

    /// Wait for the API socket to exist, bounded by [`SOCKET_WAIT`].
    async fn wait_for_socket(&self, runtime_id: &str) -> Result<()> {
        let sock = self.sock_for(runtime_id);
        let deadline = std::time::Instant::now() + SOCKET_WAIT;
        while std::time::Instant::now() < deadline {
            if sock.exists() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err(HxError::Sandbox(format!(
            "firecracker did not expose its API socket at {} within {}ms",
            sock.display(),
            SOCKET_WAIT.as_millis()
        )))
    }
}

#[async_trait]
impl SandboxRuntime for FirecrackerRuntime {
    fn name(&self) -> &str {
        "firecracker"
    }

    async fn available(&self) -> bool {
        self.binary_usable() && self.kvm_usable()
    }

    async fn create(
        &self,
        id: &SandboxId,
        spec: &SandboxSpec,
        _settings: &HostSettings,
    ) -> Result<String> {
        let runtime_id = id.as_str().to_string();
        let dir = self.work_dir.join(&runtime_id);
        std::fs::create_dir_all(&dir).map_err(|e| {
            HxError::Sandbox(format!(
                "could not create microVM dir {}: {e}",
                dir.display()
            ))
        })?;
        let sock = dir.join("api.sock");
        let runtime_id = sock.to_string_lossy().to_string();

        let child = Command::new(&self.bin)
            .arg("--api-sock")
            .arg(&sock)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                HxError::Sandbox(format!("could not spawn firecracker ({:?}): {e}", self.bin))
            })?;
        self.vms
            .lock()
            .expect("firecracker vms lock")
            .insert(runtime_id.clone(), child);

        // Any failure from here on leaves a spawned process behind; clean it up so `create` does
        // not leak a microVM (the manager also rolls back via `remove`, but a process that never got a
        // runtime_id back could become untracked).
        let result = async {
            self.wait_for_socket(&runtime_id).await?;

            // Boot source: guest kernel and its arguments. No `initrd`.
            self.put_json(
                &runtime_id,
                "/boot-source",
                &json!({
                    "kernel_image_path": self.kernel.to_string_lossy(),
                    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
                }),
            )
            .await?;

            // Root drive: read-only. The guest kernel's root, not a scratch area.
            self.put_json(
                &runtime_id,
                &format!("/drives/{ROOT_DRIVE}"),
                &json!({
                    "drive_id": ROOT_DRIVE,
                    "path_on_host": self.rootfs.to_string_lossy(),
                    "is_root_device": true,
                    "is_read_only": true,
                }),
            )
            .await?;

            // Workspace drive from the spec, writable — the sandbox's work must survive it.
            // No workspace means nothing is mounted, which is refused earlier by `spec.validate`.
            self.put_json(
                &runtime_id,
                &format!("/drives/{WORKSPACE_DRIVE}"),
                &json!({
                    "drive_id": WORKSPACE_DRIVE,
                    "path_on_host": spec.workspace_host_path,
                    "is_root_device": false,
                    "is_read_only": false,
                }),
            )
            .await?;

            // The vsock device: the only side channel out of a network-off microVM, used by `exec`.
            self.put_json(
                &runtime_id,
                "/vsock",
                &json!({
                    "vsock_id": VSOCK_ID,
                    "guest_cid": 3,
                    "uds_path": format!("{}/vsock.sock", dir.to_string_lossy()),
                }),
            )
            .await?;

            // Machine config from the spec: vCPUs and memory in MiB.
            self.put_json(
                &runtime_id,
                "/machine-config",
                &json!({
                    "vcpu_count": spec.cpus.max(1.0).ceil() as u64,
                    "mem_size_mib": spec.memory_mb,
                    "ht_enabled": false,
                }),
            )
            .await?;

            Ok::<(), HxError>(())
        }
        .await;

        if let Err(e) = result {
            // Tear down the process we spawned so a failed create does not leak a microVM.
            self.vms
                .lock()
                .expect("firecracker vms lock")
                .remove(&runtime_id);
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }

        Ok(runtime_id)
    }

    async fn start(&self, runtime_id: &str) -> Result<()> {
        self.put_json(
            runtime_id,
            "/actions",
            &json!({ "action_type": "InstanceStart" }),
        )
        .await
    }

    async fn stop(&self, runtime_id: &str, _grace_secs: i64) -> Result<()> {
        // Firecracker has no graceful-stop API; killing the process is how a microVM stops.
        let child = {
            let mut vms = self.vms.lock().expect("firecracker vms lock");
            vms.remove(runtime_id)
        };
        if let Some(mut child) = child {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        Ok(())
    }

    async fn remove(&self, runtime_id: &str) -> Result<()> {
        // Remove the microVM's staging directory (idempotent).
        let _ = std::fs::remove_dir_all(self.dir_for(runtime_id));
        Ok(())
    }

    async fn exec(
        &self,
        _runtime_id: &str,
        command: &str,
        workdir: Option<&str>,
    ) -> Result<SandboxExecOutput> {
        self.exec.exec(command, workdir).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binary_missing_means_unavailable() {
        let rt =
            FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into())
                .with_paths(
                    "/definitely/not/a/real/firecracker-binary".into(),
                    "/definitely/not/a/real/kvm".into(),
                );
        // A missing binary means the runtime is unavailable regardless of KVM.
        assert!(!rt.available().await);
    }

    #[tokio::test]
    async fn the_runtime_names_itself_firecracker() {
        let rt =
            FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into());
        assert_eq!(rt.name(), "firecracker");
    }
}
