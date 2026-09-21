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
//! - `create` resolves the binary through `PATH` (a bare `firecracker` name is looked up like a
//!   shell would, not `stat`ed against the current directory), provisions a bounded workspace
//!   block image, spawns `firecracker --api-sock <path>`, waits for the socket, then PUTs the
//!   boot source (kernel + rootfs, plus which guest path the workspace mounts at), the drives
//!   (root plus the provisioned workspace image, which is what makes the sandbox's work survive
//!   it), a vsock device with a per-microVM CID (the only side channel out of a network-off
//!   microVM), and the machine config (vCPU count, memory) from the spec. The runtime id a
//! - `start` PUTs `InstanceStart`.
//! - `stop` kills the owned `firecracker` process but retains the microVM's identity (CID,
//!   workspace mapping) until `remove`; Firecracker has no graceful-stop API, so killing the
//!   process is how a microVM is stopped.
//! - `remove` drops that identity — the CID returns to the pool — and removes the temp directory
//!   the microVM was built in.
//! - `exec` runs in the guest over that microVM's vsock device through an [`ExecChannel`] that is
//!   told *which* microVM the command is for (see below).
//!
//! ## `exec`: the chosen path
//!
//! Firecracker has no `docker exec`-equivalent. The chosen path is a guest-side SSH daemon reached
//! over the microVM's vsock device: the runtime sets up the vsock, and an [`ExecChannel`]
//! implementation performs the command on the far side of it, addressed by the per-microVM CID
//! the runtime hands it in [`VmExecTarget`]. The seam exists because the guest must be
//! provisioned with `sshd` and a key for this to work — a real transport is deployment work, not
//! library work — and because the hermetic suite needs a transport it can observe without a KVM host.
//! The vsock device is created during `create` (an observable API call), so a profile that asks for
//! L3 always has the side channel its `exec` depends on.
//!
//! A sandbox whose L3 asks for exec must be configured with an [`ExecChannel`] (a real SSH-over-vsock
//! adapter where one is available); the default returns a clear error rather than pretending to run a command
//! that did not actually run in the guest.
//!
//! ## Workspace: a block image, not the host directory
//!
//! Firecracker's block API attaches host *files* as guest drives; handing it the spec's workspace
//! directory would fail (a directory is not a block image) and would conflate the host working
//! tree with guest block storage. So `create` provisions `<vm-dir>/workspace.ext4` — a sparse,
//! bounded regular file sized from `spec.workspace_mb` — and attaches *that* as the writable
//! drive. The guest mounts `/dev/vdb` where the boot args say (`hx_workspace=<path>`); the
//! runtime remembers which host directory the sandbox's work lives in and exposes it via
//! [`FirecrackerRuntime::host_workspace`], so an operator can map a guest write back to the host.
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
/// The file name of the provisioned workspace block image inside the microVM's dir.
const WORKSPACE_IMAGE_NAME: &str = "workspace.ext4";
/// The guest's network-free side channel.
const VSOCK_ID: &str = "vsock";

/// First guest CID handed out. CIDs 0–2 are reserved (hypervisor, host, and the well-known
/// addresses); guest microVMs start at 3 by vsock convention.
const CID_FIRST: u32 = 3;

/// Bounds for the provisioned workspace image. The spec's `workspace_mb` sizes the sandbox, but
/// the image must stay bounded: a profile asking for terabytes must not materialise terabytes.
const MIN_WORKSPACE_IMAGE_BYTES: u64 = 64 << 20;
const MAX_WORKSPACE_IMAGE_BYTES: u64 = 8 << 30;

/// Where an [`ExecChannel`] must deliver a command: the identity of one live microVM.
///
/// A single channel implementation serves every microVM this runtime owns (one SSH-over-vsock
/// client, not one per guest), so the runtime tells it *which* guest each call is for. Without
/// this, `exec` on two live microVMs would be indistinguishable at the transport and a command
/// meant for one guest could run in the other.
#[derive(Clone, Debug, PartialEq)]
pub struct VmExecTarget {
    /// The runtime id `create` returned (the microVM's API socket path).
    pub runtime_id: String,
    /// The guest CID of the vsock device this microVM was configured with.
    pub cid: u32,
    /// Host path of that vsock device's Unix socket.
    pub uds_path: PathBuf,
    /// Where the workspace is mounted inside the guest; the default working directory.
    pub guest_workspace: String,
}

/// Runs a command *inside* the guest of one Firecracker microVM.
///
/// Firecracker's API has no `exec`. The chosen path is a guest `sshd` reached over the vsock
/// device; this trait is that transport. A real implementation is deployment work (the guest must run
/// `sshd` with a key the host trusts) and deliberately lives behind a seam so the hermetic suite can
/// observe it and so a crate caller can supply a real one without the library depending on an SSH stack.
///
/// The `vm` argument is which microVM the command is for — the transport dials `vm.cid`, not a
/// shared endpoint, so concurrent guests cannot receive each other's commands.
#[async_trait]
pub trait ExecChannel: Send + Sync {
    /// Run `command` in the guest of `vm` and return its combined output.
    async fn exec(
        &self,
        vm: &VmExecTarget,
        command: &str,
        workdir: Option<&str>,
    ) -> Result<SandboxExecOutput>;
}

/// The default [`ExecChannel`]: refuse loudly rather than claim a command ran.
///
/// A microVM with no configured transport cannot execute anything, and returning a made-up success would be
/// worse than an honest error — the caller would trust output that never left the host.
struct NoExecChannel;

#[async_trait]
impl ExecChannel for NoExecChannel {
    async fn exec(
        &self,
        _vm: &VmExecTarget,
        _command: &str,
        _workdir: Option<&str>,
    ) -> Result<SandboxExecOutput> {
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

/// Clamp the spec's workspace ceiling to a bounded image size.
///
/// WHY the clamp: `workspace_mb` is an accounting ceiling, not a disk allocation — a profile
/// asking for 16 TiB must not produce a 16 TiB image. The floor keeps tiny workspaces usable;
/// the ceiling keeps a fat profile from exhausting the host.
fn workspace_image_bytes(workspace_mb: u64) -> u64 {
    workspace_mb
        .saturating_mul(1024 * 1024)
        .clamp(MIN_WORKSPACE_IMAGE_BYTES, MAX_WORKSPACE_IMAGE_BYTES)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// One live (or stopped-but-not-removed) microVM: everything `exec` and `remove` need to find it.
struct VmInfo {
    /// The owned process; `None` after `stop` (killing it is how the microVM stops).
    child: Option<Child>,
    /// The unique guest CID this microVM's vsock was configured with.
    cid: u32,
    /// The staging dir: socket, workspace image, vsock socket.
    dir: PathBuf,
    /// The provisioned workspace block image attached as the writable drive.
    image: PathBuf,
    /// The host working tree the sandbox's work lives in (from the spec).
    host_workspace: String,
    /// Where that workspace mounts inside the guest (from the spec).
    guest_workspace: String,
}

/// Owned microVMs plus the CID pool. One lock: create/stop/remove/exec are infrequent, and a
/// single lock keeps the CID pool and the VM map from disagreeing.
struct State {
    vms: HashMap<String, VmInfo>,
    /// Next never-used CID. Freed CIDs in `free_cids` are preferred over minting new ones.
    next_cid: u32,
    /// CIDs released by `remove`, ready for reuse.
    free_cids: Vec<u32>,
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
    /// runtime_id -> the microVM's owned process, CID, and workspace mapping.
    state: Mutex<State>,
    /// The transport used by `exec`, routed per microVM via [`VmExecTarget`].
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
            state: Mutex::new(State {
                vms: HashMap::new(),
                next_cid: CID_FIRST,
                free_cids: Vec::new(),
            }),
            exec: Box::new(NoExecChannel),
        }
    }

    /// Point at a specific `firecracker` binary and KVM device, for tests and non-standard hosts.
    ///
    /// A bare binary name (no path separator) is resolved through `PATH`, like a shell would.
    pub fn with_paths(mut self, bin: PathBuf, kvm: PathBuf) -> Self {
        self.bin = bin;
        self.kvm = kvm;
        self
    }

    /// Set the [`ExecChannel`] used by `exec` (the default refuses).
    ///
    /// One channel serves all microVMs; each call carries which guest it is for in
    /// [`VmExecTarget`], so a shared transport still routes to the requested microVM.
    pub fn with_exec_channel(mut self, exec: Box<dyn ExecChannel>) -> Self {
        self.exec = exec;
        self
    }

    /// Resolve the configured binary the way a shell would: an explicit path (absolute or
    /// containing a separator) is used as-is; a bare name is looked up on `PATH`.
    ///
    /// WHY: the default is `PathBuf::from("firecracker")`, and checking that with `fs::metadata`
    /// stats the *current directory* — a `PATH`-installed binary reported unavailable, and worse,
    /// a `./firecracker` lookalike in whatever directory the process happened to run from would
    /// count as usable.
    fn resolve_bin(&self) -> PathBuf {
        if self.bin.components().count() > 1 {
            return self.bin.clone();
        }
        let name = self.bin.as_os_str();
        std::env::var_os("PATH")
            .iter()
            .flat_map(std::env::split_paths)
            .map(|dir| dir.join(name))
            .find(|candidate| is_executable(candidate))
            .unwrap_or_else(|| self.bin.clone())
    }

    /// Whether the binary is present and the KVM device is usable. Both must hold for a microVM.
    fn binary_usable(&self) -> bool {
        let bin = self.bin.clone();
        if bin.components().count() > 1 {
            return is_executable(&bin);
        }
        // A bare name counts when `PATH` resolves it to an executable.
        std::env::var_os("PATH")
            .iter()
            .flat_map(std::env::split_paths)
            .map(|dir| dir.join(&bin))
            .any(|candidate| is_executable(&candidate))
    }

    fn kvm_usable(&self) -> bool {
        std::fs::metadata(&self.kvm).is_ok()
    }

    /// Hand out a guest CID no live microVM holds. Freed CIDs are reused first so the pool stays
    /// dense; otherwise the counter advances.
    fn alloc_cid(&self) -> u32 {
        let mut state = self.state.lock().expect("firecracker state lock");
        if let Some(cid) = state.free_cids.pop() {
            return cid;
        }
        let cid = state.next_cid;
        state.next_cid = state.next_cid.saturating_add(1).max(CID_FIRST);
        if state.next_cid < CID_FIRST {
            state.next_cid = CID_FIRST;
        }
        cid
    }

    /// Return a microVM's CID to the pool. Called when its identity is dropped (`remove`, or a
    /// failed `create` rolling back).
    fn release_cid(&self, runtime_id: &str) {
        let mut state = self.state.lock().expect("firecracker state lock");
        if let Some(info) = state.vms.remove(runtime_id) {
            state.free_cids.push(info.cid);
        }
    }

    /// The guest CID of a tracked microVM, if it is still owned by this runtime.
    pub fn vm_cid(&self, runtime_id: &str) -> Option<u32> {
        self.state
            .lock()
            .expect("firecracker state lock")
            .vms
            .get(runtime_id)
            .map(|info| info.cid)
    }

    /// The provisioned workspace block image attached to a microVM, if tracked.
    pub fn workspace_image(&self, runtime_id: &str) -> Option<PathBuf> {
        self.state
            .lock()
            .expect("firecracker state lock")
            .vms
            .get(runtime_id)
            .map(|info| info.image.clone())
    }

    /// The host working tree a microVM's guest workspace maps back to, if tracked.
    pub fn host_workspace(&self, runtime_id: &str) -> Option<String> {
        self.state
            .lock()
            .expect("firecracker state lock")
            .vms
            .get(runtime_id)
            .map(|info| info.host_workspace.clone())
    }

    /// Where a microVM's workspace mounts inside its guest, if tracked.
    pub fn guest_workspace(&self, runtime_id: &str) -> Option<String> {
        self.state
            .lock()
            .expect("firecracker state lock")
            .vms
            .get(runtime_id)
            .map(|info| info.guest_workspace.clone())
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

        // The workspace block image: a bounded sparse file the block API can attach. The spec's
        // host path is a directory and can never be a `path_on_host` — Firecracker would reject
        // it, and even if it did not, guest block writes would land directly in the host tree.
        let image_path = dir.join(WORKSPACE_IMAGE_NAME);
        let image_file = std::fs::File::create(&image_path).map_err(|e| {
            HxError::Sandbox(format!(
                "could not create workspace image {}: {e}",
                image_path.display()
            ))
        })?;
        image_file
            .set_len(workspace_image_bytes(spec.workspace_mb))
            .map_err(|e| {
                HxError::Sandbox(format!(
                    "could not size workspace image {}: {e}",
                    image_path.display()
                ))
            })?;
        drop(image_file);

        // A CID no live microVM holds; two guests never share the vsock identity `exec` dials.
        let cid = self.alloc_cid();
        let vsock_sock = dir.join("vsock.sock");

        let bin = self.resolve_bin();
        let child = Command::new(&bin)
            .arg("--api-sock")
            .arg(&sock)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| HxError::Sandbox(format!("could not spawn firecracker ({bin:?}): {e}")))?;
        self.state
            .lock()
            .expect("firecracker state lock")
            .vms
            .insert(
                runtime_id.clone(),
                VmInfo {
                    child: Some(child),
                    cid,
                    dir: dir.clone(),
                    image: image_path.clone(),
                    host_workspace: spec.workspace_host_path.clone(),
                    guest_workspace: spec.workspace_path.clone(),
                },
            );

        // Any failure from here on leaves a spawned process behind; clean it up so `create` does
        // not leak a microVM (the manager also rolls back via `remove`, but a process that never got a
        // runtime_id back could become untracked).
        let result = async {
            self.wait_for_socket(&runtime_id).await?;

            // Boot source: guest kernel and its arguments. The guest's init reads `hx_workspace`
            // from the cmdline and mounts the workspace drive (`/dev/vdb`) there — that is the
            // mount step, declared where the mock can see it. No `initrd`.
            self.put_json(
                &runtime_id,
                "/boot-source",
                &json!({
                    "kernel_image_path": self.kernel.to_string_lossy(),
                    "boot_args": format!(
                        "console=ttyS0 reboot=k panic=1 pci=off hx_workspace={}",
                        spec.workspace_path,
                    ),
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

            // Workspace drive: the provisioned image, writable — the sandbox's work must survive it.
            // No workspace means nothing is mounted, which is refused earlier by `spec.validate`.
            self.put_json(
                &runtime_id,
                &format!("/drives/{WORKSPACE_DRIVE}"),
                &json!({
                    "drive_id": WORKSPACE_DRIVE,
                    "path_on_host": image_path.to_string_lossy(),
                    "is_root_device": false,
                    "is_read_only": false,
                }),
            )
            .await?;

            // The vsock device: the only side channel out of a network-off microVM, used by `exec`.
            // Each microVM gets its own guest CID — the identity the exec transport dials.
            self.put_json(
                &runtime_id,
                "/vsock",
                &json!({
                    "vsock_id": VSOCK_ID,
                    "guest_cid": cid,
                    "uds_path": vsock_sock.to_string_lossy(),
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
            // Tear down the process we spawned so a failed create does not leak a microVM, and
            // hand the CID back so a retry does not drain the pool.
            self.release_cid(&runtime_id);
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
        // Firecracker has no graceful-stop API; killing the process is how a microVM stops. The
        // microVM's identity (CID, workspace mapping) is retained until `remove` — a stopped VM
        // still owns its CID, so nothing else can take it while the VM exists.
        let child = {
            let mut state = self.state.lock().expect("firecracker state lock");
            state
                .vms
                .get_mut(runtime_id)
                .and_then(|info| info.child.take())
        };
        if let Some(mut child) = child {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        Ok(())
    }

    async fn remove(&self, runtime_id: &str) -> Result<()> {
        // Dropping the identity releases the CID back to the pool; then remove the staging
        // directory (idempotent — removing an unknown or already-removed VM is fine).
        self.release_cid(runtime_id);
        let _ = std::fs::remove_dir_all(self.dir_for(runtime_id));
        Ok(())
    }

    async fn exec(
        &self,
        runtime_id: &str,
        command: &str,
        workdir: Option<&str>,
    ) -> Result<SandboxExecOutput> {
        // Route to the requested microVM: look up its live identity and hand it to the transport,
        // so the command reaches that guest's vsock CID and no other's. An untracked id is
        // refused — running it against a default endpoint would execute somewhere the caller did
        // not name. No caller-supplied workdir means the guest workspace, where the work is.
        let (target, guest_workspace) = {
            let state = self.state.lock().expect("firecracker state lock");
            match state.vms.get(runtime_id) {
                Some(info) => (
                    VmExecTarget {
                        runtime_id: runtime_id.to_string(),
                        cid: info.cid,
                        uds_path: info.dir.join("vsock.sock"),
                        guest_workspace: info.guest_workspace.clone(),
                    },
                    info.guest_workspace.clone(),
                ),
                None => {
                    return Err(HxError::Sandbox(format!(
                        "no such firecracker microVM: {runtime_id}"
                    )));
                }
            }
        };
        self.exec
            .exec(&target, command, workdir.or(Some(&guest_workspace)))
            .await
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

    #[test]
    fn workspace_image_size_is_bounded() {
        // A zero or missing ceiling still yields a usable image; a huge one is clamped.
        assert_eq!(
            workspace_image_bytes(0),
            MIN_WORKSPACE_IMAGE_BYTES,
            "no ceiling still provisions a minimal image"
        );
        assert_eq!(
            workspace_image_bytes(16_384),
            MAX_WORKSPACE_IMAGE_BYTES,
            "the default 16 GiB ceiling must not materialise 16 GiB"
        );
        assert_eq!(
            workspace_image_bytes(u64::MAX),
            MAX_WORKSPACE_IMAGE_BYTES,
            "an absurd ceiling saturates instead of overflowing"
        );
    }
}
