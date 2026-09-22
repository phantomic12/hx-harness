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
//! tree with guest block storage. So `create` provisions `<vm-dir>/workspace.ext4` — a bounded
//! sparse file formatted as a real ext4 filesystem and seeded with the host workspace's files —
//! and attaches *that* as the writable drive. A zeroed file would leave the guest's mount of
//! `/dev/vdb` with no superblock to mount; the format plus the seed is what makes the workspace
//! both mountable and populated. The guest mounts `/dev/vdb` where the boot args say
//! (`hx_workspace=<path>`); the runtime remembers which host directory the sandbox's work lives
//! in and exposes it via [`FirecrackerRuntime::host_workspace`], so an operator can map a guest
//! write back to the host.
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

/// Offset of the ext4 magic in the superblock: 1024-byte boot padding + 0x38.
const EXT4_SUPER_MAGIC_OFFSET: u64 = 1024 + 0x38;
/// The ext4 superblock magic (`0xEF53`): what a formatted image carries at the offset above.
const EXT4_SUPER_MAGIC: [u8; 2] = [0x53, 0xEF];
/// Volume label stamped on provisioned workspace images.
const WORKSPACE_VOLUME_LABEL: &str = "hx-workspace";
/// Seeding bounds: the guest image is bounded, so the host tree copied into it must be too.
const MAX_SEED_ENTRIES: usize = 4096;
const MAX_SEED_FILE_BYTES: u64 = 256 << 20;

/// Whether `path` carries an ext4 superblock (magic `0xEF53` at byte 1080).
///
/// WHY a magic check and not a mount: mounting needs root and a loop device, neither of which
/// a library (or CI) can assume. The magic is what `mount -t ext4` itself keys on before reading
/// anything else — a zeroed sparse file fails it, a `mkfs.ext4` image passes it.
fn workspace_image_has_ext4_superblock(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    if file.seek(SeekFrom::Start(EXT4_SUPER_MAGIC_OFFSET)).is_err() {
        return false;
    }
    let mut magic = [0u8; 2];
    matches!(file.read_exact(&mut magic), Ok(())) && magic == EXT4_SUPER_MAGIC
}

/// One host file to seed into the image: where it lives and where it lands in the guest.
struct SeedEntry {
    /// Absolute host path of the source file.
    source: PathBuf,
    /// Absolute guest path inside the image (`/hello.txt`, `/sub/dir/file`).
    dest: String,
    /// Source length, captured while walking so seeding can stay within the image budget.
    len: u64,
}

/// Walk `host_workspace` collecting regular files to seed, bounded so a huge host tree cannot
/// overflow the bounded image. Symlinks, sockets, devices, and oversized files are skipped: the
/// guest gets the work's bytes, not a copy of the host's special files.
fn collect_seed_entries(host_workspace: &str, image_bytes: u64) -> Vec<SeedEntry> {
    let root = PathBuf::from(host_workspace);
    if !root.is_dir() {
        return Vec::new();
    }
    let mut entries = Vec::new();
    let mut stack = vec![root.clone()];
    let mut total: u64 = 0;
    // Leave headroom for the filesystem itself: at most half the image carries seeded bytes.
    let budget = image_bytes / 2;
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(read) => read,
            Err(_) => continue,
        };
        for child in read.flatten() {
            if entries.len() >= MAX_SEED_ENTRIES || total >= budget {
                return entries;
            }
            let file_type = match child.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = child.path();
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let len = child.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
            if len > MAX_SEED_FILE_BYTES || total.saturating_add(len) > budget {
                continue;
            }
            let dest = match path.strip_prefix(&root) {
                Ok(rel) => format!("/{}", rel.to_string_lossy()),
                Err(_) => continue,
            };
            total += len;
            entries.push(SeedEntry {
                source: path,
                dest,
                len,
            });
        }
    }
    entries
}

/// Render the `debugfs` script that reproduces the seed entries inside the image: `mkdir` each
/// parent (a missing parent makes `write` fail), then `write` each file.
fn seed_script(entries: &[SeedEntry]) -> String {
    use std::collections::HashSet;
    let mut script = String::new();
    let mut made_dirs = HashSet::new();
    for entry in entries {
        let parent_is_root = Path::new(&entry.dest)
            .parent()
            .is_none_or(|p| p.to_string_lossy() == "/");
        if !parent_is_root {
            let stripped = entry.dest.strip_prefix('/').unwrap_or(&entry.dest);
            if let Some(rel_parent) = Path::new(stripped).parent() {
                let mut prefix = String::new();
                for component in rel_parent.components() {
                    prefix.push('/');
                    prefix.push_str(&component.as_os_str().to_string_lossy());
                    if made_dirs.insert(prefix.clone()) {
                        script.push_str(&format!("mkdir \"{}\"\n", prefix.replace('"', "\\\"")));
                    }
                }
            }
        }
        let _ = entry.len;
        script.push_str(&format!(
            "write \"{}\" \"{}\"\n",
            entry.source.to_string_lossy().replace('"', "\\\""),
            entry.dest.replace('"', "\\\""),
        ));
    }
    script
}

/// Provision the workspace block image at `image_path`: a bounded sparse file formatted as a
/// real ext4 filesystem and seeded with the host workspace's files.
///
/// WHY format here: Firecracker's block API attaches host *files* as guest drives, and the
/// guest mounts `/dev/vdb` where the boot args say. A zeroed sparse file has no superblock, so
/// that mount fails and the sandbox's work has nowhere to live. Formatting with `mkfs.ext4`
/// (a host requirement of this runtime, like the `firecracker` binary and KVM) gives the guest
/// a filesystem it can actually mount; copying the host tree in with `debugfs` gives the guest
/// the sandbox's work rather than an empty volume.
///
/// A missing host directory seeds nothing but still formats: the guest gets an empty but
/// mountable workspace instead of a boot failure.
async fn provision_workspace_image(
    image_path: &Path,
    image_bytes: u64,
    host_workspace: &str,
) -> Result<()> {
    let image_file = std::fs::File::create(image_path).map_err(|e| {
        HxError::Sandbox(format!(
            "could not create workspace image {}: {e}",
            image_path.display()
        ))
    })?;
    image_file.set_len(image_bytes).map_err(|e| {
        HxError::Sandbox(format!(
            "could not size workspace image {}: {e}",
            image_path.display()
        ))
    })?;
    drop(image_file);

    // Lazy table/journal init keeps even the 8 GiB ceiling image fast and sparse: the guest
    // kernel completes the init on mount, which is the standard production behaviour.
    let mkfs = tokio::process::Command::new("mkfs.ext4")
        .arg("-F")
        .arg("-q")
        .arg("-L")
        .arg(WORKSPACE_VOLUME_LABEL)
        .arg("-E")
        .arg("lazy_itable_init=1,lazy_journal_init=1")
        .arg(image_path)
        .output()
        .await
        .map_err(|e| {
            HxError::Sandbox(format!(
                "could not format workspace image {} (mkfs.ext4 required): {e}",
                image_path.display()
            ))
        })?;
    if !mkfs.status.success() {
        let detail = String::from_utf8_lossy(&mkfs.stderr).trim().to_string();
        return Err(HxError::Sandbox(format!(
            "could not format workspace image {}: mkfs.ext4 failed{detail}",
            image_path.display()
        )));
    }
    // The format is verified, not assumed: a tool that exits 0 but leaves no superblock (a
    // stub binary, a wrong device) must fail here, not as a guest mount failure later.
    if !workspace_image_has_ext4_superblock(image_path) {
        return Err(HxError::Sandbox(format!(
            "could not format workspace image {}: no ext4 superblock after mkfs.ext4",
            image_path.display()
        )));
    }

    let entries = collect_seed_entries(host_workspace, image_bytes);
    if entries.is_empty() {
        return Ok(());
    }
    let script = seed_script(&entries);
    let script_path = image_path.with_extension("debugfs.cmds");
    std::fs::write(&script_path, script).map_err(|e| {
        HxError::Sandbox(format!(
            "could not stage workspace seed script {}: {e}",
            script_path.display()
        ))
    })?;
    let seed = tokio::process::Command::new("debugfs")
        .arg("-w")
        .arg("-f")
        .arg(&script_path)
        .arg(image_path)
        .output()
        .await
        .map_err(|e| {
            HxError::Sandbox(format!(
                "could not seed workspace image {} (debugfs required): {e}",
                image_path.display()
            ))
        })?;
    let _ = std::fs::remove_file(&script_path);
    if !seed.status.success() {
        let detail = String::from_utf8_lossy(&seed.stderr).trim().to_string();
        return Err(HxError::Sandbox(format!(
            "could not seed workspace image {} from {host_workspace}: debugfs failed{detail}",
            image_path.display()
        )));
    }
    Ok(())
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

/// How `stop` kills the owned microVM process.
///
/// WHY the seam: `tokio::process::Child` is concrete, and real process semantics cannot
/// deterministically script a kill or wait failure (on Linux, killing an already-reaped pid
/// succeeds). This trait lets the hermetic suite drive `stop`'s failure paths with a fake
/// child instead of racing the process table.
#[async_trait]
trait ChildHandle: Send {
    async fn kill(&mut self) -> std::io::Result<()>;
    async fn wait(&mut self) -> std::io::Result<()>;
}

#[async_trait]
impl ChildHandle for Child {
    async fn kill(&mut self) -> std::io::Result<()> {
        tokio::process::Child::kill(self).await
    }

    async fn wait(&mut self) -> std::io::Result<()> {
        tokio::process::Child::wait(self).await.map(|_| ())
    }
}

/// One live (or stopped-but-not-removed) microVM: everything `exec` and `remove` need to find it.
struct VmInfo {
    /// The owned process; `None` after `stop` (killing it is how the microVM stops).
    child: Option<Box<dyn ChildHandle>>,
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

        // The workspace block image: a bounded sparse file formatted as a real ext4 filesystem
        // and seeded with the host workspace's files, which the block API can attach. The spec's
        // host path is a directory and can never be a `path_on_host` — Firecracker would reject
        // it, and even if it did not, guest block writes would land directly in the host tree.
        // A zeroed file alone would be no better: the guest mounts `/dev/vdb` at the workspace
        // path, and that mount needs a superblock.
        let image_path = dir.join(WORKSPACE_IMAGE_NAME);
        provision_workspace_image(
            &image_path,
            workspace_image_bytes(spec.workspace_mb),
            &spec.workspace_host_path,
        )
        .await?;

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
                    child: Some(Box::new(child)),
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
        //
        // Stopping an unknown or already-stopped VM is a no-op: both mean there is no process
        // to kill, so a repeated `stop` (a retry, or a destroy racing a reap) succeeds.
        let child = {
            let mut state = self.state.lock().expect("firecracker state lock");
            match state.vms.get_mut(runtime_id) {
                Some(info) => info.child.take(),
                None => None,
            }
        };
        let Some(mut child) = child else {
            return Ok(());
        };
        // A failed kill or wait leaves the child handle back in the map: dropping it here would
        // untrack a process that may still be alive (or unreaped), handing its CID to a new
        // microVM while the old one lingers. Keeping it tracked makes the retry possible.
        if let Err(e) = child.kill().await {
            let mut state = self.state.lock().expect("firecracker state lock");
            if let Some(info) = state.vms.get_mut(runtime_id) {
                info.child = Some(child);
            }
            return Err(HxError::Sandbox(format!(
                "could not stop firecracker microVM {runtime_id}: kill failed: {e}"
            )));
        }
        if let Err(e) = child.wait().await {
            let mut state = self.state.lock().expect("firecracker state lock");
            if let Some(info) = state.vms.get_mut(runtime_id) {
                info.child = Some(child);
            }
            return Err(HxError::Sandbox(format!(
                "could not stop firecracker microVM {runtime_id}: wait failed: {e}"
            )));
        }
        Ok(())
    }

    async fn remove(&self, runtime_id: &str) -> Result<()> {
        // The staging directory goes first; the identity (and its CID) is released only once
        // the directory is gone. Releasing first would let a new microVM reuse the CID while
        // the old VM's directory still sits on disk — and an untracked VM can never be
        // retried, so a failed cleanup would leak silently. A missing directory means there
        // is nothing to clean (already removed), so removing an unknown or already-removed
        // VM succeeds.
        let dir = {
            let state = self.state.lock().expect("firecracker state lock");
            match state.vms.get(runtime_id) {
                Some(info) => info.dir.clone(),
                None => self.dir_for(runtime_id),
            }
        };
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(HxError::Sandbox(format!(
                    "could not remove firecracker microVM dir {}: {e}",
                    dir.display()
                )));
            }
        }
        // Dropping the child handle kills a still-running process (`kill_on_drop`); the
        // directory above is already gone, so this VM cannot leak disk either way. The CID
        // returns to the pool only here, on success.
        let mut state = self.state.lock().expect("firecracker state lock");
        if let Some(info) = state.vms.remove(runtime_id) {
            state.free_cids.push(info.cid);
        }
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

    /// A tracked microVM for stop/remove tests: a stand-in child (a fake or a real process,
    /// never a firecracker binary) plus a staging dir, inserted directly into the state map.
    fn track_test_vm(
        rt: &FirecrackerRuntime,
        runtime_id: &str,
        child: Option<Box<dyn ChildHandle>>,
        dir: PathBuf,
    ) {
        rt.state.lock().expect("firecracker state lock").vms.insert(
            runtime_id.to_string(),
            VmInfo {
                child,
                cid: CID_FIRST,
                dir,
                image: PathBuf::from("/tmp/test-workspace.ext4"),
                host_workspace: "/tmp/host-work".to_string(),
                guest_workspace: "/workspace".to_string(),
            },
        );
    }

    /// A fake owned process with scripted kill/wait outcomes, standing in for the
    /// `firecracker` binary `stop` would kill. Real process semantics cannot fail a kill
    /// on demand, so the failure paths need this instead of a live child.
    struct FakeChild {
        kill_err: Option<String>,
        wait_err: Option<String>,
    }

    impl FakeChild {
        fn failing_at_kill() -> Self {
            Self {
                kill_err: Some("permission denied".to_string()),
                wait_err: None,
            }
        }

        fn failing_at_wait() -> Self {
            Self {
                kill_err: None,
                wait_err: Some("no child processes".to_string()),
            }
        }
    }

    #[async_trait]
    impl ChildHandle for FakeChild {
        async fn kill(&mut self) -> std::io::Result<()> {
            match &self.kill_err {
                Some(msg) => Err(std::io::Error::other(msg.clone())),
                None => Ok(()),
            }
        }

        async fn wait(&mut self) -> std::io::Result<()> {
            match &self.wait_err {
                Some(msg) => Err(std::io::Error::other(msg.clone())),
                None => Ok(()),
            }
        }
    }

    fn test_scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hx-firecracker-r76-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn child_still_tracked(rt: &FirecrackerRuntime, runtime_id: &str) -> bool {
        rt.state
            .lock()
            .expect("firecracker state lock")
            .vms
            .get(runtime_id)
            .is_some_and(|info| info.child.is_some())
    }

    #[tokio::test]
    async fn stop_reports_kill_failure_and_keeps_vm_tracked() {
        let rt =
            FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into());
        let dir = test_scratch_dir("stop-fail");
        let runtime_id = "stop-fail-vm";
        track_test_vm(
            &rt,
            runtime_id,
            Some(Box::new(FakeChild::failing_at_kill())),
            dir.clone(),
        );

        let err = rt
            .stop(runtime_id, 0)
            .await
            .expect_err("stop must report the kill failure");
        assert!(
            err.to_string().contains("kill failed"),
            "unexpected error: {err}"
        );
        // The failed cleanup remains tracked: the child handle is back in the map and the
        // CID is still reserved, so a retry (or a later remove) can find the VM.
        assert!(
            child_still_tracked(&rt, runtime_id),
            "failed stop must keep the child handle tracked"
        );
        assert_eq!(
            rt.vm_cid(runtime_id),
            Some(CID_FIRST),
            "failed stop must keep the CID reserved"
        );

        // The retry sees the same failure rather than silently succeeding or losing the VM.
        assert!(
            rt.stop(runtime_id, 0).await.is_err(),
            "retrying a failed stop must fail again, not report success"
        );
        assert!(
            child_still_tracked(&rt, runtime_id),
            "retry must still keep the VM tracked"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn stop_reports_wait_failure_and_keeps_vm_tracked() {
        let rt =
            FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into());
        let dir = test_scratch_dir("stop-wait-fail");
        let runtime_id = "stop-wait-fail-vm";
        track_test_vm(
            &rt,
            runtime_id,
            Some(Box::new(FakeChild::failing_at_wait())),
            dir.clone(),
        );

        let err = rt
            .stop(runtime_id, 0)
            .await
            .expect_err("stop must report the wait failure");
        assert!(
            err.to_string().contains("wait failed"),
            "unexpected error: {err}"
        );
        assert!(
            child_still_tracked(&rt, runtime_id),
            "failed stop must keep the child handle tracked"
        );
        assert_eq!(
            rt.vm_cid(runtime_id),
            Some(CID_FIRST),
            "failed stop must keep the CID reserved"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn stop_kills_a_live_child_but_keeps_the_identity_until_remove() {
        let rt =
            FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into());
        let dir = test_scratch_dir("stop-live");
        let runtime_id = "stop-live-vm";
        // A real (long-lived, harmless) process through the production `Child` impl, proving
        // the seam forwards kill/wait to the actual process.
        let live = tokio::process::Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .expect("stand-in sleep");
        track_test_vm(&rt, runtime_id, Some(Box::new(live)), dir.clone());

        rt.stop(runtime_id, 0).await.expect("live stop succeeds");
        // The process is gone but the microVM's identity (CID, workspace mapping) is retained
        // until `remove` — a stopped VM still owns its CID.
        assert_eq!(
            rt.vm_cid(runtime_id),
            Some(CID_FIRST),
            "stopped VM keeps its CID until remove"
        );
        assert!(
            !child_still_tracked(&rt, runtime_id),
            "stopped VM has no process left to kill"
        );
        rt.remove(runtime_id)
            .await
            .expect("remove after stop succeeds");
        assert_eq!(rt.vm_cid(runtime_id), None, "remove releases the CID");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn stop_is_idempotent_for_unknown_and_stopped_vms() {
        let rt =
            FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into());
        // Unknown: nothing to kill, so stopping succeeds (a destroy racing a reap retries).
        rt.stop("no-such-vm", 10).await.expect("unknown stop is Ok");

        // Already stopped (child taken by a previous stop): still tracked, still Ok.
        let dir = test_scratch_dir("stop-idempotent");
        track_test_vm(&rt, "stopped-vm", None, dir.clone());
        rt.stop("stopped-vm", 10).await.expect("stopped stop is Ok");
        assert_eq!(
            rt.vm_cid("stopped-vm"),
            Some(CID_FIRST),
            "stopping a stopped VM must keep its CID reserved until remove"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn remove_reports_dir_failure_and_keeps_cid_reserved() {
        let rt =
            FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into());
        let scratch = test_scratch_dir("remove-fail");
        // Point the VM's dir at a regular file: `remove_dir_all` on a non-directory fails,
        // deterministically standing in for an undeletable staging dir.
        let blocker = scratch.join("blocker");
        std::fs::write(&blocker, b"not a directory").expect("blocker file");
        track_test_vm(&rt, "remove-fail-vm", None, blocker.clone());

        let err = rt
            .remove("remove-fail-vm")
            .await
            .expect_err("remove must report the filesystem failure");
        assert!(
            err.to_string().contains("could not remove"),
            "unexpected error: {err}"
        );
        // The failed cleanup remains tracked: the CID stays reserved so no new microVM can
        // reuse the identity while the old staging dir still exists.
        assert_eq!(
            rt.vm_cid("remove-fail-vm"),
            Some(CID_FIRST),
            "failed remove must keep the CID reserved"
        );

        // Clearing the blocker makes the idempotent retry succeed and releases the CID.
        std::fs::remove_file(&blocker).expect("clear blocker");
        std::fs::create_dir_all(&blocker).expect("dir in place of blocker");
        rt.remove("remove-fail-vm")
            .await
            .expect("retry after fixing the dir succeeds");
        assert_eq!(
            rt.vm_cid("remove-fail-vm"),
            None,
            "successful remove releases the CID"
        );
        // The freed CID returns to the pool rather than being lost.
        assert!(
            rt.state
                .lock()
                .expect("firecracker state lock")
                .free_cids
                .contains(&CID_FIRST),
            "removed VM's CID must be recyclable"
        );
        // Removing again (already removed) is a no-op success.
        rt.remove("remove-fail-vm")
            .await
            .expect("second remove is Ok");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[tokio::test]
    async fn remove_unknown_vm_with_no_dir_succeeds() {
        let rt =
            FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into());
        rt.remove("never-existed/api.sock")
            .await
            .expect("removing an unknown VM with no leftover dir is Ok");
    }

    /// Unique scratch dir for the provisioning tests (parallel-safe, unlike a fixed name).
    fn provision_scratch_dir(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "hx-firecracker-provision-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("provision scratch dir");
        dir
    }

    /// `mkfs.ext4`/`debugfs` are host tools, not library code: skip (loudly) where they are
    /// absent instead of failing a host that cannot provision Firecracker images anyway.
    fn require_image_tools() -> bool {
        for tool in ["mkfs.ext4", "debugfs"] {
            let probe = std::process::Command::new(tool).arg("-V").output();
            if probe.is_err() {
                eprintln!("SKIP: provisioning test needs {tool} on PATH");
                return false;
            }
        }
        true
    }

    /// Read a file back out of an image through `debugfs cat`, without mounting.
    fn debugfs_cat(image: &Path, guest_path: &str) -> Option<String> {
        let out = std::process::Command::new("debugfs")
            .arg("-R")
            .arg(format!("cat \"{guest_path}\""))
            .arg(image)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout).ok()
    }

    #[test]
    fn a_blank_zeroed_file_is_not_a_valid_workspace_filesystem() {
        // Pins the original #58 bug: `File::create` + `set_len` alone is a blank file with no
        // superblock, so the guest's mount of `/dev/vdb` has nothing to mount.
        let dir = provision_scratch_dir("blank");
        let blank = dir.join("blank.ext4");
        let file = std::fs::File::create(&blank).expect("blank file");
        file.set_len(MIN_WORKSPACE_IMAGE_BYTES).expect("size blank");
        drop(file);
        assert!(
            !workspace_image_has_ext4_superblock(&blank),
            "a zeroed sparse file must not pass as a filesystem"
        );
        assert!(
            !workspace_image_has_ext4_superblock(&dir.join("missing.ext4")),
            "a missing image must not pass as a filesystem"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_script_creates_parent_dirs_before_writes() {
        // Pure check of the debugfs script: no host tools needed.
        let entries = vec![
            SeedEntry {
                source: PathBuf::from("/host/top.txt"),
                dest: "/top.txt".to_string(),
                len: 3,
            },
            SeedEntry {
                source: PathBuf::from("/host/sub/dir/nested.txt"),
                dest: "/sub/dir/nested.txt".to_string(),
                len: 6,
            },
        ];
        let script = seed_script(&entries);
        let mkdir = script.find("mkdir \"/sub\"").expect("mkdir /sub");
        let mkdir_nested = script.find("mkdir \"/sub/dir\"").expect("mkdir /sub/dir");
        let write_nested = script
            .find("write \"/host/sub/dir/nested.txt\" \"/sub/dir/nested.txt\"")
            .expect("nested write");
        assert!(mkdir < mkdir_nested, "parents before children: {script}");
        assert!(mkdir_nested < write_nested, "dirs before writes: {script}");
        assert!(
            script.starts_with("write \"/host/top.txt\" \"/top.txt\"\n"),
            "a top-level file needs no mkdir: {script}"
        );
    }

    #[tokio::test]
    async fn provisioned_image_is_a_valid_filesystem_seeded_with_the_host_tree() {
        if !require_image_tools() {
            return;
        }
        let dir = provision_scratch_dir("seeded");
        let host = dir.join("host-work");
        std::fs::create_dir_all(host.join("sub/dir")).expect("host tree");
        std::fs::write(host.join("hello.txt"), b"host bytes here").expect("host file");
        std::fs::write(host.join("sub/dir/nested.txt"), b"nested bytes").expect("nested file");

        let image = dir.join("workspace.ext4");
        provision_workspace_image(&image, MIN_WORKSPACE_IMAGE_BYTES, &host.to_string_lossy())
            .await
            .expect("provision");

        // The image is a real filesystem: the ext4 superblock magic is present.
        assert!(
            workspace_image_has_ext4_superblock(&image),
            "provisioned image must carry an ext4 superblock"
        );
        // And the host tree reached it: seeded files read back out of the image.
        assert_eq!(
            debugfs_cat(&image, "/hello.txt").as_deref(),
            Some("host bytes here"),
            "top-level host file must be seeded into the image"
        );
        assert_eq!(
            debugfs_cat(&image, "/sub/dir/nested.txt").as_deref(),
            Some("nested bytes"),
            "nested host file must be seeded into the image with its parents"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn provisioned_image_without_a_host_tree_is_still_a_valid_filesystem() {
        if !require_image_tools() {
            return;
        }
        // A configured-but-absent host dir (as in the hermetic suite) still formats: the guest
        // gets an empty but mountable workspace instead of a boot failure.
        let dir = provision_scratch_dir("empty");
        let image = dir.join("workspace.ext4");
        provision_workspace_image(
            &image,
            MIN_WORKSPACE_IMAGE_BYTES,
            &dir.join("no-such-workspace").to_string_lossy(),
        )
        .await
        .expect("provision without a host tree");
        assert!(
            workspace_image_has_ext4_superblock(&image),
            "an unseeded image must still be a valid ext4 filesystem"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
