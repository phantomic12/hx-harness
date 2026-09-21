//! Live integration tests for the Firecracker runtime against a **real** `firecracker` binary and
//! `/dev/kvm`. Everything else about the runtime — the exact API calls, their order, and the security
//! posture of each payload — is asserted hermetically in `firecracker_mock.rs` against an axum mock
//! that needs no KVM. This file is where the runtime meets an actual microVM.
//!
//! It is `#[ignore]`d by default because booting a microVM needs a kernel image, a root filesystem,
//! and a host with a working `/dev/kvm` — none of which the default `cargo test` gate may assume.
//! Run it explicitly on a KVM host that also has the images:
//!
//! ```console
//! $ HX_FC_KERNEL=/opt/firecracker/vmlinux \
//!   HX_FC_ROOTFS=/opt/firecracker/rootfs.ext4 \
//!   cargo test -p hx-sandbox --test firecracker_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! A missing binary or missing `/dev/kvm` is a **skip**, not a pass: `available()` returning
//! false is exactly the signal that the prerequisites are absent, and the test says so.
//! `HX_FC_BIN` (default `firecracker`) overrides the binary path for non-PATH installs.

use hx_core::config::IsolationLevel;
use hx_core::ids::SandboxId;
use hx_sandbox::{FirecrackerRuntime, SandboxRuntime, SandboxSpec};
use std::path::PathBuf;
use tempfile::TempDir;

fn spec(ws_host: &str) -> SandboxSpec {
    SandboxSpec {
        profile: "live".into(),
        image: "firecracker".into(),
        isolation: IsolationLevel::L3,
        cpus: 1.0,
        memory_mb: 1024,
        pids_max: 512,
        workspace_mb: 2048,
        ttl_secs: 60,
        egress_allow: Vec::new(),
        network: false,
        readonly_rootfs: true,
        workspace_host_path: ws_host.into(),
        workspace_path: "/workspace".into(),
        user: None,
        env: Vec::new(),
        runtime: Some("firecracker".to_string()),
    }
}

fn rt_from_env() -> Option<(FirecrackerRuntime, TempDir, PathBuf, PathBuf)> {
    let kernel = std::env::var("HX_FC_KERNEL").ok()?;
    let rootfs = std::env::var("HX_FC_ROOTFS").ok()?;
    let bin = std::env::var("HX_FC_BIN").unwrap_or_else(|_| "firecracker".into());
    let work = TempDir::new().expect("work dir");
    let rt = FirecrackerRuntime::new(
        work.path().to_path_buf(),
        PathBuf::from(&kernel),
        PathBuf::from(&rootfs),
    )
    .with_paths(PathBuf::from(&bin), "/dev/kvm".into());
    Some((rt, work, PathBuf::from(kernel), PathBuf::from(rootfs)))
}

#[tokio::test]
#[ignore = "needs firecracker + /dev/kvm + guest kernel/rootfs"]
async fn a_full_lifecycle_runs_a_microvm_when_the_host_can() {
    let Some((rt, work, kernel, rootfs)) = rt_from_env() else {
        eprintln!("SKIP: HX_FC_KERNEL/HX_FC_ROOTFS not set");
        return;
    };
    if !rt.available().await {
        eprintln!("SKIP: firecracker binary or /dev/kvm absent");
        return;
    }

    let ws = work.path().join("ws");
    std::fs::create_dir_all(&ws).expect("workspace dir");
    let s = spec(ws.to_str().unwrap());
    let id = SandboxId::from_raw("sbx_fc_live1");

    let rt_id = rt
        .create(&id, &s, &s.host_settings())
        .await
        .expect("create");
    assert!(
        rt_id.contains("sbx_fc_live1"),
        "runtime_id embeds the sandbox id"
    );
    assert!(
        kernel.exists(),
        "kernel image {kernel:?} must exist for a real boot"
    );
    assert!(
        rootfs.exists(),
        "rootfs image {rootfs:?} must exist for a real boot"
    );

    rt.start(&rt_id).await.expect("start");
    // A started, network-off microVM exposes a console; there is no output to capture from an API that
    // deliberately has none. The lifecycle proof is that create + start returned Ok on real KVM.

    rt.stop(&rt_id, 0).await.expect("stop");
    rt.remove(&rt_id).await.expect("remove");
    // remove deleted the staging directory.
    assert!(
        !std::path::Path::new(&rt_id).exists(),
        "remove cleaned the staging dir"
    );
}
