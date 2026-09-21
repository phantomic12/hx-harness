//! Hermetic tests for the Firecracker runtime, against a tiny axum mock of the Firecracker HTTP
//! API on a Unix socket.
//!
//! Real `firecracker` needs `/dev/kvm` and a guest kernel/rootfs; none of that exists on a
//! build host. The runtime calls its `bin` with `--api-sock <path>` and then PUTs over that
//! socket. These tests point `bin` at `/bin/sleep` (a real spawnable file that never reads its
//! args, but also never creates the socket — the mock does that) and bind an axum listener exactly
//! where the runtime expects the socket. They assert on the requests the runtime sends: the exact order
//! (`/boot-source`, the drives, `/vsock`, `/machine-config`) and the security posture of each
//! payload (network off — no NIC is ever configured; root read-only; workspace writable; resources
//! match the spec). A hardening knob that silently dropped out of a payload, or a network interface
//! that appeared, would fail here.

use axum::{
    extract::{Request as AxumRequest, State},
    http::{Method, StatusCode},
    routing::put,
    Router,
};
use http_body_util::BodyExt;
use hx_core::config::IsolationLevel;
use hx_core::ids::SandboxId;
use hx_sandbox::{FirecrackerRuntime, SandboxRuntime, SandboxSpec};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// Records every PUT the runtime makes: the method, the path, and the parsed body.
#[derive(Default, Clone)]
struct Mock {
    calls: Arc<Mutex<Vec<(String, String, Value)>>>,
}

async fn handler(State(mock): State<Mock>, method: Method, req: AxumRequest) -> StatusCode {
    if method != Method::PUT {
        return StatusCode::METHOD_NOT_ALLOWED;
    }
    let path = req.uri().path().to_string();
    let whole = req.into_body().collect().await.unwrap_or_default();
    let parsed = serde_json::from_slice(&whole.to_bytes()).unwrap_or(Value::Null);
    mock.calls
        .lock()
        .expect("mock lock")
        .push((method.to_string(), path, parsed));
    StatusCode::NO_CONTENT
}

/// Build a runtime whose binary is a harmless real file and whose API socket location is served by the
/// mock. Returns (runtime, mock, work_dir).
fn runtime_on_mock() -> (FirecrackerRuntime, Mock, TempDir) {
    let work_dir = TempDir::new().expect("work temp dir");
    let runtime = FirecrackerRuntime::new(
        work_dir.path().to_path_buf(),
        "/images/kernel.bin".into(),
        "/images/rootfs.ext4".into(),
    )
    .with_paths("/bin/sleep".into(), "/dev/null".into());
    (runtime, Mock::default(), work_dir)
}

/// Start an axum mock bound to the socket `<work_dir>/<id>/api.sock` that the runtime will use.
async fn serve_mock(work_dir: &TempDir, id: &str, mock: Mock) {
    let sock = work_dir.path().join(id).join("api.sock");
    std::fs::create_dir_all(sock.parent().unwrap()).expect("create api dir");
    let app = Router::new()
        .route("/boot-source", put(handler))
        .route("/drives/{drive}", put(handler))
        .route("/vsock", put(handler))
        .route("/machine-config", put(handler))
        .route("/actions", put(handler))
        .with_state(mock.clone());

    let listener = tokio::net::UnixListener::bind(&sock).expect("bind unix socket");
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("mock server");
    });

    // Wait for accepting before `create` spawns the fake binary, so the socket exists when the
    // runtime polls for it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if tokio::net::UnixStream::connect(&sock).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn spec() -> SandboxSpec {
    SandboxSpec {
        profile: "dev".into(),
        image: "debian:stable-slim".into(),
        isolation: IsolationLevel::L3,
        cpus: 2.0,
        memory_mb: 4096,
        pids_max: 1024,
        workspace_mb: 16_384,
        ttl_secs: 3600,
        egress_allow: Vec::new(),
        network: false,
        readonly_rootfs: true,
        workspace_host_path: "/mnt/ws".into(),
        workspace_path: "/workspace".into(),
        user: None,
        env: Vec::new(),
        runtime: Some("firecracker".to_string()),
    }
}

fn paths(calls: &[(String, String, Value)]) -> Vec<String> {
    calls.iter().map(|(_, p, _)| p.clone()).collect()
}

#[tokio::test]
async fn create_puts_every_resource_in_the_reviewed_order() {
    let (runtime, mock, work_dir) = runtime_on_mock();
    serve_mock(&work_dir, "sbx_test123", mock.clone()).await;

    let rt_id = runtime
        .create(
            &SandboxId::from_raw("sbx_test123"),
            &spec(),
            &spec().host_settings(),
        )
        .await
        .expect("create");

    let calls = mock.calls.lock().unwrap().clone();
    let got: Vec<String> = paths(&calls);
    assert_eq!(
        got,
        vec![
            "/boot-source",
            "/drives/rootfs",
            "/drives/workspace",
            "/vsock",
            "/machine-config",
        ],
        "the create sequence must configure the microVM in order: {got:?}"
    );
    assert!(rt_id.contains("sbx_test123"));
}

#[tokio::test]
async fn the_microvm_has_no_network_interface() {
    let (runtime, mock, work_dir) = runtime_on_mock();
    serve_mock(&work_dir, "sbx_netoff", mock.clone()).await;

    runtime
        .create(
            &SandboxId::from_raw("sbx_netoff"),
            &spec(),
            &spec().host_settings(),
        )
        .await
        .expect("create");

    let calls = mock.calls.lock().unwrap().clone();
    assert!(
        !paths(&calls).iter().any(|p| p.starts_with("/network")),
        "a network-off microVM must have no NIC: {calls:?}"
    );
}

#[tokio::test]
async fn the_root_drive_is_read_only_and_the_workspace_is_writable() {
    let (runtime, mock, work_dir) = runtime_on_mock();
    serve_mock(&work_dir, "sbx_drives", mock.clone()).await;

    runtime
        .create(
            &SandboxId::from_raw("sbx_drives"),
            &spec(),
            &spec().host_settings(),
        )
        .await
        .expect("create");

    let calls = mock.calls.lock().unwrap().clone();
    let root = calls
        .iter()
        .find(|(_, p, _)| p == "/drives/rootfs")
        .expect("root drive configured");
    let ws = calls
        .iter()
        .find(|(_, p, _)| p == "/drives/workspace")
        .expect("workspace drive configured");

    assert_eq!(root.2["is_root_device"], true);
    assert_eq!(
        root.2["is_read_only"], true,
        "the guest root must be read-only"
    );
    assert_eq!(root.2["path_on_host"], "/images/rootfs.ext4");

    // #58: the workspace is now a provisioned block image in the sandbox drive dir,
    // not the bare host directory.
    assert_eq!(
        ws.2["is_read_only"], false,
        "the workspace drive must be writable"
    );
    let ws_path = ws.2["path_on_host"].as_str().unwrap_or_default();
    assert!(
        ws_path.ends_with(".ext4") && ws_path.contains("sbx_drives"),
        "workspace drive must be a provisioned block image, got {ws_path}"
    );
}

#[tokio::test]
async fn the_machine_config_matches_the_spec_resources() {
    let (runtime, mock, work_dir) = runtime_on_mock();
    serve_mock(&work_dir, "sbx_machine", mock.clone()).await;

    runtime
        .create(
            &SandboxId::from_raw("sbx_machine"),
            &spec(),
            &spec().host_settings(),
        )
        .await
        .expect("create");

    let calls = mock.calls.lock().unwrap().clone();
    let mc = calls
        .iter()
        .find(|(_, p, _)| p == "/machine-config")
        .expect("machine config");
    assert_eq!(mc.2["vcpu_count"], 2);
    assert_eq!(mc.2["mem_size_mib"], 4096);
    assert_eq!(mc.2["ht_enabled"], false);
}

#[tokio::test]
async fn the_vsock_side_channel_is_created_for_exec() {
    let (runtime, mock, work_dir) = runtime_on_mock();
    serve_mock(&work_dir, "sbx_vsock", mock.clone()).await;

    runtime
        .create(
            &SandboxId::from_raw("sbx_vsock"),
            &spec(),
            &spec().host_settings(),
        )
        .await
        .expect("create");

    let calls = mock.calls.lock().unwrap().clone();
    let vsock = calls
        .iter()
        .find(|(_, p, _)| p == "/vsock")
        .expect("vsock created");
    assert_eq!(vsock.2["vsock_id"], "vsock");
    assert_eq!(vsock.2["guest_cid"], 3);
}

#[tokio::test]
async fn a_missing_binary_reports_unavailable() {
    let runtime =
        FirecrackerRuntime::new("/tmp/fc".into(), "/tmp/kernel".into(), "/tmp/rootfs".into())
            .with_paths("/definitely/not/a/real/binary".into(), "/dev/null".into());
    assert!(!runtime.available().await);
}

/// The set of endpoints the runtime ever PUTs — a tripwire so an unexpected one fails.
#[tokio::test]
async fn only_the_documented_endpoints_are_touched() {
    let (runtime, mock, work_dir) = runtime_on_mock();
    serve_mock(&work_dir, "sbx_trip", mock.clone()).await;

    runtime
        .create(
            &SandboxId::from_raw("sbx_trip"),
            &spec(),
            &spec().host_settings(),
        )
        .await
        .expect("create");

    let calls = mock.calls.lock().unwrap().clone();
    let allowed: HashSet<&str> = [
        "/boot-source",
        "/drives/rootfs",
        "/drives/workspace",
        "/vsock",
        "/machine-config",
    ]
    .into_iter()
    .collect();
    for (_, p, _) in &calls {
        assert!(
            allowed.contains(p.as_str()),
            "unexpected endpoint {p} in {calls:?}"
        );
    }
}

#[tokio::test]
async fn start_puts_instancestart_after_create() {
    let (runtime, mock, work_dir) = runtime_on_mock();
    serve_mock(&work_dir, "sbx_start", mock.clone()).await;

    let rt_id = runtime
        .create(
            &SandboxId::from_raw("sbx_start"),
            &spec(),
            &spec().host_settings(),
        )
        .await
        .expect("create");
    runtime.start(&rt_id).await.expect("start");

    let calls = mock.calls.lock().unwrap().clone();
    assert_eq!(
        paths(&calls),
        vec![
            "/boot-source",
            "/drives/rootfs",
            "/drives/workspace",
            "/vsock",
            "/machine-config",
            "/actions",
        ],
        "start appends InstanceStart after all create-time config: {calls:?}"
    );
    let last = calls.last().expect("at least one call");
    assert_eq!(
        last.1, "/actions",
        "start is the InstanceStart action: {calls:?}"
    );
    assert_eq!(last.2["action_type"], "InstanceStart");
}

#[tokio::test]
async fn the_default_exec_channel_refuses_instead_of_lying() {
    // The mock serves the socket but the runtime uses the default (no) exec channel: exec must error
    // loudly, not claim a command ran that never ran in a guest.
    let (runtime, mock, work_dir) = runtime_on_mock();
    serve_mock(&work_dir, "sbx_exec", mock.clone()).await;
    let rt_id = runtime
        .create(
            &SandboxId::from_raw("sbx_exec"),
            &spec(),
            &spec().host_settings(),
        )
        .await
        .expect("create");

    let out = runtime.exec(&rt_id, "echo hi", None).await;
    assert!(
        out.is_err(),
        "exec with no transport must refuse, got {out:?}"
    );
    // A refused exec adds no API calls of its own; the count is unchanged from create's five.
    let calls = mock.calls.lock().unwrap().clone();
    assert_eq!(
        calls.len(),
        5,
        "a refused exec must not touch the API: {calls:?}"
    );
}
