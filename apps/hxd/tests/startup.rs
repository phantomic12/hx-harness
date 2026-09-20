//! Integration tests for `hxd` startup and bind security.
//!
//! ## What is pinned here
//!
//! `docs/approvals.md` §9 and `ROADMAP.md` M6 record the startup rule as the control that closed
//! the unauthenticated-remote-caller hole: `require_token_for_bind` refuses to start when the bind
//! address is not loopback and no token was resolved.
//!
//! Unit tests cover the pure function in `crates/hx-core/src/api_auth.rs`. These tests prove the
//! **composition**: that the real `hxd` binary built by Cargo refuses to start on a routable bind
//! when no token is configured, names the missing setting in its error, and leaves nothing listening
//! on the port.
//!
//! The positive control proves that with a token configured, the daemon does start and serve on
//! that same non-loopback bind — distinguishing a deliberate security refusal from a daemon that
//! crashes on startup.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const HXD: &str = env!("CARGO_BIN_EXE_hxd");
const TOKEN: &str = "hx-startup-control-token-9b3c1a";

/// Obtain a free local port by binding port 0 and dropping the listener.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// Verify that nothing is listening on `port`.
///
/// Both checks must hold:
/// 1. An outbound connect to loopback must fail (connection refused).
/// 2. Binding `0.0.0.0:port` must succeed (the port is not already bound).
fn is_nothing_listening(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
        return false;
    }
    match TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(_) => false,
    }
}

/// Write a minimal configuration for `hxd` inside `dir`.
fn write_config(dir: &Path, token: Option<&str>) -> PathBuf {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let api_section = match token {
        Some(tok) => format!("api:\n  token: \"{tok}\"\n"),
        None => String::new(),
    };

    let yaml = format!(
        r#"daemon:
  data_dir: "{}"
{}providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["dead-model"]
    credentials:
      - id: local-1
        secret: "env:HX_TEST_KEY_NOT_SET"
pools:
  interactive:
    members: ["local/dead-model"]
roles:
  builder: interactive
search:
  backends: []
"#,
        data_dir.display(),
        api_section
    );

    let config_path = dir.join("hx.yaml");
    std::fs::write(&config_path, yaml).expect("write config");
    config_path
}

/// RAII guard to kill a child process on drop across all exit and panic paths.
struct ChildGuard(Option<tokio::process::Child>);

impl ChildGuard {
    fn new(child: tokio::process::Child) -> Self {
        Self(Some(child))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.start_kill();
        }
    }
}

#[tokio::test]
async fn a_non_loopback_bind_with_no_token_refuses_to_start_and_leaves_nothing_listening() {
    let port = free_port();
    let bind_addr = format!("0.0.0.0:{port}");
    let temp = TempDir::new().expect("temp dir");
    let config_path = write_config(temp.path(), None);

    // Scrub ambient credentials: an inherited HX_API_TOKEN from the developer's shell
    // would make the daemon find a token and start, turning this into a test that passes
    // or fails based on ambient environment state.
    let mut cmd = Command::new(HXD);
    cmd.args([
        "--config",
        config_path.to_str().unwrap(),
        "--bind",
        &bind_addr,
    ]);
    cmd.env_remove("HX_API_TOKEN");
    cmd.env_remove("HX_BIND");
    cmd.env_remove("HX_CONFIG");
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    let child = cmd.spawn().expect("failed to spawn hxd");

    // Bounded wait with timeout — no sleeps.
    let wait_res = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await;

    let output = match wait_res {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => panic!("failed waiting for hxd child: {err}"),
        Err(_) => {
            panic!("hxd did not exit within timeout on a non-loopback bind without a token; it may have started serving unauthenticated");
        }
    };

    // Assert 1: non-zero exit.
    assert!(
        !output.status.success(),
        "hxd must exit with non-zero status on unauthenticated non-loopback bind, got: {:?}",
        output.status.code()
    );

    // Assert 2: stderr must name the settings to guide the operator.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("api.token"),
        "stderr must name `api.token`, got: {stderr}"
    );
    assert!(
        stderr.contains("HX_API_TOKEN"),
        "stderr must name `HX_API_TOKEN`, got: {stderr}"
    );

    // Assert 3: nothing is listening on that port.
    assert!(
        is_nothing_listening(port),
        "nothing should be listening on port {port} after refusal"
    );
}

#[tokio::test]
async fn a_non_loopback_bind_with_a_token_starts_and_serves() {
    let port = free_port();
    let bind_addr = format!("0.0.0.0:{port}");
    let temp = TempDir::new().expect("temp dir");
    let config_path = write_config(temp.path(), Some(TOKEN));

    let mut cmd = Command::new(HXD);
    cmd.args([
        "--config",
        config_path.to_str().unwrap(),
        "--bind",
        &bind_addr,
    ]);
    cmd.env_remove("HX_API_TOKEN");
    cmd.env_remove("HX_BIND");
    cmd.env_remove("HX_CONFIG");
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    let mut child = cmd.spawn().expect("failed to spawn hxd");
    let stdout = child.stdout.take().expect("piped stdout");

    let mut guard = ChildGuard::new(child);

    // Read lines from stdout until "hxd listening" confirms startup — no sleeps.
    let mut reader = BufReader::new(stdout).lines();
    let started = tokio::time::timeout(Duration::from_secs(5), async {
        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("hxd listening") {
                return true;
            }
        }
        false
    })
    .await;

    assert!(
        matches!(started, Ok(true)),
        "hxd must start and log that it is listening within timeout"
    );

    // Health probe: /healthz is exempt and answers 200 OK.
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect to healthz");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write healthz request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read healthz response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected 200 OK for /healthz, got: {response}"
    );

    // Authenticated probe: /v1/status with correct token answers 200 OK.
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect to status");
    let req = format!(
        "GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write status request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read status response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected 200 OK for authenticated /v1/status, got: {response}"
    );

    // Unauthenticated probe: /v1/status with no token is refused with 401 Unauthorized.
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect to status without token");
    let req = "GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write status request without token");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read status response without token");
    assert!(
        response.starts_with("HTTP/1.1 401 Unauthorized"),
        "expected 401 Unauthorized for unauthenticated /v1/status, got: {response}"
    );

    // Terminate the child gracefully.
    if let Some(mut child) = guard.0.take() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}
