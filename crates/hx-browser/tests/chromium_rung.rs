//! The interactive Chromium rung, driven over CDP against real Chromium 153.
//!
//! Drives headless Chromium over CDP, enforcing target admission on every request via CDP
//! `Fetch.enable` request interception before bytes reach the wire, and reaping the browser child
//! process on every exit path.
//!
//! Linux-only: it launches a local Chromium binary and inspects `/proc/<pid>` for reaping
//! assertions, so it cannot run on macOS/Windows CI runners. When the Chromium binary is not
//! installed (e.g. a minimal CI image) each test self-skips instead of failing.

#![cfg(target_os = "linux")]

use hx_browser::error::FetchError;
use hx_browser::profile::{PoolRoot, SessionProfile};
use hx_browser::rung::{FetchRequest, Fetcher, RungKind};
use hx_browser::rungs::chromium::ChromiumRung;
use hx_browser::rungs::http::MAX_BODY_BYTES;
use hx_browser::target::{Admission, BlockReason, TargetUrl};
use hx_core::ids::SessionId;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// A stub server.
struct Stub {
    addr: SocketAddr,
    task: JoinHandle<()>,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}

impl Stub {
    async fn new<F, Fut>(handler: F) -> Self
    where
        F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let conns_clone = connections.clone();

        let task = tokio::spawn(async move {
            while let Ok((socket, peer)) = listener.accept().await {
                eprintln!("STUB ACCEPTED from peer: {peer}");
                conns_clone.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(handler(socket));
            }
        });

        Self {
            addr,
            task,
            connections,
            requests,
        }
    }

    /// A listener that records connections and request lines, and answers nothing.
    async fn silent() -> Self {
        let requests = Arc::new(AtomicUsize::new(0));
        let reqs = requests.clone();
        let mut stub = Self::new(move |mut socket| {
            let reqs = reqs.clone();
            async move {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]);
                eprintln!("TARGET RECEIVED: {text}");
                if n > 0 && text.lines().any(|line| line.contains("HTTP/")) {
                    reqs.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .await;
        stub.requests = requests;
        stub
    }

    /// A listener that accepts connections, reads incoming bytes, and hangs forever without answering.
    async fn hanging() -> Self {
        let requests = Arc::new(AtomicUsize::new(0));
        let reqs = requests.clone();
        let mut stub = Self::new(move |mut socket| {
            let reqs = reqs.clone();
            async move {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]);
                eprintln!("TARGET RECEIVED: {text}");
                if n > 0 && text.lines().any(|line| line.contains("HTTP/")) {
                    reqs.fetch_add(1, Ordering::SeqCst);
                }
                std::future::pending::<()>().await;
            }
        })
        .await;
        stub.requests = requests;
        stub
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn profile(name: &str) -> (tempfile::TempDir, Arc<SessionProfile>) {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = PoolRoot::new(temp.path().join("pool")).expect("pool root");
    let session = root
        .session(&SessionId::from_raw(name))
        .expect("session profile");
    (temp, Arc::new(session))
}

fn request_for(url: &str, admission: Admission, profile: Arc<SessionProfile>) -> FetchRequest {
    FetchRequest {
        target: TargetUrl::parse_with(admission, url).expect("an admitted target"),
        profile,
        timeout: Duration::from_secs(10),
    }
}

/// Skip the test if the Chromium binary the rung drives is not installed.
///
/// These are true integration tests that launch a local Chromium over CDP and inspect
/// `/proc/<pid>`. On CI images that don't carry Chromium (and on any host where it is not
/// installed) they cannot run, so self-skip rather than fail.
macro_rules! require_chromium {
    () => {
        if !std::path::Path::new(hx_browser::rungs::chromium::DEFAULT_CHROMIUM_PATH).exists() {
            eprintln!(
                "SKIP: no Chromium at {}",
                hx_browser::rungs::chromium::DEFAULT_CHROMIUM_PATH
            );
            return;
        }
    };
}

#[tokio::test]
async fn a_page_whose_script_fetches_a_private_address_is_blocked_and_the_listener_accepts_zero_connections(
) {
    require_chromium!();
    // The target of the page's JS fetch is a REAL listener.
    // If the admission guard ran after connecting or failed to intercept the request,
    // this counter would move. Zero connections proves admission before the wire.
    let target = Stub::silent().await;
    let target_addr = target.addr;

    let stub = Stub::new(move |mut socket| async move {
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head><title>Interception Test</title></head>
<body>
<h1>Interception Test</h1>
<script>
fetch('http://{target_addr}/stolen')
  .then(() => {{ document.body.innerText = 'STOLEN_CONNECTED'; }})
  .catch(err => {{ document.body.innerText = 'STOLEN_BLOCKED: ' + err.message; }});
</script>
</body>
</html>"#
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = socket.write_all(resp.as_bytes()).await;
    })
    .await;

    // The rung enforces PublicInternet admission on every intercepted request.
    let rung = ChromiumRung::with_admission(Admission::PublicInternet).expect("rung");
    let (_temp, session_profile) = profile("interception-test");
    let request = request_for(&stub.url("/"), Admission::AllowLocal, session_profile);

    let page = rung.fetch(&request).await.expect("page");
    assert_eq!(page.rung, RungKind::Interactive);
    assert_eq!(page.status, 200);

    // The page's own script was blocked before reaching the wire
    assert!(
        page.body_untrusted().contains("STOLEN_BLOCKED"),
        "page body must show the fetch was blocked: {}",
        page.body_untrusted()
    );
    assert!(
        !page.body_untrusted().contains("STOLEN_CONNECTED"),
        "page body must not show connected"
    );

    // Zero connections reached the target listener
    assert_eq!(
        target.connections(),
        0,
        "the intercepted request reached the listener on the wire!"
    );
}

#[tokio::test]
async fn a_page_whose_script_navigates_to_a_private_address_is_blocked_and_the_listener_receives_zero_requests(
) {
    require_chromium!();
    let target = Stub::silent().await;
    let target_addr = target.addr;

    let stub = Stub::new(move |mut socket| async move {
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head><title>Nav Test</title></head>
<body>
<script>
window.location.href = 'http://{target_addr}/stolen';
</script>
</body>
</html>"#
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = socket.write_all(resp.as_bytes()).await;
    })
    .await;

    let rung = ChromiumRung::with_admission(Admission::PublicInternet).expect("rung");
    let (_temp, session_profile) = profile("nav-block-test");
    let request = request_for(&stub.url("/"), Admission::AllowLocal, session_profile);

    let err = rung.fetch(&request).await.expect_err("blocked navigation");
    match &err {
        FetchError::Blocked(refusal) => {
            assert!(
                matches!(refusal.reason, BlockReason::Redirected { .. }),
                "expected BlockReason::Redirected, got {refusal:?}"
            );
        }
        other => panic!("expected FetchError::Blocked, got {other:?}"),
    }

    // Chromium's speculative preconnect opens raw TCP sockets below CDP request interception,
    // so connections may be accepted on top-level navigation, but zero HTTP request bytes reach the wire.
    assert_eq!(
        target.requests(),
        0,
        "the intercepted navigation delivered a request to the listener on the wire!"
    );
}

#[tokio::test]
async fn the_browser_child_process_is_reaped_after_a_successful_fetch() {
    require_chromium!();
    let stub = Stub::new(|mut socket| async move {
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 16\r\n\r\n<h1>success</h1>";
        let _ = socket.write_all(resp.as_bytes()).await;
    })
    .await;

    let rung = ChromiumRung::with_admission(Admission::AllowLocal).expect("rung");
    let (_temp, session_profile) = profile("reap-success");
    let request = request_for(&stub.url("/"), Admission::AllowLocal, session_profile);

    let page = rung.fetch(&request).await.expect("page");
    assert!(page.body_untrusted().contains("success"));

    let pid = rung.last_pid().expect("browser pid");
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "browser child pid {pid} was not reaped after success!"
    );
}

#[tokio::test]
async fn the_browser_child_process_is_reaped_after_a_transport_failure() {
    require_chromium!();
    let rung = ChromiumRung::with_admission(Admission::AllowLocal).expect("rung");
    let (_temp, session_profile) = profile("reap-fail");
    // Port 1 is closed, so navigation fails immediately
    let request = request_for(
        "http://127.0.0.1:1/nonexistent",
        Admission::AllowLocal,
        session_profile,
    );

    let err = rung.fetch(&request).await.expect_err("transport failure");
    assert!(matches!(err, FetchError::Transport { .. }), "{err:?}");

    let pid = rung.last_pid().expect("browser pid");
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "browser child pid {pid} was not reaped after transport failure!"
    );
}

#[tokio::test]
async fn the_browser_child_process_is_reaped_when_the_fetch_times_out() {
    require_chromium!();
    // Stub accepts connection and hangs forever.
    let stub = Stub::hanging().await;

    let rung = ChromiumRung::with_admission(Admission::AllowLocal).expect("rung");
    let (_temp, session_profile) = profile("reap-timeout");
    let mut request = request_for(&stub.url("/hang"), Admission::AllowLocal, session_profile);
    // Must be at least the startup cap (BROWSER_STARTUP_TIMEOUT) so launching Chromium is never
    // the thing that runs out of time: `fetch` budgets startup with `min(request.timeout, 5s)`, so
    // an 800ms request timeout made the whole test hostage to whether Chromium happened to start fast enough.
    // At 5s the startup budget is the full cap and the hanging target alone forces the fetch-timeout path.
    request.timeout = Duration::from_secs(5);

    let err = rung.fetch(&request).await.expect_err("timeout");
    assert!(matches!(err, FetchError::Transport { .. }), "{err:?}");
    // The rung reports a timeout across several messages ("did not answer within Ns" from the outer budget,
    // or "timed out waiting for …" from the CDP driver's own loop, or "did not write DevToolsActivePort
    // within startup budget"). Which one wins is a scheduling race; all of them are the timeout family. What the
    // test must assert is that this is a timeout, not a refusal, an admission block, or a served empty page.
    let reason = err.to_string();
    assert!(
        reason.contains("did not answer")
            || reason.contains("timed out")
            || reason.contains("within startup budget"),
        "the timeout must surface as a timeout-family transport error, got: {reason}"
    );

    let pid = rung.last_pid().expect("browser pid");
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "browser child pid {pid} was not reaped after timeout!"
    );
}

#[tokio::test]
async fn the_browser_child_process_is_reaped_when_the_fetch_future_is_dropped() {
    require_chromium!();
    let stub = Stub::silent().await;

    let rung = ChromiumRung::with_admission(Admission::AllowLocal).expect("rung");
    let (_temp, session_profile) = profile("reap-drop");
    let mut request = request_for(&stub.url("/hang"), Admission::AllowLocal, session_profile);
    request.timeout = Duration::from_secs(30);

    // Spawn the fetch future in a task, let it run briefly so the child spawns, then abort the task
    let rung_clone = rung.clone();
    let handle = tokio::spawn(async move {
        let _ = rung_clone.fetch(&request).await;
    });

    // Wait until browser pid is recorded
    let mut pid = None;
    for _ in 0..50 {
        if let Some(p) = rung.last_pid() {
            pid = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pid = pid.expect("browser pid before drop");
    assert!(
        Path::new(&format!("/proc/{pid}")).exists(),
        "browser process should be alive before drop"
    );

    // Abort the task, dropping the fetch future
    handle.abort();

    // Give Tokio runtime up to 1 second to execute the drop and reap the child
    let mut gone = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if !Path::new(&format!("/proc/{pid}")).exists() {
            gone = true;
            break;
        }
    }
    assert!(
        gone,
        "browser child pid {pid} was not reaped after future drop!"
    );
}

#[tokio::test]
async fn a_wall_status_escalates_and_a_challenge_marker_escalates_too() {
    require_chromium!();
    let forbidden = Stub::new(|mut socket| async move {
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        let resp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 17\r\n\r\n<h1>forbidden</h1>";
        let _ = socket.write_all(resp.as_bytes()).await;
    })
    .await;

    let challenged = Stub::new(|mut socket| async move {
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 46\r\n\r\n<html><body>just a moment... please</body></html>";
        let _ = socket.write_all(resp.as_bytes()).await;
    })
    .await;

    let rung = ChromiumRung::with_admission(Admission::AllowLocal).expect("rung");
    let (_temp, session_profile) = profile("wall-tests");

    let wall_req = request_for(
        &forbidden.url("/"),
        Admission::AllowLocal,
        session_profile.clone(),
    );
    let wall_err = rung.fetch(&wall_req).await.expect_err("wall error");
    assert!(wall_err.is_refusal(), "403 must escalate: {wall_err}");
    assert!(wall_err.to_string().contains("403"), "{wall_err}");

    let chal_req = request_for(&challenged.url("/"), Admission::AllowLocal, session_profile);
    let chal_err = rung.fetch(&chal_req).await.expect_err("challenge error");
    assert!(chal_err.is_refusal(), "challenge must escalate: {chal_err}");
    assert!(chal_err.to_string().contains("just a moment"), "{chal_err}");
}

#[tokio::test]
async fn a_body_over_the_cap_is_refused_rather_than_buffered() {
    require_chromium!();
    let oversize = "x".repeat(MAX_BODY_BYTES + 1024);
    let stub = Stub::new(move |mut socket| {
        let body = oversize.clone();
        async move {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    })
    .await;

    let rung = ChromiumRung::with_admission(Admission::AllowLocal).expect("rung");
    let (_temp, session_profile) = profile("body-cap");
    let request = request_for(&stub.url("/"), Admission::AllowLocal, session_profile);

    let err = rung.fetch(&request).await.expect_err("oversized body");
    match err {
        FetchError::TooLarge { bytes, limit, .. } => {
            assert!(bytes > limit, "{bytes} > {limit}");
            assert_eq!(limit, MAX_BODY_BYTES);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert!(!err.is_refusal(), "TooLarge must not escalate: {err}");
}

#[tokio::test]
async fn the_rung_names_itself_without_a_url_or_a_credential() {
    require_chromium!();
    let rung = ChromiumRung::new().expect("rung");
    assert_eq!(rung.name(), "chromium");
    assert_eq!(rung.kind(), RungKind::Interactive);
    assert_eq!(rung.admission(), Admission::PublicInternet);
    assert_eq!(rung.path(), Path::new("/usr/lib/chromium/chromium"));
}
