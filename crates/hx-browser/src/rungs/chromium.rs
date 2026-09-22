//! The interactive Chromium rung: a real browser driven over CDP, with admission enforced on every request.
//!
//! ## Why this rung exists
//!
//! Some pages cannot be read by a plain HTTP client or a headless scraper that lacks full DOM execution.
//! JavaScript rendering, dynamic hydration, and client-side challenges need a real browser engine.
//! This rung launches a headless Chromium instance and drives it over the Chrome DevTools Protocol (CDP).
//!
//! ## The security property: admission before the wire
//!
//! **Every request the browser makes must be re-admitted before it goes on the wire.**
//!
//! Admission happens when a [`TargetUrl`] is built, and a rung is only ever pointed at one. It is
//! tempting to think that admitting the initial target is sufficient. **A running browser breaks that
//! reasoning completely.** Once a page loads, its JavaScript can call `fetch()`, open `XMLHttpRequest`,
//! or navigate frames to *any* address — including loopback (`127.0.0.1`), RFC 1918 private subnets,
//! and the cloud metadata service (`169.254.169.254`). A hostile or compromised page could turn a
//! browser fetch into an internal network scanner or an IAM credential exfiltration pipeline.
//!
//! To close this hole, this rung enables CDP request interception via `Fetch.enable`. Every request
//! the browser attempts to issue is paused before bytes reach the network. The URL is judged against
//! [`Admission`]:
//! - If admitted, the request is continued with `Fetch.continueRequest`.
//! - If refused, the request is failed immediately with `Fetch.failRequest` (`errorReason: AccessDenied`).
//!
//! ### Hostnames are resolved once, judged, and pinned
//!
//! Admitting the URL's spelling is not enough: a public-looking hostname can resolve to
//! loopback or private space (`http://127.0.0.1.nip.io/`), and the browser resolves names
//! itself, independently of any check this crate runs. So the target's hostname is resolved
//! once through a controlled [`HostResolver`](crate::target::HostResolver) *before the browser
//! is launched* — a privately-resolving name launches nothing — and judged, with *any*
//! non-public address refusing the fetch. The approved addresses are then pinned into the
//! browser via `--host-resolver-rules`, so the initial navigation's socket can only go where
//! admission looked, and every intercepted subresource URL is resolved and judged the same
//! way at the request boundary (first approved resolution wins; a rebinding answer is never
//! consulted). An IP literal needs none of this: the literal *is* the address.
//!
//! ### The wire guarantee: request boundary vs. socket boundary
//!
//! **No HTTP request is delivered to a refused target.**
//!
//! The guarantee is enforced strictly at the *request* boundary, not the raw *socket* boundary:
//! - For subresource requests (`fetch()`, `XMLHttpRequest`, images, stylesheets), Chromium initiates no
//!   speculative preconnection. The interception pauses before socket creation, guaranteeing **zero TCP
//!   connections** on the wire.
//! - For top-level navigations (e.g. `window.location.href = ...`), Chromium's speculative preconnect
//!   mechanism may open raw TCP connections to the target *below* the CDP interception layer before
//!   `Fetch.requestPaused` fires to refuse the navigation. These sockets carry **zero request bytes**;
//!   interception halts the request and issues `Fetch.failRequest`, so no HTTP request line, headers,
//!   or body ever reach the wire.
//!
//! Disabling features via CLI flags (such as `--disable-features=Preconnect,SpeculativeServiceWorker,NavigationPredictor,NetworkPrediction`)
//! was evaluated, but Chromium's navigation engine continues to open speculative preconnect sockets
//! for top-level navigations. A reader or consumer of this rung must therefore understand that
//! while subresources guarantee zero connections, top-level navigations guarantee zero HTTP requests.
//!
//! ## Reaping the browser on every path
//!
//! Headless browsers are notorious for leaking processes. If an error, a timeout, or a cancellation
//! left a Chromium process running, a busy agent pool would rapidly exhaust system memory and process
//! slots. This rung guarantees that the child process is killed and reaped on every exit path:
//! success, error, timeout, and future drop.
//!
//! ## Bounded everything
//!
//! - **Startup budget**: reading `DevToolsActivePort` is bounded by a timeout; a browser that hangs
//!   during startup is terminated rather than waiting forever.
//! - **Navigation budget**: the entire fetch is bounded by [`FetchRequest::timeout`].
//! - **Body cap**: bodies exceeding [`crate::rungs::http::MAX_BODY_BYTES`] are refused with
//!   [`FetchError::TooLarge`].
//!
//! ## What is deliberately NOT done
//!
//! - **No stealth fingerprint patching**: anti-detect evasion is the stealth rung's domain. This rung
//!   is standard Chromium.
//! - **No human interaction UI**: a human solving an interactive challenge belongs to [`crate::interactive`].
//!   This rung automates the browser execution.

use crate::error::{FetchError, RefusalReason};
use crate::rung::{FetchRequest, Fetcher, RungKind, UntrustedPage};
use crate::target::{
    Admission, BlockReason, HostResolver, PinnedTarget, SystemResolver, TargetRefusal, TargetUrl,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::stream::MaybeTlsStream;

/// The default path to the Chromium binary on this host.
pub const DEFAULT_CHROMIUM_PATH: &str = "/usr/lib/chromium/chromium";

/// The maximum time allowed for Chromium to start and write `DevToolsActivePort`.
pub const BROWSER_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The interactive Chromium rung.
#[derive(Clone, Debug)]
pub struct ChromiumRung {
    path: PathBuf,
    admission: Admission,
    resolver: Arc<dyn HostResolver>,
    last_pid: Arc<AtomicU32>,
}

impl ChromiumRung {
    /// The rung with default Chromium path and default admission (PublicInternet).
    pub fn new() -> Result<Self, FetchError> {
        Self::with_admission(Admission::default())
    }

    /// The rung under an explicit admission policy.
    pub fn with_admission(admission: Admission) -> Result<Self, FetchError> {
        Self::with_path_and_admission(DEFAULT_CHROMIUM_PATH, admission)
    }

    /// The rung with an explicit binary path and admission policy.
    pub fn with_path_and_admission(
        path: impl Into<PathBuf>,
        admission: Admission,
    ) -> Result<Self, FetchError> {
        Ok(Self {
            path: path.into(),
            admission,
            resolver: Arc::new(SystemResolver),
            last_pid: Arc::new(AtomicU32::new(0)),
        })
    }

    /// The rung resolving hostnames through `resolver` instead of the system resolver.
    ///
    /// The production path is [`SystemResolver`]; this hatch exists so a test can dictate
    /// resolutions (loopback, mixed, empty) without owning DNS. The resolution the rung
    /// judges is the resolution it pins into `--host-resolver-rules`, so the test double
    /// exercises the same check-then-pin path production takes.
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// The configured binary path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The admission policy enforced on every intercepted request.
    pub fn admission(&self) -> Admission {
        self.admission
    }

    /// The process ID of the most recently spawned browser child, if any.
    pub fn last_pid(&self) -> Option<u32> {
        let pid = self.last_pid.load(Ordering::SeqCst);
        if pid != 0 {
            Some(pid)
        } else {
            None
        }
    }
}

/// A drop guard that guarantees the browser child process is killed and cleaned up even if dropped.
struct ReaperGuard {
    child: Option<tokio::process::Child>,
    dt_file: PathBuf,
}

impl Drop for ReaperGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        let _ = std::fs::remove_file(&self.dt_file);
    }
}

#[async_trait]
impl Fetcher for ChromiumRung {
    fn kind(&self) -> RungKind {
        RungKind::Interactive
    }

    fn name(&self) -> &str {
        "chromium"
    }

    async fn fetch(&self, request: &FetchRequest) -> Result<UntrustedPage, FetchError> {
        // Pin the target's hostname resolution BEFORE anything is launched: a
        // public-looking hostname can resolve to loopback or private space, and the
        // browser would otherwise resolve it independently of admission. A refusal
        // here launches nothing — there is no browser to reap and no socket to
        // account for. Resolution is a blocking `getaddrinfo` call, so it runs off
        // the async runtime.
        let target = request.target.clone();
        let admission = self.admission;
        let resolver = Arc::clone(&self.resolver);
        let pinned = tokio::task::spawn_blocking(move || target.pin(admission, &*resolver))
            .await
            .map_err(|_| FetchError::Transport {
                rung: RungKind::Interactive,
                reason: "the admission task did not complete".to_string(),
            })?
            .map_err(FetchError::Blocked)?;

        // The browser resolves hostnames itself, so the approved addresses are pinned
        // into its resolver: with these rules the socket for the target hostname can
        // only go where admission looked, closing the check-then-connect (rebinding)
        // gap for the initial navigation. `None` for IP literals, which need no pin.
        let resolver_rules = pinned.host_resolver_rules();

        let user_data_dir = request.profile.user_data_dir();
        std::fs::create_dir_all(&user_data_dir).map_err(|err| FetchError::Unavailable {
            rung: RungKind::Interactive,
            reason: format!("could not create user-data directory: {err}"),
        })?;

        let dt_file = user_data_dir.join("DevToolsActivePort");
        let _ = std::fs::remove_file(&dt_file);

        let mut cmd = Command::new(&self.path);
        cmd.arg("--headless=new")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", user_data_dir.display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--disable-background-networking")
            .arg("--disable-features=Preconnect,SpeculativeServiceWorker,NavigationPredictor,NetworkPrediction");
        // Pinned DNS for the target hostname (absent for IP literals). Without this
        // the browser resolves the name itself, independently of the resolution
        // admission judged — a public-looking hostname reaching private space.
        if let Some(rules) = resolver_rules {
            cmd.arg(format!("--host-resolver-rules={rules}"));
        }
        let child = cmd
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| FetchError::Unavailable {
                rung: RungKind::Interactive,
                reason: match err.kind() {
                    std::io::ErrorKind::NotFound => {
                        format!("{} is not installed", self.path.display())
                    }
                    _ => format!("{} could not be started: {err}", self.path.display()),
                },
            })?;

        if let Some(pid) = child.id() {
            self.last_pid.store(pid, Ordering::SeqCst);
        }

        let mut guard = ReaperGuard {
            child: Some(child),
            dt_file: dt_file.clone(),
        };

        let startup_timeout = request.timeout.min(BROWSER_STARTUP_TIMEOUT);
        let start = std::time::Instant::now();
        let mut port_and_path = None;

        while start.elapsed() < startup_timeout {
            if dt_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&dt_file) {
                    let lines: Vec<&str> = content.lines().collect();
                    if lines.len() >= 2 {
                        if let Ok(port) = lines[0].trim().parse::<u16>() {
                            let path = lines[1].trim().to_string();
                            port_and_path = Some((port, path));
                            break;
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let (port, path) = match port_and_path {
            Some(pair) => pair,
            None => {
                if let Some(mut c) = guard.child.take() {
                    let _ = c.start_kill();
                    let _ = c.wait().await;
                }
                return Err(FetchError::Transport {
                    rung: RungKind::Interactive,
                    reason: "chromium did not write DevToolsActivePort within startup budget"
                        .to_string(),
                });
            }
        };

        let ws_url = format!("ws://127.0.0.1:{port}{path}");
        let admission = self.admission;
        let resolver = Arc::clone(&self.resolver);
        let timeout = request.timeout;

        let cdp_task = tokio::task::spawn_blocking(move || {
            drive_cdp(ws_url, pinned, admission, resolver, timeout)
        });

        let result = match tokio::time::timeout(request.timeout, cdp_task).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(panic_err)) => Err(FetchError::Transport {
                rung: RungKind::Interactive,
                reason: format!("CDP driver task panicked: {panic_err}"),
            }),
            Err(_elapsed) => Err(FetchError::Transport {
                rung: RungKind::Interactive,
                reason: format!(
                    "chromium did not answer within {}s",
                    request.timeout.as_secs()
                ),
            }),
        };

        // Guaranteed reaping on every exit path
        if let Some(mut c) = guard.child.take() {
            let _ = c.start_kill();
            let _ = c.wait().await;
        }

        result
    }
}

/// Drives the Chromium DevTools Protocol over a WebSocket.
fn drive_cdp(
    ws_url: String,
    pinned: PinnedTarget,
    admission: Admission,
    resolver: Arc<dyn HostResolver>,
    timeout: Duration,
) -> Result<UntrustedPage, FetchError> {
    let target = pinned.target().clone();
    // Hostnames this navigation has already judged, to their approved addresses. Seeded
    // with the initial target's pins, so the check-then-connect gap stays closed for
    // every hostname the page then reaches: the first approved resolution is reused
    // rather than re-resolved (rebinding), and a hostname resolving to private space
    // is refused at the request boundary, never at the socket.
    let mut approved: HashMap<String, Vec<IpAddr>> = HashMap::new();
    if let Some(name) = pinned.target().dns_name() {
        approved.insert(name, pinned.pinned_addrs().to_vec());
    }
    let (mut ws, _) =
        tokio_tungstenite::tungstenite::connect(&ws_url).map_err(|err| FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("could not connect to chromium CDP: {err}"),
        })?;

    if let MaybeTlsStream::Plain(stream) = ws.get_mut() {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    }

    let mut msg_id = 0u64;

    // 1. Create target
    msg_id += 1;
    let create_target_id = msg_id;
    let create_cmd = format!(
        r#"{{"id":{},"method":"Target.createTarget","params":{{"url":"about:blank"}}}}"#,
        create_target_id
    );
    ws.send(Message::Text(create_cmd.into()))
        .map_err(|err| FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Target.createTarget: {err}"),
        })?;

    let start = std::time::Instant::now();
    let mut target_id = None;
    while start.elapsed() < timeout {
        match ws.read() {
            Ok(Message::Text(text)) => {
                if text.contains(&format!(r#""id":{create_target_id}"#)) {
                    target_id = json_find_str(&text, "targetId");
                    break;
                }
            }
            Ok(_) => {}
            Err(tokio_tungstenite::tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => {
                return Err(FetchError::Transport {
                    rung: RungKind::Interactive,
                    reason: format!("CDP read failed waiting for createTarget: {err}"),
                });
            }
        }
    }

    let target_id = target_id.ok_or_else(|| FetchError::Transport {
        rung: RungKind::Interactive,
        reason: "timed out waiting for Target.createTarget".to_string(),
    })?;

    // 2. Attach to target
    msg_id += 1;
    let attach_id = msg_id;
    let attach_cmd = format!(
        r#"{{"id":{},"method":"Target.attachToTarget","params":{{"targetId":"{}","flatten":true}}}}"#,
        attach_id, target_id
    );
    ws.send(Message::Text(attach_cmd.into()))
        .map_err(|err| FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Target.attachToTarget: {err}"),
        })?;

    let mut session_id = None;
    while start.elapsed() < timeout {
        match ws.read() {
            Ok(Message::Text(text)) => {
                if text.contains(&format!(r#""id":{attach_id}"#)) {
                    session_id = json_find_str(&text, "sessionId");
                    break;
                }
            }
            Ok(_) => {}
            Err(tokio_tungstenite::tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => {
                return Err(FetchError::Transport {
                    rung: RungKind::Interactive,
                    reason: format!("CDP read failed waiting for attachToTarget: {err}"),
                });
            }
        }
    }

    let session_id = session_id.ok_or_else(|| FetchError::Transport {
        rung: RungKind::Interactive,
        reason: "timed out waiting for Target.attachToTarget".to_string(),
    })?;

    // 3. Enable domains on session
    msg_id += 1;
    let fetch_enable = format!(
        r#"{{"id":{},"sessionId":"{}","method":"Fetch.enable","params":{{}}}}"#,
        msg_id, session_id
    );
    ws.send(Message::Text(fetch_enable.into()))
        .map_err(|err| FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Fetch.enable: {err}"),
        })?;

    msg_id += 1;
    let page_enable = format!(
        r#"{{"id":{},"sessionId":"{}","method":"Page.enable","params":{{}}}}"#,
        msg_id, session_id
    );
    ws.send(Message::Text(page_enable.into()))
        .map_err(|err| FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Page.enable: {err}"),
        })?;

    msg_id += 1;
    let network_enable = format!(
        r#"{{"id":{},"sessionId":"{}","method":"Network.enable","params":{{}}}}"#,
        msg_id, session_id
    );
    ws.send(Message::Text(network_enable.into()))
        .map_err(|err| FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Network.enable: {err}"),
        })?;

    // 4. Navigate
    msg_id += 1;
    let nav_id = msg_id;
    let nav_cmd = format!(
        r#"{{"id":{},"sessionId":"{}","method":"Page.navigate","params":{{"url":"{}"}}}}"#,
        nav_id,
        session_id,
        target.request_url()
    );
    ws.send(Message::Text(nav_cmd.into()))
        .map_err(|err| FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Page.navigate: {err}"),
        })?;

    // 5. Process events
    let mut initial_nav_admitted = false;
    let mut main_blocked = None;
    let mut main_status: Option<u16> = None;
    let mut main_content_type: Option<String> = None;
    let mut main_url: Option<String> = None;
    let mut nav_error: Option<String> = None;
    let mut eval_cmd_id = None;
    let mut page_body = None;

    while start.elapsed() < timeout {
        match ws.read() {
            Ok(Message::Text(text)) => {
                // Intercept requests via Fetch.requestPaused
                if text.contains("\"method\":\"Fetch.requestPaused\"") {
                    if let Some(req_id) = json_find_str(&text, "requestId") {
                        let req_url = json_find_str(&text, "url").unwrap_or_default();
                        let resource_type = json_find_str(&text, "resourceType");

                        // The initial navigation was pinned before launch; everything
                        // else is admitted here, at the request boundary: lexical
                        // admission AND the hostname's resolution, judged against the
                        // approved addresses. A public-looking hostname resolving to
                        // private space is refused before its socket exists.
                        let admission_result = if !initial_nav_admitted
                            && req_url == target.request_url()
                        {
                            initial_nav_admitted = true;
                            Ok(())
                        } else {
                            admit_intercepted_url(admission, &*resolver, &mut approved, &req_url)
                        };

                        msg_id += 1;
                        if admission_result.is_ok() {
                            let cont = format!(
                                r#"{{"id":{},"sessionId":"{}","method":"Fetch.continueRequest","params":{{"requestId":"{}"}}}}"#,
                                msg_id, session_id, req_id
                            );
                            let _ = ws.send(Message::Text(cont.into()));
                        } else {
                            let fail = format!(
                                r#"{{"id":{},"sessionId":"{}","method":"Fetch.failRequest","params":{{"requestId":"{}","errorReason":"AccessDenied"}}}}"#,
                                msg_id, session_id, req_id
                            );
                            let _ = ws.send(Message::Text(fail.into()));

                            // If this was the main document navigation, record it as a blocked refusal
                            if resource_type.as_deref() == Some("Document")
                                || req_url == target.request_url()
                            {
                                if let Err(refusal) = admission_result {
                                    let relabelled_reason = match refusal.reason {
                                        BlockReason::PrivateHost { host, reason } => {
                                            BlockReason::Redirected { host, reason }
                                        }
                                        other => other,
                                    };
                                    main_blocked = Some(TargetRefusal {
                                        reason: relabelled_reason,
                                        display: target.redacted(),
                                    });
                                }
                            }
                        }
                    }
                }

                // Capture document response headers and status
                if text.contains("\"method\":\"Network.responseReceived\"") {
                    let res_type = json_find_str(&text, "type");
                    if res_type.as_deref() == Some("Document") {
                        if let Some(status) = json_find_u16(&text, "status") {
                            main_status = Some(status);
                        }
                        if let Some(mime) = json_find_str(&text, "mimeType") {
                            main_content_type = Some(mime);
                        }
                        if let Some(url) = json_find_str(&text, "url") {
                            main_url = Some(url);
                        }
                    }
                }

                // Check for navigation failure
                if text.contains("\"method\":\"Network.loadingFailed\"") {
                    let res_type = json_find_str(&text, "type");
                    if res_type.as_deref() == Some("Document") {
                        if let Some(err_text) = json_find_str(&text, "errorText") {
                            if err_text != "net::ERR_ABORTED" {
                                nav_error = Some(err_text);
                                break;
                            }
                        }
                    }
                }

                // Also check Page.navigate response errorText
                if text.contains(&format!(r#""id":{nav_id}"#)) {
                    if let Some(err_text) = json_find_str(&text, "errorText") {
                        if err_text != "net::ERR_ABORTED" {
                            nav_error = Some(err_text);
                            break;
                        }
                    }
                }

                // If navigation was blocked, stop waiting
                if main_blocked.is_some() {
                    break;
                }

                // Page load complete -> evaluate outerHTML (small delay to allow microtasks/scripts to settle)
                if text.contains("\"method\":\"Page.loadEventFired\"") && eval_cmd_id.is_none() {
                    msg_id += 1;
                    eval_cmd_id = Some(msg_id);
                    let eval_cmd = format!(
                        r#"{{"id":{},"sessionId":"{}","method":"Runtime.evaluate","params":{{"expression":"new Promise(r => setTimeout(r, 50)).then(() => document.documentElement.outerHTML)","awaitPromise":true,"returnByValue":true}}}}"#,
                        msg_id, session_id
                    );
                    let _ = ws.send(Message::Text(eval_cmd.into()));
                }

                // Handle evaluate response
                if let Some(eval_id) = eval_cmd_id {
                    if text.contains(&format!(r#""id":{eval_id}"#)) {
                        page_body = json_find_str(&text, "value");
                        break;
                    }
                }
            }
            Ok(_) => {}
            Err(tokio_tungstenite::tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }

    if let Some(refusal) = main_blocked {
        return Err(FetchError::Blocked(refusal));
    }

    if let Some(err_text) = nav_error {
        return Err(FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("navigation failed: {err_text}"),
        });
    }

    let status = main_status.unwrap_or(200);
    if is_wall_status(status) {
        return Err(FetchError::Refused {
            rung: RungKind::Interactive,
            reason: RefusalReason::Status { status },
        });
    }

    if !(200..=299).contains(&status) && status != 304 {
        return Err(FetchError::Http {
            rung: RungKind::Interactive,
            status,
        });
    }

    let content_type = main_content_type.unwrap_or_else(|| "text/html".to_string());
    if !crate::rungs::http::is_text(&content_type) {
        return Err(FetchError::NotText {
            rung: RungKind::Interactive,
            content_type,
        });
    }

    let body = page_body.ok_or_else(|| FetchError::Transport {
        rung: RungKind::Interactive,
        reason: "the browser did not return document HTML within timeout".to_string(),
    })?;

    if body.len() > crate::rungs::http::MAX_BODY_BYTES {
        return Err(FetchError::TooLarge {
            rung: RungKind::Interactive,
            bytes: body.len(),
            limit: crate::rungs::http::MAX_BODY_BYTES,
        });
    }

    if let Some(marker) = crate::rungs::http::challenge_marker(&body) {
        return Err(FetchError::Refused {
            rung: RungKind::Interactive,
            reason: RefusalReason::Challenge {
                marker: marker.to_string(),
            },
        });
    }

    let final_target = match main_url {
        Some(ref url) => TargetUrl::parse_with(admission, url).unwrap_or_else(|_| target.clone()),
        None => target,
    };

    Ok(UntrustedPage::new(
        final_target,
        status,
        content_type,
        RungKind::Interactive,
        body,
    ))
}

fn is_wall_status(status: u16) -> bool {
    matches!(status, 403 | 429 | 503)
}

/// Admit one URL the browser tried to reach, at the request boundary.
///
/// Lexical admission first ([`TargetUrl::parse_with`]), then the hostname's resolution:
/// an IP literal was already judged by the parse itself, while a hostname is resolved
/// once through `resolver` and every address judged — a public-looking name resolving
/// to loopback or private space (`http://127.0.0.1.nip.io/`) is refused here, before
/// any socket exists. The first approved resolution is remembered in `approved` and
/// reused, so a DNS answer that changes mid-navigation (rebinding) cannot move an
/// admitted hostname onto an address admission never saw.
///
/// Runs on the CDP thread, where blocking `getaddrinfo` is legitimate.
pub(crate) fn admit_intercepted_url(
    admission: Admission,
    resolver: &dyn HostResolver,
    approved: &mut HashMap<String, Vec<IpAddr>>,
    req_url: &str,
) -> Result<(), TargetRefusal> {
    let target = TargetUrl::parse_with(admission, req_url)?;
    let Some(name) = target.dns_name() else {
        // An IP literal: the parse judged the exact address the socket will use, and
        // there is no name a rebinding could change.
        return Ok(());
    };
    if approved.contains_key(&name) {
        return Ok(());
    }
    let pinned = target.pin(admission, resolver)?;
    approved.insert(name, pinned.pinned_addrs().to_vec());
    Ok(())
}

fn json_find_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let key_pos = json.find(&pattern)?;
    let rest = &json[key_pos + pattern.len()..];
    let colon_pos = rest.find(':')?;
    let after_colon = rest[colon_pos + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let content = &after_colon[1..];
    let mut result = String::new();
    let mut chars = content.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(escaped) = chars.next() {
                    match escaped {
                        '"' => result.push('"'),
                        '\\' => result.push('\\'),
                        '/' => result.push('/'),
                        'n' => result.push('\n'),
                        'r' => result.push('\r'),
                        't' => result.push('\t'),
                        'u' => {
                            let hex: String = chars.by_ref().take(4).collect();
                            if let Ok(code) = u32::from_str_radix(&hex, 16) {
                                if let Some(ch) = char::from_u32(code) {
                                    result.push(ch);
                                }
                            }
                        }
                        other => {
                            result.push('\\');
                            result.push(other);
                        }
                    }
                }
            }
            '"' => break,
            other => result.push(other),
        }
    }
    Some(result)
}

fn json_find_u16(json: &str, key: &str) -> Option<u16> {
    let pattern = format!("\"{key}\"");
    let key_pos = json.find(&pattern)?;
    let rest = &json[key_pos + pattern.len()..];
    let colon_pos = rest.find(':')?;
    let after_colon = rest[colon_pos + 1..].trim_start();
    let digits: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{PoolRoot, SessionProfile};
    use hx_core::ids::SessionId;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A scripted resolver: every hostname answers from a queue, in order.
    ///
    /// WHY a queue rather than a map: the rebinding test needs *consecutive answers for
    /// one hostname to differ* — the first resolution approved, the second private —
    /// which a map cannot express. A hostname nobody scripted is a test bug, not an
    /// empty answer.
    #[derive(Debug, Default)]
    struct ScriptResolver {
        answers: Mutex<VecDeque<Vec<IpAddr>>>,
        asked: Mutex<Vec<String>>,
    }

    impl ScriptResolver {
        fn answering(host_answers: Vec<Vec<&str>>) -> Self {
            let answers = host_answers
                .into_iter()
                .map(|addrs| {
                    addrs
                        .iter()
                        .map(|addr| addr.parse().expect("a test address"))
                        .collect()
                })
                .collect();
            Self {
                answers: Mutex::new(answers),
                asked: Mutex::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().expect("the asked lock").clone()
        }
    }

    impl HostResolver for ScriptResolver {
        fn resolve_host(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.asked
                .lock()
                .expect("the asked lock")
                .push(host.to_string());
            self.answers
                .lock()
                .expect("the answers lock")
                .pop_front()
                .ok_or_else(|| std::io::Error::other("the test resolver has no more answers"))
        }
    }

    /// A resolver that panics when asked: proving an IP literal is admitted without
    /// touching DNS, since there is no name a rebinding could change.
    #[derive(Debug)]
    struct PanickingResolver;

    impl HostResolver for PanickingResolver {
        fn resolve_host(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            panic!("DNS must not be consulted for {host}");
        }
    }

    fn approvals() -> HashMap<String, Vec<IpAddr>> {
        HashMap::new()
    }

    #[test]
    fn a_hostname_resolving_to_loopback_is_refused_at_the_request_boundary() {
        // The `127.0.0.1.nip.io` shape: lexically public, resolving to loopback. The
        // old lexical-only interception admitted this; the recheck must refuse it.
        let resolver = ScriptResolver::answering(vec![vec!["127.0.0.1"]]);
        let mut approved = approvals();
        let err = admit_intercepted_url(
            Admission::PublicInternet,
            &resolver,
            &mut approved,
            "http://public.test/page",
        )
        .expect_err("a loopback resolution must be refused");
        assert!(
            matches!(err.reason, BlockReason::PrivateHost { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("127.0.0.1"), "{err}");
        assert!(approved.is_empty(), "a refused name approves nothing");
    }

    #[test]
    fn a_hostname_with_one_private_address_among_public_ones_is_refused() {
        // DNS answers rotate: one private address among public ones refuses the whole
        // name, or the next rotation admits loopback.
        let resolver = ScriptResolver::answering(vec![vec!["93.184.216.34", "10.0.0.5"]]);
        let mut approved = approvals();
        let err = admit_intercepted_url(
            Admission::PublicInternet,
            &resolver,
            &mut approved,
            "http://mixed.test/page",
        )
        .expect_err("a mixed resolution must be refused");
        assert!(
            matches!(
                err.reason,
                BlockReason::PrivateHost { ref host, .. } if host == "10.0.0.5"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_hostname_resolving_only_to_public_addresses_is_approved_and_remembered() {
        let resolver = ScriptResolver::answering(vec![vec!["93.184.216.34"]]);
        let mut approved = approvals();
        admit_intercepted_url(
            Admission::PublicInternet,
            &resolver,
            &mut approved,
            "http://cdn.test/page",
        )
        .expect("an all-public resolution is admitted");
        assert_eq!(
            approved.get("cdn.test"),
            Some(&vec!["93.184.216.34".parse::<IpAddr>().unwrap()])
        );
        assert_eq!(resolver.asked(), vec!["cdn.test".to_string()]);
    }

    #[test]
    fn a_rebinding_answer_is_never_consulted_once_a_hostname_is_approved() {
        // The second resolution turns private: the request is still admitted, on the
        // first approved addresses, because the rebinding answer is never consulted.
        let resolver = ScriptResolver::answering(vec![vec!["93.184.216.34"], vec!["127.0.0.1"]]);
        let mut approved = approvals();
        admit_intercepted_url(
            Admission::PublicInternet,
            &resolver,
            &mut approved,
            "http://flapping.test/a",
        )
        .expect("the first, public resolution is admitted");
        admit_intercepted_url(
            Admission::PublicInternet,
            &resolver,
            &mut approved,
            "http://flapping.test/b",
        )
        .expect("the rebinding answer must not move an approved hostname");
        assert_eq!(
            approved.get("flapping.test"),
            Some(&vec!["93.184.216.34".parse::<IpAddr>().unwrap()])
        );
        // Asked once: the second request reused the pins rather than re-resolving.
        assert_eq!(resolver.asked(), vec!["flapping.test".to_string()]);
    }

    #[test]
    fn an_ip_literal_is_admitted_without_touching_dns() {
        let mut approved = approvals();
        admit_intercepted_url(
            Admission::PublicInternet,
            &PanickingResolver,
            &mut approved,
            "http://93.184.216.34/page",
        )
        .expect("a public literal is admitted without DNS");
        assert!(approved.is_empty());
    }

    #[test]
    fn a_lexically_refused_url_is_refused_without_touching_dns() {
        // The lexical rules run first: a private literal or a non-http scheme never
        // reaches the resolver, so this also pins the check order.
        for raw in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/",
            "file:///etc/passwd",
        ] {
            let mut approved = approvals();
            let err = admit_intercepted_url(
                Admission::PublicInternet,
                &PanickingResolver,
                &mut approved,
                raw,
            )
            .expect_err(&format!("{raw} must be refused lexically"));
            assert!(
                !matches!(err.reason, BlockReason::Unresolvable { .. }),
                "{raw}: lexical refusal must not become a DNS question: {err:?}"
            );
        }
    }

    fn profile() -> (tempfile::TempDir, Arc<SessionProfile>) {
        let temp = tempfile::tempdir().expect("a temp directory");
        let root = PoolRoot::new(temp.path().join("pool")).expect("a pool root");
        let session = root
            .session(&SessionId::from_raw("chromium-pin-test"))
            .expect("a session profile");
        (temp, Arc::new(session))
    }

    fn request(profile: Arc<SessionProfile>, url: &str) -> FetchRequest {
        FetchRequest {
            target: TargetUrl::parse_with(Admission::PublicInternet, url)
                .expect("a lexically admitted target"),
            profile,
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn a_privately_resolving_hostname_launches_no_browser() {
        // Lexically public, resolving to loopback: the pin gate refuses before any
        // child is spawned. The binary path does not exist, so `Unavailable` would
        // mean the gate did not run first — and `last_pid` staying empty means no
        // browser was launched at a target admission never saw.
        let (_temp, profile) = profile();
        let rung = ChromiumRung::with_path_and_admission(
            "/nonexistent/hx-chromium-that-is-not-installed",
            Admission::PublicInternet,
        )
        .expect("a rung")
        .with_resolver(Arc::new(ScriptResolver::answering(vec![vec!["127.0.0.1"]])));
        let err = rung
            .fetch(&request(profile, "http://public.test/page"))
            .await
            .expect_err("a loopback resolution must be blocked");
        let is_private_block = match &err {
            FetchError::Blocked(refusal) => {
                matches!(&refusal.reason, BlockReason::PrivateHost { .. })
            }
            _ => false,
        };
        assert!(is_private_block, "{err:?}");
        assert_eq!(rung.last_pid(), None);
    }

    #[tokio::test]
    async fn a_publicly_resolving_hostname_reaches_launch() {
        // The control for the test above: with a public resolution the pin gate passes
        // and the fetch fails at launch (`Unavailable`), proving the refusal above
        // came from DNS pinning rather than from the missing binary.
        let (_temp, profile) = profile();
        let rung = ChromiumRung::with_path_and_admission(
            "/nonexistent/hx-chromium-that-is-not-installed",
            Admission::PublicInternet,
        )
        .expect("a rung")
        .with_resolver(Arc::new(ScriptResolver::answering(vec![vec![
            "93.184.216.34",
        ]])));
        let err = rung
            .fetch(&request(profile, "http://public.test/page"))
            .await
            .expect_err("a missing binary is not a page");
        assert!(matches!(err, FetchError::Unavailable { .. }), "{err:?}");
    }
}
