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
use crate::target::{Admission, BlockReason, TargetRefusal, TargetUrl};
use async_trait::async_trait;
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
            last_pid: Arc::new(AtomicU32::new(0)),
        })
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
        let user_data_dir = request.profile.user_data_dir();
        std::fs::create_dir_all(&user_data_dir).map_err(|err| FetchError::Unavailable {
            rung: RungKind::Interactive,
            reason: format!("could not create user-data directory: {err}"),
        })?;

        let dt_file = user_data_dir.join("DevToolsActivePort");
        let _ = std::fs::remove_file(&dt_file);

        let child = Command::new(&self.path)
            .arg("--headless=new")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", user_data_dir.display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--disable-background-networking")
            .arg("--disable-features=Preconnect,SpeculativeServiceWorker,NavigationPredictor,NetworkPrediction")
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
        let target = request.target.clone();
        let admission = self.admission;
        let timeout = request.timeout;

        let cdp_task = tokio::task::spawn_blocking(move || {
            drive_cdp(ws_url, target, admission, timeout)
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
    target: TargetUrl,
    admission: Admission,
    timeout: Duration,
) -> Result<UntrustedPage, FetchError> {
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
    ws.send(Message::Text(create_cmd.into())).map_err(|err| {
        FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Target.createTarget: {err}"),
        }
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
    ws.send(Message::Text(attach_cmd.into())).map_err(|err| {
        FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Target.attachToTarget: {err}"),
        }
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
    ws.send(Message::Text(nav_cmd.into())).map_err(|err| {
        FetchError::Transport {
            rung: RungKind::Interactive,
            reason: format!("failed to send Page.navigate: {err}"),
        }
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

                        let is_admitted =
                            if !initial_nav_admitted && req_url == target.request_url() {
                                initial_nav_admitted = true;
                                true
                            } else {
                                TargetUrl::parse_with(admission, &req_url).is_ok()
                            };

                        msg_id += 1;
                        if is_admitted {
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
                                if let Err(refusal) = TargetUrl::parse_with(admission, &req_url) {
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
