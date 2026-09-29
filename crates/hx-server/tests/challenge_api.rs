//! The human in the loop over HTTP: a refused page asks a person, and the person's answer ends the
//! fetch.
//!
//! The loop this covers is `hx-browser`'s contract, end to end, with nothing stubbed at the seam that
//! matters: a page that refuses the plain rung is handed to `crate::pane::ScreenPane`, which launches
//! a **real browser** on the session's own profile and registers a challenge; the person's answer
//! arrives over `POST /v1/challenges/{id}` from an ordinary HTTP client (which is what the web client
//! is); and the waiting fetch is told what happened.
//!
//! Two halves, and the split is the point. The **hermetic** half needs no browser: the routes are
//! mounted, an empty registry is a listing, an id that was never a challenge is a `404` and a decline
//! with no note is a `400`. Those are the answers a client acts on and they are the same answers on a
//! machine with no browser installed, so they are asserted everywhere.
//!
//! The **live** half self-skips (does not fail) on a host with no browser, the way `screen_api.rs` and
//! `hx-browser`'s own screen tests do.
//!
//! One of those live tests is about *who* is asked. A challenge is addressed to the operator the
//! config names and announced to their own notification channel, so that test stands a relay on the
//! loopback (`Relay`), points `approval.push_url` at it, configures an **api token** so the daemon is
//! not accidentally open, and then answers the challenge through the notification's own one-time URL
//! with no bearer header at all. Those three are what make the claim testable: without the token the
//! request would be a `401`, and without the token being *this* challenge's it would be a `403`.
//!
//! Why a real HTTP server rather than calling handlers: the answer has to arrive from a client that is
//! *not* the fetch. A test that answered the pane by calling it directly would agree with itself about
//! a wire nobody had to speak, and the whole point of this path is that a person is on the other end
//! of one.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hx_agent::{ApprovalQueue, ModelCall};
use hx_browser::Admission;
use hx_core::config::Config;
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId, SessionId};
use hx_provider::{ChatRequest, ChatResponse, ModelRouter, ProviderRegistry};
use hx_search::{BackendRegistry, BrowserFetcher};
use hx_secrets::{EnvSecrets, SecretStores};
use hx_server::{app, AppState, AppStateParts, ModelFactory};
use hx_store::Store;

/// The challenge routes need no model: a person is not an agent. This exists only so the harness
/// builds the way the daemon does rather than through a test-only constructor that could drift.
struct DeadModel;

#[async_trait]
impl ModelCall for DeadModel {
    async fn complete(&self, _req: ChatRequest) -> Result<ChatResponse> {
        Err(HxError::Provider("not used in this test".to_string()))
    }
    fn model(&self) -> String {
        "dead".to_string()
    }
    fn provider_id(&self) -> ProviderId {
        ProviderId::from_raw("local")
    }
    fn credential_id(&self) -> CredentialId {
        CredentialId::from_raw("local-1")
    }
}

struct Dead(Arc<DeadModel>);

impl ModelFactory for Dead {
    fn for_role(&self, _role: &str) -> Result<Arc<dyn ModelCall>> {
        Ok(Arc::clone(&self.0) as Arc<dyn ModelCall>)
    }
}

const CONFIG: &str = r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["dead-model"]
    credentials:
      - { id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }

pools:
  interactive: { members: ["local/dead-model"] }

roles:
  builder: interactive

search:
  backends: []
"#;

/// A page server that answers every request with one fixed refusal.
///
/// A site that refuses the automated rungs is the whole input to this path, so the stub's job is to
/// refuse: `403` with a body, which is both a status a real bot wall uses and what `HttpRung`
/// classifies as a refusal rather than a transport failure.
struct Stub {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Stub {
    async fn refusing() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const BODY: &str =
            "<html><head><title>Just a moment…</title></head><body>captcha</body></html>";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                        BODY.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { addr, task }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A relay: the operator's webhook, which records what the daemon pushes and answers `200`.
///
/// The daemon's push is fired off a spawned task and its result is only logged, so the *only* way to
/// assert that an operator was told is to be standing where the notification lands. This is that
/// place, and it reads the bodies rather than being handed them, because the wire shape is exactly
/// what a relay author would have to parse.
struct Relay {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
    seen: Arc<Mutex<Vec<serde_json::Value>>>,
    /// Whose channel this is. Only a *label*: it is not sent anywhere, but the failure messages of
    /// a test running two of these name the person rather than a port.
    for_whom: &'static str,
}

impl Relay {
    async fn start() -> Self {
        Self::for_person("the operator").await
    }

    async fn for_person(for_whom: &'static str) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let recorder = Arc::clone(&recorder);
                tokio::spawn(async move {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let body = loop {
                        let read = match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break None,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&chunk[..read]);
                        let Some(head) = header_end(&buf) else { continue };
                        let Some(len) = content_length(&buf[..head]) else { continue };
                        if buf.len() >= head + len {
                            break Some(buf[head..head + len].to_vec());
                        }
                    };
                    if let Some(body) = body {
                        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
                            recorder.lock().expect("the relay's log").push(value);
                        }
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self {
            addr,
            task,
            seen,
            for_whom,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/hook", self.addr)
    }

    /// The kinds of push this channel received, in order — `[]` when it was left alone.
    fn kinds(&self) -> Vec<String> {
        self.seen()
            .iter()
            .filter_map(|value| value["kind"].as_str().map(str::to_string))
            .collect()
    }

    fn seen(&self) -> Vec<serde_json::Value> {
        self.seen.lock().expect("the relay's log").clone()
    }

    /// Wait for the first push of `kind`, or say what did arrive instead.
    ///
    /// The message names the person this channel reaches, because a test that stands up two relays
    /// needs its failure to say *whose* phone did not ring rather than which port stayed silent.
    async fn wait_for(&self, kind: &str) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let seen = self.seen();
            let found = seen
                .iter()
                .find(|value| value["kind"] == serde_json::json!(kind));
            if let Some(found) = found {
                return found.clone();
            }
            if Instant::now() > deadline {
                panic!(
                    "no {kind} push arrived on {}'s relay ({}); it saw {seen:#?}",
                    self.for_whom,
                    self.url()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The offset just past a request's headers, or `None` while they are still arriving.
fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|at| at + 4)
}

/// The `Content-Length` a request announced, read case-insensitively as a real server would.
fn content_length(head: &[u8]) -> Option<usize> {
    let head = String::from_utf8_lossy(head).to_ascii_lowercase();
    let at = head.find("content-length:")? + "content-length:".len();
    head[at..]
        .split('\r')
        .next()?
        .trim()
        .parse::<usize>()
        .ok()
}

/// A real server on an ephemeral port, the daemon behind it, and the temp dir that must outlive both.
struct Server {
    addr: String,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

/// Build a daemon, letting the test adjust the config first.
async fn harness(configure: impl FnOnce(&mut Config)) -> Server {
    harness_with(configure, None).await
}

/// Build a daemon that authenticates, so a test can prove *which* credential answered.
async fn harness_with(configure: impl FnOnce(&mut Config), api_token: Option<&str>) -> Server {
    let mut config = Config::from_yaml(CONFIG).expect("config parses");
    let dir = tempfile::tempdir().expect("temp dir");
    config.daemon.data_dir = dir.path().join("data").display().to_string();
    // Profiles go under the test's own directory rather than the system temp default: a test that
    // left browser profiles in `/tmp` (or `%TEMP%`) would be a test that litters, and `tempfile`
    // takes them away again.
    config.screen.profile_root = dir.path().join("screens").display().to_string();
    // Bound before the daemon is built rather than after, so the address the config names *is* the
    // address this test serves on. That is what makes a pushed `respond_url` a URL a test can follow
    // instead of a string it can only pattern-match. See `origin_of`.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    config.daemon.http_addr = addr.to_string();
    configure(&mut config);

    let now = chrono::Utc::now();
    let router = ModelRouter::from_config(&config, now).expect("router builds");
    let client = reqwest::Client::new();
    let providers =
        ProviderRegistry::from_config(&config, client.clone()).expect("providers build");
    let search = BackendRegistry::from_config(
        &config.search,
        client.clone(),
        &hx_secrets::SecretStores::new(),
    )
    .expect("search");
    let store = Store::from_config(&config).expect("store opens");

    let state = AppState::from_parts(AppStateParts {
        config,
        router: Arc::new(Mutex::new(router)),
        providers: Arc::new(RwLock::new(providers)),
        provider_configs: Default::default(),
        config_path: None,
        secrets: Arc::new(SecretStores::new().with(Arc::new(EnvSecrets))),
        store: Arc::new(store),
        models: Arc::new(RwLock::new(Arc::new(Dead(Arc::new(DeadModel))))),
        tools: Arc::new(hx_server::chat::default_tools(vec![], client)),
        approvals: ApprovalQueue::new(Duration::from_secs(1)),
        phone: None,
        search: Arc::new(search),
        sandboxes: None,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now,
        // No token unless the test asked for one: these tests bind loopback, which is exactly the
        // deployment where a token is optional. A test that needed one here would mean the rule, not
        // the test, was wrong. The one that *does* ask for one is about which credential answered.
        api_token: api_token.map(hx_core::api_auth::ApiToken::new),
        allowed_origins: Vec::new(),
        webhooks: Default::default(),
    });

    let router = app(Arc::clone(&state));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    Server {
        addr: addr.to_string(),
        state,
        _dir: dir,
    }
}

/// Skip the live test when no browser is installed, naming where the search looked.
macro_rules! require_browser {
    () => {
        match hx_browser::screen::discover_browser(None) {
            Ok(path) => eprintln!("challenge_api: driving {}", path.display()),
            Err(err) => {
                eprintln!("SKIP: {err}");
                return;
            }
        }
    };
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// What a listing says about one challenge, as the test needs it.
#[derive(Debug, serde::Deserialize)]
struct ListedChallenge {
    id: String,
    screen: String,
    session: String,
    url: String,
    reason: String,
    seconds_left: u64,
    operator: String,
    notified: bool,
}

async fn listed(base: &str) -> Vec<ListedChallenge> {
    listed_as(base, None).await
}

/// The listing, with whatever credential the test wants to present — nothing on a daemon with no
/// token, and `Some("hx-test-token")` on the one that has one.
async fn listed_as(base: &str, token: Option<&str>) -> Vec<ListedChallenge> {
    let mut request = client().get(format!("{base}/v1/challenges"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let body: serde_json::Value = request
        .send()
        .await
        .expect("the route answers")
        .json()
        .await
        .expect("a JSON body");
    serde_json::from_value(body["challenges"].clone()).expect("the listing shape")
}

/// Wait for a challenge, or say what was there instead.
///
/// Bounded rather than unbounded: a challenge that never appears is a bug to report, and a test that
/// waited forever on one would hang the suite instead of naming it.
async fn wait_for_challenge(base: &str) -> ListedChallenge {
    wait_for_challenge_as(base, None).await
}

/// The same wait on a daemon that authenticates. The listing is the daemon's own surface, so it
/// needs the bearer token even though the *answer* — the notification's half — does not.
async fn wait_for_challenge_as(base: &str, token: Option<&str>) -> ListedChallenge {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let found = listed_as(base, token).await;
        if let Some(first) = found.into_iter().next() {
            return first;
        }
        if Instant::now() > deadline {
            panic!("no challenge was ever presented");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// -----------------------------------------------------------------------------------------
// Hermetic: the routes, and the answers a client acts on
// -----------------------------------------------------------------------------------------

#[tokio::test]
async fn the_challenge_routes_are_mounted_and_an_empty_registry_is_a_listing() {
    let server = harness(|_| {}).await;
    let base = format!("http://{}", server.addr);

    // A listing is a listing even when it is empty: the handler's own key, never a 404 body.
    let response = client()
        .get(format!("{base}/v1/challenges"))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("a JSON body");
    assert_eq!(
        body["challenges"],
        serde_json::json!([]),
        "nothing is waiting on a daemon nobody has asked: {body}"
    );
}

#[tokio::test]
async fn an_unknown_challenge_is_a_404_and_a_nameless_decline_is_a_400() {
    let server = harness(|_| {}).await;
    let base = format!("http://{}", server.addr);

    let unknown = client()
        .post(format!("{base}/v1/challenges/chal_never_existed"))
        .json(&serde_json::json!({ "outcome": "solved" }))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(
        unknown.status(),
        404,
        "an id that was never a challenge is not a challenge that is over"
    );

    // Checked *before* the id is looked up, and deliberately: a body the daemon cannot read is the
    // caller's mistake whether or not the id happens to exist, and answering 404 would hide it.
    let nameless = client()
        .post(format!("{base}/v1/challenges/chal_never_existed"))
        .json(&serde_json::json!({ "outcome": "abandoned", "note": "   " }))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(nameless.status(), 400);
    let body: serde_json::Value = nameless.json().await.expect("a JSON body");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("must carry a note"),
        "the refusal says what was wanted: {body}"
    );

    let nonsense = client()
        .post(format!("{base}/v1/challenges/chal_never_existed"))
        .json(&serde_json::json!({ "outcome": "maybe" }))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(
        nonsense.status(),
        422,
        "an outcome the daemon does not know is a parse error, not a default"
    );
}

// -----------------------------------------------------------------------------------------
// Live: a refused page asks a person, and the answer ends the fetch
// -----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_refused_page_asks_a_person_and_their_answer_ends_the_fetch() {
    require_browser!();

    let server = harness(|config| {
        // The rung is what enforces this, and the pane is what shows it. Long enough that the answer
        // below is certainly the thing that ends the wait.
        config.screen.challenge_budget_secs = 30;
    })
    .await;
    let base = format!("http://{}", server.addr);

    let stub = Stub::refusing().await;
    // A session profile of the test's own, so the browser the pane launches writes nowhere that
    // another test reads.
    let pool_root = tempfile::tempdir().expect("a pool root");
    let fetcher = BrowserFetcher::new(pool_root.path().join("pool"))
        .expect("the auto shape")
        .with_admission(Admission::AllowLocal)
        .expect("widened for a loopback stub")
        .with_pane(
            Arc::clone(&server.state.pane) as Arc<dyn hx_browser::HumanPane>,
            Duration::from_secs(30),
        )
        .expect("a fetcher with a person behind it");

    // The person answers over HTTP, from a client that is not the fetch — which is the shape of the
    // real thing: the web client is a different process's tab.
    let answering = {
        let base = base.clone();
        let target = stub.url();
        tokio::spawn(async move {
            let challenge = wait_for_challenge(&base).await;
            assert_eq!(challenge.screen, challenge.id, "the challenge names its screen");
            assert!(
                challenge.url.starts_with("http://127.0.0.1:"),
                "the person is shown the site that refused, redacted: {}",
                challenge.url
            );
            assert!(
                challenge.reason.contains("challenge"),
                "and why they are being asked: {}",
                challenge.reason
            );
            assert!(
                challenge.seconds_left <= 30,
                "the countdown cannot exceed the budget the rung enforces: {}",
                challenge.seconds_left
            );
            assert!(
                !target.is_empty() && challenge.session.starts_with("browser_"),
                "the session is named, and it is the one-shot session the fetch opened: {}",
                challenge.session
            );

            let answered = client()
                .post(format!("{base}/v1/challenges/{}", challenge.id))
                .json(&serde_json::json!({ "outcome": "solved" }))
                .send()
                .await
                .expect("the route answers");
            assert_eq!(answered.status(), 200, "the pane was waiting");
            let body: serde_json::Value = answered.json().await.expect("a JSON body");
            assert_eq!(body["answered"], serde_json::json!(true), "{body}");

            // A second click, which is what a person does when the first one seems slow. The
            // challenge is over, and saying so is not the same as saying the id was wrong.
            let twice = client()
                .post(format!("{base}/v1/challenges/{}", challenge.id))
                .json(&serde_json::json!({ "outcome": "solved" }))
                .send()
                .await
                .expect("the route answers");
            assert_eq!(twice.status(), 409, "the challenge is over, not unknown");

            challenge.id
        })
    };

    let session = SessionId::from_raw("browser_challenge_test");
    let report = fetcher.pool().fetch(&session, &stub.url()).await;

    let answered = answering.await.expect("the answerer");
    assert!(!answered.is_empty());

    // The climb is the assertion: a refusal at the cheap rung, then the browser, then a person.
    let names: Vec<&str> = report
        .attempts
        .iter()
        .map(|attempt| attempt.rung_name.as_str())
        .collect();
    // Printed rather than asserted on, and printed with each rung's own words: *which* rung refused
    // and *why* is a fact about the host as much as about the loop — a machine with no Chromium
    // reaches the person through a capability gap rather than a bot wall — and a run that hid that
    // would be reporting a green test rather than a measured one.
    for attempt in &report.attempts {
        eprintln!(
            "challenge_api: {}ms {} -> {}",
            attempt.elapsed_ms,
            attempt.rung_name,
            attempt.failure.as_deref().unwrap_or("a page")
        );
    }
    eprintln!(
        "challenge_api: the loop took {}ms over {} attempts: {} at {}",
        report.elapsed_ms,
        report.attempts.len(),
        names.join(" -> "),
        stub.url()
    );
    assert_eq!(
        names.last(),
        Some(&"interactive-cdp"),
        "the last rung is the person: {names:?}"
    );
    assert!(
        names.contains(&"http"),
        "and the cheap rung ran first: {names:?}"
    );
    assert!(
        report.page.is_none(),
        "a person clearing a wall leaves the reading to the ladder, so there is no page here"
    );

    let stop = report.stop_reason.clone().unwrap_or_default();
    assert!(
        stop.contains("screen-pane") && stop.contains("cleared the challenge"),
        "the fetch reports what the person did, by the pane's own name: {stop}"
    );

    // And the browser the person was shown is gone, because the pane waits for it before the rung is
    // told anything: an outcome that arrived while a renderer was still exiting would be a report of a
    // state that had not been reached.
    let screens: serde_json::Value = client()
        .get(format!("{base}/v1/screens"))
        .send()
        .await
        .expect("the route answers")
        .json()
        .await
        .expect("a JSON body");
    assert_eq!(screens["screens"], serde_json::json!([]), "{screens}");
    assert!(
        listed(&base).await.is_empty(),
        "and the challenge is over rather than still listed"
    );
}

#[tokio::test]
async fn a_challenge_nobody_answers_leaves_no_browser_and_no_question_behind() {
    // The cancellation path, end to end and through the real screen registry: the rung's budget
    // expires, the pane's `present` future is dropped mid-await, and what must be true afterwards is
    // that no browser is left running and no question is left being asked. This is the property the
    // contract calls out as the one a pane gets wrong, and it is the only test that exercises
    // `Screens::forget` — the synchronous half of `remove` — against a real browser.
    require_browser!();

    let server = harness(|config| {
        config.screen.challenge_budget_secs = 1;
    })
    .await;
    let base = format!("http://{}", server.addr);
    let stub = Stub::refusing().await;
    let pool_root = tempfile::tempdir().expect("a pool root");

    let fetcher = BrowserFetcher::new(pool_root.path().join("pool"))
        .expect("the auto shape")
        .with_admission(Admission::AllowLocal)
        .expect("widened for a loopback stub")
        .with_pane(
            Arc::clone(&server.state.pane) as Arc<dyn hx_browser::HumanPane>,
            Duration::from_millis(1200),
        )
        .expect("a fetcher with a person behind it");

    // Watched *while* the fetch waits, so the id below is the one the daemon really minted rather than
    // a string this test hopes it chose.
    let watching = {
        let base = base.clone();
        tokio::spawn(async move { wait_for_challenge(&base).await })
    };
    let session = SessionId::from_raw("browser_expiry_test");
    let report = tokio::time::timeout(
        Duration::from_secs(60),
        fetcher.pool().fetch(&session, &stub.url()),
    )
    .await
    .expect("a budget is a deadline, not a wait for a person who may never come");
    let presented = watching.await.expect("the watcher");

    let stop = report.stop_reason.clone().unwrap_or_default();
    assert!(
        stop.contains("nobody answered within"),
        "and the report names the budget that expired: {stop}"
    );

    // The screen is gone from the daemon's own registry. It is `forget` that took it, so this is also
    // the assertion that the synchronous path removes: waiting for the process is the one thing a
    // `Drop` cannot do, and the browser dies with the handle either way.
    let mut screens = serde_json::Value::Null;
    for _ in 0..60 {
        screens = client()
            .get(format!("{base}/v1/screens"))
            .send()
            .await
            .expect("the route answers")
            .json()
            .await
            .expect("a JSON body");
        if screens["screens"] == serde_json::json!([]) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(screens["screens"], serde_json::json!([]), "{screens}");
    assert!(
        listed(&base).await.is_empty(),
        "and the question is withdrawn rather than left being asked"
    );

    // A person who arrives late is told the truth about the id they were shown: it was a challenge,
    // and it is over.
    let late = client()
        .post(format!("{base}/v1/challenges/{}", presented.id))
        .json(&serde_json::json!({ "outcome": "solved" }))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(
        late.status(),
        409,
        "the id was presented and the budget ran out — not the same answer as one that never existed"
    );
}

// -----------------------------------------------------------------------------------------
// Live: the question is addressed to one operator, and they are told
// -----------------------------------------------------------------------------------------

#[tokio::test]
async fn an_addressed_challenge_is_announced_to_the_operator_and_its_token_answers_it() {
    // The whole claim in one test. A challenge is a question for a *person*, so: the daemon names
    // them (listing and notification), it tells them on their own channel through the token's own
    // one-time URL, and the answer that URL carries needs no bearer token at all — while a request
    // with no credential, or with another challenge's token, ends nothing.
    require_browser!();

    let relay = Relay::start().await;
    let server = harness_with(
        |config| {
            config.screen.challenge_budget_secs = 30;
            config.screen.operator = Some("yoav".to_string());
            config.approval.push_url = Some(relay.url());
        },
        Some("hx-test-token"),
    )
    .await;
    let base = format!("http://{}", server.addr);
    let stub = Stub::refusing().await;
    let pool_root = tempfile::tempdir().expect("a pool root");

    let fetcher = BrowserFetcher::new(pool_root.path().join("pool"))
        .expect("the auto shape")
        .with_admission(Admission::AllowLocal)
        .expect("widened for a loopback stub")
        .with_pane(
            Arc::clone(&server.state.pane) as Arc<dyn hx_browser::HumanPane>,
            Duration::from_secs(30),
        )
        .expect("a fetcher with a person behind it");

    let session = SessionId::from_raw("browser_addressed_test");
    let target = stub.url();
    let fetching = {
        let target = target.clone();
        tokio::spawn(async move { fetcher.pool().fetch(&session, &target).await })
    };

    // The notification came first, and it names the operator, the site and the clock.
    let notice = relay.wait_for("challenge").await;
    assert_eq!(notice["kind"], serde_json::json!("challenge"));
    assert_eq!(
        notice["operator"],
        serde_json::json!("yoav"),
        "the question is addressed to a person, by the name the config gives: {notice}"
    );
    assert_eq!(
        notice["url"],
        serde_json::json!(target),
        "the person is shown the site that refused, redacted: {notice}"
    );
    assert!(
        notice["seconds_left"].as_u64().unwrap_or(0) <= 30,
        "the clock in the notification is the budget the rung enforces: {notice}"
    );
    assert!(
        notice["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("challenge"),
        "and why the machines gave up: {notice}"
    );

    let listed = wait_for_challenge_as(&base, Some("hx-test-token")).await;
    assert_eq!(listed.id, notice["id"].as_str().unwrap_or_default());
    assert_eq!(listed.operator, "yoav", "the listing names the same person");
    assert!(
        listed.notified,
        "and reports that they were told, because a push really went out"
    );
    assert_eq!(listed.session, "browser_addressed_test", "{listed:?}");

    // The notification's answer URL, used exactly as a relay would: no `Authorization` header, this
    // request's only credential being the one-time token inside it.
    let respond_url = notice["respond_url"].as_str().expect("a respond_url");
    assert!(
        respond_url.starts_with(&format!("{base}/v1/challenges/{}", listed.id)),
        "the answer URL points back at this daemon and this challenge: {respond_url}"
    );

    // A token that is not this challenge's is refused *and* leaves the question open, which is the
    // difference between answering and interrupting.
    let wrong = client()
        .post(format!("{base}/v1/challenges/{}?token=deadbeef", listed.id))
        .json(&serde_json::json!({ "outcome": "solved" }))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(
        wrong.status(),
        403,
        "a misnamed token is not an answer, and the daemon says so rather than pretending otherwise"
    );
    assert_eq!(
        listed_as(&base, Some("hx-test-token")).await.len(),
        1,
        "the challenge is still waiting for the person who was actually asked"
    );

    // And with *no* credential at all there is nothing to answer with: the token is the way in, not
    // an open door beside the bearer token.
    let anonymous = client()
        .post(format!("{base}/v1/challenges/{}", listed.id))
        .json(&serde_json::json!({ "outcome": "solved" }))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(anonymous.status(), 401, "no token and no bearer is not an answer");

    let answered = client()
        .post(respond_url)
        .json(&serde_json::json!({ "outcome": "solved" }))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(
        answered.status(),
        200,
        "the notification's own token answers the question it announced"
    );

    let report = fetching.await.expect("the fetch task");
    let stop = report.stop_reason.clone().unwrap_or_default();
    assert!(
        stop.contains("screen-pane") && stop.contains("cleared the challenge"),
        "the fetch reports what the person did, by the pane's own name: {stop}"
    );

    // And they are told it is over, which is what lets them stop looking at the clock.
    let resolved = relay.wait_for("challenge_resolved").await;
    assert_eq!(resolved["id"], serde_json::json!(listed.id));
    assert_eq!(resolved["operator"], serde_json::json!("yoav"));
    assert_eq!(
        resolved["outcome"],
        serde_json::json!("solved"),
        "a person cleared it, and the notification says which way it ended: {resolved}"
    );
    eprintln!(
        "challenge_api: addressed to {} — pushed {} then {} to {}",
        notice["operator"].as_str().unwrap_or_default(),
        notice["kind"].as_str().unwrap_or_default(),
        resolved["kind"].as_str().unwrap_or_default(),
        relay.url()
    );

    // Nothing is left behind: no browser, no question.
    let screens: serde_json::Value = client()
        .get(format!("{base}/v1/screens"))
        .bearer_auth("hx-test-token")
        .send()
        .await
        .expect("the route answers")
        .json()
        .await
        .expect("a JSON body");
    assert_eq!(screens["screens"], serde_json::json!([]), "{screens}");
    assert!(listed_as(&base, Some("hx-test-token")).await.is_empty());
}

#[tokio::test]
async fn a_challenge_goes_to_the_operator_it_names_and_to_nobody_elses_relay() {
    // The roster, end to end, with the thing that cannot be unit-tested: two real HTTP relays on the
    // loopback, two `push_url`s in the config, and a live browser refusing a page. What has to be
    // true is not that a push happened but *which relay received it* — the whole point of naming
    // several operators is that a question addressed to one person does not land on somebody else's
    // phone, and a single-relay test would pass just as happily if the daemon pushed to a constant.
    require_browser!();

    let yoav_relay = Relay::for_person("yoav").await;
    let dana_relay = Relay::for_person("dana").await;
    let yoav_url = yoav_relay.url();
    let dana_url = dana_relay.url();
    let server = harness(|config| {
        config.screen.challenge_budget_secs = 30;
        config.screen.operators = vec![
            hx_core::config::ChallengeOperator {
                name: "yoav".to_string(),
                push_url: Some(yoav_url.clone()),
            },
            hx_core::config::ChallengeOperator {
                name: "dana".to_string(),
                push_url: Some(dana_url.clone()),
            },
        ];
        // A shared webhook as well, on purpose: the single-operator key. If the daemon merged the
        // two shapes it would push here too, and this is the assertion that it does not.
        config.approval.push_url = Some("http://127.0.0.1:9/never".to_string());
    })
    .await;
    let base = format!("http://{}", server.addr);
    let stub = Stub::refusing().await;
    let pool_root = tempfile::tempdir().expect("a pool root");

    let fetcher = BrowserFetcher::new(pool_root.path().join("pool"))
        .expect("the auto shape")
        .with_admission(Admission::AllowLocal)
        .expect("widened for a loopback stub")
        .with_pane(
            Arc::clone(&server.state.pane) as Arc<dyn hx_browser::HumanPane>,
            Duration::from_secs(30),
        )
        .expect("a fetcher with a person behind it");

    let session = SessionId::from_raw("browser_roster_test");
    let target = stub.url();
    let fetching = {
        let target = target.clone();
        tokio::spawn(async move { fetcher.pool().fetch(&session, &target).await })
    };

    // The first question goes to the first name in the roster, and only to them.
    let notice = yoav_relay.wait_for("challenge").await;
    assert_eq!(
        notice["operator"],
        serde_json::json!("yoav"),
        "the addressee is the first operator in the config, and it is on the payload: {notice}"
    );
    assert_eq!(
        notice["url"],
        serde_json::json!(target),
        "and the question is the real one, not a placeholder: {notice}"
    );

    let listed = wait_for_challenge(&base).await;
    assert_eq!(listed.id, notice["id"].as_str().unwrap_or_default());
    assert_eq!(
        listed.operator, "yoav",
        "the listing names the same person the notification did"
    );
    assert!(listed.notified, "and says they were really pushed to");

    // The other half of the claim, which a "was a push delivered" assertion could never see: while
    // yoav's relay is busy, dana's has heard nothing at all.
    assert_eq!(
        dana_relay.kinds(),
        Vec::<String>::new(),
        "a challenge addressed to yoav is not broadcast, so dana's relay is untouched"
    );

    // And the answer still comes from the one-time URL, with no bearer token.
    let answered = client()
        .post(notice["respond_url"].as_str().expect("a respond_url"))
        .json(&serde_json::json!({ "outcome": "solved" }))
        .send()
        .await
        .expect("the route answers");
    assert_eq!(answered.status(), 200, "{:?}", answered);

    let report = fetching.await.expect("the fetch task");
    let stop = report.stop_reason.clone().unwrap_or_default();
    assert!(
        stop.contains("screen-pane") && stop.contains("cleared the challenge"),
        "the fetch reports what the person did: {stop}"
    );

    // The resolution goes back down the same route it came up: to yoav, and to nobody else.
    let resolved = yoav_relay.wait_for("challenge_resolved").await;
    assert_eq!(resolved["operator"], serde_json::json!("yoav"));
    assert_eq!(resolved["outcome"], serde_json::json!("solved"), "{resolved}");
    eprintln!(
        "challenge_api: {} relays — yoav got {:?}, dana got {:?}",
        2,
        yoav_relay.kinds(),
        dana_relay.kinds()
    );
    assert_eq!(
        yoav_relay.kinds(),
        vec!["challenge".to_string(), "challenge_resolved".to_string()],
        "exactly the two pushes about this run, and no third"
    );
    assert_eq!(
        dana_relay.kinds(),
        Vec::<String>::new(),
        "the other operator's channel stays quiet: they were not asked, so they are not told"
    );
}

#[tokio::test]
async fn a_fetcher_with_no_person_ends_at_the_browser_rather_than_waiting() {
    // The other half of the wiring, and the one that must never hang: with no pane the interactive
    // rung is still there, still reports, and returns immediately.
    let server = harness(|_| {}).await;
    let stub = Stub::refusing().await;
    let pool_root = tempfile::tempdir().expect("a pool root");

    let fetcher = BrowserFetcher::new(pool_root.path().join("pool"))
        .expect("the auto shape")
        .with_admission(Admission::AllowLocal)
        .expect("widened for a loopback stub");
    assert!(
        fetcher.human().is_none(),
        "nothing was attached, so the fail-closed rung is what the ladder carries"
    );

    let session = SessionId::from_raw("browser_no_pane_test");
    let report = tokio::time::timeout(
        Duration::from_secs(60),
        fetcher.pool().fetch(&session, &stub.url()),
    )
    .await
    .expect("a fetch with nobody to ask must not hang");

    let names: Vec<&str> = report
        .attempts
        .iter()
        .map(|attempt| attempt.rung_name.as_str())
        .collect();
    assert!(
        names.contains(&"interactive-cdp"),
        "the person's rung is present even when nobody is there: {names:?}"
    );
    let stop = report.stop_reason.clone().unwrap_or_default();
    assert!(
        stop.contains("no human pane is attached"),
        "and the report says so rather than leaving the reader to guess: {stop}"
    );
    assert!(
        listed(&format!("http://{}", server.addr)).await.is_empty(),
        "no pane means no challenge, which is what fails closed means"
    );
}
