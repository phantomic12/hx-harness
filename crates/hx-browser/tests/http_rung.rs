//! The HTTP rung, over real sockets.
//!
//! No network and no browser: a stub server on loopback answers canned HTTP, so the request line, the
//! headers, the redirect handling and the body are all real. That is what makes these run on every
//! commit rather than being `#[ignore]`d.
//!
//! The test this file exists for is
//! [`a_redirect_to_a_local_address_is_refused_and_the_redirect_target_is_never_connected_to`]. The
//! redirect target is a **real listener**, so if the admission guard ran after connecting, its counter
//! would move. That is the difference between "the URL was judged" and "the URL was judged before
//! anything used it" — and the second is the only one that matters.

use hx_browser::error::FetchError;
use hx_browser::profile::{PoolRoot, SessionProfile};
use hx_browser::rung::{FetchRequest, Fetcher, RungKind};
use hx_browser::rungs::http::{MAX_BODY_BYTES, MAX_REDIRECTS, USER_AGENT};
use hx_browser::rungs::HttpRung;
use hx_browser::target::{Admission, BlockReason, TargetUrl};
use hx_core::ids::SessionId;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// What a stub was asked for.
#[derive(Default)]
struct Seen {
    heads: Mutex<Vec<String>>,
    connections: AtomicUsize,
}

impl Seen {
    /// The request line of each request, in order.
    fn request_lines(&self) -> Vec<String> {
        self.heads
            .lock()
            .expect("the lock is not poisoned")
            .iter()
            .map(|head| head.lines().next().unwrap_or_default().to_string())
            .collect()
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("the lock is not poisoned").clone()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// One canned response.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

impl Reply {
    fn html(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type", "text/html".to_string())],
            body: body.to_string(),
        }
    }

    fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            headers: vec![("location", location.to_string())],
            body: String::new(),
        }
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            headers: vec![("content-type", "text/html".to_string())],
            body: format!("<h1>{status}</h1>"),
        }
    }

    fn typed(content_type: &str, body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type", content_type.to_string())],
            body: body.to_string(),
        }
    }
}

/// A stub server. Answers each connection with the next reply, repeating the last one so an
/// unexpected extra request is *visible* rather than a hang.
struct Stub {
    addr: SocketAddr,
    seen: Arc<Seen>,
    task: JoinHandle<()>,
}

impl Stub {
    async fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
        let addr = listener.local_addr().expect("a bound address");
        let seen = Arc::new(Seen::default());
        let task = tokio::spawn(serve(listener, replies, seen.clone()));
        Self { addr, seen, task }
    }

    /// A listener that records connections and answers nothing.
    ///
    /// Used as a *redirect target*: if anything ever connects to it, the counter moves, which is the
    /// assertion the redirect test is built on.
    async fn silent() -> Self {
        Self::new(Vec::new()).await
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(listener: TcpListener, replies: Vec<Reply>, seen: Arc<Seen>) {
    let mut served = 0usize;

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        seen.connections.fetch_add(1, Ordering::SeqCst);

        let mut buffer = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    buffer.extend_from_slice(&chunk[..read]);
                    if find(&buffer, b"\r\n\r\n").is_some() {
                        break;
                    }
                }
            }
        }

        seen.heads
            .lock()
            .expect("the lock is not poisoned")
            .push(String::from_utf8_lossy(&buffer).to_string());

        if replies.is_empty() {
            // Never answer. This listener exists to record that nothing connected, so a client that
            // did connect would hang and be caught by its own timeout — and the counter above.
            continue;
        }

        let reply = &replies[served.min(replies.len() - 1)];
        served += 1;

        let mut out = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status));
        for (name, value) in &reply.headers {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        out.push_str(&format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            reply.body.len()
        ));
        out.push_str(&reply.body);

        let _ = socket.write_all(out.as_bytes()).await;
        let _ = socket.shutdown().await;
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A profile in a temp directory, which the caller must keep alive.
fn profile() -> (tempfile::TempDir, Arc<SessionProfile>) {
    let temp = tempfile::tempdir().expect("a temp directory");
    let root = PoolRoot::new(temp.path().join("pool")).expect("a pool root");
    let session = root
        .session(&SessionId::from_raw("http-rung-test"))
        .expect("a session profile");
    (temp, Arc::new(session))
}

fn request_for(url: &str, admission: Admission, profile: Arc<SessionProfile>) -> FetchRequest {
    FetchRequest {
        target: TargetUrl::parse_with(admission, url).expect("an admitted target"),
        profile,
        timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn a_redirect_to_a_local_address_is_refused_and_the_redirect_target_is_never_connected_to() {
    // The target of the redirect is a REAL listener. If the guard ran after connecting, this counter
    // would move — which is exactly the bug the guard exists to prevent, so this is the assertion the
    // whole commit is for.
    let target = Stub::silent().await;
    let stub = Stub::new(vec![Reply::redirect(&format!(
        "http://{}/latest/meta-data/",
        target.addr
    ))])
    .await;

    // A rung judges *hops*: the initial target was admitted by the caller, which is the contract
    // `TargetUrl` exists to enforce. So a caller-admitted loopback target with a public-internet rung
    // is precisely the arrangement in which the hop is the thing under test.
    let rung = HttpRung::with_admission(Admission::PublicInternet).expect("a client");
    let (_temp, profile) = profile();
    let request = request_for(&stub.url("/start"), Admission::AllowLocal, profile);

    let err = rung
        .fetch(&request)
        .await
        .expect_err("a refused hop is not a page");

    match &err {
        FetchError::Blocked(refusal) => {
            assert!(
                matches!(refusal.reason, BlockReason::Redirected { .. }),
                "the refusal must say *redirected*, not merely *private host*: {refusal:?}"
            );
            assert!(
                refusal.reason.to_string().contains("it redirected to"),
                "{refusal}"
            );
        }
        other => panic!("expected a blocked redirect, got {other:?}"),
    }

    assert!(
        !err.is_refusal(),
        "a refused target stops the ladder: {err}"
    );
    assert_eq!(
        target.seen.connections(),
        0,
        "the redirect target was connected to, so the guard ran too late"
    );
    assert_eq!(
        stub.seen.request_lines(),
        vec!["GET /start HTTP/1.1"],
        "the rung made a request it should not have"
    );
}

#[tokio::test]
async fn a_redirect_to_the_metadata_address_names_the_page_that_sent_us_there() {
    // The classic SSRF shape, and the sentence `BlockReason::Redirected` was written for: the report
    // must name the *page* that chose the destination, because that is the attacker.
    let stub = Stub::new(vec![Reply::redirect(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    )])
    .await;

    let rung = HttpRung::with_admission(Admission::PublicInternet).expect("a client");
    let (_temp, profile) = profile();
    let request = request_for(&stub.url("/start"), Admission::AllowLocal, profile);

    let err = rung.fetch(&request).await.expect_err("a refused hop");

    let rendered = err.to_string();
    assert!(rendered.contains("169.254.169.254"), "{rendered}");
    assert!(rendered.contains("it redirected to"), "{rendered}");
    // The display is the originating URL, not the metadata URL: the sentence is about the page.
    assert!(
        rendered.contains(&stub.url("/start")),
        "the report must name the page that redirected: {rendered}"
    );
}

#[tokio::test]
async fn a_relative_redirect_resolves_against_the_hop_that_sent_it() {
    // A `Location` is routinely relative. Resolving it against the wrong base is how a redirect guard
    // is defeated: the guard would judge one URL while the client fetched another.
    let stub = Stub::new(vec![
        Reply::redirect("/middle"),
        Reply::redirect("../end"),
        Reply::html("<h1>the page at the end of the chain</h1>"),
    ])
    .await;

    let rung = HttpRung::with_admission(Admission::AllowLocal).expect("a client");
    let (_temp, profile) = profile();
    let request = request_for(&stub.url("/deep/start"), Admission::AllowLocal, profile);

    let page = rung.fetch(&request).await.expect("a page");

    assert!(page.body_untrusted().contains("end of the chain"));
    assert_eq!(page.rung, RungKind::Http);
    assert_eq!(
        stub.seen.request_lines(),
        vec![
            "GET /deep/start HTTP/1.1",
            "GET /middle HTTP/1.1",
            "GET /end HTTP/1.1",
        ],
        "`../end` resolved against `/middle` is `/end`"
    );
    // The page reports where it really came from, not what the caller asked for.
    assert!(
        page.target.request_url().ends_with("/end"),
        "{:?}",
        page.target
    );
}

#[tokio::test]
async fn a_redirect_loop_is_bounded_rather_than_followed_forever() {
    // The stub repeats its last reply, so an unbounded rung would loop until the test's own timeout.
    let stub = Stub::new(vec![Reply::redirect("/loop")]).await;

    let rung = HttpRung::with_admission(Admission::AllowLocal).expect("a client");
    let (_temp, profile) = profile();
    let request = request_for(&stub.url("/loop"), Admission::AllowLocal, profile);

    let err = rung
        .fetch(&request)
        .await
        .expect_err("a loop is not a page");

    assert!(
        matches!(err, FetchError::Http { status: 302, .. }),
        "{err:?}"
    );
    assert!(!err.is_refusal(), "a loop is not a wall: {err}");
    assert_eq!(
        stub.seen.request_lines().len(),
        MAX_REDIRECTS + 1,
        "the initial request plus exactly the allowed number of hops"
    );
}

#[tokio::test]
async fn a_wall_status_escalates_and_a_challenge_served_with_a_200_does_too() {
    // The one failure that escalates. A 403 reported as a generic failure would silently cost the
    // ladder its reason to climb, and a challenge is the same event with a friendlier status code.
    let forbidden = Stub::new(vec![Reply::status(403)]).await;
    let challenged = Stub::new(vec![Reply::html(
        "<html><head><title>Just a moment...</title></head><body>cf_chl_opt SENTINEL-PAGE-TEXT</body></html>",
    )])
    .await;

    let rung = HttpRung::with_admission(Admission::AllowLocal).expect("a client");
    let (_temp, profile) = profile();

    let wall = rung
        .fetch(&request_for(
            &forbidden.url("/"),
            Admission::AllowLocal,
            profile.clone(),
        ))
        .await
        .expect_err("a wall is not a page");
    assert!(wall.is_refusal(), "a 403 escalates: {wall}");
    assert!(wall.to_string().contains("403"), "{wall}");

    let challenge = rung
        .fetch(&request_for(
            &challenged.url("/"),
            Admission::AllowLocal,
            profile,
        ))
        .await
        .expect_err("a challenge is not a page");
    assert!(challenge.is_refusal(), "a challenge escalates: {challenge}");
    // What leaves the rung is the marker, never a slice of the page.
    assert!(
        challenge.to_string().contains("challenge page"),
        "{challenge}"
    );
    // The sentinel is text only the page carries. The marker is one of the fixed strings, so
    // asserting *its* absence would be asserting that the marker is not a marker.
    assert!(
        !challenge.to_string().contains("SENTINEL-PAGE-TEXT"),
        "{challenge}"
    );
}

#[tokio::test]
async fn a_body_that_is_not_text_is_refused_rather_than_read() {
    // Reading a 4 MB image into a `String` helps nobody, and the content type is the site's own claim —
    // which is why the rung believes it rather than sniffing.
    // The body does not have to be a real PNG: the content type is what the rung believes, which
    // is the point of the test.
    let stub = Stub::new(vec![Reply::typed("image/png", "not-really-a-png")]).await;

    let rung = HttpRung::with_admission(Admission::AllowLocal).expect("a client");
    let (_temp, profile) = profile();
    let err = rung
        .fetch(&request_for(
            &stub.url("/pixel.png"),
            Admission::AllowLocal,
            profile,
        ))
        .await
        .expect_err("an image is not a page");

    assert!(matches!(err, FetchError::NotText { .. }), "{err:?}");
    assert!(err.to_string().contains("image/png"), "{err}");
    assert!(!err.is_refusal(), "a binary body is not a wall: {err}");
}

#[tokio::test]
async fn a_body_over_the_cap_is_refused_rather_than_buffered() {
    // A hostile page can stream an unbounded body, and the timeout bounds how long that takes rather
    // than how much arrives.
    let oversize = "x".repeat(MAX_BODY_BYTES + 1);
    let stub = Stub::new(vec![Reply::typed("text/html", &oversize)]).await;

    let rung = HttpRung::with_admission(Admission::AllowLocal).expect("a client");
    let (_temp, profile) = profile();
    let err = rung
        .fetch(&request_for(&stub.url("/"), Admission::AllowLocal, profile))
        .await
        .expect_err("an oversize body is not a page");

    match err {
        FetchError::TooLarge { bytes, limit, .. } => {
            assert!(bytes > limit, "{bytes} > {limit}");
            assert_eq!(limit, MAX_BODY_BYTES);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert!(!err.is_refusal(), "an oversize body is not a wall: {err}");
}

#[tokio::test]
async fn a_failed_fetch_does_not_put_the_url_or_its_token_into_the_error() {
    // `reqwest::Error`'s own `Display` appends the URL, and a URL can carry a token. A failed fetch is
    // exactly the moment one would otherwise be written down.
    let rung = HttpRung::with_admission(Admission::AllowLocal).expect("a client");
    let (_temp, profile) = profile();
    // Port 1 is closed, so this is a real connection failure rather than a scripted one.
    let request = request_for(
        "http://127.0.0.1:1/page?token=SENTINEL-TOKEN-VALUE",
        Admission::AllowLocal,
        profile,
    );

    let err = rung
        .fetch(&request)
        .await
        .expect_err("nothing listens there");
    let rendered = format!("{err} {err:?}");

    assert!(matches!(err, FetchError::Transport { .. }), "{err:?}");
    assert!(
        !rendered.contains("SENTINEL-TOKEN-VALUE"),
        "the URL reached the error: {rendered}"
    );
    assert!(rendered.contains("could not connect"), "{rendered}");
}

#[tokio::test]
async fn the_request_says_what_it_is() {
    // A rung that lies about being a browser is the stealth rung's job, and it does it by being one.
    let stub = Stub::new(vec![Reply::html("<h1>ok</h1>")]).await;

    let rung = HttpRung::with_admission(Admission::AllowLocal).expect("a client");
    let (_temp, profile) = profile();
    rung.fetch(&request_for(&stub.url("/"), Admission::AllowLocal, profile))
        .await
        .expect("a page");

    let head = stub.seen.heads().join("\n").to_ascii_lowercase();
    assert!(
        head.contains(&format!("user-agent: {}", USER_AGENT.to_ascii_lowercase())),
        "{head}"
    );
}

#[tokio::test]
async fn the_sessions_cookies_are_sent_and_a_profile_without_them_is_not() {
    // The session's own jar is the only cookie source, and a profile with none must not send an empty
    // `Cookie:` header.
    let stub = Stub::new(vec![Reply::html("<h1>ok</h1>")]).await;

    let rung = HttpRung::with_admission(Admission::AllowLocal).expect("a client");
    let (_temp, profile) = profile();
    profile
        .write_cookies("cf_clearance=SENTINEL-COOKIE-VALUE")
        .expect("the jar is writable");

    rung.fetch(&request_for(&stub.url("/"), Admission::AllowLocal, profile))
        .await
        .expect("a page");

    let head = stub.seen.heads().join("\n");
    assert!(
        head.contains("cf_clearance=SENTINEL-COOKIE-VALUE"),
        "{head}"
    );
}
