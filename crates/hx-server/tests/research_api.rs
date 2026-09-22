//! `POST /v1/research` end to end over the real router.
//!
//! What is **real** here: the `AppState`, the axum router and its bearer-token middleware, the
//! route's own `select_fetcher` call, the `ResearchTask` pipeline, the extraction `Ladder`, and an
//! `HttpFetcher` reading a page over a real loopback socket.
//!
//! What is **scripted**: the search backends, and only them. They are the part of the pipeline that
//! would otherwise scrape third-party sites, and scripting them is what lets a test assert *which
//! URLs* were cited without the network.
//!
//! The page server is deliberately a real HTTP server rather than an injected `Fetcher`: the M6
//! route's job is to reach the pipeline through the fetch selection, so a test that handed the
//! route a scripted fetcher would prove the wiring while saying nothing about whether the route's
//! own fetch path can read a page. This one serves real HTML over loopback and lets the ladder
//! extract it for real.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use hx_core::config::Config;
use hx_search::{
    BackendKind, BackendRegistry, SearchBackend, SearchError, SearchQuery, SearchResult,
};
use hx_server::{app, AppState, AppStateParts};
use hx_store::Store;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

/// The word the served pages carry, so a citation's snippet can be traced back to the bytes the
/// loopback server actually sent rather than to a title the scripted backend also happened to know.
const SENTINEL: &str = "SENTINEL-ALPHA";

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed test timestamp")
}

/// A backend whose answers are dictated, counting its calls so a test can show it was reached
/// (or, for a backend that must be skipped, that it was not).
///
/// `failure` makes the one call error, which is how the route's handling of a *partly* broken
/// fan-out is exercised: one backend must not sink a report the other one answered.
struct ScriptedBackend {
    id: &'static str,
    results: Vec<SearchResult>,
    failure: Option<SearchError>,
    calls: Arc<AtomicUsize>,
}

impl ScriptedBackend {
    fn answering(id: &'static str, results: Vec<SearchResult>) -> Arc<Self> {
        Arc::new(Self {
            id,
            results,
            failure: None,
            calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn failing(id: &'static str, failure: SearchError) -> Arc<Self> {
        Arc::new(Self {
            id,
            results: Vec::new(),
            failure: Some(failure),
            calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SearchBackend for ScriptedBackend {
    fn id(&self) -> &str {
        self.id
    }

    fn kind(&self) -> BackendKind {
        // Keyless: a keyed backend would be skipped structurally before it was ever called, which
        // would make an assertion about the fan-out vacuous.
        BackendKind::Keyless
    }

    async fn search(
        &self,
        _client: &reqwest::Client,
        _query: &SearchQuery,
    ) -> std::result::Result<Vec<SearchResult>, SearchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.failure {
            Some(err) => Err(match err {
                SearchError::Http { status } => SearchError::Http { status: *status },
                other => SearchError::NotConfigured(other.to_string()),
            }),
            None => Ok(self.results.clone()),
        }
    }
}

/// A real HTTP server over loopback, serving real HTML.
///
/// `connection: close` and one response per connection, because that is all the route's
/// `HttpFetcher` needs and it keeps the server small enough to read. Every wait is bounded: a
/// client that connects and then says nothing is dropped after [`READ_TIMEOUT`] rather than
/// holding a task forever.
struct PageServer {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

/// How long a connection may take to send its request head before it is dropped.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl PageServer {
    async fn serve(pages: Vec<(&'static str, String)>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a free loopback port");
        let addr = listener.local_addr().expect("local addr");
        let pages: std::collections::HashMap<String, String> = pages
            .into_iter()
            .map(|(path, body)| (path.to_string(), body))
            .collect();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    // The listener was closed: nothing left to serve.
                    return;
                };
                let pages = pages.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};

                    let mut head = vec![0u8; 4096];
                    let read = tokio::time::timeout(READ_TIMEOUT, socket.read(&mut head)).await;
                    let n = match read {
                        Ok(Ok(n)) => n,
                        _ => return,
                    };
                    let request = String::from_utf8_lossy(&head[..n]).to_string();
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();

                    // An unknown path is a 404 with an empty body, so a test that mistyped a URL
                    // gets an empty citation and a red assertion rather than a silently served
                    // page that made the citation look right for the wrong reason.
                    let response = match pages.get(&path) {
                        Some(body) => format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\n\
                             content-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        ),
                        None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\
                                 connection: close\r\n\r\n"
                            .to_string(),
                    };
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        Self { addr, handle }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for PageServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Real HTML with a `<title>`, chrome, and enough continuous prose to clear the readability rung's
/// main-block floor. Long enough that the pipeline's snippet cap has to bite, so the cap is a
/// property the route is observed to hold rather than one its docs assert.
fn article(title: &str, heading: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
</head>
<body>
<header><p>Header Chrome That Must Not Be Cited</p></header>
<nav><a href="/">Home</a></nav>
<main>
<div id="content">
<h2>{heading}</h2>
<p>{SENTINEL} opens this paragraph and is the traceable marker for the served bytes.</p>
<p>This paragraph provides additional continuous prose so the element holding the page's text
clears the readability pass's share-of-text floor before the pass will consider it the main block
of the document. Without this run of words the pass declines and the plain rung answers instead,
which is a different claim about which rung produced the citation.</p>
<p>A third paragraph, because one paragraph is a fragment case and the milestone's extraction
story is about articles: prose that continues past the point where a snippet would be cut off, so
the truncation boundary is exercised by a real body rather than a fixture built to sit under it.</p>
</div>
</main>
<footer><p>Footer Chrome That Must Not Be Cited</p></footer>
</body>
</html>"#
    )
}

/// A harness with a search registry the test controls and nothing else it needs.
///
/// Mirrors `fanout_api.rs`: a real `Store` on disk, a real router built from a default config, and
/// no API token — a loopback bind is exactly the deployment where one is optional.
async fn harness(search: Arc<BackendRegistry>) -> Arc<AppState> {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let mut config = Config::default();
    config.daemon.data_dir = tempfile::tempdir()
        .expect("temp dir")
        .keep()
        .display()
        .to_string();

    let mut store_path = std::env::temp_dir();
    store_path.push(format!("hx-research-api-{}-{n}.db", std::process::id()));
    let store = Arc::new(Store::open(store_path).expect("test store opens"));

    let router = Arc::new(std::sync::Mutex::new(
        hx_provider::ModelRouter::from_config(&config, now()).expect("empty router"),
    ));

    AppState::from_parts(AppStateParts {
        router: Arc::clone(&router),
        providers: Arc::new(hx_provider::ProviderRegistry::new()),
        secrets: Arc::new(hx_secrets::SecretStores::new()),
        store,
        models: Arc::new(hx_server::chat::RouterModels::new(
            router,
            Arc::new(hx_provider::ProviderRegistry::new()),
            Arc::new(hx_secrets::SecretStores::new()),
        )),
        tools: Arc::new(hx_server::chat::default_tools(
            vec![],
            reqwest::Client::new(),
        )),
        approvals: hx_agent::ApprovalQueue::new(std::time::Duration::from_secs(1)),
        search,
        config,
        sandboxes: None::<Arc<hx_sandbox::SandboxManager>>,
        sandbox_unavailable_reason: Some("no container engine in a test".to_string()),
        started_at: now(),
        api_token: None,
        allowed_origins: Vec::new(),
        phone: None,
        webhooks: Default::default(),
    })
}

/// A registry holding exactly `backends`, over one shared client.
fn registry_of(backends: Vec<Arc<dyn SearchBackend>>) -> Arc<BackendRegistry> {
    let mut registry = BackendRegistry::new(reqwest::Client::new());
    for backend in backends {
        registry.insert(backend);
    }
    Arc::new(registry)
}

async fn post(state: Arc<AppState>, body: &str) -> (StatusCode, serde_json::Value) {
    let response = app(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/research")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("the router answers");

    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("a body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// The milestone's whole claim over HTTP: a research request reaches the fan-out, the extraction
/// ladder reads the pages a *scripted* backend pointed at, and the response carries the citations,
/// each backend's outcome, and the fetcher that was chosen — all through the route, with nothing
/// asserted about a fixture the code under test did not produce.
#[tokio::test]
async fn a_research_request_over_http_returns_citations_and_names_the_fetcher() {
    let pages = PageServer::serve(vec![
        ("/alpha", article("Alpha Article", SENTINEL)),
        ("/beta", article("Beta Article", "SENTINEL-BETA")),
    ])
    .await;

    let answering = ScriptedBackend::answering(
        "answering",
        vec![
            SearchResult::new(
                "Alpha from the backend",
                pages.url("/alpha"),
                "backend snippet",
            )
            .with_rank(0),
            SearchResult::new(
                "Beta from the backend",
                pages.url("/beta"),
                "backend snippet",
            )
            .with_rank(1),
        ],
    );
    let failing = ScriptedBackend::failing("failing", SearchError::Http { status: 503 });

    let state = harness(registry_of(vec![answering.clone(), failing.clone()])).await;

    let (status, body) = post(
        state,
        r#"{"query": "rust ownership", "fetch_mode": "http"}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a research request must succeed: {body}"
    );

    assert_eq!(
        body["query"], "rust ownership",
        "the query is echoed: {body}"
    );
    assert_eq!(
        body["fetcher"], "http",
        "an explicit http mode must be served by the plain fetcher: {body}"
    );
    assert!(
        body["fetch_note"]
            .as_str()
            .is_some_and(|note| !note.contains("browser")),
        "the http path must not claim any browser involvement: {body}"
    );
    assert_eq!(
        body["paid_calls"], 0,
        "keyless research makes no paid calls: {body}"
    );

    // Both backends were reached and both outcomes are reported — one failure does not sink the
    // report, and it is named rather than dropped.
    assert_eq!(
        answering.calls(),
        1,
        "the answering backend was queried once"
    );
    assert_eq!(failing.calls(), 1, "the failing backend was queried once");
    let backends = body["backends"].as_array().expect("backends is a list");
    assert_eq!(backends.len(), 2, "one outcome per backend: {body}");
    let answered = backends
        .iter()
        .find(|o| o["status"] == "answered")
        .expect("an answered outcome");
    assert_eq!(answered["backend"], "answering");
    let failed = backends
        .iter()
        .find(|o| o["status"] == "failed")
        .expect("a failed outcome");
    assert_eq!(failed["backend"], "failing");
    assert!(
        failed["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("503")),
        "the failure names what went wrong: {failed}"
    );

    // The citations came from the real pages the loopback server sent, extracted by the ladder the
    // route's own fetch path runs.
    let sources = body["sources"].as_array().expect("sources is a list");
    assert_eq!(sources.len(), 2, "both searched URLs must be cited: {body}");

    let alpha = sources
        .iter()
        .find(|s| s["url"].as_str().is_some_and(|url| url.ends_with("/alpha")))
        .expect("the alpha page is cited");
    assert_eq!(
        alpha["title"], "Alpha Article",
        "the title must come from the served page's <title>, not from the backend: {alpha}"
    );
    assert!(
        alpha["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains(SENTINEL)),
        "the snippet must carry the bytes the page server sent: {alpha}"
    );
    let snippet_len = alpha["snippet"]
        .as_str()
        .map(str::chars)
        .map(Iterator::count)
        .unwrap_or(0);
    assert!(
        snippet_len <= hx_search::DEFAULT_SNIPPET_MAX_CHARS + 1,
        "the snippet cap must bite over HTTP too ({snippet_len} chars): {alpha}"
    );
    assert!(
        matches!(alpha["rung"].as_str(), Some("plain") | Some("readability")),
        "the citation names the rung that produced it: {alpha}"
    );

    // Both pages were really fetched. `beta` is the second result, so it is the one that proves the
    // pipeline followed every URL it cited rather than only the first.
    let beta = sources
        .iter()
        .find(|s| s["url"].as_str().is_some_and(|url| url.ends_with("/beta")))
        .expect("the beta page is cited");
    assert_eq!(beta["title"], "Beta Article", "{beta}");
    assert!(
        beta["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains("SENTINEL-BETA")),
        "the second source is extracted too, not merely listed: {beta}"
    );

    // Ranks come from the fusion, not from the order the JSON happened to be built in.
    assert_eq!(alpha["rank"], 0, "{alpha}");
    assert_eq!(beta["rank"], 1, "{beta}");
}

/// A query that is empty or only whitespace is the caller's mistake, and the answer is a 400 that
/// says which field — never a 200 with an empty report, which a client would read as "no sources
/// exist" rather than "you sent no query".
#[tokio::test]
async fn a_blank_research_query_is_refused_as_a_bad_request() {
    let state = harness(registry_of(vec![ScriptedBackend::answering(
        "answering",
        Vec::new(),
    )]))
    .await;

    for body in [
        r#"{"query": "", "fetch_mode": "http"}"#,
        r#"{"query": "   ", "fetch_mode": "http"}"#,
    ] {
        let (status, out) = post(state.clone(), body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a blank query is the caller's to fix: {body} -> {out}"
        );
        assert!(
            out["error"]
                .as_str()
                .is_some_and(|message| message.contains("query")),
            "the 400 must name the field: {out}"
        );
    }
}

/// A daemon with no search backends configured cannot research anything, and says so with the same
/// 503 `/v1/search` gives — an empty registry is a configuration problem, not an empty report.
#[tokio::test]
async fn a_daemon_with_no_search_backends_refuses_research_with_503() {
    let state = harness(registry_of(Vec::new())).await;

    let (status, body) = post(
        state,
        r#"{"query": "rust ownership", "fetch_mode": "http"}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unconfigured daemon says so: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("search")),
        "the 503 must point at the configuration: {body}"
    );
}

/// An explicit `browser` request is answered by the browser or refused with a 409 — never silently
/// served by a plain fetch.
///
/// The branch is taken on the real host, because the route calls the real selector and no test can
/// install a pretend Chromium. Both branches are load-bearing: on a host with Chromium the response
/// must say `browser`, and on one without it must be a 409 naming Chromium. What is *never*
/// acceptable — and what both branches assert against — is a 200 that quietly did a plain fetch for
/// a caller who asked for a browser.
///
/// The scripted backend answers with no results, deliberately: the fetch selection happens before
/// any page is fetched, so the routing decision is fully exercised without launching Chromium at a
/// loopback URL the pool would refuse anyway.
#[tokio::test]
async fn an_explicit_browser_fetch_mode_is_answered_or_refused_but_never_downgraded() {
    let state = harness(registry_of(vec![ScriptedBackend::answering(
        "answering",
        Vec::new(),
    )]))
    .await;

    let (status, body) = post(state, r#"{"query": "rust", "fetch_mode": "browser"}"#).await;

    if hx_search::browser_available() {
        assert_eq!(
            status,
            StatusCode::OK,
            "a host with Chromium must honour an explicit browser request: {body}"
        );
        assert_eq!(
            body["fetcher"], "browser",
            "an explicit browser request must not be answered by the plain fetcher: {body}"
        );
        assert!(
            body["fetch_note"]
                .as_str()
                .is_some_and(|note| note.contains("browser")),
            "the note must record the browser decision: {body}"
        );
    } else {
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "explicit browser with no browser is a conflict, not a 500: {body}"
        );
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|message| message.contains("Chromium")),
            "the refusal must name the unavailable rung: {body}"
        );
        assert_eq!(
            body["fetcher"],
            serde_json::Value::Null,
            "a refused selection must not be reported as a fetcher that ran: {body}"
        );
    }
}

/// A body that is not JSON, and a body that is JSON but not a research request, are both the
/// caller's mistake: the route maps every `JsonRejection` to 400 rather than axum's default 422,
/// so one client error has one answer.
#[tokio::test]
async fn a_body_that_is_not_a_research_request_is_refused_as_a_bad_request() {
    let state = harness(registry_of(vec![ScriptedBackend::answering(
        "answering",
        Vec::new(),
    )]))
    .await;

    for (body, why) in [
        ("{\"query\":", "truncated JSON"),
        (
            r#"{"query": "rust", "fetch_mode": "telepathy"}"#,
            "a mode that is not in the FetchMode vocabulary",
        ),
    ] {
        let (status, out) = post(state.clone(), body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{why} is a 400, not a 422 or a 500: {out}"
        );
    }
}
