//! The live canary for the browser rung, with a **negative control**.
//!
//! Everything else about this wiring is asserted in-process: `hx-browser`'s unit tests and
//! `chromium_rung.rs` drive real Chromium for the rung's own security properties, and
//! `research.rs`'s tests drive the caller's decisions with scripted rungs. What none of them shows
//! is the point of the rung: **fetch a page whose text only exists after JavaScript runs, and get
//! that text out — through a rung that a plain fetch could not have used.**
//!
//! ## The pair is the proof
//!
//! A test that only showed the browser rung succeeding would pass on a build where the browser rung
//! was never launched: the extraction ladder strips tags, so a page of markup yields *some* text
//! either way. So this file asserts a **pair** over one page served by one loopback server:
//!
//! | Path | Assertion |
//! |---|---|
//! | browser-first `BrowserFetcher`, through the research pipeline | the citation's snippet **contains** the JS-inserted token |
//! | plain `HttpFetcher`, through `research_with_fetch_mode(FetchMode::Http)` | the same page's citation snippet **does not contain** the token, and **does** contain a static sentinel from the page's prose (so it really read the page, rather than failing to) |
//!
//! The token is assembled by the page's script from parts, so it is not a substring of the bytes
//! the server sends — asserted directly on the served HTML, before anything fetches it. The
//! mutation that proves the pair can go red is recorded in `TESTING.md`: make the token a literal
//! in the HTML and the negative control fails.
//!
//! ## Which rung, and through which path
//!
//! The page is served on `127.0.0.1` — the address a hermetic test server has — and the default
//! admission policy refuses it, so the browser-side fetcher is built by the **same constructor the
//! selector's `Browser` arm calls** ([`BrowserFetcher::browser_first`]) and widened with the
//! **named** [`BrowserFetcher::with_admission`] hatch. That widening is not a workaround for a
//! broken selector: `select_fetcher(FetchMode::Browser, …)` is asserted here to choose the browser
//! fetcher on this host, and *its* product is asserted to **refuse** the loopback stub — admission
//! still runs. The plain side goes through the real running path end to end
//! (`research_with_fetch_mode(FetchMode::Http, …)`), which is a plain fetch and needs no hatch.
//!
//! ## Running it
//!
//! It needs a real Chromium binary at `/usr/lib/chromium/chromium`, which **bigwhite** (the
//! developer host) has and **garlic-clove** (the build host) does not — so it is `#[ignore]`d and
//! never runs in the gate:
//!
//! ```console
//! $ cargo test -p hx-search --test browser_rung_canary -- --ignored --nocapture --test-threads=1
//! ```
//!
//! On a host without the browser the test **prints why it skipped** and returns; it is not a silent
//! pass, and it is not a failure. (`docker_live.rs` uses the same rule: "asked for" is not the same
//! as "this machine has Docker".)

use hx_browser::rung::RungKind;
use hx_browser::rungs::chromium::DEFAULT_CHROMIUM_PATH;
use hx_browser::Admission;
use hx_core::ids::SessionId;
use hx_search::backends::USER_AGENT;
use hx_search::{
    browser_available, research, research_with_fetch_mode, select_fetcher, BackendOutcome,
    BrowserFetcher, FetchMode, ResearchReport, ResearchRequest, SearchBackend, SearxngBackend,
    SelectedFetcher,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// How long the browser may take. A cold Chromium launch is ~1s; this is the bound that fails a
/// hung one rather than letting the test hang.
const CANARY_TIMEOUT: Duration = Duration::from_secs(60);

/// Text that is in the served HTML itself, so a plain fetch can see it.
const STATIC_SENTINEL: &str = "STATIC_PROSE_SENTINEL";

/// The stub server: the page, and a SearXNG-shaped search endpoint that points at it.
struct CanaryServer {
    addr: SocketAddr,
    page_html: String,
    task: JoinHandle<()>,
}

impl CanaryServer {
    async fn start(token: &str) -> Self {
        let page_html = js_rendered_page(token);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener on a free port");
        let addr = listener.local_addr().expect("the bound address");

        // The search endpoint a research task starts from: one result, whose URL is the local page.
        // This is the shape `SearxngBackend` parses, so the pipeline really runs its fan-out and
        // citation steps rather than being handed a page to extract.
        let search_json = format!(
            r#"{{"results":[{{"title":"JS canary page","url":"http://{addr}/js-rendered","content":"a page whose text is inserted by script"}}]}}"#
        );

        let served_html = page_html.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let html = served_html.clone();
                let json = search_json.clone();

                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();

                    let (content_type, body) = if path.starts_with("/search") {
                        ("application/json", json)
                    } else {
                        ("text/html; charset=utf-8", html)
                    };

                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });

        Self {
            addr,
            page_html,
            task,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for CanaryServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The page the canary is about: a `<h2>` whose text is inserted by the page's own script, and
/// prose that is in the HTML.
///
/// `token` is deliberately **not** present as a single run of characters in the source: the script
/// joins it back together from its pieces, so the bytes a plain fetch receives do not contain it.
/// That is the whole canary, and the test asserts it on the served HTML before anything fetches —
/// a token that leaked into the HTML would make the negative control vacuous.
fn js_rendered_page(token: &str) -> String {
    // Every underscore-separated piece of the token, as JS string literals. Built from the token
    // itself rather than indexed by hand, so a token shape change cannot silently drop a piece (an
    // earlier version of this file split the token into four parts and spliced three of them in,
    // which left the page rendering a prefix of the token and the canary failing).
    let pieces: Vec<String> = token
        .split('_')
        .map(|piece| format!("'{piece}'"))
        .collect();
    let array = pieces.join(", ");

    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>JS canary</title></head>
<body>
<main>
<div id="content">
<h2 id="slot"></h2>
<p>{STATIC_SENTINEL}: this paragraph is in the served HTML, so a plain fetch reads it. The
paragraph exists so the negative control cannot pass by failing to fetch the page at all — a
citation that had read nothing would be empty, and empty is not the same answer as "the text is
not there".</p>
<p>A second paragraph gives the extraction ladder's readability pass a block that holds most of the
document's text and clears its two-hundred-character floor, so the text below is extracted by the
same rung for both fetches rather than by two different ones.</p>
</div>
</main>
<script>
  document.getElementById('slot').textContent = [{array}].join('_');
</script>
</body>
</html>"#
    )
}

/// The citation the research pipeline produced for the canary page, if it kept one.
fn citation_for<'a>(report: &'a ResearchReport, page_url: &str) -> &'a str {
    let source = report
        .sources
        .iter()
        .find(|source| source.url.contains("/js-rendered"))
        .unwrap_or_else(|| {
            panic!(
                "the pipeline produced no citation for {page_url}: {:?}",
                report.sources
            )
        });
    &source.snippet
}

/// The research pipeline's own request, so both sides run the same extraction and citation steps.
fn canary_request() -> ResearchRequest {
    ResearchRequest::new("js rendered canary").with_max_sources(1)
}

#[tokio::test]
#[ignore = "requires a Chromium binary at /usr/lib/chromium/chromium (bigwhite has it, garlic-clove does not)"]
async fn the_browser_rung_reads_what_a_plain_fetch_cannot() {
    if !browser_available() {
        eprintln!(
            "skipped: no Chromium at {DEFAULT_CHROMIUM_PATH} — this canary runs on a host that has \
             one (bigwhite; see TESTING.md)"
        );
        return;
    }

    // A token unique to this process, so a stale profile or a cached body from another run cannot
    // produce a false positive.
    let token = format!("JS_RENDERED_CANARY_{:08x}", std::process::id());
    let server = CanaryServer::start(&token).await;
    let page_url = server.url("/js-rendered");

    // The page's own bytes do not contain the token: it exists only after the script joins it. This
    // is asserted before anything fetches, because it is what makes the negative control below mean
    // something.
    assert!(
        !server.page_html.contains(&token),
        "the token is a literal in the served HTML, so the plain-rung control would prove nothing"
    );

    let pool_root = tempfile::tempdir().expect("a scratch directory for the browser pool");
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(CANARY_TIMEOUT)
        .build()
        .expect("an HTTP client");

    // The research task starts from a stub search backend that returns the local page, so both
    // paths below run the pipeline's real fan-out, dedup, extraction and citation steps.
    let backends: Vec<Arc<dyn SearchBackend>> = vec![Arc::new(SearxngBackend::new(
        server.base_url(),
    ))];

    // ---------------------------------------------------------------------------------------
    // The real selection path, on this host
    // ---------------------------------------------------------------------------------------
    let auto = select_fetcher(&client, FetchMode::Auto, pool_root.path().join("auto"))
        .expect("auto selection is infallible");
    assert_eq!(
        auto.kind,
        SelectedFetcher::Browser,
        "with Chromium installed, the research path's Auto mode must select the browser fetcher"
    );
    let selected = select_fetcher(
        &client,
        FetchMode::Browser,
        pool_root.path().join("browser"),
    )
    .expect("browser mode with a browser installed");
    assert_eq!(selected.kind, SelectedFetcher::Browser);
    let plain_selection = select_fetcher(&client, FetchMode::Http, pool_root.path().join("plain"))
        .expect("http mode never fails");
    assert_eq!(plain_selection.kind, SelectedFetcher::Http);

    // The selector's *own* browser fetcher refuses this page, because the page is on loopback and
    // admission still runs. Asserted rather than worked around: it is why the browser half below is
    // built with the same constructor plus the named local hatch.
    let refused = research_with_fetch_mode(
        &backends,
        &client,
        FetchMode::Browser,
        pool_root.path().join("refused"),
        &canary_request(),
    )
    .await
    .expect("browser mode with a browser installed");
    let refused_snippet = citation_for(&refused, &page_url);
    assert!(
        refused_snippet.is_empty(),
        "the selector's browser fetcher must refuse a loopback target (admission still runs), but \
         it produced: {refused_snippet}"
    );
    eprintln!("selection: auto={:?}, browser={:?}", auto.kind, selected.kind);
    eprintln!("the selector's own browser fetcher on a loopback page: refused (admission runs)");

    // ---------------------------------------------------------------------------------------
    // The browser rung: an admitted loopback page, read by a real browser
    // ---------------------------------------------------------------------------------------
    let browser_fetcher = BrowserFetcher::browser_first(pool_root.path().join("canary"))
        .expect("the browser-first fetcher")
        .with_admission(Admission::AllowLocal)
        .expect("the named local hatch")
        .with_timeout(CANARY_TIMEOUT);

    // Which rung answered. The pipeline's citation names the *extraction* rung, not the fetch rung,
    // so the fetch rung is read from the pool's own report before the fetcher is handed over.
    let report = browser_fetcher
        .pool()
        .fetch(&SessionId::from_raw("canary_browser"), &page_url)
        .await;
    let rung_page = report.page.as_ref().unwrap_or_else(|| {
        panic!(
            "the browser rung produced no page: {:?}",
            report.stop_reason
        )
    });
    assert_eq!(
        rung_page.rung,
        RungKind::Interactive,
        "the page must come from the browser rung, not the plain one: {:?}",
        report.attempts
    );
    assert!(
        rung_page.body_untrusted().contains(&token),
        "the browser rung's body must contain the JS-inserted token"
    );
    eprintln!(
        "browser rung: {} bytes, rung={:?}, escalated={}, attempts={:?}",
        rung_page.body_len(),
        rung_page.rung,
        report.escalated(),
        report.attempts
    );

    let browser_report = research(
        &backends,
        &client,
        Arc::new(browser_fetcher),
        &canary_request(),
    )
    .await;
    let browser_snippet = citation_for(&browser_report, &page_url);
    assert!(
        browser_snippet.contains(&token),
        "the pipeline's citation of a JS-rendered page must contain the rendered text {token:?}, \
         but the snippet was: {browser_snippet}"
    );
    eprintln!("browser path citation: {browser_snippet}");

    // ---------------------------------------------------------------------------------------
    // The plain rung: the same page, the same pipeline, no browser
    // ---------------------------------------------------------------------------------------
    let plain_report = research_with_fetch_mode(
        &backends,
        &client,
        FetchMode::Http,
        pool_root.path().join("plain-path"),
        &canary_request(),
    )
    .await
    .expect("http mode never fails");
    let plain_snippet = citation_for(&plain_report, &page_url);

    assert!(
        plain_snippet.contains(STATIC_SENTINEL),
        "the plain fetch must have read the page (or the negative control proves nothing): \
         {plain_snippet}"
    );
    assert!(
        !plain_snippet.contains(&token),
        "the plain rung produced the JS-inserted token, so the browser rung is not doing the work: \
         {plain_snippet}"
    );
    eprintln!("plain path citation: {plain_snippet}");

    // Both sides read the same page, and both citations came from the same extraction ladder, so
    // the only difference is which fetcher produced the bytes.
    assert!(
        !browser_report.sources.is_empty() && !plain_report.sources.is_empty(),
        "both paths must cite the page"
    );
    for report in [&browser_report, &plain_report] {
        assert!(
            report
                .backends
                .iter()
                .any(|outcome| matches!(outcome, BackendOutcome::Answered { .. })),
            "the stub search backend must have answered: {:?}",
            report.backends
        );
        assert_eq!(report.paid_calls, 0, "a keyless run must spend nothing");
    }
}
