//! Research task: multi-backend fan-out, RRF rank fusion, caching, extraction, and citation.
//!
//! ## The target property: zero paid API calls
//!
//! M6's exit criterion states: *\"a research task runs 6 free backends in parallel, dedupes,
//! RRF-ranks, extracts the top 8, and cites them — with zero paid API calls.\"*
//!
//! This module wires together the components built across `hx-search`:
//! 1. Concurrent fan-out to the keyless backends ([`crate::aggregate::fanout`]).
//! 2. Canonical URL de-duplication ([`crate::types::canonicalize_url`]).
//! 3. Reciprocal Rank Fusion ([`crate::types::fuse`]).
//! 4. Bounded extraction of top sources through the URL cache ([`crate::cache::UrlCache`])
//!    and the extraction ladder ([`crate::extract::Ladder`]).
//! 5. Observable accounting of paid API calls, structurally guaranteed to be zero when
//!    running against the keyless backend set.
//!
//! ## Why no `hx-browser` dependency
//!
//! `hx-search` intentionally does not depend on `hx-browser`. Doing so would invert the system's
//! dependency hierarchy: the browser pool is the heavy escalation layer *above* search extraction
//! (for pages requiring full JavaScript execution or challenge solving), not a primitive underneath
//! it. Extraction here operates via a minimal, in-crate [`Fetcher`] abstraction backed by `reqwest`
//! and the synchronous [`crate::extract::Ladder`] parser.
//!
//! ## Body cap and timeout
//!
//! Hostile or bloated web pages must not consume unbounded memory or stall the research task.
//! Every fetch is bounded by a per-request timeout ([`DEFAULT_FETCH_TIMEOUT`]) and a maximum body
//! size ([`DEFAULT_MAX_BODY_BYTES`]). Crucially, a page exceeding the body cap is **skipped**
//! rather than truncated into a citation: extracting text from an arbitrarily truncated HTML
//! document yields malformed fragments and presents a false view of what the origin published.
//!
//! ## Bounded concurrency and honesty
//!
//! Fetching extracted content is constrained by [`DEFAULT_FETCH_CONCURRENCY`] (4 parallel fetches).
//! This bound overlaps network latency across distinct hosts while avoiding socket exhaustion or
//! aggressive traffic spikes to individual origins.
//!
//! If a page fetch fails (HTTP error, timeout, or transport disconnect), it yields a [`Citation`]
//! with an empty snippet rather than being silently dropped from the report. A report that quietly
//! returns 6 of 8 requested sources is worse than one that explicitly acknowledges two pages could
//! not be read. Conversely, a report that finds no matching results across all backends is a
//! successful report that found nothing, not an error.

use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::cache::{cache_key, CacheOutcome, UrlCache};
use crate::extract::{FetchedPage, Ladder, Rung};
use crate::types::{FusedResult, SearchQuery};
use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Default per-fetch timeout for page extraction.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Default body size cap for page extraction (500 KiB).
///
/// Pages exceeding this limit are skipped rather than truncated into citations.
pub const DEFAULT_MAX_BODY_BYTES: usize = 500 * 1024;

/// Default maximum number of sources cited in a research report.
pub const DEFAULT_MAX_SOURCES: usize = 8;

/// Default maximum snippet length in characters for citations.
pub const DEFAULT_SNIPPET_MAX_CHARS: usize = 500;

/// Default concurrency limit for fetching extracted pages.
///
/// Bounded to 4 to balance network latency hiding with socket hygiene.
pub const DEFAULT_FETCH_CONCURRENCY: usize = 4;

/// A minimal page fetcher for extraction.
///
/// Decoupled from `hx-browser`: operates over HTTP with strict timeouts and body caps.
#[async_trait]
pub trait Fetcher: Send + Sync {
    /// Fetch a page by URL.
    ///
    /// Returns:
    /// - `Ok(Some(page))` if fetched successfully within limits.
    /// - `Ok(None)` if the page was skipped (e.g. exceeded body cap).
    /// - `Err(err)` if a network, HTTP, or timeout failure occurred.
    async fn fetch(&self, url: &str) -> Result<Option<FetchedPage>, SearchError>;
}

/// A `reqwest`-backed HTTP fetcher with timeout, body cap, and optional URL caching.
pub struct HttpFetcher {
    client: reqwest::Client,
    timeout: Duration,
    max_body_bytes: usize,
    cache: Option<Arc<UrlCache>>,
}

impl std::fmt::Debug for HttpFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpFetcher")
            .field("timeout", &self.timeout)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("has_cache", &self.cache.is_some())
            .finish()
    }
}

impl HttpFetcher {
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            timeout: DEFAULT_FETCH_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            cache: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn with_cache(mut self, cache: Arc<UrlCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_cache_dir(mut self, root: impl Into<std::path::PathBuf>) -> Self {
        self.cache = Some(Arc::new(UrlCache::new(root, 1000, self.max_body_bytes)));
        self
    }
}

#[async_trait]
impl Fetcher for HttpFetcher {
    async fn fetch(&self, url: &str) -> Result<Option<FetchedPage>, SearchError> {
        if let Some(cache) = &self.cache {
            let outcome = match tokio::time::timeout(self.timeout, cache.fetch(&self.client, url))
                .await
            {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    return Err(SearchError::TransportRedacted {
                        reason: format!("fetch timed out after {:.1}s", self.timeout.as_secs_f64()),
                    });
                }
            };

            match outcome {
                CacheOutcome::Fresh(body)
                | CacheOutcome::Revalidated(body)
                | CacheOutcome::Fetched(body) => {
                    if body.len() > self.max_body_bytes {
                        // Page exceeded the cap: skip it rather than citing a truncated body.
                        Ok(None)
                    } else {
                        Ok(Some(FetchedPage::new(url, None, body)))
                    }
                }
                CacheOutcome::Miss304 => Ok(None),
            }
        } else {
            let request = self
                .client
                .get(url)
                .header(reqwest::header::USER_AGENT, crate::backends::USER_AGENT);

            let response = match tokio::time::timeout(self.timeout, request.send()).await {
                Ok(Ok(res)) => res,
                Ok(Err(err)) => return Err(SearchError::Transport(err)),
                Err(_) => {
                    return Err(SearchError::TransportRedacted {
                        reason: format!("fetch timed out after {:.1}s", self.timeout.as_secs_f64()),
                    });
                }
            };

            let status = response.status();
            if !status.is_success() {
                return Err(SearchError::Http {
                    status: status.as_u16(),
                });
            }

            if let Some(content_length) = response.content_length() {
                if content_length as usize > self.max_body_bytes {
                    return Ok(None);
                }
            }

            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            let body = match tokio::time::timeout(self.timeout, response.text()).await {
                Ok(Ok(body)) => body,
                Ok(Err(err)) => return Err(SearchError::Transport(err)),
                Err(_) => {
                    return Err(SearchError::TransportRedacted {
                        reason: format!(
                            "reading body timed out after {:.1}s",
                            self.timeout.as_secs_f64()
                        ),
                    });
                }
            };

            if body.len() > self.max_body_bytes {
                Ok(None)
            } else {
                Ok(Some(FetchedPage::new(url, content_type.as_deref(), body)))
            }
        }
    }
}

/// A request for a multi-source research report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchRequest {
    pub query: String,
    pub max_sources: usize,
}

impl ResearchRequest {
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            max_sources: DEFAULT_MAX_SOURCES,
        }
    }

    pub fn with_max_sources(mut self, max: usize) -> Self {
        self.max_sources = max.max(1);
        self
    }
}

/// An extracted and ranked source citation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Citation {
    pub title: Option<String>,
    pub url: String,
    /// Extracted text, truncated to a documented bound ([`DEFAULT_SNIPPET_MAX_CHARS`]).
    pub snippet: String,
    /// The 0-based RRF position it came from.
    pub rank: usize,
    /// Which extraction rung produced the text.
    pub rung: Rung,
}

impl std::fmt::Debug for Citation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Query parameters might hold tokens; sanitize the URL in Debug output using cache_key.
        f.debug_struct("Citation")
            .field("title", &self.title)
            .field("url", &cache_key(&self.url))
            .field("snippet_len", &self.snippet.len())
            .field("rank", &self.rank)
            .field("rung", &self.rung)
            .finish()
    }
}

/// Outcome of querying a single backend in the fan-out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BackendOutcome {
    Answered { backend: String },
    Failed { backend: String, reason: String },
}

impl BackendOutcome {
    pub fn answered(backend: impl Into<String>) -> Self {
        Self::Answered {
            backend: backend.into(),
        }
    }

    pub fn failed(backend: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Failed {
            backend: backend.into(),
            reason: reason.into(),
        }
    }

    pub fn backend(&self) -> &str {
        match self {
            BackendOutcome::Answered { backend } => backend,
            BackendOutcome::Failed { backend, .. } => backend,
        }
    }

    pub fn is_answered(&self) -> bool {
        matches!(self, BackendOutcome::Answered { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, BackendOutcome::Failed { .. })
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            BackendOutcome::Answered { .. } => None,
            BackendOutcome::Failed { reason, .. } => Some(reason),
        }
    }
}

/// The final report produced by a research task.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResearchReport {
    pub query: String,
    /// Backends that answered or failed — one failure must not sink the report.
    pub backends: Vec<BackendOutcome>,
    /// Extracted source citations.
    pub sources: Vec<Citation>,
    /// Observable count of paid API calls made during this task (must be 0 for keyless).
    pub paid_calls: usize,
}

impl std::fmt::Debug for ResearchReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResearchReport")
            .field("query", &self.query)
            .field("backends", &self.backends)
            .field("sources_count", &self.sources.len())
            .field("paid_calls", &self.paid_calls)
            .finish()
    }
}

/// A research task executor.
pub struct ResearchTask {
    backends: Vec<Arc<dyn SearchBackend>>,
    client: reqwest::Client,
    fetcher: Arc<dyn Fetcher>,
    ladder: Ladder,
    timeout: Duration,
    fetch_concurrency: usize,
    snippet_max_chars: usize,
    allow_paid: bool,
}

impl ResearchTask {
    pub fn new(
        backends: Vec<Arc<dyn SearchBackend>>,
        client: reqwest::Client,
        fetcher: Arc<dyn Fetcher>,
    ) -> Self {
        Self {
            backends,
            client,
            fetcher,
            ladder: Ladder::default_rungs(),
            timeout: crate::aggregate::DEFAULT_BACKEND_TIMEOUT,
            fetch_concurrency: DEFAULT_FETCH_CONCURRENCY,
            snippet_max_chars: DEFAULT_SNIPPET_MAX_CHARS,
            allow_paid: false,
        }
    }

    pub fn with_ladder(mut self, ladder: Ladder) -> Self {
        self.ladder = ladder;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_fetch_concurrency(mut self, concurrency: usize) -> Self {
        self.fetch_concurrency = concurrency.max(1);
        self
    }

    pub fn with_snippet_max_chars(mut self, max_chars: usize) -> Self {
        self.snippet_max_chars = max_chars;
        self
    }

    pub fn with_allow_paid(mut self, allow_paid: bool) -> Self {
        self.allow_paid = allow_paid;
        self
    }

    /// Execute the research task pipeline.
    pub async fn run(&self, request: &ResearchRequest) -> ResearchReport {
        let mut active_backends: Vec<Arc<dyn SearchBackend>> = Vec::new();
        let mut paid_calls = 0;

        for backend in &self.backends {
            let is_keyed = backend.kind() == BackendKind::Keyed || backend.requires_key();
            if is_keyed {
                if self.allow_paid {
                    active_backends.push(Arc::clone(backend));
                    paid_calls += 1;
                }
                // Keyed backends without opt-in are skipped structurally.
            } else {
                active_backends.push(Arc::clone(backend));
            }
        }

        let query = SearchQuery::new(&request.query).with_limit(request.max_sources);
        let search_report =
            crate::aggregate::fanout(&active_backends, &self.client, &query, self.timeout).await;

        let mut backends =
            Vec::with_capacity(search_report.answered.len() + search_report.failures.len());
        for backend in search_report.answered {
            backends.push(BackendOutcome::answered(backend));
        }
        for failure in search_report.failures {
            backends.push(BackendOutcome::failed(failure.backend, failure.reason));
        }

        let top_results: Vec<(usize, FusedResult)> = search_report
            .results
            .into_iter()
            .take(request.max_sources)
            .enumerate()
            .collect();

        let sources_stream = stream::iter(top_results).map(|(rank, fused)| {
            let fetcher = Arc::clone(&self.fetcher);
            let ladder = &self.ladder;
            let snippet_max_chars = self.snippet_max_chars;

            async move {
                let fetch_result = fetcher.fetch(&fused.url).await;
                match fetch_result {
                    Ok(Some(page)) => {
                        if let Some(extracted) = ladder.extract(&page) {
                            let title = extracted.title.or(if fused.title.is_empty() {
                                None
                            } else {
                                Some(fused.title)
                            });

                            let snippet = truncate_snippet(&extracted.text, snippet_max_chars);

                            Citation {
                                title,
                                url: fused.url,
                                snippet,
                                rank,
                                rung: extracted.rung,
                            }
                        } else {
                            // Page produced no extractable text.
                            Citation {
                                title: if fused.title.is_empty() {
                                    None
                                } else {
                                    Some(fused.title)
                                },
                                url: fused.url,
                                snippet: String::new(),
                                rank,
                                rung: Rung::Plain,
                            }
                        }
                    }
                    Ok(None) => {
                        // Page was skipped (e.g. exceeded body cap).
                        // Not cited with a truncated body; yields a citation with an empty snippet.
                        Citation {
                            title: if fused.title.is_empty() {
                                None
                            } else {
                                Some(fused.title)
                            },
                            url: fused.url,
                            snippet: String::new(),
                            rank,
                            rung: Rung::Plain,
                        }
                    }
                    Err(_) => {
                        // Fetch failure (transport, HTTP status, or timeout).
                        // Report honestly with an empty snippet rather than dropping the source silently.
                        Citation {
                            title: if fused.title.is_empty() {
                                None
                            } else {
                                Some(fused.title)
                            },
                            url: fused.url,
                            snippet: String::new(),
                            rank,
                            rung: Rung::Plain,
                        }
                    }
                }
            }
        });

        let sources: Vec<Citation> = sources_stream
            .buffered(self.fetch_concurrency)
            .collect()
            .await;

        ResearchReport {
            query: request.query.clone(),
            backends,
            sources,
            paid_calls,
        }
    }
}

/// Truncate snippet text to `max_chars` on a character boundary, adding an ellipsis if truncated.
fn truncate_snippet(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() > max_chars {
        let mut snippet: String = trimmed.chars().take(max_chars).collect();
        snippet.push('…');
        snippet
    } else {
        trimmed.to_string()
    }
}

/// Convenience function to execute a research task over keyless backends.
pub async fn research(
    backends: &[Arc<dyn SearchBackend>],
    client: &reqwest::Client,
    fetcher: Arc<dyn Fetcher>,
    request: &ResearchRequest,
) -> ResearchReport {
    let task = ResearchTask::new(backends.to_vec(), client.clone(), fetcher);
    task.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::{
        BraveBackend, DuckDuckGoBackend, HnAlgoliaBackend, MarginaliaBackend, MojeekBackend,
        SearxngBackend, WikipediaBackend,
    };
    use hx_secrets::Secret;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    /// A scripted loopback HTTP server.
    struct TestServer {
        addr: std::net::SocketAddr,
        connections: Arc<AtomicUsize>,
        _requests: Arc<Mutex<Vec<String>>>,
        _handle: tokio::task::JoinHandle<()>,
    }

    type ResponseFuture = std::pin::Pin<
        Box<dyn std::future::Future<Output = (u16, Vec<(&'static str, String)>, Vec<u8>)> + Send>,
    >;
    type HandlerFn = dyn Fn(String) -> ResponseFuture + Send + Sync;

    impl TestServer {
        async fn serve_sync<F>(handler: F) -> Self
        where
            F: Fn(String) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + Sync + 'static,
        {
            Self::serve(Arc::new(move |req| {
                let res = handler(req);
                Box::pin(async move { res })
            }))
            .await
        }

        async fn serve(handler: Arc<HandlerFn>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind free port");
            let addr = listener.local_addr().expect("local addr");
            let connections = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));

            let c = connections.clone();
            let r = requests.clone();
            let h = handler.clone();

            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    c.fetch_add(1, Ordering::SeqCst);
                    let r = r.clone();
                    let h = h.clone();

                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while let Ok(n) = socket.read(&mut chunk).await {
                            if n == 0 {
                                break;
                            }
                            buffer.extend_from_slice(&chunk[..n]);
                            if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let head = String::from_utf8_lossy(&buffer).to_string();
                        r.lock().unwrap().push(head.clone());

                        let (status, headers, body) = h(head).await;
                        if status == 0 {
                            // Drop connection abruptly mid-response.
                            let _ = socket.shutdown().await;
                            return;
                        }

                        let mut resp = format!("HTTP/1.1 {status} OK\r\n");
                        for (k, v) in headers {
                            resp.push_str(&format!("{k}: {v}\r\n"));
                        }
                        resp.push_str(&format!("content-length: {}\r\n", body.len()));
                        resp.push_str("connection: close\r\n\r\n");

                        let mut resp_bytes = resp.into_bytes();
                        resp_bytes.extend_from_slice(&body);
                        let _ = socket.write_all(&resp_bytes).await;
                        let _ = socket.flush().await;
                    });
                }
            });

            Self {
                addr,
                connections,
                _requests: requests,
                _handle: handle,
            }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.addr)
        }

        fn connection_count(&self) -> usize {
            self.connections.load(Ordering::SeqCst)
        }
    }

    /// Realistic HTML article fixture clearing 200 chars for readability.
    fn make_article_html(title: &str, text: &str) -> String {
        format!(
            r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
</head>
<body>
<header><p>Header Chrome</p></header>
<nav><a href="/">Home</a></nav>
<main>
<div id="content">
<h2>{title}</h2>
<p>{text}</p>
<p>This paragraph provides additional continuous prose to clear the two-hundred-character floor required by the readability extraction pass before it will consider an element to be the main block of the document.</p>
</div>
</main>
<footer><p>Footer Chrome</p></footer>
</body>
</html>"#
        )
    }

    /// Real captured responses adapted with target URLs pointing to `web_port`.
    struct Cluster {
        searxng_server: TestServer,
        ddg_server: TestServer,
        mojeek_server: TestServer,
        marginalia_server: TestServer,
        wiki_server: TestServer,
        hn_server: TestServer,
        keyed_server: TestServer,
        _web_server: TestServer,
    }

    impl Cluster {
        async fn start() -> Self {
            let web_server = TestServer::serve_sync(|head| {
                let path = head.split_whitespace().nth(1).unwrap_or("/");
                if path.contains("/shared") {
                    let html = make_article_html(
                        "Shared Title",
                        "The shared article discusses multi-engine rank fusion and canonical URL de-duplication across diverse search providers.",
                    );
                    (200, vec![("content-type", "text/html; charset=utf-8".to_string())], html.into_bytes())
                } else if path.contains("/oversized") {
                    // Larger than body cap
                    let big_body = "x".repeat(1024 * 600);
                    (200, vec![("content-type", "text/html".to_string())], big_body.into_bytes())
                } else if path.contains("/failing") {
                    (500, vec![], b"Internal Server Error".to_vec())
                } else {
                    let html = make_article_html(
                        "Individual Source",
                        "Detailed source prose explaining specific domain topics with ample text to clear the extraction floor.",
                    );
                    (200, vec![("content-type", "text/html; charset=utf-8".to_string())], html.into_bytes())
                }
            })
            .await;

            let web_addr = web_server.addr.to_string();

            // 1. SearXNG: captured JSON shape
            let w1 = web_addr.clone();
            let searxng_server = TestServer::serve_sync(move |_| {
                let json = format!(
                    r#"{{"results":[{{"title":"Shared Title","url":"http://{w1}/shared","content":"SearXNG shared snippet"}},{{"title":"SearXNG Only","url":"http://{w1}/searxng-only","content":"SearXNG exclusive"}}]}}"#
                );
                (200, vec![("content-type", "application/json".to_string())], json.into_bytes())
            })
            .await;

            // 2. DuckDuckGo: captured lite HTML shape
            let w2 = web_addr.clone();
            let ddg_server = TestServer::serve_sync(move |_| {
                let html = format!(
                    r#"<html><body>
<table class="results_links">
  <tr><td class="result-link-td">
    <a href="/l/?uddg=http%3A%2F%2F{w2}%2Fshared%3Futm_source%3Dddg" class='result-link'>Shared Title DDG</a>
  </td></tr>
  <tr><td class='result-snippet'>DDG shared snippet.</td></tr>
  <tr><td class="result-link-td">
    <a href="/l/?uddg=http%3A%2F%2F{w2}%2Fddg-only" class='result-link'>DDG Only Title</a>
  </td></tr>
  <tr><td class='result-snippet'>DDG exclusive snippet.</td></tr>
</table>
</body></html>"#
                );
                (200, vec![("content-type", "text/html".to_string())], html.into_bytes())
            })
            .await;

            // 3. Mojeek: captured results-standard markup shape
            let w3 = web_addr.clone();
            let mojeek_server = TestServer::serve_sync(move |_| {
                let html = format!(
                    r#"<html><body>
  <div class="results">
    <ul class="results-standard">
      <li>
        <h2><a class="ob" href="http://{w3}/mojeek-only" title="Mojeek Title">Mojeek Title</a></h2>
        <p class="s">Mojeek exclusive snippet.</p>
      </li>
    </ul>
  </div>
</body></html>"#
                );
                (
                    200,
                    vec![("content-type", "text/html".to_string())],
                    html.into_bytes(),
                )
            })
            .await;

            // 4. Marginalia: captured HTML shape
            let w4 = web_addr.clone();
            let marginalia_server = TestServer::serve_sync(move |_| {
                let html = format!(
                    r#"<!doctype html>
<html><body>
<div class="flex flex-col grow">
    <div class="flex grow justify-between items-start">
        <div class="flex-1">
            <h2 class="text-md sm:text-xl text-green-800 dark:text-green-200 font-serif mr-4 break-words hyphens-auto">
                <a href="http://{w4}/marginalia-only" rel="noopener noreferrer" dir="auto">Marginalia Title</a>
            </h2>
        </div>
    </div>
</div>
<div class="overflow-auto flex-1">
<p class="mt-2 text-sm text-black dark:text-white leading-relaxed break-words" dir="auto">
    Marginalia exclusive snippet.
</p>
</div>
</body></html>"#
                );
                (200, vec![("content-type", "text/html".to_string())], html.into_bytes())
            })
            .await;

            // 5. Wikipedia: MediaWiki API JSON shape
            let wiki_server = TestServer::serve_sync(|head| {
                let path = head.split_whitespace().nth(1).unwrap_or("/");
                if path.contains("/wiki/") {
                    let html = make_article_html(
                        "Wikipedia Article",
                        "Wikipedia article text explaining encyclopedic knowledge with sufficient length to pass readability.",
                    );
                    (200, vec![("content-type", "text/html; charset=utf-8".to_string())], html.into_bytes())
                } else {
                    let json = r#"{"batchcomplete":"","query":{"search":[{"ns":0,"title":"Wikipedia_Article","pageid":123,"size":1000,"wordcount":100,"snippet":"Wikipedia lead snippet","timestamp":"2026-09-18T17:06:40Z"}]}}"#;
                    (200, vec![("content-type", "application/json".to_string())], json.as_bytes().to_vec())
                }
            })
            .await;

            // 6. Hacker News: Algolia JSON shape
            let w6 = web_addr.clone();
            let hn_server = TestServer::serve_sync(move |_| {
                let json = format!(
                    r#"{{"hits":[{{"author":"alice","created_at":"2026-01-01T00:00:00Z","objectID":"123","points":100,"title":"HN Title","url":"http://{w6}/hn-only"}}]}}"#
                );
                (200, vec![("content-type", "application/json".to_string())], json.into_bytes())
            })
            .await;

            // 7. Keyed (Brave): documented JSON shape
            let w7 = web_addr.clone();
            let keyed_server = TestServer::serve_sync(move |_| {
                let json = format!(
                    r#"{{"web":{{"results":[{{"title":"Brave Title","url":"http://{w7}/brave-only","description":"Brave snippet"}}]}}}}"#
                );
                (200, vec![("content-type", "application/json".to_string())], json.into_bytes())
            })
            .await;

            Self {
                searxng_server,
                ddg_server,
                mojeek_server,
                marginalia_server,
                wiki_server,
                hn_server,
                keyed_server,
                _web_server: web_server,
            }
        }

        fn keyless_backends(&self) -> Vec<Arc<dyn SearchBackend>> {
            vec![
                Arc::new(SearxngBackend::new(self.searxng_server.base_url())),
                Arc::new(DuckDuckGoBackend::with_endpoint(
                    self.ddg_server.url("/lite/"),
                )),
                Arc::new(MojeekBackend::with_endpoint(
                    self.mojeek_server.url("/search"),
                )),
                Arc::new(MarginaliaBackend::with_endpoint(
                    self.marginalia_server.url("/search"),
                )),
                Arc::new(WikipediaBackend::with_endpoint(
                    self.wiki_server.url("/w/api.php"),
                )),
                Arc::new(HnAlgoliaBackend::with_endpoint(
                    self.hn_server.url("/api/v1/search"),
                )),
            ]
        }

        fn keyed_backend(&self) -> Arc<dyn SearchBackend> {
            Arc::new(BraveBackend::with_endpoint(
                Secret::new("test-key"),
                self.keyed_server.url("/res/v1/web/search"),
            ))
        }
    }

    #[tokio::test]
    async fn six_keyless_backends_are_queried_in_parallel_before_any_completes() {
        // Property: fan-out queries all six free backends in parallel.
        // A barrier of size 6 enforces that all 6 backend connections are active and waiting
        // before any single stub sends a response.
        let barrier = Arc::new(tokio::sync::Barrier::new(6));

        let search_connections = Arc::new(AtomicUsize::new(0));
        let make_handler = |_name: &'static str, response_body: Vec<u8>, is_json: bool| {
            let b = barrier.clone();
            let sc = search_connections.clone();
            Arc::new(move |req: String| {
                let b = b.clone();
                let sc = sc.clone();
                let body = response_body.clone();
                Box::pin(async move {
                    // Only wait on the barrier for search queries, not downstream extraction fetches.
                    if req.contains("GET /search")
                        || req.contains("GET /lite")
                        || req.contains("POST /lite")
                        || req.contains("action=query")
                        || req.contains("/api/v1/search")
                    {
                        sc.fetch_add(1, Ordering::SeqCst);
                        // All 6 backends must reach this barrier concurrently.
                        let wait_res = tokio::time::timeout(Duration::from_secs(5), b.wait()).await;
                        assert!(
                            wait_res.is_ok(),
                            "timed out waiting for all 6 backends to connect in parallel"
                        );
                    }
                    let ct = if is_json {
                        "application/json"
                    } else {
                        "text/html"
                    };
                    (200u16, vec![("content-type", ct.to_string())], body)
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<
                                    Output = (u16, Vec<(&'static str, String)>, Vec<u8>),
                                > + Send,
                        >,
                    >
            })
        };

        let s1 = TestServer::serve(make_handler(
            "searxng",
            b"{\"results\":[{\"title\":\"T1\",\"url\":\"https://1.test/\",\"content\":\"s1\"}]}"
                .to_vec(),
            true,
        ))
        .await;
        let s2 = TestServer::serve(make_handler(
            "ddg",
            b"<html><body><table class='results_links'><tr><td class='result-link-td'><a href='/l/?uddg=https%3A%2F%2F2.test%2F' class='result-link'>T2</a></td></tr><tr><td class='result-snippet'>s2</td></tr></table></body></html>".to_vec(),
            false,
        )).await;
        let s3 = TestServer::serve(make_handler(
            "mojeek",
            b"<html><body><div class='results'><ul class='results-standard'><li><h2><a class='ob' href='https://3.test/'>T3</a></h2><p class='s'>s3</p></li></ul></div></body></html>".to_vec(),
            false,
        )).await;
        let s4 = TestServer::serve(make_handler(
            "marginalia",
            b"<!doctype html><html><body><div class='flex flex-col grow'><h2 class='font-serif mr-4 break-words hyphens-auto'><a href='https://4.test/' dir='auto'>T4</a></h2></div><p class='break-words' dir='auto'>s4</p></body></html>".to_vec(),
            false,
        )).await;
        let s5 = TestServer::serve(make_handler(
            "wikipedia",
            b"{\"batchcomplete\":\"\",\"query\":{\"search\":[{\"ns\":0,\"title\":\"T5\",\"snippet\":\"s5\"}]}}".to_vec(),
            true,
        )).await;
        let s6 = TestServer::serve(make_handler(
            "hn",
            b"{\"hits\":[{\"title\":\"T6\",\"url\":\"https://6.test/\"}]}".to_vec(),
            true,
        ))
        .await;

        let backends: Vec<Arc<dyn SearchBackend>> = vec![
            Arc::new(SearxngBackend::new(s1.base_url())),
            Arc::new(DuckDuckGoBackend::with_endpoint(s2.url("/lite/"))),
            Arc::new(MojeekBackend::with_endpoint(s3.url("/search"))),
            Arc::new(MarginaliaBackend::with_endpoint(s4.url("/search"))),
            Arc::new(WikipediaBackend::with_endpoint(s5.url("/w/api.php"))),
            Arc::new(HnAlgoliaBackend::with_endpoint(s6.url("/api/v1/search"))),
        ];

        let client = reqwest::Client::new();
        let fetcher = Arc::new(HttpFetcher::new(client.clone()));
        let report = research(
            &backends,
            &client,
            fetcher,
            &ResearchRequest::new("rust parallel"),
        )
        .await;

        assert_eq!(report.backends.len(), 6);
        assert!(report.backends.iter().all(|b| b.is_answered()));
        assert_eq!(
            search_connections.load(Ordering::SeqCst),
            6,
            "all 6 search backends must have connected and waited at the barrier in parallel"
        );
    }

    #[tokio::test]
    async fn a_url_shared_by_two_backends_collapses_to_one_source_at_fused_rank() {
        let cluster = Cluster::start().await;
        let client = reqwest::Client::new();
        let fetcher = Arc::new(HttpFetcher::new(client.clone()));

        let backends = cluster.keyless_backends();
        let report = research(
            &backends,
            &client,
            fetcher,
            &ResearchRequest::new("test query"),
        )
        .await;

        let shared_count = report
            .sources
            .iter()
            .filter(|c| c.url.contains("/shared"))
            .count();
        assert_eq!(
            shared_count, 1,
            "canonicalisation must collapse duplicate URLs across backends into one source"
        );

        // The shared URL had agreement from 2 engines (SearXNG + DDG), so it should hold rank 0.
        let first = &report.sources[0];
        assert!(first.url.contains("/shared"));
        assert_eq!(first.rank, 0);
    }

    #[tokio::test]
    async fn exactly_max_sources_extractions_are_performed_in_rrf_order() {
        let cluster = Cluster::start().await;
        let client = reqwest::Client::new();
        let fetcher = Arc::new(HttpFetcher::new(client.clone()));

        let backends = cluster.keyless_backends();
        let req = ResearchRequest::new("test query").with_max_sources(3);
        let report = research(&backends, &client, fetcher, &req).await;

        assert_eq!(report.sources.len(), 3);
        for (idx, citation) in report.sources.iter().enumerate() {
            assert_eq!(
                citation.rank, idx,
                "citations must retain their RRF rank order"
            );
        }
    }

    #[tokio::test]
    async fn citations_carry_title_and_url_and_rung_names_the_extraction_pass() {
        let cluster = Cluster::start().await;
        let client = reqwest::Client::new();
        let fetcher = Arc::new(HttpFetcher::new(client.clone()));

        let backends = cluster.keyless_backends();
        let report = research(
            &backends,
            &client,
            fetcher,
            &ResearchRequest::new("test query"),
        )
        .await;

        let shared = report
            .sources
            .iter()
            .find(|c| c.url.contains("/shared"))
            .expect("shared source must be present");

        assert_eq!(shared.title.as_deref(), Some("Shared Title"));
        assert!(shared.url.contains("/shared"));
        assert_eq!(shared.rung, Rung::Readability);
        assert!(
            shared.snippet.contains("multi-engine rank fusion"),
            "snippet should carry extracted text: {}",
            shared.snippet
        );
    }

    #[tokio::test]
    async fn a_keyed_backend_sees_zero_requests_and_paid_calls_is_zero() {
        let cluster = Cluster::start().await;
        let client = reqwest::Client::new();
        let fetcher = Arc::new(HttpFetcher::new(client.clone()));

        let mut backends = cluster.keyless_backends();
        backends.push(cluster.keyed_backend());

        // Default ResearchTask (allow_paid = false)
        let report = research(
            &backends,
            &client,
            fetcher,
            &ResearchRequest::new("test query"),
        )
        .await;

        assert_eq!(
            report.paid_calls, 0,
            "zero paid API calls must hold structurally"
        );
        assert_eq!(
            cluster.keyed_server.connection_count(),
            0,
            "keyed stub must see zero requests when keyless research is requested"
        );
    }

    #[tokio::test]
    async fn one_failing_backend_does_not_sink_the_report_and_is_named_in_failures() {
        let cluster = Cluster::start().await;
        let client = reqwest::Client::new();
        let fetcher = Arc::new(HttpFetcher::new(client.clone()));

        // Create a failing stub that closes connection immediately
        let dead_server = TestServer::serve_sync(|_| (0, vec![], vec![])).await;
        let dead_backend = Arc::new(MojeekBackend::with_endpoint(dead_server.url("/search")));

        let backends: Vec<Arc<dyn SearchBackend>> = vec![
            Arc::new(SearxngBackend::new(cluster.searxng_server.base_url())),
            Arc::new(DuckDuckGoBackend::with_endpoint(
                cluster.ddg_server.url("/lite/"),
            )),
            dead_backend,
            Arc::new(MarginaliaBackend::with_endpoint(
                cluster.marginalia_server.url("/search"),
            )),
            Arc::new(WikipediaBackend::with_endpoint(
                cluster.wiki_server.url("/w/api.php"),
            )),
            Arc::new(HnAlgoliaBackend::with_endpoint(
                cluster.hn_server.url("/api/v1/search"),
            )),
        ];

        let report = research(
            &backends,
            &client,
            fetcher,
            &ResearchRequest::new("test query"),
        )
        .await;

        assert_eq!(report.backends.len(), 6);
        let failures: Vec<&BackendOutcome> =
            report.backends.iter().filter(|b| b.is_failed()).collect();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].backend(), "mojeek");
        assert!(failures[0].reason().is_some());

        let answered: Vec<&BackendOutcome> =
            report.backends.iter().filter(|b| b.is_answered()).collect();
        assert_eq!(answered.len(), 5);
        assert!(
            !report.sources.is_empty(),
            "working backends must still produce citations"
        );
    }

    #[tokio::test]
    async fn a_page_over_the_body_cap_is_skipped_rather_than_cited_with_truncated_body() {
        let web_server = TestServer::serve_sync(|head| {
            let path = head.split_whitespace().nth(1).unwrap_or("/");
            if path.contains("/oversized") {
                let big_body = "A".repeat(10_000);
                (
                    200,
                    vec![("content-type", "text/html".to_string())],
                    big_body.into_bytes(),
                )
            } else {
                let html =
                    make_article_html("Small Page", "This is a normal sized page for testing.");
                (
                    200,
                    vec![("content-type", "text/html; charset=utf-8".to_string())],
                    html.into_bytes(),
                )
            }
        })
        .await;

        let w = web_server.addr.to_string();
        let searxng_server = TestServer::serve_sync(move |_| {
            let json = format!(
                r#"{{"results":[{{"title":"Big Page","url":"http://{w}/oversized","content":"big"}},{{"title":"Small Page","url":"http://{w}/normal","content":"small"}}]}}"#
            );
            (200, vec![("content-type", "application/json".to_string())], json.into_bytes())
        })
        .await;

        let client = reqwest::Client::new();
        // Set body cap to 2000 bytes: small page is ~600 bytes (< 2000), big page is 10,000 bytes (> 2000).
        let fetcher = Arc::new(HttpFetcher::new(client.clone()).with_max_body_bytes(2000));
        let backends: Vec<Arc<dyn SearchBackend>> =
            vec![Arc::new(SearxngBackend::new(searxng_server.base_url()))];

        let report = research(&backends, &client, fetcher, &ResearchRequest::new("test")).await;

        let big_citation = report
            .sources
            .iter()
            .find(|c| c.url.contains("/oversized"))
            .expect("big page citation must exist");

        assert_eq!(
            big_citation.snippet, "",
            "a page over the body cap must be skipped (empty snippet), not cited with a truncated body"
        );

        let small_citation = report
            .sources
            .iter()
            .find(|c| c.url.contains("/normal"))
            .expect("small page citation must exist");
        assert!(
            !small_citation.snippet.is_empty(),
            "small page within cap must be extracted normally"
        );
    }

    #[tokio::test]
    async fn a_report_that_finds_nothing_is_ok_with_empty_sources() {
        let empty_searx = TestServer::serve_sync(|_| {
            (
                200,
                vec![("content-type", "application/json".to_string())],
                b"{\"results\":[]}".to_vec(),
            )
        })
        .await;

        let client = reqwest::Client::new();
        let fetcher = Arc::new(HttpFetcher::new(client.clone()));
        let backends: Vec<Arc<dyn SearchBackend>> =
            vec![Arc::new(SearxngBackend::new(empty_searx.base_url()))];

        let report = research(
            &backends,
            &client,
            fetcher,
            &ResearchRequest::new("nonexistent query"),
        )
        .await;

        assert!(report.sources.is_empty());
        assert_eq!(report.backends.len(), 1);
        assert!(report.backends[0].is_answered());
        assert_eq!(report.paid_calls, 0);
    }

    #[tokio::test]
    #[ignore]
    async fn research_live_against_real_keyless_backends_over_the_internet() {
        let client = reqwest::Client::builder()
            .user_agent(crate::backends::USER_AGENT)
            .timeout(Duration::from_secs(15))
            .build()
            .expect("client");

        let backends: Vec<Arc<dyn SearchBackend>> = vec![
            Arc::new(WikipediaBackend::new()),
            Arc::new(DuckDuckGoBackend::new()),
            Arc::new(MojeekBackend::new()),
            Arc::new(MarginaliaBackend::new()),
            Arc::new(HnAlgoliaBackend::new()),
        ];

        let fetcher = Arc::new(HttpFetcher::new(client.clone()));
        let report = research(
            &backends,
            &client,
            fetcher,
            &ResearchRequest::new("rust programming language").with_max_sources(3),
        )
        .await;

        eprintln!(
            "Live research report: query='{}', answered={}, failed={}, sources={}, paid_calls={}",
            report.query,
            report.backends.iter().filter(|b| b.is_answered()).count(),
            report.backends.iter().filter(|b| b.is_failed()).count(),
            report.sources.len(),
            report.paid_calls
        );
        for source in &report.sources {
            eprintln!(
                "  [{}] {} ({})",
                source.rank,
                source.url,
                source.rung.name()
            );
        }

        assert_eq!(report.paid_calls, 0);
    }
}
