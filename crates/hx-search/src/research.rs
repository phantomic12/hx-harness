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
}

#[async_trait]
impl Fetcher for HttpFetcher {
    async fn fetch(&self, url: &str) -> Result<Option<FetchedPage>, SearchError> {
        if let Some(cache) = &self.cache {
            let outcome = match tokio::time::timeout(self.timeout, cache.fetch(&self.client, url)).await {
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
                        reason: format!("reading body timed out after {:.1}s", self.timeout.as_secs_f64()),
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
        let search_report = crate::aggregate::fanout(
            &active_backends,
            &self.client,
            &query,
            self.timeout,
        )
        .await;

        let mut backends = Vec::with_capacity(search_report.answered.len() + search_report.failures.len());
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
                            let title = extracted.title.or_else(|| {
                                if fused.title.is_empty() {
                                    None
                                } else {
                                    Some(fused.title)
                                }
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
                                title: if fused.title.is_empty() { None } else { Some(fused.title) },
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
                            title: if fused.title.is_empty() { None } else { Some(fused.title) },
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
                            title: if fused.title.is_empty() { None } else { Some(fused.title) },
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
