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
//! ## How the browser pool fits
//!
//! `hx-search` depends on `hx-browser` and uses it for one thing: [`BrowserFetcher`], which
//! fetches a page through the pool's ladder. It has two shapes, and the difference is the whole
//! `Auto`/`Browser` distinction: `Auto` takes the plain HTTP rung first and escalates to real
//! Chromium only when the site **refused**, while `Browser` puts no plain rung in front of the
//! browser at all — see [`BrowserFetcher::browser_first`] and [`FetchMode`]. The pool is the layer
//! *for* the pages a plain fetch cannot read (full JavaScript execution, challenge solving), and the
//! dependency is one-way and deliberate: search does not own the pool, it consumes it.
//!
//! The bulk of extraction still happens through the in-crate [`Fetcher`] abstraction; [`HttpFetcher`]
//! is the plain path, and [`BrowserFetcher`] is a [`Fetcher`] the same research loop can be handed.
//! The research path's **fetch step** — [`select_fetcher`] and [`research_with_fetch_mode`] — is what
//! makes that a running decision rather than a manual construction: it chooses `BrowserFetcher` for the
//! `Auto` or `Browser` modes and `HttpFetcher` otherwise, honours browser availability with a fallback that
//! cannot lie (see [`select_fetcher`]), and records the choice for tests and honest reporting.
//! The chromium tests that drive real Chromium run **locally** — the browser is installed on the developer
//! host (`/usr/lib/chromium/chromium`) and not on the remote build host — and are `#[ignore]`d so
//! they never run in the offload gate. `tests/browser_rung_canary.rs` is the live one: it proves the
//! browser rung reads a page whose text only exists after JavaScript runs, and that the plain path
//! does **not**.
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
use crate::cache::{
    admit_initial, admit_redirect_from, cache_key, fnv1a, hop_client, is_followable_status,
    CacheOutcome, UrlCache, MAX_REDIRECTS,
};
use crate::extract::{FetchedPage, Ladder, Rung};
use crate::types::{FusedResult, SearchQuery};
use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use hx_browser::profile::PoolRoot;
use hx_browser::{Admission, BrowserPool, Ladder as RungLadder};
use hx_core::ids::SessionId;
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
///
/// Both paths admit every target before connecting: the cache-backed path through
/// [`UrlCache::fetch`], the uncached path through the same admission helpers directly
/// (initial admission plus DNS pinning, `redirect::Policy::none`, and per-hop re-admission
/// of every redirect). A fetcher built with the default [`Admission`] refuses loopback,
/// private, link-local and metadata targets; [`HttpFetcher::with_admission`] is the named
/// hatch that widens it, mirroring [`BrowserFetcher::with_admission`].
pub struct HttpFetcher {
    timeout: Duration,
    max_body_bytes: usize,
    cache: Option<Arc<UrlCache>>,
    admission: Admission,
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
    /// A plain fetcher with the default timeout, body cap, no cache, and the default
    /// ([`Admission::PublicInternet`]) policy.
    ///
    /// `client` is accepted so every construction site — [`select_fetcher`], the tests —
    /// keeps sharing the daemon's connection pool for the *backend* searches; the fetcher
    /// itself never sends through it. Each admitted hop builds its own `Policy::none`
    /// client (pinned to the DNS answers admission approved for hostnames), because a
    /// shared client follows redirects on its own and the next URL would be connected to
    /// before admission could judge it.
    pub fn new(_client: reqwest::Client) -> Self {
        Self {
            timeout: DEFAULT_FETCH_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            cache: None,
            admission: Admission::default(),
        }
    }

    /// The same **named** admission hatch [`BrowserFetcher::with_admission`] documents, so a
    /// caller that widens the browser fetch can widen this one identically.
    pub fn with_admission(mut self, admission: Admission) -> Self {
        self.admission = admission;
        self
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
            let outcome = match tokio::time::timeout(self.timeout, cache.fetch(url, self.admission))
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
                // The cache aborted an over-cap body mid-stream without assembling it: skip.
                CacheOutcome::TooLarge => Ok(None),
                CacheOutcome::Miss304 => Ok(None),
            }
        } else {
            // The uncached production path admits exactly like the cache path: the initial
            // target is admitted and DNS-pinned before anything connects, every hop goes
            // through a `Policy::none` client so `reqwest` cannot follow a redirect on its
            // own, and each redirect destination is re-admitted before the next send. A
            // public-looking result URL that points at loopback/private/metadata space — or
            // redirects there — is refused rather than fetched.
            let mut current = admit_initial(self.admission, url).await?;
            let mut hops = 0usize;
            loop {
                let hop = hop_client(&current)?;
                let request = hop
                    .get(current.target().request_url())
                    .header(reqwest::header::USER_AGENT, crate::backends::USER_AGENT);

                let response = match tokio::time::timeout(self.timeout, request.send()).await {
                    Ok(Ok(res)) => res,
                    // `SearchError::Transport` would echo the request URL, and a URL can carry a token in its
                    // query string. `without_url` drops the URL so a `?token=`/`key=` credential cannot reach
                    // an error the research report (and so the model) reads.
                    Ok(Err(err)) => return Err(transport_error(err)),
                    Err(_) => {
                        return Err(SearchError::TransportRedacted {
                            reason: format!(
                                "fetch timed out after {:.1}s",
                                self.timeout.as_secs_f64()
                            ),
                        });
                    }
                };

                let status = response.status();
                if is_followable_status(status) {
                    if hops >= MAX_REDIRECTS {
                        return Err(SearchError::Http {
                            status: status.as_u16(),
                        });
                    }
                    let location = response.headers().get(reqwest::header::LOCATION).ok_or(
                        SearchError::Http {
                            status: status.as_u16(),
                        },
                    )?;
                    let location = location
                        .to_str()
                        .map_err(|_| SearchError::Http {
                            status: status.as_u16(),
                        })?
                        .to_string();
                    // Admitted before the next send, so nothing connects to an unadmitted hop.
                    current = admit_redirect_from(self.admission, &current, &location).await?;
                    hops += 1;
                    continue;
                }

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

                // The same bounded reader the cache uses: `Content-Length` above is only a fast
                // path — a missing or dishonest header must not buy an unbounded allocation — so the
                // body is still consumed chunk by chunk and aborted past the cap before any `String`
                // is built.
                let body = match tokio::time::timeout(
                    self.timeout,
                    crate::cache::read_bounded_text(response, self.max_body_bytes),
                )
                .await
                {
                    Ok(Ok(Some(body))) => body,
                    Ok(Ok(None)) => return Ok(None),
                    // Same as above: the body-read error's `Display` echoes the request URL, which can carry a
                    // `?token=`/`key=` credential. Strip the URL so it cannot reach an error the model reads.
                    Ok(Err(err)) => return Err(transport_error(err)),
                    Err(_) => {
                        return Err(SearchError::TransportRedacted {
                            reason: format!(
                                "reading body timed out after {:.1}s",
                                self.timeout.as_secs_f64()
                            ),
                        });
                    }
                };

                return Ok(Some(FetchedPage::new(url, content_type.as_deref(), body)));
            }
        }
    }
}

/// Convert a `reqwest::Error` to a credential-free transport error.
///
/// `reqwest::Error`'s `Display` (and `Debug`) append the request URL, and a URL can carry a token in
/// its query string (`?token=`, `?key=`, `?apikey=`). `without_url` drops the URL, so such a
/// credential cannot reach an error the research report — and so the model — reads. This is the plain
/// [`HttpFetcher`]'s answer to the same problem the browser rungs solve with `transport_reason`.
fn transport_error(err: reqwest::Error) -> SearchError {
    SearchError::TransportRedacted {
        reason: err.without_url().to_string(),
    }
}

/// A `Fetcher` backed by the browser pool — the caller the interactive Chromium rung exists for.
///
/// ## Why this is the caller
///
/// The plain [`HttpFetcher`] reads what a `GET` returns. The pages the research task meets that
/// a plain fetch cannot read — a JS-rendered page, or one served only after a client-side
/// challenge — need a browser. This is that caller: its [`fetch`](Fetcher::fetch) runs the URL
/// through a [`BrowserPool`], whose ladder tries the plain rung first and escalates to real Chromium
/// only when the site refuses.
///
/// Every browser fetch runs in its **own session's profile** (see `hx-browser`'s `profile`
/// for why that is a security boundary, not housekeeping): each URL is its own one-shot session, so a
/// page a browser renders for one URL can never read another URL task's cookies. The session id is made
/// from the URL's redacted form — a token in the query cannot reach a directory name.
///
/// ## Two shapes, because `Auto` and `Browser` mean different things
///
/// [`BrowserFetcher::new`] is the **`Auto` shape**: the pool's ladder is the cheap `HttpRung` first,
/// escalating to real Chromium only when the site *refused*. That is the ladder's cost rule, and it
/// is why a page a plain `GET` already answered never spends a browser launch.
///
/// [`BrowserFetcher::browser_first`] is the **`Browser` shape**: the pool's ladder holds the
/// `ChromiumRung` and nothing else, so every page is read by a real browser. It exists because
/// `FetchMode::Browser`'s promise is exactly that — *a browser even for a page a plain fetch could
/// read* — and the escalating ladder cannot keep it: a JavaScript-rendered page answers `200` with
/// its text injected by script, a `200` ends the climb at the cheap rung, and no browser is ever
/// launched. So `Auto` does not reach a browser for such a page and `Browser` is how a caller asks
/// for one. `crates/hx-search/tests/browser_rung_canary.rs` is the live proof of the difference: the
/// same page yields the JS-inserted text through a browser-first fetcher and does not yield it
/// through the plain path.
///
/// ## The security properties survive the wiring
///
/// The caller does **not** weaken anything the rung holds:
/// - **Admission still runs.** A [`BrowserPool`] admits every target before any rung runs; a caller
///   cannot pass an unchecked target. (In fact the pool refuses loopback — including a local test
///   stub — so the caller's decisions are driven with a browser-launching double, and the live
///   canary widens admission with the **named** [`BrowserFetcher::with_admission`] hatch rather than
///   by loosening a default.)
/// - **A refusal is a refusal.** The pool's [`FetchReport`] carries a [`Disposition`]: a wall, a
///   challenge or an admission block. This fetcher turns one into [`SearchError::Refused`] — never an
///   `Ok(Some(""))`, which would look to extraction exactly like a page the origin served.
/// - **The body cap applies here too.** The rung's own cap refuses an oversized body [`Disposition::Stop`];
///   that reaches this fetcher as an error and surfaces as a refusal sentence, never as a truncated body.
/// - **No browser leaks.** The rung already reaps its child on every exit path. The pool runs each
///   fetch under its own timeout, and this fetcher adds its own `tokio::time::timeout` around the
///   whole call — both bounded, so a fetch that times out (or is dropped) cannot leave Chromium behind.
///
/// ## Where the chromium tests run
///
/// A real browser is at `/usr/lib/chromium/chromium` on the **developer host** (bigwhite) and not on
/// the build host (garlic-clove), so any test of this fetcher that would touch the rung runs
/// **locally**. The server-side tests below therefore drive the *decision* with a browser-launching
/// double and serve all pages from a local stub — no test depends on a third-party site — and the
/// live run (real Chromium end to end, both rungs, against a local server whose page is filled in by
/// JavaScript) is `crates/hx-search/tests/browser_rung_canary.rs`, `#[ignore]`d for the local host.
pub struct BrowserFetcher {
    /// The pool's profile root, kept so a shape change (`with_admission`) can rebuild the ladder
    /// rather than leaving the rungs pointed at a policy the pool no longer holds.
    root: PoolRoot,
    /// The policy the pool **and** every rung were built on.
    admission: Admission,
    /// Whether the ladder is browser-only (`FetchMode::Browser`) or starts at the cheap rung (`Auto`).
    browser_first: bool,
    pool: BrowserPool,
    timeout: Duration,
    max_body_bytes: usize,
}

impl std::fmt::Debug for BrowserFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserFetcher")
            .field("pool", &self.pool)
            .field("browser_first", &self.browser_first)
            .field("timeout", &self.timeout)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish()
    }
}

impl BrowserFetcher {
    /// The `Auto` shape: a browser-backed fetcher over `root` (the pool's profile root) with the
    /// default cap, escalating from the plain rung to Chromium only on a refusal.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Result<Self, std::io::Error> {
        Self::assemble(root, Admission::default(), false)
    }

    /// The `Browser` shape: a real Chromium for **every** page, with no plain rung in front of it.
    ///
    /// This is what [`FetchMode::Browser`] selects. A caller that builds it directly is opting into
    /// a browser launch per fetched page, which is the cost the mode documents.
    pub fn browser_first(root: impl Into<std::path::PathBuf>) -> Result<Self, std::io::Error> {
        Self::assemble(root, Admission::default(), true)
    }

    /// Admit loopback and private targets as well, rebuilding the pool's ladder on the same policy.
    ///
    /// The same **named** escape hatch [`BrowserPool::with_admission`] documents, one layer up: the
    /// hermetic suite serves its pages on `127.0.0.1`, which the default policy refuses. The rungs
    /// are rebuilt with the pool rather than left at the old policy, because the two admissions are
    /// independent (`BrowserPool::fetch` admits the target; a rung admits every *intercepted* request
    /// a loaded page makes) and a pool that admits a host its rung then refuses would be a fetcher
    /// that silently drops a page's subresources.
    pub fn with_admission(mut self, admission: Admission) -> Result<Self, std::io::Error> {
        let pool = Self::build_pool(&self.root, admission, self.browser_first)?;
        self.admission = admission;
        self.pool = pool;
        Ok(self)
    }

    /// The pool, for a test that wants to see which rung answered.
    pub fn pool(&self) -> &BrowserPool {
        &self.pool
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// A fetcher over a caller-supplied rung, for the hermetic tests.
    ///
    /// Same shape as [`BrowserFetcher::new`] with a scripted rung in place of the real ladder, so a
    /// test can drive the caller's decisions (caps, refusals, timeouts) without real Chromium.
    #[cfg(test)]
    pub(crate) fn over_scripted_rung(
        root: PoolRoot,
        rung: Arc<dyn hx_browser::rung::Fetcher>,
        admission: Admission,
    ) -> Self {
        let pool =
            BrowserPool::new(root.clone(), RungLadder::new(vec![rung])).with_admission(admission);
        Self {
            root,
            admission,
            browser_first: false,
            pool,
            timeout: DEFAULT_FETCH_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    fn assemble(
        root: impl Into<std::path::PathBuf>,
        admission: Admission,
        browser_first: bool,
    ) -> Result<Self, std::io::Error> {
        let root = PoolRoot::new(root).map_err(|err| std::io::Error::other(err.to_string()))?;
        let pool = Self::build_pool(&root, admission, browser_first)?;
        Ok(Self {
            root,
            admission,
            browser_first,
            pool,
            timeout: DEFAULT_FETCH_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        })
    }

    /// The pool's ladder, over **real** rungs.
    ///
    /// One place builds it, so `new`, `browser_first` and `with_admission` cannot drift into three
    /// different ladders — which is what a second construction site would do to the one property
    /// that separates `Auto` from `Browser`.
    fn build_pool(
        root: &PoolRoot,
        admission: Admission,
        browser_first: bool,
    ) -> Result<BrowserPool, std::io::Error> {
        let chromium = Arc::new(
            hx_browser::ChromiumRung::with_admission(admission)
                .map_err(|_| std::io::Error::other("could not build the Chromium rung"))?,
        );

        let ladder = if browser_first {
            RungLadder::new(vec![chromium])
        } else {
            let http = Arc::new(
                hx_browser::HttpRung::with_admission(admission)
                    .map_err(|_| std::io::Error::other("could not build the HTTP rung"))?,
            );
            RungLadder::new(vec![http, chromium])
        };

        Ok(BrowserPool::new(root.clone(), ladder).with_admission(admission))
    }
}

#[async_trait]
impl Fetcher for BrowserFetcher {
    async fn fetch(&self, url: &str) -> Result<Option<FetchedPage>, SearchError> {
        // The session id is a hash of the URL, *not* the URL: a URL (or a token in its query)
        // must not become a directory name. Each URL is its own one-shot session, so a page a browser
        // renders for one URL can never read another URL task's cookies.
        let session = SessionId::from_raw(format!("browser_{:016x}", fnv1a(url)));
        let report = match tokio::time::timeout(self.timeout, self.pool.fetch(&session, url)).await
        {
            Ok(report) => report,
            Err(_) => {
                return Err(SearchError::Refused {
                    reason: format!("fetch timed out after {:.1}s", self.timeout.as_secs_f64()),
                })
            }
        };

        let page = report.page.ok_or_else(|| SearchError::Refused {
            reason: report
                .stop_reason
                .unwrap_or_else(|| "no rung produced a page".to_string()),
        })?;

        let content_type = page.content_type().to_string();
        if page.body_len() > self.max_body_bytes {
            // Same policy as HttpFetcher: skip an oversized page rather than cite a truncated body.
            return Ok(None);
        }
        Ok(Some(FetchedPage::new(
            url,
            Some(&content_type),
            page.into_body_untrusted(),
        )))
    }
}

/// Which fetcher the research path runs for a target.
///
/// This is the **selection** a running research task makes, and it is the documented cost rule:
/// launching a browser is expensive and observable, so it is never something an ordinary plain fetch
/// quietly becomes. A caller picks one of these modes; the choice is deliberate and recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchMode {
    /// Plain HTTP only. Never launches a browser, no matter what a page needs.
    Http,
    /// Plain HTTP first, escalating to a browser when the cheap rung **refused** the page — a bot
    /// wall, a challenge interstitial, a `403`/`429`/`503`.
    ///
    /// **A page that answers `200` ends the climb.** A JavaScript-rendered page is exactly that
    /// shape: a `200` shell whose text only exists after its own script runs. So this mode does
    /// *not* reach a browser for one, and the earlier version of this sentence — "escalating to a
    /// browser only for a page a plain fetch cannot read (JS-rendered, or behind a bot wall)" —
    /// claimed more than the ladder does; it is corrected here rather than quietly left standing.
    /// The escalation rule is `hx-browser`'s `Ladder`, and it is deliberate: a page a plain `GET`
    /// already answered must not spend a browser launch. [`FetchMode::Browser`] is how a caller asks
    /// for a browser anyway.
    Auto,
    /// Drive a browser even for a page a plain fetch could read. Deliberate and costly; a caller
    /// that selects this is opting into a browser launch per fetched page.
    ///
    /// The fetcher this selects drives a real Chromium **for every page**: it has no plain rung in
    /// front of it ([`BrowserFetcher::browser_first`]), which is the one property that separates it
    /// from [`FetchMode::Auto`]'s escalating ladder.
    Browser,
}

impl FetchMode {
    /// True when this mode may launch a browser at all.
    pub fn may_launch_browser(&self) -> bool {
        !matches!(self, FetchMode::Http)
    }
}

/// Which fetcher a [`FetchSelection`] landed on, so the choice is observable (and testable) rather
/// than merely present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedFetcher {
    /// The plain HTTP path.
    Http,
    /// The browser-backed path (its ladder tries plain HTTP first, then real Chromium).
    Browser,
}

/// The outcome of the research path's fetch step: a ready [`Fetcher`] plus an honest record of
/// which one was chosen and why.
pub struct FetchSelection {
    fetcher: Arc<dyn Fetcher>,
    pub kind: SelectedFetcher,
    pub note: &'static str,
}

impl std::fmt::Debug for FetchSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchSelection")
            .field("kind", &self.kind)
            .field("note", &self.note)
            .finish()
    }
}

impl FetchSelection {
    /// The chosen fetcher, ready to hand to a [`ResearchTask`].
    pub fn fetcher(&self) -> Arc<dyn Fetcher> {
        Arc::clone(&self.fetcher)
    }
}

/// A selection that could not be made — used only when a caller explicitly asked for a browser and
/// none is available, which must fail rather than silently degrade to a fetch it did not intend.
#[derive(Debug)]
pub struct FetchRouteError {
    pub reason: String,
}

impl std::fmt::Display for FetchRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for FetchRouteError {}

/// True when a runnable Chromium binary is installed on **this** host.
///
/// Chromium is at `/usr/lib/chromium/chromium` on the developer host and **not** on the remote
/// build host nor necessarily in a deployment, so the routing below must not assume it exists. This
/// check is the honest gate the fallback rules key off: a browser that is not installed can neither
/// be selected for `Auto` nor fulfil an explicit `Browser` request.
pub fn browser_available() -> bool {
    std::path::Path::new(hx_browser::rungs::chromium::DEFAULT_CHROMIUM_PATH).is_file()
}

/// Where the browser pool keeps its per-session profiles, for [`select_fetcher`]'s `BrowserFetcher`.
///
/// A real research run backs this with a real directory under the daemon's data root; a test supplies
/// a scratch directory (and serves all pages from a local stub, never a third-party site).
pub fn default_pool_root() -> std::path::PathBuf {
    std::env::temp_dir().join("hx-search-browser-pool")
}

/// The research path's **fetch step**: choose the fetcher to run for `mode`.
///
/// ## The rule (and the cost/consent it documents)
///
/// | mode | browser installed? | result | why |
/// |------|-------------------|--------|-----|
/// | `Http` | (irrelevant) | plain `HttpFetcher` | plain fetch never launches a browser. |
/// | `Auto` | yes | escalating `BrowserFetcher` | escalation for pages a plain fetch was **refused** by (a wall, a challenge). |
/// | `Auto` | no | plain `HttpFetcher` | no browser to escalate to; degrading to plain is the honest default — it never returns a page it did not fetch. |
/// | `Browser` | yes | browser-first `BrowserFetcher` | explicit opt-in: a real browser for **every** page, including one a plain fetch could read. |
/// | `Browser` | no | **error** | a caller that explicitly asked for a browser must not silently get a plain fetch; that would be lying about what it fetched. |
///
/// The runtime honesty — a browser that runs but cannot fetch a page is a `Refused`, never an empty
/// body — is enforced by [`BrowserFetcher`] itself (and its rungs), not by this selector.
pub fn select_fetcher(
    client: &reqwest::Client,
    mode: FetchMode,
    pool_root: impl Into<std::path::PathBuf>,
) -> Result<FetchSelection, FetchRouteError> {
    select_fetcher_by(client, mode, pool_root, browser_available)
}

/// The [`select_fetcher`] decision under an injected browser-availability check, so the choice is
/// brittleness-proof in tests rather than depending on which host the test happens to run on.
pub(crate) fn select_fetcher_by(
    client: &reqwest::Client,
    mode: FetchMode,
    pool_root: impl Into<std::path::PathBuf>,
    available: impl Fn() -> bool,
) -> Result<FetchSelection, FetchRouteError> {
    match mode {
        FetchMode::Http => Ok(FetchSelection {
            fetcher: Arc::new(HttpFetcher::new(client.clone())),
            kind: SelectedFetcher::Http,
            note: "http: plain fetch policy, no escalation",
        }),
        FetchMode::Auto if available() => {
            let fetcher = BrowserFetcher::new(pool_root).map_err(|err| FetchRouteError {
                reason: format!("could not build the browser fetcher: {err}"),
            })?;
            Ok(FetchSelection {
                fetcher: Arc::new(fetcher),
                kind: SelectedFetcher::Browser,
                note: "auto: browser available, escalating plain-HTTP-then-Chromium",
            })
        }
        FetchMode::Auto => Ok(FetchSelection {
            fetcher: Arc::new(HttpFetcher::new(client.clone())),
            kind: SelectedFetcher::Http,
            note: "auto: no browser on this host, degraded to plain fetch (honest default)",
        }),
        FetchMode::Browser if available() => {
            let fetcher =
                BrowserFetcher::browser_first(pool_root).map_err(|err| FetchRouteError {
                    reason: format!("could not build the browser fetcher: {err}"),
                })?;
            Ok(FetchSelection {
                fetcher: Arc::new(fetcher),
                kind: SelectedFetcher::Browser,
                note: "browser: explicit opt-in, driving Chromium for every page",
            })
        }
        FetchMode::Browser => Err(FetchRouteError {
            reason: format!(
                "browser mode requested but no Chromium is installed at {}",
                hx_browser::rungs::chromium::DEFAULT_CHROMIUM_PATH
            ),
        }),
    }
}

/// Run a research task through the fetch-selection **running path**: choose the fetcher for `mode`,
/// then execute the normal research pipeline over it.
///
/// This is the entry a production caller uses when it wants the research extraction step to select a
/// fetcher — plain HTTP, or browser escalation — rather than construct one by hand. It is deliberately
/// fallible only in the one case that must not be papered over (an explicit `Browser` request with no
/// browser); every other mode returns a report exactly as [`research`] does.
pub async fn research_with_fetch_mode(
    backends: &[Arc<dyn SearchBackend>],
    client: &reqwest::Client,
    mode: FetchMode,
    pool_root: impl Into<std::path::PathBuf>,
    request: &ResearchRequest,
) -> Result<ResearchReport, FetchRouteError> {
    let selection = select_fetcher(client, mode, pool_root)?;
    let task = ResearchTask::new(backends.to_vec(), client.clone(), selection.fetcher);
    Ok(task.run(request).await)
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
mod browser_fetcher_tests {
    use super::*;
    use hx_browser::error::{FetchError, RefusalReason};
    use hx_browser::rung::{FetchRequest, Fetcher as RungFetcher, RungKind, UntrustedPage};
    use hx_browser::Admission;

    /// A browser pool under the named policy whose single rung is a scripted double.
    ///
    /// The production [`BrowserFetcher::new`] ladder uses real rungs and the default (public-only)
    /// admission; this builds the *same* fetcher shape the caller uses, over a scripted rung, so
    /// the caller's decision and its caps can be asserted without touching real Chromium or the network.
    fn fetcher_over(
        root: std::path::PathBuf,
        admission: Admission,
        rung: Arc<dyn RungFetcher>,
        timeout: Duration,
    ) -> BrowserFetcher {
        let pool_root = PoolRoot::new(root).expect("pool root");
        BrowserFetcher::over_scripted_rung(pool_root, rung, admission).with_timeout(timeout)
    }

    /// A rung whose behaviour is dictated per call, panicking when called with no script left so an
    /// unexpected call is a loud failure rather than a silent one.
    struct DictatedRung {
        script: std::sync::Mutex<VecDequeue>,
        calls: std::sync::atomic::AtomicUsize,
    }

    enum Verdict {
        Page(usize),
        Refused(&'static str),
        Hang,
    }

    struct VecDequeue(std::collections::VecDeque<Verdict>);

    impl VecDequeue {
        fn pop(&mut self) -> Verdict {
            self.0
                .pop_front()
                .unwrap_or_else(|| panic!("dictated rung called with no verdict left"))
        }
    }

    impl DictatedRung {
        fn new(script: Vec<Verdict>) -> Arc<Self> {
            Arc::new(Self {
                script: std::sync::Mutex::new(VecDequeue(script.into())),
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl RungFetcher for DictatedRung {
        fn kind(&self) -> RungKind {
            RungKind::Interactive
        }
        fn name(&self) -> &str {
            "dictated"
        }
        async fn fetch(&self, request: &FetchRequest) -> Result<UntrustedPage, FetchError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let verdict = self.script.lock().expect("script lock").pop();
            match verdict {
                Verdict::Page(size) => Ok(UntrustedPage::new(
                    request.target.clone(),
                    200,
                    "text/html",
                    RungKind::Interactive,
                    "x".repeat(size),
                )),
                Verdict::Refused(marker) => Err(FetchError::Refused {
                    rung: RungKind::Interactive,
                    reason: RefusalReason::Challenge {
                        marker: marker.to_string(),
                    },
                }),
                Verdict::Hang => std::future::pending::<Result<UntrustedPage, FetchError>>().await,
            }
        }
    }

    fn tmp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hx-browser-fetcher-test-{}", std::process::id()))
    }

    /// A plain page the plain fetch can read — the ordinary case — is fetched through the caller.
    #[tokio::test]
    async fn a_browser_fetcher_returns_an_ordinary_admitted_page() {
        let rung = DictatedRung::new(vec![Verdict::Page(20)]);
        let fetcher = fetcher_over(
            tmp_root(),
            Admission::AllowLocal,
            rung.clone(),
            Duration::from_secs(5),
        );
        // A local stub is loopback; the pool admits it under AllowLocal, and the rung answers.
        let out = fetcher
            .fetch("http://127.0.0.1:9/plain")
            .await
            .expect("a page");
        let page = out.expect("a page, not a skip");
        assert_eq!(page.body, "x".repeat(20));
        assert_eq!(rung.calls(), 1);
    }

    /// Admission still runs: a URL the pool refuses is a refusal, and it is never an empty body.
    #[tokio::test]
    async fn a_browser_fetcher_never_skips_admission_and_a_refusal_is_a_refusal_not_an_empty_body()
    {
        // Default (public-only) admission: a loopback address is refused before any rung runs.
        let rung = DictatedRung::new(vec![Verdict::Page(20)]);
        let fetcher = fetcher_over(
            tmp_root(),
            Admission::PublicInternet,
            rung.clone(),
            Duration::from_secs(5),
        );
        let err = fetcher
            .fetch("http://127.0.0.1:9/plain")
            .await
            .expect_err("refused");
        assert!(matches!(err, SearchError::Refused { .. }), "{err}");
        assert!(
            !matches!(err, SearchError::Parse { .. }),
            "a refusal must not look like a body: {err}"
        );
        assert_eq!(rung.calls(), 0, "no rung may run for a refused target");
    }

    /// A rung refusal surfaces as a refusal, never as an `Ok(Some(""))`.
    #[tokio::test]
    async fn a_browser_fetcher_surfaces_a_refusal_as_a_refusal_not_an_empty_page() {
        let rung = DictatedRung::new(vec![Verdict::Refused("cf-challenge")]);
        let fetcher = fetcher_over(
            tmp_root(),
            Admission::AllowLocal,
            rung.clone(),
            Duration::from_secs(5),
        );
        let err = fetcher
            .fetch("http://127.0.0.1:9/walled")
            .await
            .expect_err("refused");
        assert!(matches!(err, SearchError::Refused { .. }), "{err}");
        assert!(err.to_string().contains("cf-challenge"), "{err}");
        assert_eq!(rung.calls(), 1);
    }

    /// The body cap is enforced by the caller too: an oversized page is skipped, never truncated.
    #[tokio::test]
    async fn a_browser_fetcher_enforces_the_body_cap_at_the_caller() {
        let rung = DictatedRung::new(vec![Verdict::Page(DEFAULT_MAX_BODY_BYTES + 1024)]);
        let mut fetcher = fetcher_over(
            tmp_root(),
            Admission::AllowLocal,
            rung.clone(),
            Duration::from_secs(5),
        );
        fetcher.max_body_bytes = DEFAULT_MAX_BODY_BYTES;
        let out = fetcher
            .fetch("http://127.0.0.1:9/big")
            .await
            .expect("a skip, not an error");
        assert!(
            out.is_none(),
            "an oversized page must be skipped, not truncated into a body"
        );
    }

    /// A fetch that never answers times out and surfaces as a refusal, and makes no rung leak.
    #[tokio::test]
    async fn a_browser_fetcher_times_out_instead_of_hanging_or_returning_empty() {
        let rung = DictatedRung::new(vec![Verdict::Hang]);
        let fetcher = fetcher_over(
            tmp_root(),
            Admission::AllowLocal,
            rung.clone(),
            Duration::from_millis(100),
        );
        let err = fetcher
            .fetch("http://127.0.0.1:9/hang")
            .await
            .expect_err("timeout");
        assert!(matches!(err, SearchError::Refused { .. }), "{err}");
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    /// The caller turns a report with no page into a refusal sentence, and never an empty body.
    #[tokio::test]
    async fn a_report_with_no_page_is_a_refusal_sentence_not_an_empty_body() {
        let rung = DictatedRung::new(vec![Verdict::Refused("no page")]);
        let fetcher = fetcher_over(
            tmp_root(),
            Admission::AllowLocal,
            rung.clone(),
            Duration::from_secs(5),
        );
        let err = fetcher
            .fetch("http://127.0.0.1:9/x")
            .await
            .expect_err("refused");
        assert!(matches!(err, SearchError::Refused { .. }), "{err}");
    }
}

#[cfg(test)]
mod fetch_router_tests {
    use super::*;
    use hx_browser::{Admission, RungKind};

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    fn pool_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hx-fetch-router-test-{}", std::process::id()))
    }

    /// Http mode must always select the plain fetcher and never a browser, even on a host that has one.
    #[test]
    fn http_mode_selects_the_plain_fetcher_even_when_a_browser_is_installed() {
        let selection = select_fetcher_by(&client(), FetchMode::Http, pool_root(), || true)
            .expect("http mode never fails");
        assert_eq!(selection.kind, SelectedFetcher::Http);
        assert!(
            !selection.note.contains("browser"),
            "the http note must not claim any browser involvement: {}",
            selection.note
        );
        assert!(!FetchMode::Http.may_launch_browser());
    }

    /// Auto mode escalates to the browser exactly when one is available — the case the rung exists for.
    #[test]
    fn auto_mode_selects_the_browser_fetcher_when_a_browser_is_available() {
        let selection = select_fetcher_by(&client(), FetchMode::Auto, pool_root(), || true)
            .expect("auto mode with a browser succeeds");
        assert_eq!(selection.kind, SelectedFetcher::Browser);
        assert!(
            selection.note.contains("escalat"),
            "the auto note must describe escalation: {}",
            selection.note
        );
        assert!(FetchMode::Auto.may_launch_browser());
    }

    /// Auto mode degrades to plain HTTP when no browser is installed — an honest default, never a lie.
    #[test]
    fn auto_mode_without_a_browser_degrades_to_plain_http() {
        let selection = select_fetcher_by(&client(), FetchMode::Auto, pool_root(), || false)
            .expect("auto mode without a browser degrades, it does not fail");
        assert_eq!(
            selection.kind,
            SelectedFetcher::Http,
            "no browser means plain fetch, never a pretend browser"
        );
        assert!(
            selection.note.contains("degraded"),
            "the note must record the degradation honestly: {}",
            selection.note
        );
    }

    /// Explicit Browser with no browser must FAIL, never silently degrade to a fetch the caller did not
    /// ask for — that would be returning a page it did not fetch the way the caller intended.
    #[test]
    fn explicit_browser_mode_without_a_browser_fails_honestly() {
        let err = select_fetcher_by(&client(), FetchMode::Browser, pool_root(), || false)
            .expect_err("explicit browser with no browser must not silently degrade");
        assert!(
            err.reason.contains("no Chromium"),
            "the error must name the missing browser: {}",
            err.reason
        );
    }

    /// Explicit Browser with a browser honours the request.
    #[test]
    fn explicit_browser_mode_with_a_browser_selects_the_browser_fetcher() {
        let selection = select_fetcher_by(&client(), FetchMode::Browser, pool_root(), || true)
            .expect("explicit browser with a browser succeeds");
        assert_eq!(selection.kind, SelectedFetcher::Browser);
        assert!(
            selection.note.contains("every page"),
            "the note must say this mode drives a browser for every page, not only for a refusal: {}",
            selection.note
        );
    }

    /// The two browser shapes differ in exactly one thing, and it is the plain rung.
    ///
    /// `FetchMode::Browser`'s promise is "drive a browser **even for a page a plain fetch could
    /// read**", so the fetcher it selects must not consult a plain rung first — a `200` would end
    /// the climb there and no browser would ever launch, which is precisely the JavaScript-rendered
    /// page this is about. `Auto`'s shape keeps the cheap rung first, which is its own documented
    /// cost rule. Asserted on the ladders rather than on a fetch, so it holds on a host with no
    /// Chromium — the live behavioural half is `tests/browser_rung_canary.rs`.
    #[test]
    fn the_two_browser_shapes_differ_in_exactly_the_plain_rung() {
        let root = pool_root();
        let escalating = BrowserFetcher::new(root.clone()).expect("the auto shape");
        let browser_first = BrowserFetcher::browser_first(root).expect("the browser shape");

        assert_eq!(
            escalating.pool().ladder().rungs(),
            vec![RungKind::Http, RungKind::Interactive],
            "Auto escalates: the cheap rung first, Chromium on a refusal"
        );
        assert_eq!(
            browser_first.pool().ladder().rungs(),
            vec![RungKind::Interactive],
            "Browser must not have a plain rung in front of the browser"
        );
    }

    /// `with_admission` rebuilds the pool's ladder rather than only relabelling the pool, so a
    /// fetcher widened for a loopback stub cannot leave a **strict** rung behind it to refuse the
    /// page's own subresources.
    #[test]
    fn widening_admission_rebuilds_the_rungs_on_the_same_policy() {
        let fetcher = BrowserFetcher::browser_first(pool_root())
            .expect("the browser shape")
            .with_admission(Admission::AllowLocal)
            .expect("the widened shape");

        assert_eq!(fetcher.admission, Admission::AllowLocal);
        assert_eq!(
            fetcher.pool().admission(),
            Admission::AllowLocal,
            "the pool held the new policy"
        );
        assert_eq!(
            fetcher.pool().ladder().rungs(),
            vec![RungKind::Interactive],
            "rebuilding must keep the shape it was built with"
        );

        let escalating = BrowserFetcher::new(pool_root())
            .expect("the auto shape")
            .with_admission(Admission::AllowLocal)
            .expect("the widened shape");
        assert_eq!(
            escalating.pool().ladder().rungs(),
            vec![RungKind::Http, RungKind::Interactive],
            "and the other shape's plain rung must survive the rebuild"
        );
    }

    /// The public, host-real selector agrees with the injected one on this host: if Chromium is present
    /// here, Auto escalates and Browser succeeds; if it is not, Auto degrades to plain and Browser fails.
    /// This is gated on the real host's browser so it never fails on a host without Chromium.
    #[test]
    fn the_public_selector_tracks_the_real_host_browser() {
        let real_available = browser_available();
        let sel =
            select_fetcher(&client(), FetchMode::Auto, pool_root()).expect("auto is infallible");
        if real_available {
            assert_eq!(
                sel.kind,
                SelectedFetcher::Browser,
                "on a host with Chromium, auto must escalate"
            );
        } else {
            assert_eq!(
                sel.kind,
                SelectedFetcher::Http,
                "on a host without Chromium, auto must degrade to plain"
            );
        }
        let browser_mode = select_fetcher(&client(), FetchMode::Browser, pool_root());
        if real_available {
            assert!(browser_mode.is_ok());
        } else {
            assert!(browser_mode.is_err());
        }
    }

    /// The plain fetchers the selector hands out admit their targets: `select_fetcher`
    /// builds `HttpFetcher::new(client)` with no cache — the production uncached path — so
    /// the fetcher it returns must still refuse a loopback target rather than `GET` it.
    #[tokio::test]
    async fn the_plain_fetchers_the_selector_hands_out_admit_their_targets() {
        for mode in [FetchMode::Http, FetchMode::Auto] {
            let selection = select_fetcher_by(&client(), mode, pool_root(), || false)
                .expect("http/auto never fail without a browser");
            assert_eq!(selection.kind, SelectedFetcher::Http);
            let err = selection
                .fetcher()
                .fetch("http://127.0.0.1:9/ssrf")
                .await
                .expect_err("a loopback target must be refused, not fetched");
            assert!(
                matches!(err, SearchError::Refused { .. }),
                "{mode:?} handed out a fetcher that did not refuse loopback: {err}"
            );
        }
    }
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

    /// The pipeline's types must be usable as state held across an `await` on a threaded runtime.
    ///
    /// This is a compile-time assertion, and it is the test that would have caught the M6 research
    /// route failing to compile: `ResearchTask` holds a `Ladder`, the ladder holds
    /// `Box<dyn ExtractionRung>`, and a trait object without the `Send + Sync` supertraits makes
    /// `&ResearchTask` non-`Send` — so *any* `async fn` that awaits `run` is rejected, with an
    /// error that names the caller's route rather than the missing bound. Remove `Send + Sync` from
    /// [`crate::extract::ExtractionRung`] and this test stops compiling; that is the whole point of
    /// it. A `#[test]` and not a doc claim, because a doc claim cannot fail a build.
    #[test]
    fn the_research_pipeline_can_be_held_across_an_await_on_a_threaded_runtime() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ResearchTask>();
        assert_send_sync::<Ladder>();
        assert_send_sync::<Arc<dyn Fetcher>>();
    }

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
        // The cluster serves on loopback, which the default policy refuses: the named hatch.
        let fetcher =
            Arc::new(HttpFetcher::new(client.clone()).with_admission(Admission::AllowLocal));

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
        // The pages are served on loopback, which the default policy refuses: the named hatch.
        let fetcher = Arc::new(
            HttpFetcher::new(client.clone())
                .with_max_body_bytes(2000)
                .with_admission(Admission::AllowLocal),
        );
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
    async fn a_chunked_response_without_content_length_is_bounded_while_streaming() {
        // No `Content-Length` anywhere: the cap can only hold if the body is measured while it
        // streams. Over the cap the page is skipped without ever assembling the body; under the
        // cap the chunks still assemble exactly.
        let big = ChunkedServer::serve(vec![b'A'; 32 * 1024]).await;
        // Chunked bodies are served on loopback, which the default policy refuses.
        let fetcher = HttpFetcher::new(reqwest::Client::new())
            .with_max_body_bytes(1024)
            .with_admission(Admission::AllowLocal);

        let skipped = fetcher.fetch(&big.url()).await.unwrap();
        assert!(
            skipped.is_none(),
            "an over-cap chunked body must be skipped, not cited"
        );

        let small_body = vec![b'B'; 700];
        let small = ChunkedServer::serve(small_body).await;
        let page = fetcher
            .fetch(&small.url())
            .await
            .unwrap()
            .expect("a within-cap chunked body must be fetched");
        assert_eq!(page.body.len(), 700);
        assert!(
            page.body.bytes().all(|b| b == b'B'),
            "chunks must assemble exactly across boundaries"
        );
    }

    /// A one-shot origin answering `Transfer-Encoding: chunked` with no `Content-Length` — the
    /// shape whose missing length used to bypass the body cap's early check.
    struct ChunkedServer {
        addr: std::net::SocketAddr,
        _handle: tokio::task::JoinHandle<()>,
    }

    impl ChunkedServer {
        async fn serve(body: Vec<u8>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind free port");
            let addr = listener.local_addr().expect("local addr");
            let handle = tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                // Drain the request head so the client never blocks on a full socket buffer.
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
                let mut head =
                    b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                        .to_vec();
                for piece in body.chunks(1024) {
                    head.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                    head.extend_from_slice(piece);
                    head.extend_from_slice(b"\r\n");
                }
                head.extend_from_slice(b"0\r\n\r\n");
                let _ = socket.write_all(&head).await;
                let _ = socket.flush().await;
            });
            Self {
                addr,
                _handle: handle,
            }
        }

        fn url(&self) -> String {
            format!("http://{}/stream", self.addr)
        }
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

    /// The plain fetcher's transport errors must not carry a `?token=`/`key=` credential: `reqwest`'s
    /// error `Display` appends the request URL, so a token-bearing URL would otherwise reach the report (and
    /// so the model). `transport_error` strips the URL.
    #[tokio::test]
    async fn a_transport_error_does_not_carry_a_query_token() {
        let token = "signed-token-9f3a2b7c";
        // A dead port on loopback forces a connect (transport) error carrying the request URL.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind free port");
        let addr = listener.local_addr().expect("addr");
        drop(listener); // now nothing listens; connecting fails with a transport error
        let url = format!("http://{addr}/page?token={token}");

        // `AllowLocal`: the dead port is on loopback, and this test needs the *transport*
        // error (connection refused) rather than the admission refusal the default policy
        // would produce before connecting.
        let fetcher =
            HttpFetcher::new(reqwest::Client::new()).with_admission(Admission::AllowLocal);
        let err = fetcher
            .fetch(&url)
            .await
            .expect_err("a dead port must be a transport error");

        let display = err.to_string();
        assert!(
            !display.contains(token),
            "the query token must not reach the error: {display}"
        );
        assert!(display.contains("transport error"), "{display}");
    }

    // -----------------------------------------------------------------------------------------
    // SSRF: the uncached production path admits like the cache path
    // -----------------------------------------------------------------------------------------
    //
    // `select_fetcher` hands the production route an `HttpFetcher` with no cache, so this is
    // the path `POST /v1/research` actually fetches through. It used to `GET` whatever URL a
    // backend returned with `reqwest`'s default redirect-following and no admission — a
    // result pointing at loopback, private space or the metadata service reached the local
    // network, and a public-looking URL could redirect there. These tests pin the fix: the
    // initial target is admitted and DNS-pinned before anything connects, redirects go
    // through a `Policy::none` client, and every redirect destination is re-admitted.

    #[tokio::test]
    async fn uncached_default_policy_refuses_a_loopback_target_before_connecting() {
        // A result URL pointing at the local machine is not public internet: admission runs
        // before the socket is touched, so the origin never hears a byte.
        let origin = TestServer::serve_sync(|_| {
            (
                200u16,
                vec![("content-type", "text/html".to_string())],
                b"<html><body><p>never served</p></body></html>".to_vec(),
            )
        })
        .await;
        let fetcher = HttpFetcher::new(reqwest::Client::new());

        match fetcher.fetch(&origin.url("/private")).await {
            Err(SearchError::Refused { reason }) => {
                assert!(
                    reason.contains("loopback"),
                    "the reason should name the private address: {reason}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        assert_eq!(
            origin.connection_count(),
            0,
            "admission refuses before any byte reaches the origin"
        );
    }

    #[tokio::test]
    async fn uncached_default_policy_refuses_the_cloud_metadata_endpoint() {
        // 169.254.169.254 is link-local: the metadata service that turns an SSRF into
        // credential theft. Refused by the literal rule, so no connection is attempted.
        let fetcher = HttpFetcher::new(reqwest::Client::new()).with_timeout(Duration::from_secs(5));

        match fetcher
            .fetch("http://169.254.169.254/latest/meta-data/")
            .await
        {
            Err(SearchError::Refused { reason }) => {
                assert!(
                    reason.contains("not on the public internet"),
                    "the reason should name the refusal: {reason}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn uncached_refuses_a_non_http_scheme_without_a_request() {
        // `file://` is not a page; it is this process opening a local file. Refused under
        // either policy, before anything is opened.
        let fetcher = HttpFetcher::new(reqwest::Client::new());

        match fetcher.fetch("file:///etc/hostname").await {
            Err(SearchError::Refused { reason }) => {
                assert!(
                    reason.contains("scheme"),
                    "the reason should name the scheme rule: {reason}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn uncached_refuses_a_local_hostname_without_resolving_it() {
        // `localhost` is refused by the name rule — no DNS lookup is needed to know it is
        // not the public internet.
        let origin = TestServer::serve_sync(|_| {
            (
                200u16,
                vec![("content-type", "text/html".to_string())],
                b"<html><body><p>never served</p></body></html>".to_vec(),
            )
        })
        .await;
        let url = format!("http://localhost:{}/page", origin.addr.port());
        let fetcher = HttpFetcher::new(reqwest::Client::new());

        match fetcher.fetch(&url).await {
            Err(SearchError::Refused { reason }) => {
                assert!(
                    reason.contains("localhost"),
                    "the reason should name the refused host: {reason}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        assert_eq!(
            origin.connection_count(),
            0,
            "a refused name is never resolved nor connected to"
        );
    }

    #[tokio::test]
    async fn uncached_allow_local_reaches_a_loopback_origin() {
        // The positive control for the named hatch: `AllowLocal` admits the loopback stub,
        // so a widened fetcher still reads the page. Without this, every hermetic caller of
        // the uncached path would have no honest way to test against a local server.
        let origin = TestServer::serve_sync(|_| {
            (
                200u16,
                vec![("content-type", "text/html".to_string())],
                b"SENTINEL-BYTES".to_vec(),
            )
        })
        .await;
        let fetcher =
            HttpFetcher::new(reqwest::Client::new()).with_admission(Admission::AllowLocal);

        let page = fetcher
            .fetch(&origin.url("/page"))
            .await
            .expect("an admitted target must fetch")
            .expect("a 200 with a body must not be skipped");
        assert!(
            page.body.contains("SENTINEL-BYTES"),
            "the body must be the served bytes: {}",
            page.body
        );
        assert_eq!(origin.connection_count(), 1);
    }

    #[tokio::test]
    async fn uncached_does_not_follow_a_redirect_it_has_not_admitted() {
        // The page a caller reached may point onward at a non-fetchable target. The hop
        // client follows nothing on its own (`Policy::none`), so the `Location` is admitted
        // before the next send — and refused here — instead of being connected to.
        let origin = TestServer::serve_sync(|head| {
            let path = head.split_whitespace().nth(1).unwrap_or("/");
            if path.starts_with("/start") {
                (
                    302u16,
                    vec![("location", "file:///etc/hostname".to_string())],
                    Vec::new(),
                )
            } else {
                (
                    200u16,
                    vec![("content-type", "text/html".to_string())],
                    b"never".to_vec(),
                )
            }
        })
        .await;
        let fetcher =
            HttpFetcher::new(reqwest::Client::new()).with_admission(Admission::AllowLocal);

        match fetcher.fetch(&origin.url("/start")).await {
            Err(SearchError::Refused { reason }) => {
                assert!(
                    reason.contains("scheme"),
                    "the redirect refusal should name the scheme rule: {reason}"
                );
            }
            other => panic!("expected a redirect refusal, got {other:?}"),
        }

        assert_eq!(
            origin.connection_count(),
            1,
            "exactly the initial hop was sent; the redirect was judged, not followed"
        );
    }

    #[tokio::test]
    async fn uncached_redirect_to_an_unresolvable_host_is_refused_not_followed() {
        // The DNS leg of the redirect check: a `Location` whose host resolves to nothing is
        // refused — there is nothing admission looked at — rather than retried or followed.
        // `.invalid` never resolves (RFC 2606), so this needs no network to be decisive.
        let origin = TestServer::serve_sync(|head| {
            let path = head.split_whitespace().nth(1).unwrap_or("/");
            if path.starts_with("/start") {
                (
                    302u16,
                    vec![("location", "http://no-such-host.invalid/".to_string())],
                    Vec::new(),
                )
            } else {
                (
                    200u16,
                    vec![("content-type", "text/html".to_string())],
                    b"never".to_vec(),
                )
            }
        })
        .await;
        let fetcher =
            HttpFetcher::new(reqwest::Client::new()).with_admission(Admission::AllowLocal);

        match fetcher.fetch(&origin.url("/start")).await {
            Err(SearchError::Refused { reason }) => {
                assert!(
                    reason.contains("did not resolve"),
                    "the redirect refusal should name the unresolvable host: {reason}"
                );
            }
            other => panic!("expected a redirect refusal, got {other:?}"),
        }

        assert_eq!(
            origin.connection_count(),
            1,
            "exactly the initial hop was sent; the redirect was judged, not followed"
        );
    }

    #[tokio::test]
    async fn uncached_redirect_loop_is_cut_off_after_max_redirects() {
        // Two pages that keep redirecting into each other must not spin forever: the hop
        // counter caps the chain. The loop is on loopback, so `AllowLocal` reaches it — the
        // point here is the budget, not the admission.
        let origin = TestServer::serve_sync(|head| {
            let path = head.split_whitespace().nth(1).unwrap_or("/");
            let next = if path.starts_with("/a") { "/b" } else { "/a" };
            (302u16, vec![("location", next.to_string())], Vec::new())
        })
        .await;
        let fetcher =
            HttpFetcher::new(reqwest::Client::new()).with_admission(Admission::AllowLocal);

        // Whatever the outcome, the fetch must return — a redirect loop that never
        // terminated would hang the test (and the harness).
        let _ = fetcher.fetch(&origin.url("/a")).await;

        let hops = origin.connection_count();
        assert!(
            hops <= MAX_REDIRECTS + 1,
            "redirect loop exceeded the hop budget: {hops} connections"
        );
        assert!(
            hops >= 2,
            "the loop should have been followed at least once: {hops}"
        );
    }
}
