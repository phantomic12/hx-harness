//! Mojeek — keyless, scraped from its own index.
//!
//! Mojeek runs its own crawler rather than reselling another engine's index, which is why it is
//! worth a direct backend: its results are *independent evidence* in the RRF fusion rather than
//! a second view of the same index. It is also the engine most likely to disagree with the big
//! two, which is exactly the signal agreement-based fusion is looking for.
//!
//! ## Honesty about the live path
//!
//! As of this writing `www.mojeek.com/search` answers a plain HTTP client with a **Captcha**
//! page: `curl`'s own user-agent gets `403`, a browser user-agent gets `200` and a page whose
//! `<title>` is `Captcha`. So the parser here is exercised against a *transcription of Mojeek's
//! result markup*, not against a live capture, and the live path has **not** been exercised from
//! this environment. The canary in `tests/search_live.rs` is what would notice if that changes.
//! The bot-check branch below is therefore load-bearing rather than theoretical: from a bare
//! HTTP client this backend's normal outcome is that error.
//!
//! ## What is deliberately NOT done
//!
//! - **Recency is not forwarded.** Mojeek's advanced-search form
//!   (`https://www.mojeek.com/advanced.html`, read live) exposes `q`, `qm`, `t`, `si`, `site`,
//!   `date`, `size` and `country` — and `date` is a *display* toggle ("show the crawl date"),
//!   not a date-range filter. There is no recency parameter to send. Inventing one would be
//!   worse than omitting it, so `recency` is ignored here and this note is the disclosure.
//! - **`site:` is folded into `q`** rather than sent as the dedicated `site` parameter, because
//!   `SearchQuery::effective_text` already folds it and Mojeek documents `site:` as a query
//!   operator. One source of truth for the query text beats two.

use super::{clean_text, looks_like_a_bot_check, USER_AGENT};
use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{SearchQuery, SearchResult};
use async_trait::async_trait;
use regex::Regex;
use std::sync::OnceLock;
use url::Url;

/// The keyless Mojeek scraper.
pub struct MojeekBackend {
    endpoint: String,
}

impl MojeekBackend {
    pub fn new() -> Self {
        Self {
            endpoint: "https://www.mojeek.com/search".to_string(),
        }
    }

    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

impl Default for MojeekBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// The result counts Mojeek's `t` parameter accepts, read from its advanced-search form.
pub const MOJEEK_PAGE_SIZES: [u32; 7] = [10, 15, 20, 25, 30, 35, 40];

/// The `t` value that covers `limit`, or `None` when no supported page size reaches it.
///
/// Mojeek takes a fixed menu of counts rather than an arbitrary number, so asking for "up to N"
/// means rounding *up* to the next supported size and truncating locally. Rounding down would
/// silently return fewer results than the caller asked for.
pub fn mojeek_result_count(limit: usize) -> Option<u32> {
    MOJEEK_PAGE_SIZES
        .iter()
        .copied()
        .find(|size| *size as usize >= limit)
}

/// Build the `/search` URL for a query. Pure, so the parameter mapping is testable.
pub fn mojeek_search_url(base: &str, query: &SearchQuery) -> Result<Url, SearchError> {
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(SearchError::NotConfigured(
            "mojeek endpoint is empty".to_string(),
        ));
    }
    let mut url = Url::parse(base).map_err(|e| {
        SearchError::NotConfigured(format!("mojeek endpoint {base:?} is not a valid URL: {e}"))
    })?;

    {
        let mut params = url.query_pairs_mut();
        params.append_pair("q", &query.effective_text());
        if let Some(count) = mojeek_result_count(query.limit) {
            params.append_pair("t", &count.to_string());
        }
    }

    Ok(url)
}

fn h2_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<h2\b[^>]*>(.*?)</h2>").expect("valid regex"))
}

fn paragraph_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<p\b([^>]*)>(.*?)</p>").expect("valid regex"))
}

fn anchor_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<a\b([^>]*)>(.*?)</a>").expect("valid regex"))
}

fn href_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?is)href\s*=\s*["']([^"']*)["']"#).expect("valid regex"))
}

fn class_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?is)class\s*=\s*["']([^"']*)["']"#).expect("valid regex"))
}

/// True when a tag's attributes carry `token` as a whole CSS class.
///
/// Whole-token matching, not `contains`: `class="search-results"` contains the substring "s",
/// and a substring test would turn every wrapper into a snippet.
fn has_class(attrs: &str, token: &str) -> bool {
    class_re()
        .captures(attrs)
        .and_then(|c| c.get(1))
        .map(|classes| classes.as_str().split_whitespace().any(|c| c == token))
        .unwrap_or(false)
}

/// Parse a Mojeek results page.
///
/// Everything after the `results-standard` list marker is scanned, rather than trying to match
/// the list element itself: Mojeek nests a `<ul class="meta">` inside each result, so a
/// non-greedy match to the first `</ul>` stops inside the first result. Titles come from the
/// `<h2>` anchors and snippets from `<p class="s">`; they are paired by position, which is the
/// order the page lays them out.
pub fn parse_mojeek_html(html: &str) -> Vec<SearchResult> {
    let Some(start) = html.find("results-standard") else {
        // No results list at all: either no results or an interstitial. Both are "nothing to
        // report"; the caller decides whether that is a failure by consulting the bot-check
        // signal.
        return Vec::new();
    };
    let body = &html[start..];

    let mut titles: Vec<(String, String)> = Vec::new();
    for h2 in h2_re().captures_iter(body) {
        let Some(inner) = h2.get(1) else { continue };
        let Some(anchor) = anchor_re().captures(inner.as_str()) else {
            continue;
        };
        let attrs = anchor.get(1).map(|m| m.as_str()).unwrap_or_default();
        let Some(href) = href_re().captures(attrs).and_then(|c| c.get(1)) else {
            continue;
        };
        let href = href.as_str().trim();
        if !href.starts_with("http") {
            // Mojeek's own navigation and "related searches" are relative or fragment links.
            continue;
        }
        let title = clean_text(anchor.get(2).map(|m| m.as_str()).unwrap_or_default());
        if title.is_empty() {
            continue;
        }
        titles.push((title, href.to_string()));
    }

    let snippets: Vec<String> = paragraph_re()
        .captures_iter(body)
        .filter(|c| has_class(c.get(1).map(|m| m.as_str()).unwrap_or_default(), "s"))
        .map(|c| clean_text(c.get(2).map(|m| m.as_str()).unwrap_or_default()))
        .collect();

    titles
        .into_iter()
        .enumerate()
        .map(|(rank, (title, url))| SearchResult {
            title,
            url,
            snippet: snippets.get(rank).cloned().unwrap_or_default(),
            rank,
        })
        .collect()
}

#[async_trait]
impl SearchBackend for MojeekBackend {
    fn id(&self) -> &str {
        "mojeek"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Keyless
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let url = mojeek_search_url(&self.endpoint, query)?;

        let response = client
            .get(url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(
                reqwest::header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(SearchError::Http {
                status: status.as_u16(),
            });
        }

        let html = response.text().await?;
        let results = parse_mojeek_html(&html);

        if results.is_empty() && looks_like_a_bot_check(&html) {
            return Err(SearchError::Parse {
                reason: "Mojeek served a bot check (its results endpoint is Captcha-walled for \
                         non-browser clients) instead of results"
                    .to_string(),
            });
        }

        Ok(results.into_iter().take(query.limit).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Recency;

    /// A transcription of Mojeek's result markup — `<ul class="results-standard">`, one `<li>`
    /// per result with an `<h2>` anchor and a `<p class="s">` snippet, a nested `<ul class="meta">`
    /// that must not terminate the scan early, and a "related searches" link that must not become
    /// a result.
    ///
    /// **This is not a live capture.** `www.mojeek.com/search` served a Captcha page to every
    /// user-agent tried from this environment, so the shape below comes from Mojeek's published
    /// result markup rather than from a saved response. The live path is not exercised by this
    /// test and is not claimed to work; see the module docs.
    const MOJEEK_FIXTURE: &str = r#"
<html><body>
  <div class="results">
    <ul class="results-standard">
      <li>
        <h2><a class="ob" href="https://example.com/one" title="Example &mdash; Docs">Example &mdash; Docs</a></h2>
        <p class="s">A snippet about <b>example</b> things.</p>
        <ul class="meta"><li><a class="u" href="https://example.com/one">example.com/one</a></li></ul>
      </li>
      <li>
        <h2><a class="ob" href="https://second.example.org/two">Second result</a></h2>
        <p class="s">Another snippet.</p>
        <ul class="meta"><li><a class="u" href="https://second.example.org/two">second.example.org</a></li></ul>
      </li>
    </ul>
  </div>
  <div class="related"><ul><li><a href="/search?q=more">More results</a></li></ul></div>
</body></html>
"#;

    #[test]
    fn parses_titles_urls_and_snippets_from_the_results_list() {
        let results = parse_mojeek_html(MOJEEK_FIXTURE);

        assert_eq!(results.len(), 2, "{results:#?}");
        assert_eq!(results[0].title, "Example — Docs");
        assert_eq!(results[0].url, "https://example.com/one");
        assert_eq!(results[0].snippet, "A snippet about example things.");
        assert_eq!(results[0].rank, 0);
        assert_eq!(results[1].url, "https://second.example.org/two");
        assert_eq!(results[1].snippet, "Another snippet.");
    }

    #[test]
    fn a_nested_meta_list_does_not_truncate_the_scan() {
        // The bug this guards: matching the results list non-greedily to the first `</ul>`
        // stops inside the first result's `<ul class="meta">` and silently yields one result.
        assert_eq!(parse_mojeek_html(MOJEEK_FIXTURE).len(), 2);
    }

    #[test]
    fn relative_and_navigation_links_are_not_results() {
        let results = parse_mojeek_html(MOJEEK_FIXTURE);
        assert!(
            !results.iter().any(|r| r.url.contains("/search?q=")),
            "a related-searches link must not become a result: {results:#?}"
        );
    }

    #[test]
    fn a_substring_class_does_not_make_a_snippet() {
        // `class="search-results"` contains the letter "s"; only a whole `s` token counts.
        assert!(has_class(r#" class="s""#, "s"));
        assert!(has_class(r#" class="s clearfix""#, "s"));
        assert!(!has_class(r#" class="search-results""#, "s"));
        assert!(!has_class("", "s"));
    }

    #[test]
    fn a_page_with_no_results_list_parses_to_nothing() {
        assert!(parse_mojeek_html("<html><body>nothing</body></html>").is_empty());
        assert!(parse_mojeek_html("").is_empty());
    }

    #[test]
    fn a_captcha_page_is_recognised_as_a_bot_check() {
        // The real outcome from this environment, and the reason the backend reports a failure
        // rather than an empty result set.
        let captcha = "<html><head><title>Captcha</title></head><body>\
                       <div class=\"captcha-wrap\">Please prove you are human</div></body></html>";
        assert!(parse_mojeek_html(captcha).is_empty());
        assert!(looks_like_a_bot_check(captcha));
    }

    // ---- URL construction ----

    #[test]
    fn mojeek_url_carries_the_query_and_a_supported_page_size() {
        let url = mojeek_search_url(
            "https://www.mojeek.com/search",
            &SearchQuery::new("rust async").with_limit(15),
        )
        .unwrap();
        let q = url.query().unwrap();
        assert!(
            q.contains("q=rust+async") || q.contains("q=rust%20async"),
            "{q}"
        );
        assert!(q.contains("t=15"), "{q}");
    }

    #[test]
    fn mojeek_page_size_rounds_up_and_is_omitted_past_the_menu() {
        // Rounding down would return fewer results than asked for.
        assert_eq!(mojeek_result_count(1), Some(10));
        assert_eq!(mojeek_result_count(11), Some(15));
        assert_eq!(mojeek_result_count(40), Some(40));
        assert_eq!(mojeek_result_count(41), None, "past the menu, send nothing");

        let url = mojeek_search_url(
            "https://www.mojeek.com/search",
            &SearchQuery::new("x").with_limit(41),
        )
        .unwrap();
        assert!(!url.query().unwrap().contains("t="), "{}", url);
    }

    #[test]
    fn mojeek_url_folds_the_site_filter_and_sends_no_recency_parameter() {
        let query = SearchQuery::new("async rust")
            .with_recency(Recency::Week)
            .with_site("docs.rs");
        let url = mojeek_search_url("https://www.mojeek.com/search", &query).unwrap();

        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        assert!(
            pairs.iter().any(|(_, v)| v.contains("site:docs.rs")),
            "the site filter must be folded into q: {pairs:?}"
        );

        // Recency is deliberately absent: Mojeek's advanced form exposes `q, qm, t, si, site,
        // date, size, country`, and `date` is a *display* toggle rather than a date range — there
        // is no recency parameter to send. Asserting the exact key set (rather than the absence of
        // one guessed name) means adding a parameter has to be a deliberate act that updates this
        // test, instead of an unverified one slipping in.
        let mut keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["q", "t"], "{pairs:?}");
    }

    #[test]
    fn mojeek_url_rejects_an_empty_endpoint() {
        let err = mojeek_search_url("  ", &SearchQuery::new("x")).unwrap_err();
        assert!(matches!(err, SearchError::NotConfigured(_)), "{err}");
    }
}
