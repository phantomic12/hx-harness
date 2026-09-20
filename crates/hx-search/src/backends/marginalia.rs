//! Marginalia — keyless, scraped from its own index of the non-commercial web.
//!
//! Marginalia deliberately indexes the part of the web the big engines have stopped ranking:
//! personal sites, forums, hand-written documentation, small blogs. That makes it the most
//! *diverse* backend in the fan-out — its top ten share almost nothing with DuckDuckGo's, which
//! is precisely the disagreement RRF is designed to arbitrate. It is the backend least likely to
//! be an echo of the others.
//!
//! ## What is deliberately NOT done
//!
//! - **No page-size parameter.** The obvious `&count=` was tried live and makes the site return
//!   a page with *zero* results (the query is dropped), so the backend sends only `query` and
//!   truncates locally. A parameter that silently empties the result set is worse than no
//!   parameter at all.
//! - **Recency is not forwarded.** Marginalia's UI has no date filter and it indexes by
//!   *quality of the page*, not by publication date; there is no parameter to send. Inventing
//!   one would be worse than omitting it.
//! - **`site:` is not folded into the query.** MediaWiki-style `site:` folding is a convention
//!   shared with SearXNG and DDG, but Marginalia's operator support could not be verified from
//!   here, and a folded token an engine does not understand is *noise in the query* — it makes
//!   results worse rather than filtering them. Instead the filter is applied to the **returned
//!   URLs** by host, which can only ever remove results that violate it.
//!
//! ## The endpoint moved
//!
//! `search.marginalia.nu` now 302s to `marginalia-search.com`, and the old JSON API
//! (`api.marginalia.nu/public/search/…`) redirects to the HTML page — the keyless JSON endpoint
//! is gone. The default here is the current host, so the fan-out does not pay a redirect per
//! query; `with_endpoint` exists for a self-hosted instance.

use super::{clean_text, USER_AGENT};
use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{host_matches, SearchQuery, SearchResult};
use async_trait::async_trait;
use regex::Regex;
use std::sync::OnceLock;
use url::Url;

/// The keyless Marginalia scraper.
pub struct MarginaliaBackend {
    endpoint: String,
}

impl MarginaliaBackend {
    pub fn new() -> Self {
        Self {
            endpoint: "https://marginalia-search.com/search".to_string(),
        }
    }

    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

impl Default for MarginaliaBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the `/search` URL for a query. Pure, so the parameter mapping is testable.
pub fn marginalia_search_url(base: &str, query: &SearchQuery) -> Result<Url, SearchError> {
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(SearchError::NotConfigured(
            "marginalia endpoint is empty".to_string(),
        ));
    }
    let mut url = Url::parse(base).map_err(|e| {
        SearchError::NotConfigured(format!(
            "marginalia endpoint {base:?} is not a valid URL: {e}"
        ))
    })?;

    {
        let mut params = url.query_pairs_mut();
        // `query.text`, not `effective_text`: see the module docs on why `site:` is not folded.
        params.append_pair("query", &query.text);
    }

    Ok(url)
}

fn anchor_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<a\b([^>]*)>(.*?)</a>").expect("valid regex"))
}

fn href_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?is)href\s*=\s*["']([^"']*)["']"#).expect("valid regex"))
}

fn snippet_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<p\b([^>]*)>(.*?)</p>").expect("valid regex"))
}

/// A result *title* anchor, identified by its attribute pair.
///
/// The page has three anchors per result — the title, the URL spelled out underneath it, and a
/// Wayback Machine link — and they are not distinguishable by class (all three are styled
/// differently on purpose). What separates them is stable and semantic: the title carries
/// `rel="noopener noreferrer" dir="auto"`, the URL duplicate carries `rel` plus `tabindex="-1"`,
/// and the archive link carries neither. Matching on the pair rather than on Tailwind classes
/// means a restyle does not break the parser.
fn is_title_anchor(attrs: &str) -> bool {
    let lower = attrs.to_ascii_lowercase();
    lower.contains("noopener noreferrer") && lower.contains("dir=\"auto\"")
}

/// A result snippet paragraph: the body text carries both `break-words` and `dir="auto"`.
fn is_snippet_paragraph(attrs: &str) -> bool {
    let lower = attrs.to_ascii_lowercase();
    lower.contains("break-words") && lower.contains("dir=\"auto\"")
}

/// Parse a Marginalia results page.
///
/// Titles and snippets are collected independently and paired by position, which is the order
/// the page lays them out. On a real capture the two counts were exactly equal (25 and 25), so
/// the pairing is not a guess about a ragged page — it is the page's own structure.
pub fn parse_marginalia_html(html: &str) -> Vec<SearchResult> {
    let hrefs = href_re();

    let mut titles: Vec<(String, String)> = Vec::new();
    for capture in anchor_re().captures_iter(html) {
        let attrs = capture.get(1).map(|m| m.as_str()).unwrap_or_default();
        if !is_title_anchor(attrs) {
            continue;
        }
        let Some(href) = hrefs.captures(attrs).and_then(|c| c.get(1)) else {
            continue;
        };
        let href = href.as_str().trim();
        if !href.starts_with("http") {
            continue;
        }
        // `<wbr>` is sprinkled through both the title and the URL text; `clean_text` strips it.
        let title = clean_text(capture.get(2).map(|m| m.as_str()).unwrap_or_default());
        if title.is_empty() {
            continue;
        }
        titles.push((title, href.to_string()));
    }

    let snippets: Vec<String> = snippet_re()
        .captures_iter(html)
        .filter(|c| is_snippet_paragraph(c.get(1).map(|m| m.as_str()).unwrap_or_default()))
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
impl SearchBackend for MarginaliaBackend {
    fn id(&self) -> &str {
        "marginalia"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Keyless
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let url = marginalia_search_url(&self.endpoint, query)?;

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
        let mut results = parse_marginalia_html(&html);

        // The site filter is applied here rather than folded into the query: see the module
        // docs. Every Marginalia hit is on the indexed host, so a `site:` naming anything else
        // correctly yields nothing from this backend while the rest of the fan-out still answers.
        if let Some(site) = &query.site {
            results.retain(|result| host_matches(&result.url, site));
        }

        Ok(results.into_iter().take(query.limit).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A live capture**, trimmed: `GET https://marginalia-search.com/search?query=rust+programming`
    /// from this environment, 200, one result block copied verbatim (the real Tailwind classes,
    /// the real `<wbr>` markers) and the rest dropped. The three-anchor structure per result is
    /// exactly as the site sends it, including the archive link that must not become a result.
    const MARGINALIA_FIXTURE: &str = r#"
<html><head><title>rust programming - Marginalia Search</title></head>
<body>
<div class="flex flex-col grow" >
    <div class="flex grow justify-between items-start">
        <div class="flex-1">
            <h2 class="text-md sm:text-xl text-green-800 dark:text-green-200 font-serif mr-4 break-words hyphens-auto">
                <a href="https://en.wikipedia.org/wiki/Rust_%28programming_language%29" rel="noopener noreferrer" dir="auto">Rust (<wbr>programming language)<wbr></a>
            </h2>
            <div class="text-sm mt-1">
                <a class="text-liteblue dark:text-blue-200 underline break-all" href="https://en.wikipedia.org/wiki/Rust_%28programming_language%29"
                   rel="noopener noreferrer" tabindex="-1">https:<wbr>/<wbr>/<wbr>en.<wbr>wikipedia.<wbr>org/<wbr>wiki/<wbr>Rust_<wbr>(<wbr>programming_<wbr>language)<wbr></a>
            </div>
        </div>
    </div>
</div>
<div class="overflow-auto flex-1">
<p class="mt-2 text-sm text-black dark:text-white leading-relaxed break-words" dir="auto">
    Rust supports multiple programming paradigms. It was influenced by ideas from functional programming, including immutability, higher-order functions, algebraic data types, and pattern matching.
</p>
</div>

<div class="flex flex-col grow" >
    <div class="flex grow justify-between items-start">
        <div class="flex-1">
            <h2 class="text-md sm:text-xl text-blue-950 dark:text-blue-50 font-serif mr-4 break-words hyphens-auto">
                <a href="https://steveklabnik.com/writing/whats-new-with-the-rust-programming-language/" rel="noopener noreferrer" dir="auto">What'<wbr>s new with "The Rust Programming Language"</a>
            </h2>
            <div class="text-sm mt-1">
                <a class="text-liteblue dark:text-blue-200 underline break-all" href="https://steveklabnik.com/writing/whats-new-with-the-rust-programming-language/"
                   rel="noopener noreferrer" tabindex="-1">https:<wbr>/<wbr>/<wbr>steveklabnik.<wbr>com/<wbr>writing/<wbr>whats-new-with-the-rust-programming-language/<wbr></a>
            </div>
        </div>
    </div>
    <div class="flex flex-col ml-5 content-center items-center space-y-2">
        <a href="/site/steveklabnik.com" class="p-1.5" title="About this domain">
            <i class="fas fa-info text-sm"></i>
        </a>
        <a href="https://web.archive.org/web/*/https://steveklabnik.com/writing/whats-new-with-the-rust-programming-language/"
           class="p-1.5" title="Wayback Machine">
            <i class="fas fa-clock-rotate-left text-sm"></i>
        </a>
    </div>
</div>
<div class="overflow-auto flex-1">
<p class="mt-2 text-sm text-black dark:text-white leading-relaxed break-words" dir="auto">
    A look at what has changed in the book.
</p>
</div>
</body></html>
"#;

    #[test]
    fn parses_titles_urls_and_snippets_from_a_live_capture() {
        let results = parse_marginalia_html(MARGINALIA_FIXTURE);

        assert_eq!(results.len(), 2, "{results:#?}");
        assert_eq!(results[0].title, "Rust (programming language)");
        assert_eq!(
            results[0].url,
            "https://en.wikipedia.org/wiki/Rust_%28programming_language%29"
        );
        assert!(results[0]
            .snippet
            .starts_with("Rust supports multiple programming paradigms"));
        assert_eq!(results[0].rank, 0);

        assert_eq!(
            results[1].title,
            "What's new with \"The Rust Programming Language\""
        );
        assert_eq!(
            results[1].snippet,
            "A look at what has changed in the book."
        );
    }

    #[test]
    fn the_url_duplicate_and_the_archive_link_are_not_separate_results() {
        // Three anchors per result; only the title carries `rel` + `dir="auto"`. Getting this
        // wrong triples the result count and hands the fusion three votes for one page.
        let results = parse_marginalia_html(MARGINALIA_FIXTURE);
        assert_eq!(results.len(), 2, "{results:#?}");
        assert!(
            !results.iter().any(|r| r.url.contains("web.archive.org")),
            "the Wayback link must not become a result: {results:#?}"
        );
    }

    #[test]
    fn the_wbr_markers_do_not_survive_into_titles() {
        let results = parse_marginalia_html(MARGINALIA_FIXTURE);
        assert!(
            !results[0].title.contains("<wbr>") && !results[0].title.contains("wbr"),
            "{}",
            results[0].title
        );
    }

    #[test]
    fn a_page_with_no_results_parses_to_nothing() {
        assert!(parse_marginalia_html("<html><body>nothing</body></html>").is_empty());
        assert!(parse_marginalia_html("").is_empty());
    }

    // ---- URL construction ----

    #[test]
    fn marginalia_url_sends_the_query_and_nothing_else() {
        let url = marginalia_search_url(
            "https://marginalia-search.com/search",
            &SearchQuery::new("rust async").with_limit(15),
        )
        .unwrap();
        let q = url.query().unwrap();
        assert!(
            q.contains("query=rust+async") || q.contains("query=rust%20async"),
            "{q}"
        );
        // Verified live: `&count=` makes the site return zero results, so it is never sent.
        assert!(
            !q.contains("count="),
            "a page-size parameter empties the result set: {q}"
        );
    }

    #[test]
    fn marginalia_does_not_fold_a_site_filter_into_the_query() {
        // A folded `site:` an engine does not understand is noise, not a filter — the filter is
        // applied to returned URLs instead.
        let query = SearchQuery::new("async rust").with_site("docs.rs");
        let url = marginalia_search_url("https://marginalia-search.com/search", &query).unwrap();
        let q = url.query().unwrap();
        assert!(!q.contains("site"), "{q}");
        assert!(!q.contains("docs.rs"), "{q}");
    }

    #[test]
    fn marginalia_url_tolerates_a_trailing_slash_and_rejects_an_empty_endpoint() {
        let a = marginalia_search_url(
            "https://marginalia-search.com/search/",
            &SearchQuery::new("x"),
        )
        .unwrap();
        assert!(a.path().ends_with("/search"), "{a}");

        let err = marginalia_search_url("  ", &SearchQuery::new("x")).unwrap_err();
        assert!(matches!(err, SearchError::NotConfigured(_)), "{err}");
    }
}
