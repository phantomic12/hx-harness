//! Wikipedia — keyless, through the MediaWiki API.
//!
//! The one backend here that is a *documented API* rather than a scrape: no bot wall, no
//! markup to transcribe, a stable JSON shape and a published rate-limit policy. That makes it
//! the most reliable member of the fan-out and the one whose live path is genuinely exercised
//! (see `tests/search_live.rs`).
//!
//! It is also the most *different* kind of evidence. A search engine answers "what does the web
//! say about this"; Wikipedia answers "is there an encyclopaedia article about this, and what
//! does its lead say". For a research task those are complementary: a term with a Wikipedia
//! article and no engine hits is an obscure-but-real thing, and a term with engine hits and no
//! article is a product, an error message or a person's blog post.
//!
//! ## What is deliberately NOT done
//!
//! - **`formatversion=1` is pinned explicitly.** The parser is written against the v1 shape
//!   (captured live), and v2 changes both the `snippet` nesting and the `continue` field from a
//!   string to an object. Pinning means a change of MediaWiki default cannot silently start
//!   returning zero results.
//! - **`site:` is not folded into `srsearch`.** MediaWiki has no `site:` operator — a folded
//!   `site:docs.rs` would be searched as the literal token `site:docs.rs` and would return
//!   nothing. Instead the filter is applied to the returned URLs by host, so `site:docs.rs`
//!   correctly yields nothing from this backend while the rest of the fan-out still answers.
//! - **Recency is not forwarded.** `list=search` offers `srsort` (an ordering) but no date-range
//!   filter, and a sort is not a filter: presenting "most recently edited" as "published this
//!   week" would be a lie about the results. Omitted, and disclosed here.
//! - **`srlimit` is clamped to 50.** The API allows up to 500; a fan-out backend that can return
//!   500 results would dominate the fusion by sheer volume. 50 is well past the point where an
//!   RRF contribution matters and keeps the response small.

use super::{clean_text, USER_AGENT};
use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{host_matches, SearchQuery, SearchResult};
use async_trait::async_trait;
use url::Url;

/// The highest `srlimit` this backend will send.
pub const WIKIPEDIA_MAX_RESULTS: usize = 50;

/// The keyless Wikipedia backend.
pub struct WikipediaBackend {
    api_base: String,
}

impl WikipediaBackend {
    /// English Wikipedia.
    pub fn new() -> Self {
        Self {
            api_base: "https://en.wikipedia.org/w/api.php".to_string(),
        }
    }

    /// A different wiki — any MediaWiki with the API enabled, e.g. a self-hosted one.
    pub fn with_endpoint(api_base: impl Into<String>) -> Self {
        Self {
            api_base: api_base.into(),
        }
    }
}

impl Default for WikipediaBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the `api.php` URL for a query. Pure, so the parameter mapping is testable.
pub fn wikipedia_search_url(api_base: &str, query: &SearchQuery) -> Result<Url, SearchError> {
    let base = api_base.trim();
    if base.is_empty() {
        return Err(SearchError::NotConfigured(
            "wikipedia api_base is empty".to_string(),
        ));
    }
    let mut url = Url::parse(base).map_err(|e| {
        SearchError::NotConfigured(format!(
            "wikipedia api_base {base:?} is not a valid URL: {e}"
        ))
    })?;

    {
        let mut params = url.query_pairs_mut();
        params.append_pair("action", "query");
        params.append_pair("list", "search");
        // `query.text`, not `effective_text`: MediaWiki has no `site:` operator, and a folded
        // token would be searched literally.
        params.append_pair("srsearch", &query.text);
        params.append_pair(
            "srlimit",
            &query.limit.clamp(1, WIKIPEDIA_MAX_RESULTS).to_string(),
        );
        params.append_pair("format", "json");
        // Pinned, not defaulted: the parser is written against v1 (see the module docs).
        params.append_pair("formatversion", "1");
    }

    Ok(url)
}

/// The canonical article URL for a page title, or `None` if the API base has no usable origin.
///
/// Titles carry spaces, parentheses, commas, apostrophes, ampersands and plus signs.
/// `path_segments_mut().push` percent-encodes most of them and turns spaces into underscores the
/// way MediaWiki spells them; `&` is the one it leaves bare, and the one that has to be spelled
/// `%26`.
///
/// ## Why `&` is escaped — measured, not assumed
///
/// An earlier version of this comment claimed a bare `&` "starts a query string". That is false,
/// and false in the one place it can be checked: `Url::parse("https://en.wikipedia.org/wiki/AT&T")`
/// has `query() == None`. The path stays the path. The reasons to escape it are different, and all
/// of them are real:
///
/// - **`&` *is* the query-string parameter separator**, so every consumer that re-reads a URL as a
///   query string — a log scrubber, an analytics tagger, a naive `split('&')` — reads a different
///   URL from the one that was fetched. Two spellings of one article is how a result set comes to
///   look bigger than it is.
/// - **It is a shell hazard.** This harness runs shell commands, and an unquoted `&` in a command
///   line backgrounds the command and silently discards the rest of it. A URL a model copies into
///   a command has to survive being pasted.
/// - **It is how Wikipedia spells its own article links** (`Barnes_%26_Noble`), so the same page
///   found by another engine and by this one canonicalise to one string and fuse into one result
///   rather than two.
///
/// ## What is deliberately NOT done
///
/// - **MediaWiki's own escaping exception list is not mirrored.** It is a spec this crate does not
///   own, and `push` already produces a correct URL for every character but `&`; reimplementing
///   the list would be guessing.
/// - **`+` is not escaped.** It is legal in a path and carries no path-level or shell-level
///   meaning, so escaping it would only make the emitted URL differ from the one a browser shows.
///   The asymmetry — `&` escaped, `+` left alone — is a decision, not an oversight.
pub fn wikipedia_article_url(api_base: &str, title: &str) -> Option<String> {
    let base = Url::parse(api_base).ok()?;
    let host = base.host_str()?;
    let scheme = base.scheme();
    // Only http(s) can address an article; a `mailto:` or `data:` base has no origin to build on.
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let origin = match base.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    let mut url = Url::parse(&format!("{origin}/wiki/")).ok()?;
    // `pop_if_empty` first: the base path ends in `/`, and pushing onto it without popping
    // produces `//wiki//Title` — a URL that still resolves on MediaWiki but is not the canonical
    // one, and would not de-duplicate against the same article found by another engine.
    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .push(&title.replace(' ', "_"));

    // `push` escapes `?`, `#` and `%` but leaves a bare `&` (measured above). There is no API to
    // ask it for one more character, and there is no point re-parsing the serialized form: `Url`
    // keeps an existing `%26` in a path verbatim, so it would neither help nor hurt. The fix is
    // therefore applied to the finished string. Doing it to the whole string rather than the path
    // segment alone is safe: this URL is built from `{origin}/wiki/` with no query and no
    // fragment, so the only `&` in it came out of the title. A title containing a literal `%` was
    // already escaped by `push` to `%25`, so nothing can be double-escaped here.
    Some(url.to_string().replace('&', "%26"))
}

#[derive(serde::Deserialize)]
struct MediaWikiResponse {
    #[serde(default)]
    query: Option<MediaWikiQuery>,
}

#[derive(serde::Deserialize)]
struct MediaWikiQuery {
    #[serde(default)]
    search: Vec<MediaWikiHit>,
}

#[derive(serde::Deserialize)]
struct MediaWikiHit {
    #[serde(default)]
    title: String,
    /// Carries `<span class="searchmatch">` around the matched terms.
    #[serde(default)]
    snippet: String,
}

#[async_trait]
impl SearchBackend for WikipediaBackend {
    fn id(&self) -> &str {
        "wikipedia"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Keyless
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let url = wikipedia_search_url(&self.api_base, query)?;
        let request_url = url.to_string();

        let response = client
            .get(url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(SearchError::Http {
                status: status.as_u16(),
            });
        }

        let body: MediaWikiResponse = response.json().await.map_err(|e| SearchError::Parse {
            reason: format!("expected MediaWiki JSON from {request_url}: {e}"),
        })?;

        let hits = body.query.map(|q| q.search).unwrap_or_default();

        let mut results: Vec<SearchResult> = hits
            .into_iter()
            .enumerate()
            .filter_map(|(rank, hit)| {
                let url = wikipedia_article_url(&self.api_base, &hit.title)?;
                Some(SearchResult {
                    title: hit.title,
                    url,
                    // The lead sentence is the snippet: MediaWiki marks the matched terms and
                    // `clean_text` strips the marks rather than showing the markup to the model.
                    snippet: clean_text(&hit.snippet),
                    rank,
                })
            })
            .collect();

        if let Some(site) = &query.site {
            results.retain(|result| host_matches(&result.url, site));
        }

        Ok(results.into_iter().take(query.limit).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A live capture**: `GET https://en.wikipedia.org/w/api.php?action=query&list=search&
    /// srsearch=rust%20programming&format=json&srlimit=3` from this environment, verbatim. The
    /// `continue` field and the `searchmatch` spans are the real shapes.
    const WIKIPEDIA_FIXTURE: &str = r#"{"batchcomplete":"","continue":{"sroffset":3,"continue":"-||"},"query":{"searchinfo":{"totalhits":4725,"suggestion":"ruby programming","suggestionsnippet":"ruby programming"},"search":[{"ns":0,"title":"Rust (programming language)","pageid":29414838,"size":119319,"wordcount":10928,"snippet":"<span class=\"searchmatch\">Rust</span> is a general-purpose <span class=\"searchmatch\">programming</span> language that emphasizes performance, type safety, concurrency, and memory safety. <span class=\"searchmatch\">Rust</span> supports multiple programming","timestamp":"2026-09-18T17:06:40Z"},{"ns":0,"title":"Outline of the Rust programming language","pageid":81297551,"size":16807,"wordcount":1080,"snippet":"topical guide to <span class=\"searchmatch\">Rust</span>: <span class=\"searchmatch\">Rust</span> is a multi-paradigm <span class=\"searchmatch\">programming</span> language emphasizing performance, memory safety, and concurrency. <span class=\"searchmatch\">Rust</span> was initially developed","timestamp":"2026-05-27T12:01:42Z"},{"ns":0,"title":"Rust syntax","pageid":66392073,"size":50650,"wordcount":4777,"snippet":"functional <span class=\"searchmatch\">programming</span> languages such as OCaml. Although <span class=\"searchmatch\">Rust</span> syntax is heavily influenced by the syntaxes of C and C++, the syntax of <span class=\"searchmatch\">Rust</span> is far more","timestamp":"2026-04-08T07:11:07Z"}]}}"#;

    fn parse(json: &str) -> Vec<SearchResult> {
        let body: MediaWikiResponse = serde_json::from_str(json).expect("the captured shape");
        let hits = body.query.map(|q| q.search).unwrap_or_default();
        hits.into_iter()
            .enumerate()
            .filter_map(|(rank, hit)| {
                let url = wikipedia_article_url("https://en.wikipedia.org/w/api.php", &hit.title)?;
                Some(SearchResult {
                    title: hit.title,
                    url,
                    snippet: clean_text(&hit.snippet),
                    rank,
                })
            })
            .collect()
    }

    #[test]
    fn parses_titles_urls_and_snippets_from_a_live_capture() {
        let results = parse(WIKIPEDIA_FIXTURE);

        assert_eq!(results.len(), 3, "{results:#?}");
        assert_eq!(results[0].title, "Rust (programming language)");
        assert_eq!(
            results[0].url,
            "https://en.wikipedia.org/wiki/Rust_(programming_language)"
        );
        assert_eq!(results[0].rank, 0);
        assert_eq!(results[2].url, "https://en.wikipedia.org/wiki/Rust_syntax");
    }

    #[test]
    fn the_searchmatch_spans_are_stripped_from_snippets() {
        // Showing `<span class="searchmatch">` to a model is showing it markup.
        let results = parse(WIKIPEDIA_FIXTURE);
        assert!(
            results
                .iter()
                .all(|r| !r.snippet.contains("searchmatch") && !r.snippet.contains('<')),
            "{results:#?}"
        );
        assert!(
            results[0]
                .snippet
                .starts_with("Rust is a general-purpose programming language"),
            "{}",
            results[0].snippet
        );
    }

    #[test]
    fn a_response_with_no_query_object_parses_to_nothing() {
        assert!(parse(r#"{"batchcomplete":""}"#).is_empty());
        assert!(parse(r#"{"query":{"search":[]}}"#).is_empty());
    }

    #[test]
    fn article_urls_encode_spaces_and_punctuation() {
        assert_eq!(
            wikipedia_article_url(
                "https://en.wikipedia.org/w/api.php",
                "Rust (programming language)"
            )
            .unwrap(),
            "https://en.wikipedia.org/wiki/Rust_(programming_language)"
        );
        // `+` is a legal path character and carries no path-level or shell-level meaning, so it
        // survives unescaped. That asymmetry with `&` is deliberate — see `wikipedia_article_url`.
        assert_eq!(
            wikipedia_article_url("https://en.wikipedia.org/w/api.php", "C++").unwrap(),
            "https://en.wikipedia.org/wiki/C++"
        );
        // An ampersand is escaped to `%26`. The comment that used to sit here claimed a bare `&`
        // "starts a query string" — it does not; `Url::parse(".../AT&T").query()` is `None`. It is
        // escaped because `&` is the parameter separator for anything that re-reads the URL as a
        // query string, because an unquoted `&` backgrounds a shell command, and because `%26` is
        // how Wikipedia spells the same link — so one article found by two engines fuses once.
        assert_eq!(
            wikipedia_article_url("https://en.wikipedia.org/w/api.php", "AT&T").unwrap(),
            "https://en.wikipedia.org/wiki/AT%26T"
        );
        // And a title with no `&` is emitted unchanged: the fix must not touch anything else.
        assert_eq!(
            wikipedia_article_url("https://en.wikipedia.org/w/api.php", "Barnes & Noble").unwrap(),
            "https://en.wikipedia.org/wiki/Barnes_%26_Noble"
        );
    }

    #[test]
    fn article_urls_follow_a_self_hosted_api_base() {
        assert_eq!(
            wikipedia_article_url("http://wiki.internal/w/api.php", "Main Page").unwrap(),
            "http://wiki.internal/wiki/Main_Page"
        );
        // A base with no origin cannot name an article.
        assert!(wikipedia_article_url("not a url", "X").is_none());
    }

    // ---- URL construction ----

    #[test]
    fn wikipedia_url_asks_the_search_list_and_pins_formatversion_one() {
        let url = wikipedia_search_url(
            "https://en.wikipedia.org/w/api.php",
            &SearchQuery::new("rust programming").with_limit(8),
        )
        .unwrap();
        let q = url.query().unwrap();
        assert!(q.contains("action=query"), "{q}");
        assert!(q.contains("list=search"), "{q}");
        assert!(q.contains("formatversion=1"), "{q}");
        assert!(q.contains("srlimit=8"), "{q}");
        assert!(
            q.contains("srsearch=rust+programming") || q.contains("srsearch=rust%20programming"),
            "{q}"
        );
    }

    #[test]
    fn wikipedia_result_limit_is_clamped_below_the_apis_ceiling() {
        // 500 results from one backend would dominate the fusion by volume alone.
        let url = wikipedia_search_url(
            "https://en.wikipedia.org/w/api.php",
            &SearchQuery::new("x").with_limit(5000),
        )
        .unwrap();
        assert!(
            url.query().unwrap().contains("srlimit=50"),
            "{}",
            url.query().unwrap()
        );
    }

    #[test]
    fn wikipedia_does_not_fold_a_site_filter_into_the_search_terms() {
        // MediaWiki has no `site:` operator; folding would search for the literal token.
        let query = SearchQuery::new("async rust").with_site("docs.rs");
        let url = wikipedia_search_url("https://en.wikipedia.org/w/api.php", &query).unwrap();
        let q = url.query().unwrap();
        assert!(!q.contains("site"), "{q}");
        assert!(!q.contains("docs.rs"), "{q}");
    }

    #[test]
    fn wikipedia_url_rejects_an_empty_base() {
        let err = wikipedia_search_url("  ", &SearchQuery::new("x")).unwrap_err();
        assert!(matches!(err, SearchError::NotConfigured(_)), "{err}");
    }
}
