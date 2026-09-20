//! Google Programmable Search — **keyed**, opt-in, and never a default.
//!
//! ## The one backend here whose request URL carries a credential
//!
//! Google's Custom Search JSON API takes its key as a **query parameter** (`?key=…`), not a header.
//! That single fact drives most of this file, because it turns three ordinary things into leaks:
//!
//! 1. **A transport error.** `reqwest::Error`'s `Display` includes the request URL, so the default
//!    `#[from]` conversion into [`SearchError::Transport`] would put a live key into an error the
//!    model reads. Every failure here converts through [`SearchError::transport_redacted`], which
//!    masks the value with the crate's own [`Redactor`](hx_secrets::Redactor). There is a test that
//!    builds a *real* `reqwest::Error` containing a sentinel key, asserts the raw error genuinely
//!    contains it, and then asserts the converted one does not.
//! 2. **A `Debug`.** This type's `Debug` is written by hand and shows the id and the engine id only.
//!    The engine id is not a secret — see below — but the key must not be reachable through `{:?}`.
//! 3. **A log line or a cache key.** The URL is never logged, and the cache in `cache.rs` keys on a
//!    URL whose query string is dropped rather than stored, because a key in a cache key is a key
//!    written to disk.
//!
//! ## Two values, and only one of them is a secret
//!
//! The API needs a `cx` (the id of a search engine the operator configured in Google's console) as
//! well as a `key`. `cx` appears in every result URL and identifies rather than authorises, so it is
//! a plain `search.google_cse_cx` value — putting it in the vault would obscure something that is
//! not hidden. The `key` is a credential and comes from `search.credentials.google_cse` as a
//! *reference* (`vault:google/cse` or `env:GOOGLE_CSE_KEY`), resolved once through `hx-secrets`.
//!
//! ## What is deliberately NOT done
//!
//! - **Recency is not forwarded.** Google documents `dateRestrict`, but it was not verified from
//!   this environment — a live call needs the paid key this build does not have — and an unverified
//!   parameter is a claim rather than a feature.
//! - **`site:` is not folded into `q`.** The filter is applied to the returned URLs by host, which
//!   can only ever remove a result that violates it.
//! - **`htmlTitle`/`htmlSnippet` are ignored.** Google returns the matched terms marked up
//!   (`<b>Rust</b>`) beside clean `title`/`snippet`. The clean pair is read, the same choice the
//!   Hacker News backend makes about `_highlightResult`.
//! - **`num` is clamped to 10**, the documented maximum for this endpoint.

use super::USER_AGENT;
use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{host_matches, SearchQuery, SearchResult};
use async_trait::async_trait;
use hx_secrets::Secret;
use url::Url;

/// The largest `num` the JSON API documents for one request.
pub const GOOGLE_CSE_MAX_RESULTS: usize = 10;

/// The keyed Google Programmable Search backend.
pub struct GoogleCseBackend {
    key: Secret,
    cx: String,
    endpoint: String,
}

impl GoogleCseBackend {
    /// Build the backend from an already-resolved credential and the engine id.
    pub fn new(key: Secret, cx: impl Into<String>) -> Self {
        Self {
            key,
            cx: cx.into(),
            endpoint: "https://www.googleapis.com/customsearch/v1".to_string(),
        }
    }

    pub fn with_endpoint(key: Secret, cx: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            key,
            cx: cx.into(),
            endpoint: endpoint.into(),
        }
    }
}

impl std::fmt::Debug for GoogleCseBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written: `Secret`'s own `Debug` is redacted, but this type's request URL carries the
        // key, so the habit that matters is never reaching for a derived one here.
        f.debug_struct("GoogleCseBackend")
            .field("id", &"google_cse")
            .field("endpoint", &self.endpoint)
            // The engine id identifies a configured search engine and is not a secret.
            .field("cx", &self.cx)
            .finish_non_exhaustive()
    }
}

/// Build the search URL for a query. Pure, so the parameter mapping is testable.
///
/// Takes the key explicitly because this endpoint requires it as a query parameter. The returned URL
/// **contains a credential** — callers must not log it, store it as a cache key, or put it in an
/// error message.
pub fn google_cse_search_url(
    endpoint: &str,
    key: &str,
    cx: &str,
    query: &SearchQuery,
) -> Result<Url, SearchError> {
    let base = endpoint.trim();
    if base.is_empty() {
        return Err(SearchError::NotConfigured(
            "google_cse endpoint is empty".to_string(),
        ));
    }
    if key.trim().is_empty() {
        return Err(SearchError::NotConfigured(
            "the google_cse credential resolved to an empty value".to_string(),
        ));
    }
    if cx.trim().is_empty() {
        return Err(SearchError::NotConfigured(
            "google_cse cx is empty".to_string(),
        ));
    }

    let mut url = Url::parse(base).map_err(|e| {
        SearchError::NotConfigured(format!(
            "google_cse endpoint {base:?} is not a valid URL: {e}"
        ))
    })?;

    {
        let mut params = url.query_pairs_mut();
        params.append_pair("key", key);
        params.append_pair("cx", cx);
        params.append_pair("q", &query.text);
        params.append_pair(
            "num",
            &query.limit.clamp(1, GOOGLE_CSE_MAX_RESULTS).to_string(),
        );
    }

    Ok(url)
}

#[derive(serde::Deserialize)]
struct CseResponse {
    #[serde(default)]
    items: Vec<CseItem>,
}

#[derive(serde::Deserialize)]
struct CseItem {
    /// Clean. `htmlTitle` is the marked-up twin and is deliberately not read.
    #[serde(default)]
    title: String,
    /// The result URL. Google spells it `link`.
    #[serde(default)]
    link: String,
    /// Clean. `htmlSnippet` is the marked-up twin.
    #[serde(default)]
    snippet: String,
}

/// Parse a Custom Search JSON response into results.
pub fn parse_google_cse(json: &str) -> Result<Vec<SearchResult>, SearchError> {
    let body: CseResponse = serde_json::from_str(json).map_err(|e| SearchError::Parse {
        reason: format!("expected Google Custom Search JSON: {e}"),
    })?;

    Ok(body
        .items
        .into_iter()
        .enumerate()
        .filter(|(_, item)| !item.link.trim().is_empty())
        .map(|(rank, item)| SearchResult {
            title: clean_title(&item.title, &item.link),
            url: item.link.trim().to_string(),
            snippet: super::clean_text(&item.snippet),
            rank,
        })
        .collect())
}

/// A result with an empty title still has a URL worth returning, so the title falls back to the
/// host rather than rendering as a blank line the model has to guess about.
fn clean_title(title: &str, url: &str) -> String {
    let cleaned = super::clean_text(title);
    if !cleaned.is_empty() {
        return cleaned;
    }
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

#[async_trait]
impl SearchBackend for GoogleCseBackend {
    fn id(&self) -> &str {
        "google_cse"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Keyed
    }

    fn requires_key(&self) -> bool {
        true
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let url = google_cse_search_url(&self.endpoint, self.key.expose(), &self.cx, query)?;

        let response = client
            .get(url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            // Load-bearing, not defensive: the URL above has the key in it and `reqwest::Error`
            // prints the URL. See the module docs.
            .map_err(|e| SearchError::transport_redacted(e, &self.key))?;

        let status = response.status();
        if !status.is_success() {
            // The status only — never the URL, and never the body, which can quote the request.
            return Err(SearchError::Http {
                status: status.as_u16(),
            });
        }

        // No URL in this message either, for the same reason.
        let body = response.text().await.map_err(|e| SearchError::Parse {
            reason: format!("could not read the Google Custom Search response body: {e}"),
        })?;

        let mut results = parse_google_cse(&body)?;

        if let Some(site) = &query.site {
            results.retain(|result| host_matches(&result.url, site));
        }

        Ok(results.into_iter().take(query.limit).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The documented response shape, not a live capture.** The JSON API needs a key billed to a
    /// Google Cloud project, which this build does not have, so this is the documented `cse#list`
    /// response rather than something fetched. Weaker evidence than the live captures the keyless
    /// backends are tested against, and said so here rather than glossed.
    const CSE_FIXTURE: &str = r#"{
      "kind": "customsearch#search",
      "url": {"type": "application/json", "template": "https://www.googleapis.com/customsearch/v1?q={searchTerms}&num={count?}&start={startIndex?}&cx={cx?}"},
      "queries": {"request": [{"title": "Google Custom Search - rust async", "totalResults": "1240000", "searchTerms": "rust async", "count": 2, "startIndex": 1, "inputEncoding": "utf8", "outputEncoding": "utf8", "safe": "off", "cx": "0123456789abcdef0"}]},
      "context": {"title": "docs.rs"},
      "searchInformation": {"searchTime": 0.312, "formattedSearchTime": "0.31", "totalResults": "1240000", "formattedTotalResults": "1,240,000"},
      "items": [
        {
          "kind": "customsearch#result",
          "title": "tokio - Rust",
          "htmlTitle": "<b>tokio</b> - Rust",
          "link": "https://docs.rs/tokio/latest/tokio/",
          "displayLink": "docs.rs",
          "snippet": "An asynchronous runtime &mdash; the foundation most async Rust runs on.",
          "htmlSnippet": "An asynchronous runtime &mdash; the foundation most async <b>Rust</b> runs on.",
          "cacheId": "abc123",
          "formattedUrl": "https://docs.rs/tokio/latest/tokio/",
          "htmlFormattedUrl": "https://docs.rs/tokio/latest/tokio/"
        },
        {
          "kind": "customsearch#result",
          "title": "",
          "htmlTitle": "",
          "link": "https://untitled.test/page",
          "displayLink": "untitled.test",
          "snippet": "A page whose title the index did not record."
        }
      ]
    }"#;

    fn key() -> Secret {
        Secret::new("GOOGLE-CSE-sentinel-key")
    }

    fn cx() -> &'static str {
        "0123456789abcdef0"
    }

    #[test]
    fn parses_titles_urls_and_snippets_from_the_documented_shape() {
        let results = parse_google_cse(CSE_FIXTURE).unwrap();

        assert_eq!(results.len(), 2, "{results:#?}");
        assert_eq!(results[0].title, "tokio - Rust");
        assert_eq!(results[0].url, "https://docs.rs/tokio/latest/tokio/");
        assert_eq!(results[0].rank, 0);
        assert_eq!(
            results[0].snippet,
            "An asynchronous runtime — the foundation most async Rust runs on."
        );
    }

    #[test]
    fn the_marked_up_spelling_never_reaches_a_result() {
        // `htmlTitle` is `<b>tokio</b> - Rust` and `htmlSnippet` wraps `Rust` in `<b>`. Reading
        // either would hand the model markup.
        let results = parse_google_cse(CSE_FIXTURE).unwrap();
        assert!(
            results
                .iter()
                .all(|r| !r.title.contains('<') && !r.snippet.contains('<')),
            "{results:#?}"
        );
        assert!(
            results
                .iter()
                .all(|r| !r.title.contains("&") && !r.snippet.contains("&mdash;")),
            "{results:#?}"
        );
    }

    #[test]
    fn a_result_with_no_title_falls_back_to_its_host_rather_than_rendering_blank() {
        let results = parse_google_cse(CSE_FIXTURE).unwrap();
        assert_eq!(results[1].title, "untitled.test");
    }

    #[test]
    fn a_response_with_no_items_parses_to_nothing_rather_than_failing() {
        assert!(parse_google_cse(r#"{"kind":"customsearch#search"}"#)
            .unwrap()
            .is_empty());
        assert!(parse_google_cse(r#"{"items":[]}"#).unwrap().is_empty());
        // A result with no link is nothing to point at.
        assert!(parse_google_cse(r#"{"items":[{"title":"x"}]}"#)
            .unwrap()
            .is_empty());
        // But a body that is not a Custom Search response is a loud parse error, not silence.
        let err = parse_google_cse("<html>nope</html>").unwrap_err();
        assert!(matches!(err, SearchError::Parse { .. }), "{err}");
    }

    // ---- URL construction ----

    #[test]
    fn google_cse_url_carries_the_key_the_engine_id_the_query_and_a_clamped_num() {
        let url = google_cse_search_url(
            "https://www.googleapis.com/customsearch/v1",
            "SENTINEL",
            cx(),
            &SearchQuery::new("rust async").with_limit(3),
        )
        .unwrap();
        let q = url.query().unwrap();
        assert!(q.contains("key=SENTINEL"), "{q}");
        assert!(q.contains(&format!("cx={}", cx())), "{q}");
        assert!(q.contains("num=3"), "{q}");
        assert!(
            q.contains("q=rust+async") || q.contains("q=rust%20async"),
            "{q}"
        );

        let url = google_cse_search_url(
            "https://www.googleapis.com/customsearch/v1",
            "SENTINEL",
            cx(),
            &SearchQuery::new("x").with_limit(500),
        )
        .unwrap();
        assert!(
            url.query().unwrap().contains("num=10"),
            "the documented maximum: {}",
            url.query().unwrap()
        );
    }

    #[test]
    fn google_cse_url_refuses_an_empty_endpoint_key_or_engine_id() {
        for err in [
            google_cse_search_url("  ", "k", cx(), &SearchQuery::new("x")).unwrap_err(),
            google_cse_search_url("https://a.test/", "  ", cx(), &SearchQuery::new("x"))
                .unwrap_err(),
            google_cse_search_url("https://a.test/", "k", "  ", &SearchQuery::new("x"))
                .unwrap_err(),
        ] {
            assert!(matches!(err, SearchError::NotConfigured(_)), "{err}");
            // The key is never named in a refusal.
            assert!(!err.to_string().contains("k\""), "{err}");
        }
    }

    #[test]
    fn the_debug_of_the_backend_never_prints_the_credential() {
        let backend = GoogleCseBackend::new(key(), cx());
        let printed = format!("{backend:?}");
        assert!(!printed.contains("GOOGLE-CSE-sentinel-key"), "{printed}");
        assert!(printed.contains("google_cse"), "{printed}");
        assert!(
            printed.contains(cx()),
            "the engine id is not a secret and is useful in diagnostics: {printed}"
        );
    }

    /// A **real** `reqwest::Error` carrying a sentinel, so the redaction is tested against the thing
    /// that actually leaks rather than against a string this test made up.
    #[tokio::test]
    async fn a_transport_error_never_carries_the_key_that_was_in_the_url() {
        const SENTINEL: &str = "GOOGLE-CSE-sentinel-key";
        // Port 1 on the loopback interface: refused immediately, so this suite needs no network and
        // never reaches Google. The URL shape is the one the backend really builds.
        let url = format!("http://127.0.0.1:1/customsearch/v1?key={SENTINEL}&cx=c&q=x");
        let raw = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect_err("port 1 on loopback refuses");

        // The control, first: the raw error genuinely carries the key, so this test would fail if
        // `reqwest` ever stopped printing the URL (i.e. if it stopped being a real hazard).
        assert!(
            raw.to_string().contains(SENTINEL),
            "the premise of this test is that a reqwest error prints its URL: {raw}"
        );

        let converted = SearchError::transport_redacted(raw, &Secret::new(SENTINEL));
        let text = converted.to_string();
        assert!(
            !text.contains(SENTINEL),
            "a key must never reach an error the model reads: {text}"
        );
        assert!(
            text.contains("REDACTED"),
            "the value should be masked, not the whole message discarded: {text}"
        );
    }

    #[tokio::test]
    async fn a_transport_error_with_nothing_to_redact_keeps_its_original_type() {
        // A URL with no credential in it must not be downgraded to an opaque string: the useful
        // detail, and the `#[from]` shape callers match on, survive.
        let raw = reqwest::Client::new()
            .get("http://127.0.0.1:1/customsearch/v1?q=x")
            .send()
            .await
            .expect_err("port 1 on loopback refuses");

        let converted =
            SearchError::transport_redacted(raw, &Secret::new("a-key-that-is-not-there"));
        assert!(
            matches!(converted, SearchError::Transport(_)),
            "nothing to hide means nothing to change: {converted}"
        );
    }
}
