//! Brave Search — **keyed**, opt-in, and never a default.
//!
//! ## Why it is opt-in rather than merely optional
//!
//! Every other backend in this crate costs nothing to run, which is what makes M6's "zero paid API
//! calls" a property of the configuration rather than a promise about how it is used. Brave's Web
//! Search API is metered and needs a subscription token, so it can only ever be a deliberate act:
//! it is not on [`KEYLESS_BACKENDS`](crate::KEYLESS_BACKENDS), not in `default_backends()`, and a
//! test asserts that the registry built from a default config contains no keyed backend at all.
//!
//! ## The credential is a *reference*
//!
//! `search.credentials.brave` holds `vault:brave/search` or `env:BRAVE_SEARCH_KEY` — never the key.
//! It is resolved once, at registry construction, through `hx-secrets`, and the resolved value
//! lives in a [`Secret`] whose `Debug` is redacted. Nothing here can print it:
//!
//! - `Debug` on this type is written by hand and shows the id and endpoint only.
//! - An error names the *reference* and never the value.
//! - A transport failure goes through [`SearchError::transport_redacted`], because `reqwest::Error`'s
//!   own message includes the request URL.
//!
//! ## What is deliberately NOT done
//!
//! - **Recency is not forwarded.** Brave documents a `freshness` parameter, but it was not verified
//!   from this environment — a live call needs the paid key this build does not have — and an
//!   unverified parameter is a claim, not a feature. Omitted, and disclosed.
//! - **`site:` is not folded into `q`.** The operator could be honoured, but that is unverified
//!   too; the filter is applied to the returned URLs by host instead, which can only ever remove a
//!   result that violates it.
//! - **Only `q` and `count` are sent.** Both are central to the documented request shape; anything
//!   else (`safesearch`, `country`, `search_lang`) would be a guess about defaults this build cannot
//!   test.
//! - **`count` is clamped to 20**, which is the documented maximum, and not to the caller's limit.

use super::USER_AGENT;
use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{host_matches, SearchQuery, SearchResult};
use async_trait::async_trait;
use hx_secrets::Secret;
use url::Url;

/// The largest `count` the Web Search API documents.
pub const BRAVE_MAX_RESULTS: usize = 20;

/// The keyed Brave backend.
pub struct BraveBackend {
    key: Secret,
    endpoint: String,
}

impl BraveBackend {
    /// Build the backend from an already-resolved credential.
    pub fn new(key: Secret) -> Self {
        Self {
            key,
            endpoint: "https://api.search.brave.com/res/v1/web/search".to_string(),
        }
    }

    /// A different endpoint — a proxy in front of the API, or a test server.
    pub fn with_endpoint(key: Secret, endpoint: impl Into<String>) -> Self {
        Self {
            key,
            endpoint: endpoint.into(),
        }
    }
}

impl std::fmt::Debug for BraveBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written, not derived: `Secret`'s own `Debug` is redacted, but a derived one would
        // also make the credential's presence easy to forget when a field is added later.
        f.debug_struct("BraveBackend")
            .field("id", &"brave")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// Build the search URL for a query. Pure, so the parameter mapping is testable.
///
/// The key is **not** part of this URL: Brave takes it in the `X-Subscription-Token` header, which
/// is why this backend does not need the transport redaction Google PSE does.
pub fn brave_search_url(endpoint: &str, query: &SearchQuery) -> Result<Url, SearchError> {
    let base = endpoint.trim();
    if base.is_empty() {
        return Err(SearchError::NotConfigured(
            "brave endpoint is empty".to_string(),
        ));
    }
    let mut url = Url::parse(base).map_err(|e| {
        SearchError::NotConfigured(format!("brave endpoint {base:?} is not a valid URL: {e}"))
    })?;

    {
        let mut params = url.query_pairs_mut();
        params.append_pair("q", &query.text);
        params.append_pair(
            "count",
            &query.limit.clamp(1, BRAVE_MAX_RESULTS).to_string(),
        );
    }

    Ok(url)
}

#[derive(serde::Deserialize)]
struct BraveResponse {
    #[serde(default)]
    web: Option<BraveWeb>,
}

#[derive(serde::Deserialize)]
struct BraveWeb {
    #[serde(default)]
    results: Vec<BraveResult>,
}

#[derive(serde::Deserialize)]
struct BraveResult {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    /// Plain text, unlike Google's `htmlSnippet` — but `clean_text` is applied anyway so a stray
    /// entity or tag cannot reach the model.
    #[serde(default)]
    description: String,
}

/// Parse a Brave web-search response into results.
pub fn parse_brave_web(json: &str) -> Result<Vec<SearchResult>, SearchError> {
    let body: BraveResponse = serde_json::from_str(json).map_err(|e| SearchError::Parse {
        reason: format!("expected Brave web-search JSON: {e}"),
    })?;

    let hits = body.web.map(|w| w.results).unwrap_or_default();

    Ok(hits
        .into_iter()
        .enumerate()
        .filter(|(_, hit)| !hit.url.trim().is_empty())
        .map(|(rank, hit)| SearchResult {
            title: clean_title(&hit.title, &hit.url),
            url: hit.url.trim().to_string(),
            snippet: super::clean_text(&hit.description),
            rank,
        })
        .collect())
}

/// A result with an empty title is still worth returning when it has a URL, so the title falls back
/// to the host rather than rendering as a blank line the model has to guess about.
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
impl SearchBackend for BraveBackend {
    fn id(&self) -> &str {
        "brave"
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
        let url = brave_search_url(&self.endpoint, query)?;
        let request_url = url.to_string();

        let response = client
            .get(url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("X-Subscription-Token", self.key.expose())
            .send()
            .await
            // Even though the key is in a header and not the URL, this goes through the redacting
            // conversion: `reqwest::Error` prints the request URL, and a future change that moved
            // the credential into the query string must not be able to leak it.
            .map_err(|e| SearchError::transport_redacted(e, &self.key))?;

        let status = response.status();
        if !status.is_success() {
            // The status only. A body from a metered API can quote the request, and this error
            // reaches a model.
            return Err(SearchError::Http {
                status: status.as_u16(),
            });
        }

        let body = response.text().await.map_err(|e| SearchError::Parse {
            reason: format!("could not read the response body from {request_url}: {e}"),
        })?;

        let mut results = parse_brave_web(&body)?;

        if let Some(site) = &query.site {
            results.retain(|result| host_matches(&result.url, site));
        }

        Ok(results.into_iter().take(query.limit).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The documented response shape, not a live capture.** Brave's Web Search API needs a paid
    /// subscription token, which this build does not have, so this is the example response from
    /// Brave's own response reference rather than something fetched. That is weaker evidence than
    /// the live captures the keyless backends are tested against, and it is said here rather than
    /// glossed: a field renamed upstream would not be caught until an operator with a key ran it.
    const BRAVE_FIXTURE: &str = r#"{
      "type": "search",
      "web": {
        "type": "search",
        "results": [
          {
            "title": "Brave Search API",
            "url": "https://brave.com/search/api/",
            "is_source_local": false,
            "is_source_both": false,
            "description": "The Brave Search API gives you programmatic access to Brave's independent index.",
            "profile": {"name": "Brave", "url": "https://brave.com", "long_name": "brave.com"},
            "language": "en",
            "family_friendly": true,
            "type": "search_result",
            "subtype": "generic",
            "meta_url": {"scheme": "https", "netloc": "brave.com", "hostname": "brave.com", "path": "› search › api"},
            "age": "2 days ago"
          },
          {
            "title": "Rust &amp; WebAssembly",
            "url": "https://rustwasm.test/guide",
            "description": "A guide to <b>Rust</b> and the web &mdash; compiled to wasm.",
            "language": "en",
            "family_friendly": true
          },
          {
            "title": "",
            "url": "https://untitled.test/page",
            "description": "A page whose title the index did not record."
          }
        ]
      }
    }"#;

    fn key() -> Secret {
        Secret::new("BSA-not-a-real-token")
    }

    #[test]
    fn parses_titles_urls_and_snippets_from_the_documented_shape() {
        let results = parse_brave_web(BRAVE_FIXTURE).unwrap();

        assert_eq!(results.len(), 3, "{results:#?}");
        assert_eq!(results[0].title, "Brave Search API");
        assert_eq!(results[0].url, "https://brave.com/search/api/");
        assert_eq!(results[0].rank, 0);
        assert_eq!(
            results[0].snippet,
            "The Brave Search API gives you programmatic access to Brave's independent index."
        );
    }

    #[test]
    fn entities_and_markup_are_cleaned_out_of_a_title_and_a_description() {
        let results = parse_brave_web(BRAVE_FIXTURE).unwrap();
        assert_eq!(results[1].title, "Rust & WebAssembly");
        assert!(
            !results[1].snippet.contains('<') && !results[1].snippet.contains("&mdash;"),
            "{}",
            results[1].snippet
        );
        assert!(
            results[1]
                .snippet
                .contains("Rust and the web — compiled to wasm"),
            "{}",
            results[1].snippet
        );
    }

    #[test]
    fn a_result_with_no_title_falls_back_to_its_host_rather_than_rendering_blank() {
        let results = parse_brave_web(BRAVE_FIXTURE).unwrap();
        assert_eq!(results[2].title, "untitled.test");
        assert_eq!(results[2].url, "https://untitled.test/page");
    }

    #[test]
    fn a_response_with_no_web_object_or_no_results_parses_to_nothing() {
        assert!(parse_brave_web(r#"{"type":"search"}"#).unwrap().is_empty());
        assert!(parse_brave_web(r#"{"web":{"results":[]}}"#)
            .unwrap()
            .is_empty());
        // A result with no URL is nothing to point at.
        assert!(parse_brave_web(r#"{"web":{"results":[{"title":"x"}]}}"#)
            .unwrap()
            .is_empty());
        // But a body that is not a Brave response at all is a loud parse error, not silence.
        let err = parse_brave_web("<html>nope</html>").unwrap_err();
        assert!(matches!(err, SearchError::Parse { .. }), "{err}");
    }

    // ---- URL construction ----

    #[test]
    fn brave_url_carries_the_query_and_a_clamped_count() {
        let url = brave_search_url(
            "https://api.search.brave.com/res/v1/web/search",
            &SearchQuery::new("rust async").with_limit(5),
        )
        .unwrap();
        let q = url.query().unwrap();
        assert!(q.contains("count=5"), "{q}");
        assert!(
            q.contains("q=rust+async") || q.contains("q=rust%20async"),
            "{q}"
        );

        let url = brave_search_url(
            "https://api.search.brave.com/res/v1/web/search",
            &SearchQuery::new("x").with_limit(500),
        )
        .unwrap();
        assert!(
            url.query().unwrap().contains("count=20"),
            "the documented maximum: {}",
            url.query().unwrap()
        );
    }

    #[test]
    fn brave_url_carries_no_credential() {
        // The key travels in a header. If that ever changes, the transport redaction is what stops
        // it reaching an error, and this test is the reminder that it changed.
        let url = brave_search_url(
            "https://api.search.brave.com/res/v1/web/search",
            &SearchQuery::new("x"),
        )
        .unwrap();
        assert!(!url.as_str().contains("key"), "{url}");
        assert!(!url.as_str().contains("token"), "{url}");
    }

    #[test]
    fn brave_url_rejects_an_empty_endpoint() {
        let err = brave_search_url("  ", &SearchQuery::new("x")).unwrap_err();
        assert!(matches!(err, SearchError::NotConfigured(_)), "{err}");
    }

    #[test]
    fn the_debug_of_the_backend_never_prints_the_credential() {
        let backend = BraveBackend::new(key());
        let printed = format!("{backend:?}");
        assert!(!printed.contains("BSA-not-a-real-token"), "{printed}");
        assert!(printed.contains("brave"), "{printed}");
    }
}
