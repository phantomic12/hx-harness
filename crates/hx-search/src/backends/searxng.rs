//! SearXNG — one JSON endpoint in front of ~70 engines.
//!
//! The highest-value backend to configure. Self-hosting it also means the queries are not handed
//! to a third party, and it is the one keyless backend that reliably answers a non-browser
//! client, because you host it.

use super::USER_AGENT;
use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{SearchQuery, SearchResult};
use async_trait::async_trait;
use url::Url;

/// A SearXNG instance.
pub struct SearxngBackend {
    base_url: String,
}

impl SearxngBackend {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
}

/// Build the `/search` URL for a query. Pure, so the parameter mapping is testable.
pub fn searxng_search_url(base: &str, query: &SearchQuery) -> Result<Url, SearchError> {
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(SearchError::NotConfigured(
            "searxng_url is empty".to_string(),
        ));
    }
    let mut url = Url::parse(&format!("{base}/search")).map_err(|e| {
        SearchError::NotConfigured(format!("searxng_url {base:?} is not a valid URL: {e}"))
    })?;

    {
        let mut params = url.query_pairs_mut();
        params.append_pair("q", &query.effective_text());
        params.append_pair("format", "json");
        // Search backends should not silently filter; relevance filtering is the caller's job.
        params.append_pair("safesearch", "0");
        if let Some(recency) = query.recency {
            params.append_pair("time_range", recency.searxng_code());
        }
    }

    Ok(url)
}

#[derive(serde::Deserialize)]
struct SearxResponse {
    #[serde(default)]
    results: Vec<SearxItem>,
}

#[derive(serde::Deserialize)]
struct SearxItem {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    content: String,
}

#[async_trait]
impl SearchBackend for SearxngBackend {
    fn id(&self) -> &str {
        "searxng"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Searxng
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let url = searxng_search_url(&self.base_url, query)?;

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

        let body: SearxResponse = response.json().await.map_err(|e| SearchError::Parse {
            reason: format!(
                "expected SearXNG JSON (is `format: json` enabled in the instance's \
                 settings.yml?): {e}"
            ),
        })?;

        Ok(body
            .results
            .into_iter()
            .filter(|item| !item.url.is_empty())
            .enumerate()
            .map(|(rank, item)| SearchResult {
                title: item.title,
                url: item.url,
                snippet: item.content,
                rank,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Recency;

    #[test]
    fn searxng_url_requests_json() {
        let url = searxng_search_url("http://localhost:8888", &SearchQuery::new("rust")).unwrap();
        assert!(url.path().ends_with("/search"));
        let q = url.query().unwrap();
        assert!(q.contains("format=json"), "{q}");
        assert!(q.contains("q=rust"), "{q}");
    }

    #[test]
    fn searxng_url_tolerates_a_trailing_slash_on_the_base() {
        let a = searxng_search_url("http://localhost:8888/", &SearchQuery::new("x")).unwrap();
        let b = searxng_search_url("http://localhost:8888", &SearchQuery::new("x")).unwrap();
        assert_eq!(a, b, "trailing slash must not produce //search");
        assert!(!a.as_str().contains("//search"), "{}", a);
    }

    #[test]
    fn searxng_url_carries_recency_and_site_filters() {
        let query = SearchQuery::new("async rust")
            .with_recency(Recency::Week)
            .with_site("docs.rs");
        let url = searxng_search_url("http://localhost:8888", &query).unwrap();
        let q = url.query().unwrap();
        assert!(q.contains("time_range=week"), "{q}");
        assert!(
            q.contains("site%3Adocs.rs") || q.contains("site:docs.rs"),
            "site filter must be folded into q: {q}"
        );
    }

    #[test]
    fn searxng_url_rejects_an_empty_base() {
        let err = searxng_search_url("   ", &SearchQuery::new("x")).unwrap_err();
        assert!(matches!(err, SearchError::NotConfigured(_)), "{err}");
    }

    #[test]
    fn searxng_url_rejects_a_non_url_base() {
        let err = searxng_search_url("not a url", &SearchQuery::new("x")).unwrap_err();
        assert!(err.to_string().contains("not a valid URL"), "{err}");
    }
}
