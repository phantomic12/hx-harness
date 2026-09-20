//! DuckDuckGo — keyless, scraped from the `lite.` HTML endpoint.
//!
//! Best-effort by nature: DDG will serve a bot check to a determined caller, which is why the
//! failure is surfaced as a `Parse` error mentioning the bot check rather than as "no results".
//! The result then shows up in `SearchReport::failures` where a human can see it.

use super::{clean_text, decode_entities, looks_like_a_bot_check, USER_AGENT};
use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{SearchQuery, SearchResult};
use async_trait::async_trait;
use regex::Regex;
use std::sync::OnceLock;
use url::Url;

/// The keyless DuckDuckGo scraper.
pub struct DuckDuckGoBackend {
    endpoint: String,
}

impl DuckDuckGoBackend {
    pub fn new() -> Self {
        Self {
            endpoint: "https://lite.duckduckgo.com/lite/".to_string(),
        }
    }

    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

impl Default for DuckDuckGoBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SearchBackend for DuckDuckGoBackend {
    fn id(&self) -> &str {
        "duckduckgo"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Keyless
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>, SearchError> {
        // Scoped so the `!Send` serializer is dropped before the request is awaited. Without
        // this the future is not `Send`, and `SearchBackend` could not be used from a
        // multi-threaded runtime at all.
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("q", &query.effective_text());
            form.append_pair("kl", "wt-wt");
            if let Some(recency) = query.recency {
                form.append_pair("df", recency.ddg_code());
            }
            form.finish()
        };

        let response = client
            .post(&self.endpoint)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .body(body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(SearchError::Http {
                status: status.as_u16(),
            });
        }

        let html = response.text().await?;
        let results = parse_ddg_lite(&html);

        if results.is_empty() && looks_like_a_bot_check(&html) {
            return Err(SearchError::Parse {
                reason: "DuckDuckGo served a bot check instead of results".to_string(),
            });
        }

        Ok(results.into_iter().take(query.limit).collect())
    }
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
    RE.get_or_init(|| {
        Regex::new(r#"(?is)<td[^>]*class=["']result-snippet["'][^>]*>(.*?)</td>"#)
            .expect("valid regex")
    })
}

/// Parse the `lite.duckduckgo.com` result table.
///
/// Titles and snippets come back in "link row, snippet row" pairs. Anchors are filtered on
/// `result-link` rather than positioned by index, because the page also carries navigation and
/// ad anchors that shift position between requests.
pub fn parse_ddg_lite(html: &str) -> Vec<SearchResult> {
    let anchors = anchor_re();
    let hrefs = href_re();

    let mut links: Vec<(String, String)> = Vec::new();
    for capture in anchors.captures_iter(html) {
        let attrs = capture.get(1).map(|m| m.as_str()).unwrap_or_default();
        if !attrs.contains("result-link") {
            continue;
        }
        let Some(href) = hrefs.captures(attrs).and_then(|c| c.get(1)) else {
            continue;
        };
        let title = clean_text(capture.get(2).map(|m| m.as_str()).unwrap_or_default());
        if title.is_empty() {
            continue;
        }
        links.push((title, unwrap_ddg_redirect(href.as_str())));
    }

    let snippets: Vec<String> = snippet_re()
        .captures_iter(html)
        .map(|c| clean_text(c.get(1).map(|m| m.as_str()).unwrap_or_default()))
        .collect();

    links
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

/// Recover the real destination from a DuckDuckGo click-tracking link.
///
/// DDG wraps outbound links as `/l/?uddg=<percent-encoded target>`. Fusing the wrapper URL would
/// collapse every result sharing the wrapper, so this unwrapping is load-bearing, not cosmetic.
pub fn unwrap_ddg_redirect(href: &str) -> String {
    let decoded = decode_entities(href.trim());

    let absolute = if let Some(rest) = decoded.strip_prefix("//") {
        format!("https://{rest}")
    } else if decoded.starts_with('/') {
        format!("https://duckduckgo.com{decoded}")
    } else {
        decoded.clone()
    };

    if let Ok(url) = Url::parse(&absolute) {
        for (key, value) in url.query_pairs() {
            if key == "uddg" {
                return value.into_owned();
            }
        }
    }

    absolute
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed copy of a real `lite.duckduckgo.com` response: a redirect-wrapped link, an
    /// entity in the title, markup inside the snippet, and a non-result anchor that must be
    /// ignored.
    const DDG_FIXTURE: &str = r#"
<html><body>
<table>
  <tr><td class="result-link-td">
    <a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage%3Fa%3D1%26b%3D2&amp;rut=9f3"
       class='result-link'>Example &amp; Co &mdash; Docs</a>
  </td></tr>
  <tr><td class='result-snippet'>A snippet about <b>example</b> things.</td></tr>

  <tr><td class="result-link-td">
    <a href="https://direct.example.org/second" class='result-link'>Second result</a>
  </td></tr>
  <tr><td class='result-snippet'>Another snippet.</td></tr>

  <tr><td><a href="/settings" class="nav-link">Settings</a></td></tr>
</table>
</body></html>
"#;

    #[test]
    fn parses_titles_urls_and_snippets_from_the_lite_table() {
        let results = parse_ddg_lite(DDG_FIXTURE);

        assert_eq!(results.len(), 2, "{results:#?}");
        assert_eq!(results[0].title, "Example & Co — Docs");
        assert_eq!(results[0].url, "https://example.com/page?a=1&b=2");
        assert_eq!(results[0].snippet, "A snippet about example things.");
        assert_eq!(results[0].rank, 0);
        assert_eq!(results[1].url, "https://direct.example.org/second");
        assert_eq!(results[1].rank, 1);
    }

    #[test]
    fn non_result_anchors_are_ignored() {
        let results = parse_ddg_lite(DDG_FIXTURE);
        assert!(
            !results.iter().any(|r| r.url.contains("/settings")),
            "navigation anchors must not become results"
        );
    }

    #[test]
    fn redirect_wrappers_are_unwrapped_to_the_real_destination() {
        assert_eq!(
            unwrap_ddg_redirect(
                "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage%3Fa%3D1&rut=x"
            ),
            "https://example.com/page?a=1"
        );
    }

    #[test]
    fn direct_and_relative_hrefs_are_handled() {
        assert_eq!(
            unwrap_ddg_redirect("https://example.org/x"),
            "https://example.org/x"
        );
        assert_eq!(
            unwrap_ddg_redirect("/l/?uddg=https%3A%2F%2Fa.test%2F"),
            "https://a.test/"
        );
    }

    #[test]
    fn a_paragraph_of_whitespace_still_parses_to_nothing() {
        assert!(parse_ddg_lite("<html><body>nothing here</body></html>").is_empty());
        assert!(parse_ddg_lite("").is_empty());
    }

    #[test]
    fn a_bot_check_page_yields_no_results() {
        // The pairing the backend relies on: no results *and* the marker. The error itself is
        // raised by `search`, but the parse must not invent results from a challenge page.
        let challenge = "<html><body>Our systems have detected unusual traffic from your \
                         network</body></html>";
        assert!(parse_ddg_lite(challenge).is_empty());
        assert!(looks_like_a_bot_check(challenge));
    }
}
