//! Concrete backends.
//!
//! Parsing is deliberately kept in free functions (`parse_ddg_lite`, `searxng_search_url`,
//! `unwrap_ddg_redirect`, `clean_text`) rather than buried inside the `search` methods. Scraped
//! HTML is the most fragile part of this crate and the part most likely to need fixing at short
//! notice; keeping it pure means it can be tested against a saved fixture with no network, which
//! is what makes that fix a two-minute job instead of an afternoon.

use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{SearchQuery, SearchResult};
use async_trait::async_trait;
use regex::Regex;
use std::sync::OnceLock;
use url::Url;

/// A current desktop user-agent. Keyless endpoints reject obvious library strings, and DDG in
/// particular serves a bot check to `reqwest/0.x`.
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

// ---------------------------------------------------------------------------
// SearXNG
// ---------------------------------------------------------------------------

/// A SearXNG instance.
///
/// The highest-value backend to configure: one JSON endpoint in front of ~70 engines, including
/// the ones worth having (Google, Bing, Brave, Mojeek, Marginalia, Wikipedia, GitHub, arXiv).
/// Self-hosting it also means the queries are not handed to a third party.
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

// ---------------------------------------------------------------------------
// DuckDuckGo (keyless, scraped)
// ---------------------------------------------------------------------------

/// The keyless DuckDuckGo scraper.
///
/// Best-effort by nature: DDG will serve a bot check to a determined caller, which is why the
/// failure is surfaced as a `Parse` error mentioning the bot check rather than as "no results".
/// The result then shows up in `SearchReport::failures` where a human can see it.
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

fn tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<[^>]*>").expect("valid regex"))
}

/// Parse the `lite.duckduckgo.com` result table.
///
/// Titles/snippets and snippets come back in "link row, snippet row" pairs. Anchors are filtered
/// on `result-link` rather than positioned by index, because the page also carries navigation and
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

/// Rough signal that a response is an anti-bot page rather than a result page.
pub fn looks_like_a_bot_check(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    // A real result page always contains result-link anchors, so its absence plus any of these
    // markers is strong enough evidence to report a failure instead of a silent empty result.
    lower.contains("anomaly")
        || lower.contains("unusual traffic")
        || lower.contains("enable javascript")
        || lower.contains("challenge-form")
        || lower.contains("captcha")
}

/// Strip tags, decode entities, and collapse whitespace.
pub fn clean_text(html: &str) -> String {
    let without_tags = tag_re().replace_all(html, " ");
    let decoded = decode_entities(&without_tags);
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Decode the HTML entities that appear in scraped titles and snippets.
///
/// Hand-rolled rather than pulling in an HTML library: the entity set that actually shows up in
/// search results is tiny, and an unknown entity is passed through unchanged rather than dropped.
pub fn decode_entities(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '&' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        // Find the terminating ';' within a plausible entity length, stopping at a nested '&'.
        let mut end = None;
        for (offset, ch) in chars.iter().enumerate().skip(i + 1).take(10) {
            if *ch == ';' {
                end = Some(offset);
                break;
            }
            if *ch == '&' {
                break;
            }
        }

        let Some(end) = end else {
            out.push(chars[i]);
            i += 1;
            continue;
        };

        let entity: String = chars[i + 1..end].iter().collect();
        match lookup_entity(&entity) {
            Some(decoded) => {
                out.push(decoded);
                i = end + 1;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }

    out
}

fn lookup_entity(entity: &str) -> Option<char> {
    // The markup backbone.
    match entity {
        "amp" => return Some('&'),
        "lt" => return Some('<'),
        "gt" => return Some('>'),
        "quot" => return Some('"'),
        "apos" => return Some('\''),
        "nbsp" => return Some(' '),
        _ => {}
    }

    // Typographic entities that turn up constantly in scraped titles and snippets. Without
    // these, a title reads "Docs &mdash; Getting Started", which looks like a bug to anyone
    // reading the transcript.
    match entity {
        "mdash" => return Some('—'),
        "ndash" => return Some('–'),
        "hellip" => return Some('…'),
        "lsquo" => return Some('\u{2018}'),
        "rsquo" => return Some('\u{2019}'),
        "ldquo" => return Some('\u{201C}'),
        "rdquo" => return Some('\u{201D}'),
        "laquo" => return Some('«'),
        "raquo" => return Some('»'),
        "middot" => return Some('·'),
        "bull" => return Some('•'),
        "times" => return Some('×'),
        "divide" => return Some('÷'),
        "deg" => return Some('°'),
        "plusmn" => return Some('±'),
        "euro" => return Some('€'),
        "pound" => return Some('£'),
        "yen" => return Some('¥'),
        "cent" => return Some('¢'),
        "copy" => return Some('©'),
        "reg" => return Some('®'),
        "trade" => return Some('™'),
        "sect" => return Some('§'),
        "para" => return Some('¶'),
        "prime" => return Some('′'),
        "Prime" => return Some('″'),
        "ne" => return Some('≠'),
        "le" => return Some('≤'),
        "ge" => return Some('≥'),
        "eacute" => return Some('é'),
        "egrave" => return Some('è'),
        "agrave" => return Some('à'),
        "ccedil" => return Some('ç'),
        "uuml" => return Some('ü'),
        "ouml" => return Some('ö'),
        "auml" => return Some('ä'),
        "szlig" => return Some('ß'),
        "ntilde" => return Some('ñ'),
        _ => {}
    }

    if let Some(hex) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
    }

    entity
        .strip_prefix('#')
        .and_then(|dec| dec.parse::<u32>().ok())
        .and_then(char::from_u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Recency;

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
    fn typographic_entities_are_decoded() {
        assert_eq!(decode_entities("Docs &mdash; Start"), "Docs — Start");
        assert_eq!(decode_entities("a&hellip;"), "a…");
        assert_eq!(decode_entities("it&rsquo;s"), "it’s");
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
    fn bot_check_pages_are_recognised() {
        assert!(looks_like_a_bot_check(
            "<html><body>Our systems have detected unusual traffic from your network</body></html>"
        ));
        assert!(looks_like_a_bot_check("<div class=\"challenge-form\">"));
        assert!(!looks_like_a_bot_check(DDG_FIXTURE));
    }

    #[test]
    fn entities_are_decoded_including_numeric_and_hex() {
        assert_eq!(decode_entities("a &amp; b"), "a & b");
        assert_eq!(decode_entities("&lt;tag&gt;"), "<tag>");
        assert_eq!(decode_entities("caf&#233;"), "café");
        assert_eq!(decode_entities("caf&#xe9;"), "café");
        assert_eq!(decode_entities("x&nbsp;y"), "x y");
    }

    #[test]
    fn unknown_and_unterminated_entities_pass_through_unchanged() {
        // Better a stray "&" in a title than silently deleting text.
        assert_eq!(decode_entities("a &foo; b"), "a &foo; b");
        assert_eq!(decode_entities("a & b"), "a & b");
        assert_eq!(decode_entities("R&D"), "R&D");
    }

    #[test]
    fn clean_text_strips_markup_and_collapses_whitespace() {
        assert_eq!(
            clean_text("  <b>bold</b>\n   text  <i>x</i> "),
            "bold text x"
        );
    }

    // ---- SearXNG URL construction ----

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
