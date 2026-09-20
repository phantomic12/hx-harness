//! Hacker News, through the Algolia search API — keyless, and the sixth free backend.
//!
//! ## Why this one, and what it is not
//!
//! Hacker News is not a web index. It is a *filtered* corpus — submissions that a specific
//! technical community found worth discussing — and that is exactly why it earns a slot next to
//! five general engines. Its agreement with them is meaningful precisely because it is not derived
//! from them: a term with engine hits and no HN discussion is a topic nobody has argued about; a
//! term with HN hits and no engine hits is usually a tool, a paper or an outage, which is a shape
//! general search ranks badly.
//!
//! It is also the only backend here with a **real** API contract. `hn.algolia.com/api/v1/search`
//! is a hosted Algolia index over the public Firebase dataset, needs no key, has no bot wall, and
//! answers JSON. Measured from this environment: `HTTP 200` for a plain `curl` with a browser
//! user-agent, so unlike Mojeek this backend's live path **was** exercised, and the fixture below
//! is a real capture rather than a transcription.
//!
//! ## What is deliberately NOT done
//!
//! - **`_highlightResult` is ignored.** Algolia returns the matched terms marked up twice: the
//!   top-level `title`/`story_text` are clean, and `_highlightResult.*.value` wraps the matches in
//!   `<em>`. Measured: `title` is `Futurelock: A subtle risk in async Rust` while
//!   `_highlightResult.title.value` is `Futurelock: A subtle risk in <em>async</em> <em>Rust</em>`.
//!   The clean field is read and `clean_text` decodes the entities that *are* in it (`&#x27;`,
//!   `&#x2F;` both occur) — showing `<em>` to a model is showing it markup, and re-deriving the
//!   highlights by hand would be a second parser for something already parsed.
//! - **`tags=story` is pinned.** Without it the index also returns `comment` hits, which carry no
//!   `title` of their own (only `story_title`) and would surface as blank-titled duplicates of the
//!   story they are attached to. Ask HN posts survive the filter — measured: an `ask_hn` hit's
//!   `_tags` still contains `story`.
//! - **Recency is not forwarded.** Algolia is a real search index with filter parameters, unlike
//!   Mojeek's display-only `date` toggle, but none of them were verified from this environment and
//!   a cutoff read from the wall clock would make this builder impure. Omitted, and disclosed
//!   here rather than guessed at.
//! - **`site:` is not folded into the query.** Algolia's query syntax is not `site:`-aware, so a
//!   folded token would be searched as the literal words. The filter is applied to the returned
//!   URLs by host instead, which can only ever remove a result that violates it.
//! - **`hitsPerPage` is clamped to 50.** The API accepts up to 1000; a fan-out backend that can
//!   return 1000 results would dominate the fusion by sheer volume.

use super::{clean_text, USER_AGENT};
use crate::backend::{BackendKind, SearchBackend, SearchError};
use crate::types::{host_matches, SearchQuery, SearchResult};
use async_trait::async_trait;
use url::Url;

/// The highest `hitsPerPage` this backend will send.
pub const HN_MAX_RESULTS: usize = 50;

/// Where a story with no URL of its own lives — an Ask HN or a text post.
pub const HN_ITEM_BASE: &str = "https://news.ycombinator.com/item?id=";

/// How much of a post's own text is handed to the model. Long enough to judge relevance, short
/// enough that six backends' worth of snippets do not crowd out the actual question.
pub const HN_SNIPPET_CHARS: usize = 280;

/// The keyless Hacker News backend.
pub struct HnAlgoliaBackend {
    endpoint: String,
}

impl HnAlgoliaBackend {
    pub fn new() -> Self {
        Self {
            endpoint: "https://hn.algolia.com/api/v1/search".to_string(),
        }
    }

    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

impl Default for HnAlgoliaBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the search URL for a query. Pure, so the parameter mapping is testable.
pub fn hn_search_url(endpoint: &str, query: &SearchQuery) -> Result<Url, SearchError> {
    let base = endpoint.trim();
    if base.is_empty() {
        return Err(SearchError::NotConfigured(
            "hn endpoint is empty".to_string(),
        ));
    }
    let mut url = Url::parse(base).map_err(|e| {
        SearchError::NotConfigured(format!("hn endpoint {base:?} is not a valid URL: {e}"))
    })?;

    {
        let mut params = url.query_pairs_mut();
        // `query.text`, not `effective_text`: see the module docs — a folded `site:` token would
        // be searched literally by an index that does not understand the operator.
        params.append_pair("query", &query.text);
        params.append_pair("tags", "story");
        params.append_pair(
            "hitsPerPage",
            &query.limit.clamp(1, HN_MAX_RESULTS).to_string(),
        );
    }

    Ok(url)
}

#[derive(serde::Deserialize)]
struct AlgoliaResponse {
    #[serde(default)]
    hits: Vec<AlgoliaHit>,
}

#[derive(serde::Deserialize)]
struct AlgoliaHit {
    /// Absent on a comment hit, which `tags=story` is there to prevent.
    #[serde(default)]
    title: Option<String>,
    /// `null` **and** `""` both occur for a story with no link of its own. Both were measured, on
    /// two different Ask HN posts, which is why the check is `is_empty` rather than `is_none`.
    #[serde(default)]
    url: Option<String>,
    /// The post's own body. Present on a text or Ask HN post, absent on a link post.
    #[serde(default)]
    story_text: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    points: Option<u32>,
    #[serde(default)]
    num_comments: Option<u32>,
    #[serde(default)]
    created_at: Option<String>,
    /// The story's id, and the only way to build a URL for a post that has none.
    #[serde(default, rename = "objectID")]
    object_id: Option<String>,
}

/// Parse an Algolia HN response into results.
///
/// Public and pure for the same reason every other parser here is: a hosted API is the least
/// likely thing in this crate to change shape, but when it does the fix should be a two-minute job
/// against a saved fixture with no network.
pub fn parse_hn_hits(json: &str) -> Result<Vec<SearchResult>, SearchError> {
    let body: AlgoliaResponse = serde_json::from_str(json).map_err(|e| SearchError::Parse {
        reason: format!("expected Algolia JSON from the HN search API: {e}"),
    })?;

    let mut results = Vec::new();

    for hit in body.hits {
        // A result with no title renders as a blank line the model has to guess about, which is
        // worse than not returning it.
        let Some(title) = hit
            .title
            .as_deref()
            .map(str::trim)
            .filter(|title| !title.is_empty())
        else {
            continue;
        };

        let url = match hit.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            Some(url) => url.to_string(),
            None => match hit.object_id.as_deref().filter(|id| !id.is_empty()) {
                Some(id) => format!("{HN_ITEM_BASE}{id}"),
                // No link and no id: there is nothing to point a reader at.
                None => continue,
            },
        };

        results.push(SearchResult {
            title: clean_text(title),
            url,
            snippet: hn_snippet(&hit),
            rank: results.len(),
        });
    }

    Ok(results)
}

/// What a result carries as its snippet.
///
/// A text or Ask HN post has a body, so that is the snippet. A link post has none, and an empty
/// snippet reads to a model as a parsing failure rather than as "this submission is a link" — so
/// the metadata the API does give (score, discussion size, author, date) is used, and it is
/// deliberately shaped like metadata rather than like prose so it is not mistaken for the post's
/// own words.
fn hn_snippet(hit: &AlgoliaHit) -> String {
    if let Some(text) = hit.story_text.as_deref() {
        let cleaned = clean_text(text);
        if !cleaned.is_empty() {
            return truncate_chars(&cleaned, HN_SNIPPET_CHARS);
        }
    }

    let mut parts: Vec<String> = Vec::new();
    if let Some(points) = hit.points {
        parts.push(format!("{points} points"));
    }
    if let Some(comments) = hit.num_comments {
        parts.push(format!("{comments} comments"));
    }
    if let Some(author) = hit.author.as_deref() {
        parts.push(format!("by {author}"));
    }
    if let Some(created) = hit.created_at.as_deref() {
        parts.push(created.to_string());
    }
    parts.join(" · ")
}

/// Cut `text` to at most `max` characters, on a character boundary, marking the cut.
///
/// `chars`, not bytes: slicing a `String` by byte index panics on a multi-byte boundary, and a
/// panic in a scraper is a backend that takes the fan-out down with it.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

#[async_trait]
impl SearchBackend for HnAlgoliaBackend {
    fn id(&self) -> &str {
        "hackernews"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Keyless
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let url = hn_search_url(&self.endpoint, query)?;
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

        let body = response.text().await.map_err(|e| SearchError::Parse {
            reason: format!("could not read the response body from {request_url}: {e}"),
        })?;

        let mut results = parse_hn_hits(&body)?;

        if let Some(site) = &query.site {
            results.retain(|result| host_matches(&result.url, site));
        }

        Ok(results.into_iter().take(query.limit).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A live capture**, not a transcription: `GET
    /// https://hn.algolia.com/api/v1/search?query=rust+async&tags=story&hitsPerPage=3` and
    /// `…?query=which+editor&tags=ask_hn&hitsPerPage=2`, from this environment, `HTTP 200`.
    ///
    /// Verbatim for every field the parser reads. The `children` arrays (64 and 68 comment ids on
    /// the first two hits) are elided as unused, and `_highlightResult` is kept on the first hit
    /// only — it is the field the parser deliberately ignores, and keeping one copy is what proves
    /// the marked-up spelling never reaches a result.
    const HN_FIXTURE: &str = r##"{"exhaustiveNbHits":false,"hitsPerPage":3,"nbHits":1104,"nbPages":334,"page":0,"query":"rust async","params":"query=rust+async&tags=story&hitsPerPage=3","hits":[{"_highlightResult":{"title":{"matchLevel":"full","matchedWords":["rust","async"],"value":"Why <em>async</em>hronous <em>Rust</em> doesn't work"},"url":{"matchLevel":"full","matchedWords":["rust","async"],"value":"https://theta.eu.org/2021/03/08/<em>async</em>-<em>rust</em>-2.html"}},"_tags":["story","author_tazjin","story_26406989"],"author":"tazjin","created_at":"2021-03-10T02:16:55Z","created_at_i":1615342615,"num_comments":482,"objectID":"26406989","points":603,"story_id":26406989,"title":"Why asynchronous Rust doesn't work","updated_at":"2026-04-14T23:02:23Z","url":"https://theta.eu.org/2021/03/08/async-rust-2.html"},{"_tags":["story","author_bcantrill","story_45774086"],"author":"bcantrill","created_at":"2026-01-04T20:12:30Z","created_at_i":1767557550,"num_comments":245,"objectID":"45774086","points":449,"story_id":45774086,"story_text":"This RFD describes our distillation of a really gnarly issue that we hit in the Oxide control plane.[0]  Not unlike our discovery of the async cancellation issue[1][2][3], this is larger than the issue itself -- and worse, the program that hits futurelock is correct from the programmer&#x27;s point of view.","title":"Futurelock: A subtle risk in async Rust","url":"https://rfd.shared.oxide.computer/rfd/0609"},{"_tags":["story","author_pjmlp","story_48019163"],"author":"pjmlp","created_at":"2026-04-01T09:00:00Z","created_at_i":1775034000,"num_comments":266,"objectID":"48019163","points":446,"story_id":48019163,"title":"Async Rust never left the MVP state","url":"https://tweedegolf.nl/en/blog/237/async-rust-never-left-the-mvp-state"}]}"##;

    /// **A live capture too** — the Ask HN query, which is what shows the two spellings of "no
    /// URL of its own": `null` on one hit and `""` on the other.
    const HN_ASK_FIXTURE: &str = r##"{"hitsPerPage":2,"nbHits":2,"page":0,"query":"which editor","params":"query=which+editor&tags=ask_hn&hitsPerPage=2","hits":[{"_tags":["story","author_hnjim","story_20005365","ask_hn"],"author":"hnjim","created_at":"2019-02-07T23:11:57Z","created_at_i":1549581117,"num_comments":91,"objectID":"20005365","points":112,"story_id":20005365,"story_text":"Webstorm? VS? VSCode? Any others options you think are better?","title":"Ask HN: Which editor do you use for JavaScript Development?","url":null},{"_tags":["story","author_davidbarker","story_8100094","ask_hn"],"author":"davidbarker","created_at":"2014-06-19T12:00:00Z","created_at_i":1403179200,"num_comments":53,"objectID":"8100094","points":60,"story_id":8100094,"story_text":"I&#x27;m mainly looking for Mac app suggestions, as there seem to be quite a few around (Mou, Write, Byword, Ulysses, etc.), but other OS&#x2F;online suggestions could be interesting too.","title":"Ask HN: Which Markdown editor do you use?","url":""}]}"##;

    #[test]
    fn parses_titles_urls_and_snippets_from_a_live_capture() {
        let results = parse_hn_hits(HN_FIXTURE).unwrap();

        assert_eq!(results.len(), 3, "{results:#?}");
        assert_eq!(results[0].title, "Why asynchronous Rust doesn't work");
        assert_eq!(
            results[0].url,
            "https://theta.eu.org/2021/03/08/async-rust-2.html"
        );
        assert_eq!(results[0].rank, 0);
        assert_eq!(results[1].rank, 1);
        assert_eq!(results[2].rank, 2);
        assert_eq!(
            results[2].url,
            "https://tweedegolf.nl/en/blog/237/async-rust-never-left-the-mvp-state"
        );
    }

    #[test]
    fn the_highlighted_spelling_never_reaches_a_result() {
        // `_highlightResult.title.value` for the first hit is `Why <em>async</em>hronous …`.
        // Reading it instead of the clean field would hand the model markup.
        let results = parse_hn_hits(HN_FIXTURE).unwrap();
        assert!(
            results
                .iter()
                .all(|r| !r.title.contains("<em>") && !r.snippet.contains("<em>")),
            "{results:#?}"
        );
    }

    #[test]
    fn a_text_post_uses_its_own_body_rather_than_metadata() {
        let results = parse_hn_hits(HN_FIXTURE).unwrap();
        assert!(
            results[1]
                .snippet
                .starts_with("This RFD describes our distillation"),
            "{}",
            results[1].snippet
        );
        assert!(
            !results[1].snippet.contains("points"),
            "a post with a body must not fall back to metadata: {}",
            results[1].snippet
        );
    }

    #[test]
    fn a_long_post_body_is_cut_at_the_snippet_budget_on_a_character_boundary() {
        // The captured Futurelock body is longer than the budget, so this asserts the real cut
        // rather than a shape the fixture was trimmed to fit. Byte-slicing would panic here; a
        // panic in a scraper takes the whole fan-out down.
        let results = parse_hn_hits(HN_FIXTURE).unwrap();
        assert!(
            results[1].snippet.ends_with('…'),
            "a cut snippet must say it was cut: {}",
            results[1].snippet
        );
        assert_eq!(
            results[1].snippet.chars().count(),
            HN_SNIPPET_CHARS + 1,
            "the ellipsis is the extra character"
        );

        let long = "é".repeat(HN_SNIPPET_CHARS + 50);
        let json = format!(
            r#"{{"hits":[{{"objectID":"1","title":"T","url":"https://a.test/","story_text":"{long}"}}]}}"#
        );
        let results = parse_hn_hits(&json).unwrap();
        assert_eq!(results[0].snippet.chars().count(), HN_SNIPPET_CHARS + 1);
    }

    #[test]
    fn a_link_post_gets_metadata_rather_than_an_empty_snippet() {
        // A link post has no body. An empty snippet reads as a parsing failure rather than as "this
        // submission is a link", so the score and discussion size are used — shaped like metadata
        // so they are not mistaken for the post's own words.
        let results = parse_hn_hits(HN_FIXTURE).unwrap();
        assert_eq!(
            results[0].snippet,
            "603 points · 482 comments · by tazjin · 2021-03-10T02:16:55Z"
        );
    }

    #[test]
    fn a_post_with_no_url_of_its_own_points_at_its_hn_item() {
        // Measured: `null` on one Ask HN hit and `""` on another. Both must fall back.
        let results = parse_hn_hits(HN_ASK_FIXTURE).unwrap();

        assert_eq!(results.len(), 2, "{results:#?}");
        assert_eq!(
            results[0].url, "https://news.ycombinator.com/item?id=20005365",
            "a `null` url falls back to the item page"
        );
        assert_eq!(
            results[1].url, "https://news.ycombinator.com/item?id=8100094",
            "an empty-string url falls back to the item page too"
        );
        assert!(
            results[1].snippet.contains("Mac app suggestions"),
            "{}",
            results[1].snippet
        );
        // Both entity spellings the capture actually contains: `&#x27;` and `&#x2F;`.
        assert!(
            results[1].snippet.contains("I'm mainly looking"),
            "`&#x27;` must decode to an apostrophe: {}",
            results[1].snippet
        );
        assert!(
            results[1].snippet.contains("OS/online"),
            "`&#x2F;` must decode to a slash: {}",
            results[1].snippet
        );
        assert!(!results[1].snippet.contains("&#"), "{}", results[1].snippet);
    }

    #[test]
    fn a_hit_with_no_title_is_dropped_rather_than_rendered_blank() {
        // A comment hit has no title of its own. `tags=story` should prevent one arriving, but a
        // blank title in a result list is a line the model has to guess about.
        let json = r#"{"hits":[{"objectID":"1","url":"https://a.test/","title":null},{"objectID":"2","url":"https://b.test/","title":"  "},{"objectID":"3","url":"https://c.test/","title":"Real"}]}"#;
        let results = parse_hn_hits(json).unwrap();
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].title, "Real");
        assert_eq!(results[0].rank, 0, "ranks are contiguous after the drop");
    }

    #[test]
    fn a_hit_with_neither_a_url_nor_an_id_is_dropped() {
        // No link of its own and no id to build an item URL from: there is nothing to point at.
        let json = r#"{"hits":[{"title":"No target"}]}"#;
        assert!(parse_hn_hits(json).unwrap().is_empty());

        // The control: the same hit *with* an id does become a result, so the drop is about the
        // missing target and not about the missing `url` key.
        let json = r#"{"hits":[{"objectID":"1","title":"Has target"}]}"#;
        let results = parse_hn_hits(json).unwrap();
        assert_eq!(results.len(), 1, "{results:#?}");
    }

    #[test]
    fn an_empty_or_unexpected_response_parses_to_nothing_rather_than_failing() {
        assert!(parse_hn_hits(r#"{"hits":[]}"#).unwrap().is_empty());
        assert!(parse_hn_hits("{}").unwrap().is_empty());
        // But something that is not an Algolia response at all is a loud parse error, not silence.
        let err = parse_hn_hits("<html>not json</html>").unwrap_err();
        assert!(matches!(err, SearchError::Parse { .. }), "{err}");
    }

    #[test]
    fn hn_url_asks_for_stories_and_a_page_size() {
        let url = hn_search_url(
            "https://hn.algolia.com/api/v1/search",
            &SearchQuery::new("rust async").with_limit(20),
        )
        .unwrap();
        let q = url.query().unwrap();
        assert!(q.contains("tags=story"), "{q}");
        assert!(q.contains("hitsPerPage=20"), "{q}");
        assert!(
            q.contains("query=rust+async") || q.contains("query=rust%20async"),
            "{q}"
        );
    }

    #[test]
    fn hn_result_limit_is_clamped_below_the_apis_ceiling() {
        // 1000 results from one backend would dominate the fusion by volume alone.
        let url = hn_search_url(
            "https://hn.algolia.com/api/v1/search",
            &SearchQuery::new("x").with_limit(1000),
        )
        .unwrap();
        assert!(
            url.query().unwrap().contains("hitsPerPage=50"),
            "{}",
            url.query().unwrap()
        );
    }

    #[test]
    fn hn_does_not_fold_a_site_filter_into_the_search_terms() {
        // Algolia's query syntax is not `site:`-aware; a folded token would be searched literally.
        let query = SearchQuery::new("async rust").with_site("docs.rs");
        let url = hn_search_url("https://hn.algolia.com/api/v1/search", &query).unwrap();
        let q = url.query().unwrap();
        assert!(!q.contains("site"), "{q}");
        assert!(!q.contains("docs.rs"), "{q}");
    }

    #[test]
    fn hn_url_rejects_an_empty_endpoint() {
        let err = hn_search_url("  ", &SearchQuery::new("x")).unwrap_err();
        assert!(matches!(err, SearchError::NotConfigured(_)), "{err}");
    }
}
