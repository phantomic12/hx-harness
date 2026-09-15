//! Shared search types, URL canonicalisation, and result fusion.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// How far back to constrain results.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recency {
    Day,
    Week,
    Month,
    Year,
}

impl Recency {
    /// SearXNG `time_range` spelling.
    pub fn searxng_code(self) -> &'static str {
        match self {
            Recency::Day => "day",
            Recency::Week => "week",
            Recency::Month => "month",
            Recency::Year => "year",
        }
    }

    /// DuckDuckGo `df` spelling.
    pub fn ddg_code(self) -> &'static str {
        match self {
            Recency::Day => "d",
            Recency::Week => "w",
            Recency::Month => "m",
            Recency::Year => "y",
        }
    }
}

/// One search request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: String,
    pub limit: usize,
    pub recency: Option<Recency>,
    /// Restrict to one domain, for site-scoped lookups.
    pub site: Option<String>,
}

impl SearchQuery {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            limit: 10,
            recency: None,
            site: None,
        }
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.max(1);
        self
    }

    pub fn with_recency(mut self, recency: Recency) -> Self {
        self.recency = Some(recency);
        self
    }

    pub fn with_site(mut self, site: impl Into<String>) -> Self {
        self.site = Some(site.into());
        self
    }

    /// The effective query string, with any `site:` filter folded in.
    ///
    /// `site:` is a de-facto standard across engines, and SearXNG and DDG both honour it, so
    /// it is applied by rewriting the query rather than by post-filtering results.
    pub fn effective_text(&self) -> String {
        match &self.site {
            Some(site) => format!("{} site:{site}", self.text),
            None => self.text.clone(),
        }
    }
}

/// A hit from one backend, with its position in that backend's ranking.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    /// Rank within the producing backend, 0-based.
    pub rank: usize,
}

impl SearchResult {
    pub fn new(
        title: impl Into<String>,
        url: impl Into<String>,
        snippet: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            url: url.into(),
            snippet: snippet.into(),
            rank: 0,
        }
    }

    pub fn with_rank(mut self, rank: usize) -> Self {
        self.rank = rank;
        self
    }
}

/// A hit after fusion, carrying the evidence of *why* it ranks where it does.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FusedResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    /// Summed reciprocal-rank contribution.
    pub score: f64,
    /// Backends that returned this URL, in the order they were queried.
    pub sources: Vec<String>,
}

impl FusedResult {
    /// How many independent backends agreed on this result.
    pub fn agreement(&self) -> usize {
        self.sources.len()
    }
}

/// Query parameters that identify a campaign, not a document.
fn is_tracking_param(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.starts_with("utm_")
        || matches!(
            lower.as_str(),
            "fbclid" | "gclid" | "dclid" | "msclkid" | "mc_cid" | "mc_eid" | "igshid" | "spm"
        )
}

/// Reduce a URL to a stable identity for de-duplication across backends.
///
/// Two engines rarely return byte-identical URLs for the same page — one adds `?utm_source=`,
/// one keeps `www.`, one includes a fragment. Without canonicalisation, fusion counts the same
/// page several times and the ranking degrades into "whichever engine added the least cruft".
///
/// Deliberately conservative: only transformations that cannot change *which document* is
/// addressed are applied. Path and query case are preserved, because `?id=AbC` and `?id=abc`
/// really can be different documents.
pub fn canonicalize_url(raw: &str) -> String {
    let trimmed = raw.trim();
    let Ok(mut url) = Url::parse(trimmed) else {
        // Not parseable: fall back to a case-insensitive exact key so it can still de-duplicate.
        return trimmed.to_ascii_lowercase();
    };

    url.set_fragment(None);

    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| !is_tracking_param(k))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if kept.is_empty() {
        url.set_query(None);
    } else {
        // Rebuild in place so parameter order is preserved for stable keys.
        let encoded = kept
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        url.set_query(Some(&encoded));
    }

    // Hosts are case-insensitive and `www.` is almost always the same server.
    if let Some(host) = url.host_str() {
        let lower = host.to_ascii_lowercase();
        let stripped = lower.strip_prefix("www.").unwrap_or(&lower).to_string();
        if stripped != lower {
            let _ = url.set_host(Some(&stripped));
        } else if lower != host {
            let _ = url.set_host(Some(&lower));
        }
    }

    // A bare "/" path is the same as no path.
    if url.path() == "/" {
        url.set_path("");
    }

    url.to_string()
}

/// Merge per-backend rankings into one ranking using Reciprocal Rank Fusion.
///
/// `lists` pairs each backend id with its results in rank order. Ties are broken
/// deterministically (more agreeing backends first, then URL) so that identical input always
/// produces identical output — which matters when the ranking is fed to a model.
pub fn fuse(lists: &[(String, Vec<SearchResult>)], limit: usize) -> Vec<FusedResult> {
    // Keyed by canonical URL, so the same page from different engines collapses into one entry.
    let mut merged: HashMap<String, FusedResult> = HashMap::new();
    // Preserve first-seen order for deterministic tie-breaking.
    let mut order: Vec<String> = Vec::new();

    for (backend, results) in lists {
        for (index, result) in results.iter().enumerate() {
            // Trust the position in the list over any self-reported rank: a backend that
            // mislabels ranks must not be able to corrupt the fusion.
            let rank = index + 1;
            let contribution = 1.0 / (RRF_K + rank as f64);

            let key = canonicalize_url(&result.url);
            let entry = merged.entry(key.clone()).or_insert_with(|| {
                order.push(key.clone());
                FusedResult {
                    title: result.title.clone(),
                    url: result.url.clone(),
                    snippet: result.snippet.clone(),
                    score: 0.0,
                    sources: Vec::new(),
                }
            });

            entry.score += contribution;
            if !entry.sources.iter().any(|s| s == backend) {
                entry.sources.push(backend.clone());
            }
            // Backfill from later engines when the first was terse.
            if entry.title.is_empty() && !result.title.is_empty() {
                entry.title = result.title.clone();
            }
            if entry.snippet.len() < result.snippet.len() {
                entry.snippet = result.snippet.clone();
            }
        }
    }

    let mut fused: Vec<FusedResult> = order
        .into_iter()
        .filter_map(|key| merged.remove(&key))
        .collect();

    // Rank by fused score. Assemble the key order explicitly rather than floating-point
    // subtraction, which is not a total order and would make the sort inconsistent.
    fused.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.agreement().cmp(&a.agreement()))
            .then_with(|| a.url.cmp(&b.url))
    });

    fused.truncate(limit);
    fused
}

/// The standard RRF constant from Cormack, Clarke & Buettcher (2009).
///
/// It damps the influence of rank so that engines agreeing on *presence* near the top outweighs
/// one engine's extreme confidence in its own first result.
pub const RRF_K: f64 = 60.0;

#[cfg(test)]
mod tests {
    use super::*;

    fn r(title: &str, url: &str) -> SearchResult {
        SearchResult::new(title, url, format!("snippet for {title}"))
    }

    // ---- URL canonicalisation ----

    #[test]
    fn canonicalisation_ignores_host_case_and_www() {
        assert_eq!(
            canonicalize_url("https://WWW.Example.COM/page"),
            canonicalize_url("https://example.com/page")
        );
    }

    #[test]
    fn canonicalisation_strips_tracking_parameters() {
        let clean = canonicalize_url("https://example.com/a?q=1");
        let dirty =
            canonicalize_url("https://example.com/a?q=1&utm_source=x&utm_medium=y&fbclid=z");
        assert_eq!(clean, dirty);
    }

    #[test]
    fn canonicalisation_keeps_meaningful_query_parameters() {
        // `?id=2` and `?id=1` are different documents and must not collapse.
        assert_ne!(
            canonicalize_url("https://example.com/doc?id=1"),
            canonicalize_url("https://example.com/doc?id=2")
        );
    }

    #[test]
    fn canonicalisation_is_conservative_about_query_case() {
        // Path and query values are case-sensitive; collapsing them would merge real documents.
        assert_ne!(
            canonicalize_url("https://example.com/d?id=AbC"),
            canonicalize_url("https://example.com/d?id=abc")
        );
    }

    #[test]
    fn canonicalisation_strips_fragments_and_bare_root_paths() {
        assert_eq!(
            canonicalize_url("https://example.com/#section"),
            canonicalize_url("https://example.com")
        );
    }

    #[test]
    fn unparseable_urls_still_deduplicate() {
        assert_eq!(canonicalize_url("not a url"), canonicalize_url("NOT A URL"));
    }

    // ---- fusion ----

    #[test]
    fn rrf_matches_the_hand_computed_value() {
        // Rank 1 in one list, rank 2 in another: 1/61 + 1/62.
        let lists = vec![
            ("a".to_string(), vec![r("X", "https://x.test/")]),
            (
                "b".to_string(),
                vec![r("Y", "https://y.test/"), r("X", "https://x.test/")],
            ),
        ];
        let out = fuse(&lists, 10);
        let x = out.iter().find(|f| f.url.contains("x.test")).unwrap();
        let expected = 1.0 / 61.0 + 1.0 / 62.0;
        assert!((x.score - expected).abs() < 1e-12, "got {}", x.score);
    }

    #[test]
    fn agreement_beats_a_single_strong_vote() {
        // "agreed" is rank 1 in both lists; "loud" is rank 1 in one list only.
        let lists = vec![
            (
                "a".to_string(),
                vec![
                    r("agreed", "https://agreed.test/"),
                    r("loud", "https://loud.test/"),
                ],
            ),
            ("b".to_string(), vec![r("agreed", "https://agreed.test/")]),
        ];
        let out = fuse(&lists, 10);
        assert_eq!(out[0].url, "https://agreed.test/");
        assert_eq!(out[0].agreement(), 2);
        assert_eq!(out[1].agreement(), 1);
    }

    #[test]
    fn the_same_page_from_two_engines_collapses_into_one_result() {
        let lists = vec![
            (
                "a".to_string(),
                vec![r("Doc", "https://example.com/doc?utm_source=a")],
            ),
            (
                "b".to_string(),
                vec![r("Doc", "https://WWW.example.com/doc")],
            ),
        ];
        let out = fuse(&lists, 10);
        assert_eq!(out.len(), 1, "expected one fused result, got {out:?}");
        assert_eq!(out[0].sources.len(), 2);
    }

    #[test]
    fn snippets_are_backfilled_from_whichever_engine_had_more() {
        let lists = vec![
            (
                "a".to_string(),
                vec![SearchResult::new("T", "https://x.test/", "")],
            ),
            (
                "b".to_string(),
                vec![SearchResult::new(
                    "T",
                    "https://x.test/",
                    "a much longer snippet",
                )],
            ),
        ];
        let out = fuse(&lists, 10);
        assert_eq!(out[0].snippet, "a much longer snippet");
    }

    #[test]
    fn self_reported_ranks_cannot_corrupt_the_fusion() {
        // A backend that labels every result rank 0 must not gain an advantage: position in
        // the returned list is what counts.
        let honest = vec![r("second", "https://second.test/").with_rank(1)];
        let lying = vec![
            r("first", "https://first.test/").with_rank(0),
            r("second", "https://second.test/").with_rank(0),
        ];
        let out = fuse(
            &[("honest".to_string(), honest), ("lying".to_string(), lying)],
            10,
        );

        // "first" sits at position 1 of `lying`, so it earns exactly 1/61 — the false
        // `rank: 0` contributed nothing. Had the rank field been trusted, it would have
        // scored 1/60 and could have outranked results it should not.
        let first = out.iter().find(|f| f.url.contains("first")).unwrap();
        assert!(
            (first.score - 1.0 / 61.0).abs() < 1e-12,
            "self-reported rank must be ignored entirely, got {}",
            first.score
        );

        // "second" was genuinely found by both engines, so it correctly wins.
        assert_eq!(out[0].url, "https://second.test/");
        assert_eq!(out[0].agreement(), 2);
    }

    #[test]
    fn an_empty_backend_list_is_not_an_error() {
        let out = fuse(&[("a".to_string(), vec![])], 10);
        assert!(out.is_empty());
    }

    #[test]
    fn limit_is_respected() {
        let list = (0..50)
            .map(|i| r(&format!("t{i}"), &format!("https://e.test/{i}")))
            .collect();
        let out = fuse(&[("a".to_string(), list)], 5);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn fusion_is_deterministic_for_identical_input() {
        let build = || {
            vec![
                (
                    "a".to_string(),
                    vec![r("X", "https://x.test/"), r("Y", "https://y.test/")],
                ),
                (
                    "b".to_string(),
                    vec![r("Y", "https://y.test/"), r("X", "https://x.test/")],
                ),
            ]
        };
        // Identical scores: the tie must resolve the same way every time.
        assert_eq!(fuse(&build(), 10), fuse(&build(), 10));
    }

    #[test]
    fn fused_scores_are_ordered_descending() {
        let lists = vec![
            (
                "a".to_string(),
                vec![
                    r("one", "https://one.test/"),
                    r("two", "https://two.test/"),
                    r("three", "https://three.test/"),
                ],
            ),
            ("b".to_string(), vec![r("three", "https://three.test/")]),
        ];
        let out = fuse(&lists, 10);
        for pair in out.windows(2) {
            assert!(
                pair[0].score >= pair[1].score,
                "scores out of order: {} then {}",
                pair[0].score,
                pair[1].score
            );
        }
        // "three" is rank 3 in list a but rank 1 in list b, so it should beat "two".
        assert_eq!(out[0].url, "https://three.test/");
    }

    // ---- query construction ----

    #[test]
    fn site_filter_is_folded_into_the_query_text() {
        let q = SearchQuery::new("rust async").with_site("docs.rs");
        assert_eq!(q.effective_text(), "rust async site:docs.rs");
    }

    #[test]
    fn limit_cannot_be_zero() {
        assert_eq!(SearchQuery::new("x").with_limit(0).limit, 1);
    }
}
