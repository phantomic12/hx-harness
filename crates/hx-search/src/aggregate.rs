//! Fan-out across backends, with per-backend timeouts and honest failure reporting.
//!
//! Two properties matter more than speed here:
//!
//! 1. **One broken backend must not break search.** Backends are queried concurrently and their
//!    outcomes collected independently, so a scraper that starts returning a bot-check page
//!    degrades the result set rather than emptying it.
//! 2. **The caller must learn what failed.** [`SearchReport`] carries `answered` and `failures`
//!    separately. An agent that gets three results from one engine out of four should be able to
//!    say so, instead of presenting a thin result set as complete.

use crate::backend::SearchBackend;
use crate::types::{fuse, FusedResult, SearchQuery};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Per-backend deadline. Generous enough for a slow public SearXNG, short enough that one dead
/// backend does not hold the whole search.
pub const DEFAULT_BACKEND_TIMEOUT: Duration = Duration::from_secs(8);

/// A backend that did not answer, and why.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackendFailure {
    pub backend: String,
    pub reason: String,
    pub elapsed_ms: u64,
}

/// The outcome of one search across several backends.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchReport {
    /// Fused, de-duplicated, ranked results.
    pub results: Vec<FusedResult>,
    /// Backends that returned successfully — even if they found nothing.
    pub answered: Vec<String>,
    /// Backends that errored or timed out.
    pub failures: Vec<BackendFailure>,
    pub elapsed_ms: u64,
}

impl SearchReport {
    /// True when no backend answered at all, which is different from "no results".
    pub fn is_total_failure(&self) -> bool {
        self.answered.is_empty()
    }

    /// One-line summary suitable for a tool result, so the model can judge confidence.
    pub fn summary(&self) -> String {
        if self.results.is_empty() && self.is_total_failure() {
            return format!("no backend answered ({} failed)", self.failures.len());
        }
        let mut out = format!(
            "{} result(s) from {} backend(s)",
            self.results.len(),
            self.answered.len()
        );
        if !self.failures.is_empty() {
            let names: Vec<&str> = self.failures.iter().map(|f| f.backend.as_str()).collect();
            out.push_str(&format!("; unavailable: {}", names.join(", ")));
        }
        out
    }
}

/// Query every backend concurrently and fuse whatever came back.
pub async fn fanout(
    backends: &[Arc<dyn SearchBackend>],
    client: &reqwest::Client,
    query: &SearchQuery,
    timeout: Duration,
) -> SearchReport {
    let started = Instant::now();

    let futures = backends.iter().map(|backend| {
        let backend = Arc::clone(backend);
        async move {
            let id = backend.id().to_string();
            let began = Instant::now();

            match tokio::time::timeout(timeout, backend.search(client, query)).await {
                Ok(Ok(results)) => Ok((id, results)),
                Ok(Err(err)) => Err(BackendFailure {
                    backend: id,
                    reason: err.to_string(),
                    elapsed_ms: began.elapsed().as_millis() as u64,
                }),
                Err(_) => Err(BackendFailure {
                    backend: id,
                    reason: format!("timed out after {}s", timeout.as_secs_f64()),
                    elapsed_ms: began.elapsed().as_millis() as u64,
                }),
            }
        }
    });

    let outcomes = join_all(futures).await;

    let mut lists: Vec<(String, Vec<crate::types::SearchResult>)> = Vec::new();
    let mut answered = Vec::new();
    let mut failures = Vec::new();

    for outcome in outcomes {
        match outcome {
            Ok((id, results)) => {
                // "Answered, found nothing" is a real signal and must not be reported as failure.
                answered.push(id.clone());
                lists.push((id, results));
            }
            Err(failure) => failures.push(failure),
        }
    }

    // Fusion runs in fanout order, so results are deterministic for identical input.
    let results = fuse(&lists, query.limit);

    SearchReport {
        results,
        answered,
        failures,
        elapsed_ms: started.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendKind, SearchError};
    use crate::types::SearchResult;
    use async_trait::async_trait;

    /// A backend whose behaviour each test dictates.
    struct FakeBackend {
        id: String,
        behaviour: Behaviour,
    }

    enum Behaviour {
        Returns(Vec<SearchResult>),
        Fails(&'static str),
        Hangs(Duration),
    }

    #[async_trait]
    impl SearchBackend for FakeBackend {
        fn id(&self) -> &str {
            &self.id
        }

        fn kind(&self) -> BackendKind {
            BackendKind::Stub
        }

        async fn search(
            &self,
            _client: &reqwest::Client,
            _query: &SearchQuery,
        ) -> Result<Vec<SearchResult>, SearchError> {
            match &self.behaviour {
                Behaviour::Returns(r) => Ok(r.clone()),
                Behaviour::Fails(why) => Err(SearchError::NotConfigured((*why).to_string())),
                Behaviour::Hangs(d) => {
                    tokio::time::sleep(*d).await;
                    Ok(vec![])
                }
            }
        }
    }

    fn fake(id: &str, behaviour: Behaviour) -> Arc<dyn SearchBackend> {
        Arc::new(FakeBackend {
            id: id.to_string(),
            behaviour,
        })
    }

    fn hit(title: &str, url: &str) -> SearchResult {
        SearchResult::new(title, url, "snippet")
    }

    fn query() -> SearchQuery {
        SearchQuery::new("test").with_limit(10)
    }

    #[tokio::test]
    async fn a_failing_backend_does_not_lose_the_working_ones() {
        let backends = vec![
            fake(
                "good",
                Behaviour::Returns(vec![hit("A", "https://a.test/")]),
            ),
            fake("bad", Behaviour::Fails("403 bot check")),
        ];

        let report = fanout(
            &backends,
            &reqwest::Client::new(),
            &query(),
            DEFAULT_BACKEND_TIMEOUT,
        )
        .await;

        assert_eq!(report.answered, vec!["good"]);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].backend, "bad");
        assert!(!report.is_total_failure());
    }

    #[tokio::test]
    async fn a_hanging_backend_times_out_and_is_reported() {
        let backends = vec![
            fake(
                "fast",
                Behaviour::Returns(vec![hit("A", "https://a.test/")]),
            ),
            fake("slow", Behaviour::Hangs(Duration::from_secs(30))),
        ];

        let report = fanout(
            &backends,
            &reqwest::Client::new(),
            &query(),
            Duration::from_millis(50),
        )
        .await;

        assert_eq!(report.answered, vec!["fast"]);
        assert_eq!(report.failures.len(), 1);
        assert!(
            report.failures[0].reason.contains("timed out"),
            "{}",
            report.failures[0].reason
        );
    }

    #[tokio::test]
    async fn a_backend_that_finds_nothing_counts_as_answered_not_failed() {
        // Important distinction: "no results" is information, "did not answer" is a gap.
        let backends = vec![fake("empty", Behaviour::Returns(vec![]))];
        let report = fanout(
            &backends,
            &reqwest::Client::new(),
            &query(),
            DEFAULT_BACKEND_TIMEOUT,
        )
        .await;

        assert_eq!(report.answered, vec!["empty"]);
        assert!(report.failures.is_empty());
        assert!(report.results.is_empty());
        assert!(!report.is_total_failure());
    }

    #[tokio::test]
    async fn total_failure_is_distinguishable_from_no_results() {
        let backends = vec![
            fake("a", Behaviour::Fails("down")),
            fake("b", Behaviour::Fails("down")),
        ];
        let report = fanout(
            &backends,
            &reqwest::Client::new(),
            &query(),
            DEFAULT_BACKEND_TIMEOUT,
        )
        .await;

        assert!(report.is_total_failure());
        assert!(
            report.summary().contains("no backend answered"),
            "{}",
            report.summary()
        );
    }

    #[tokio::test]
    async fn results_from_several_backends_are_fused_and_deduplicated() {
        let backends = vec![
            fake(
                "a",
                Behaviour::Returns(vec![
                    hit("Shared", "https://shared.test/"),
                    hit("OnlyA", "https://a.test/"),
                ]),
            ),
            fake(
                "b",
                Behaviour::Returns(vec![hit("Shared", "https://www.shared.test/?utm_source=b")]),
            ),
        ];

        let report = fanout(
            &backends,
            &reqwest::Client::new(),
            &query(),
            DEFAULT_BACKEND_TIMEOUT,
        )
        .await;

        assert_eq!(report.results.len(), 2, "{:?}", report.results);
        assert_eq!(report.results[0].url, "https://shared.test/");
        assert_eq!(report.results[0].agreement(), 2);
        assert_eq!(report.summary(), "2 result(s) from 2 backend(s)");
    }

    #[tokio::test]
    async fn no_backends_configured_returns_an_empty_report() {
        let report = fanout(
            &[],
            &reqwest::Client::new(),
            &query(),
            DEFAULT_BACKEND_TIMEOUT,
        )
        .await;
        assert!(report.is_total_failure());
        assert!(report.results.is_empty());
    }

    #[tokio::test]
    async fn the_limit_is_applied_after_fusion() {
        let many: Vec<SearchResult> = (0..30)
            .map(|i| hit(&format!("t{i}"), &format!("https://e.test/{i}")))
            .collect();
        let backends = vec![fake("a", Behaviour::Returns(many))];
        let report = fanout(
            &backends,
            &reqwest::Client::new(),
            &SearchQuery::new("x").with_limit(4),
            DEFAULT_BACKEND_TIMEOUT,
        )
        .await;
        assert_eq!(report.results.len(), 4);
    }
}
