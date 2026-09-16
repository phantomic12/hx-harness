//! Live search canary.
//!
//! Keyless scrapers break quietly: bot detection tightens, markup changes, an endpoint is retired.
//! Every other test in this crate runs against fixtures, and a fixture cannot notice that
//! DuckDuckGo stopped answering the way it used to. This file is the thing that notices.
//!
//! ## What it asserts, and why not "the results are good"
//!
//! As of this writing a plain HTTP client is bot-walled by every keyless engine tried from a
//! developer machine: DuckDuckGo (`anomaly` challenge on both `lite.` and `html.`), Mojeek and
//! public SearXNG instances. That is a property of the *client's TLS fingerprint*, not of the code
//! here — so a canary that demanded results would be red every night and read as noise, which is
//! how real alerts get ignored.
//!
//! The canary therefore asserts the two promises the design actually makes, both of which a
//! regression can break:
//!
//! 1. **Never a silent empty.** If no results come back, some backend said why. An empty result set
//!    with no explanation is indistinguishable from "the web has nothing about this".
//! 2. **Every failure is accounted for.** A backend that fails reports a reason — a bot wall, an
//!    HTTP status, a transport error — rather than vanishing from the report.
//!
//! Plus one capability assertion that is opt-in, because it depends on the environment rather than
//! on the code: set `HX_SEARCH_EXPECT_RESULTS=<backend>[,<backend>]` and those backends must return
//! results. A deployment with a self-hosted SearXNG sets it to `searxng`; the nightly CI job sets
//! nothing and reports instead.
//!
//! ```console
//! $ cargo test -p hx-search --test search_live -- --ignored --nocapture
//! # with a self-hosted SearXNG:
//! $ HX_SEARXNG_URL=http://127.0.0.1:8888 HX_SEARCH_EXPECT_RESULTS=searxng \
//!   cargo test -p hx-search --test search_live -- --ignored --nocapture
//! ```

use hx_search::{BackendRegistry, DuckDuckGoBackend, SearchQuery, SearchReport, SearxngBackend};
use std::sync::Arc;
use std::time::Duration;

/// Long enough for a slow public instance, short enough that a hung one fails the job.
const CANARY_TIMEOUT: Duration = Duration::from_secs(20);

fn query() -> SearchQuery {
    let text = std::env::var("HX_SEARCH_LIVE_QUERY")
        .unwrap_or_else(|_| "rust programming language".to_string());
    SearchQuery::new(text).with_limit(10)
}

fn registry() -> (BackendRegistry, Vec<String>) {
    let client = reqwest::Client::builder()
        .user_agent(hx_search::backends::USER_AGENT)
        .timeout(CANARY_TIMEOUT)
        .build()
        .expect("an HTTP client");

    let mut registry = BackendRegistry::new(client).with_timeout(CANARY_TIMEOUT);

    // Always: the keyless scraper that needs nothing configured.
    registry.insert(Arc::new(DuckDuckGoBackend::new()));
    let mut configured = vec!["duckduckgo".to_string()];

    // Optionally: a SearXNG, which fronts ~70 engines and is the one backend that reliably answers
    // a non-browser client — because you host it.
    if let Ok(url) = std::env::var("HX_SEARXNG_URL") {
        registry.insert(Arc::new(SearxngBackend::new(url)));
        configured.push("searxng".to_string());
    }

    (registry, configured)
}

/// Which backends this environment says must return results. Empty means "report, do not judge".
fn expect_results() -> Vec<String> {
    std::env::var("HX_SEARCH_EXPECT_RESULTS")
        .map(|list| {
            list.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// True when a failure is the known bot-wall condition rather than a defect in this code.
fn is_bot_wall(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("bot check")
        || lower.contains("captcha")
        || lower.contains("challenge")
        || lower.contains("anomaly")
}

/// Print the whole report: when the canary goes red, the log is the diagnosis.
fn describe(report: &SearchReport) {
    eprintln!("canary: {}", report.summary());
    for outcome in &report.answered {
        eprintln!("  answered: {outcome}");
    }
    for failure in &report.failures {
        let kind = if is_bot_wall(&failure.reason) {
            "bot wall"
        } else {
            "FAILURE"
        };
        eprintln!(
            "  {kind}: {} after {}ms: {}",
            failure.backend, failure.elapsed_ms, failure.reason
        );
    }
    for result in report.results.iter().take(5) {
        eprintln!(
            "  {:.4}  {}  <- {}",
            result.score,
            result.url,
            result.sources.join(",")
        );
    }
}

/// The invariant that matters more than any result: silence is not an answer.
fn assert_never_a_silent_empty(report: &SearchReport) {
    if report.results.is_empty() {
        assert!(
            !report.failures.is_empty(),
            "search returned nothing and reported no failure — an agent cannot tell this apart \
             from a search that worked and found nothing: {report:?}"
        );
    }

    // A failure with no reason is the same bug in a different place.
    for failure in &report.failures {
        assert!(
            !failure.reason.trim().is_empty(),
            "backend {} failed without saying why",
            failure.backend
        );
        assert!(
            failure.backend != "unknown" && !failure.backend.is_empty(),
            "a failure must name the backend that produced it: {failure:?}"
        );
    }
}

#[ignore = "requires network access to a real search backend"]
#[tokio::test]
async fn a_search_never_fails_silently() {
    let (registry, configured) = registry();
    let report = registry.search(&query()).await;
    describe(&report);

    assert_never_a_silent_empty(&report);

    // Every backend that was asked is accounted for, one way or the other.
    for backend in &configured {
        let answered = report.answered.iter().any(|a| a == backend);
        let failed = report.failures.iter().any(|f| &f.backend == backend);
        assert!(
            answered || failed,
            "backend {backend} was configured but appears in neither answered nor failures: {}",
            report.summary()
        );
    }
}

#[ignore = "requires network access to a real search backend"]
#[tokio::test]
async fn backends_that_do_answer_return_usable_results() {
    let (registry, _) = registry();
    let report = registry.search(&query()).await;
    describe(&report);

    assert_never_a_silent_empty(&report);

    if report.results.is_empty() {
        // Everything was bot-walled or otherwise unavailable. That is a *reported* condition, and
        // it is what a bare HTTP client sees today; the nightly job sets nothing, so this is not a
        // failure. A deployment that expects results says so via HX_SEARCH_EXPECT_RESULTS.
        for failure in &report.failures {
            assert!(
                is_bot_wall(&failure.reason)
                    || failure.reason.contains("HTTP")
                    || failure.reason.contains("transport")
                    || failure.reason.contains("timed out")
                    || failure.reason.contains("dns"),
                "a backend failed in a way that is not an external condition: {}: {}",
                failure.backend,
                failure.reason
            );
        }
        eprintln!(
            "note: no backend returned results in this environment ({} failure(s)); all are \
             reported above",
            report.failures.len()
        );
    } else {
        // Something answered, so the parsing has to be right: a markup change that still yields
        // *something* is the failure mode this checks for.
        for result in &report.results {
            assert!(
                result.url.starts_with("http"),
                "result url is not absolute: {result:?}"
            );
            assert!(
                !result.title.trim().is_empty(),
                "result without a title: {result:?}"
            );
            assert!(
                !result.sources.is_empty(),
                "a fused result must remember which backend produced it: {result:?}"
            );
        }

        let wrapped: Vec<&str> = report
            .results
            .iter()
            .map(|r| r.url.as_str())
            .filter(|url| {
                url.contains("duckduckgo.com/l/")
                    || url.contains("/redirect?")
                    || url.contains("mojeek.com/search")
            })
            .collect();
        assert!(
            wrapped.is_empty(),
            "results still point at a redirect wrapper: {wrapped:?}"
        );
    }
}

#[ignore = "requires network access to a real search backend"]
#[tokio::test]
async fn a_backend_that_must_answer_does() {
    let expected = expect_results();
    if expected.is_empty() {
        eprintln!(
            "skipped: HX_SEARCH_EXPECT_RESULTS is unset, so this environment does not claim any \
             backend works. Set it (e.g. `searxng`) where a SearXNG is configured."
        );
        return;
    }

    let (registry, _) = registry();
    let report = registry.search(&query()).await;
    describe(&report);

    assert_never_a_silent_empty(&report);

    for backend in &expected {
        assert!(
            report.results.iter().any(|r| r.sources.contains(backend)),
            "backend {backend} was expected to return results and did not: {}",
            report.summary()
        );
    }
}

#[ignore = "requires network access to a real search backend"]
#[tokio::test]
async fn a_query_matching_nothing_is_told_apart_from_a_failure() {
    // The one shape that legitimately returns nothing. `is_total_failure` is how a caller knows
    // the difference, so it has to stay honest under a real response.
    let (registry, _) = registry();
    let nonsense = SearchQuery::new("zzqxjwv kqxjwv hxcanary nonsense 9137").with_limit(5);
    let report = registry.search(&nonsense).await;

    eprintln!("no-results probe: {}", report.summary());
    assert_never_a_silent_empty(&report);

    if report.answered.is_empty() {
        assert!(
            report.is_total_failure(),
            "no backend answered, so this is a total failure: {}",
            report.summary()
        );
    } else {
        assert!(
            !report.is_total_failure(),
            "a backend answered, so this is not a total failure: {}",
            report.summary()
        );
    }
}
