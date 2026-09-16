//! Web search, as a tool.

use crate::tool::{parse_args, Requirement, Tool, ToolContext, ToolError, ToolOutcome};
use async_trait::async_trait;
use hx_core::capability::{Action, Resource};
use hx_search::{fanout, SearchBackend, SearchQuery, SearchReport};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// Per-backend deadline for a tool call. Shorter than the default: an agent waiting on a slow
/// engine is an agent not doing the rest of the task.
pub const SEARCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The resource name a capability is checked against, so an operator can grant "search" without
/// granting the whole network.
pub const SEARCH_RESOURCE_HOST: &str = "search";

#[derive(Debug, Deserialize)]
struct Args {
    query: String,
    #[serde(default)]
    limit: Option<usize>,
}

/// Search the web through the configured backends.
pub struct WebSearchTool {
    backends: Vec<Arc<dyn SearchBackend>>,
    client: reqwest::Client,
}

impl WebSearchTool {
    pub fn new(backends: Vec<Arc<dyn SearchBackend>>, client: reqwest::Client) -> Self {
        Self { backends, client }
    }

    /// The names of the backends this tool will fan out to, for `hx doctor` and for the model.
    pub fn backend_ids(&self) -> Vec<String> {
        self.backends.iter().map(|b| b.id().to_string()).collect()
    }

    /// Render a report for a model: results with their sources, then what failed.
    ///
    /// The failures are part of the answer on purpose. "Three results, and one engine was
    /// unreachable" is a different thing to reason from than three results presented as the whole
    /// picture — and a model that is told which source is missing can decide to try another way.
    pub fn render(report: &SearchReport, limit: usize) -> String {
        let mut out = String::new();
        if report.results.is_empty() {
            out.push_str("No results.\n");
        }
        for (index, result) in report.results.iter().take(limit).enumerate() {
            out.push_str(&format!(
                "{}. {}\n   {}\n",
                index + 1,
                result.title.trim(),
                result.url
            ));
            let snippet = result.snippet.trim();
            if !snippet.is_empty() {
                out.push_str(&format!("   {}\n", snippet.replace('\n', " ")));
            }
            if result.sources.len() > 1 {
                out.push_str(&format!("   [{} agree]\n", result.sources.join(", ")));
            }
        }
        if !report.failures.is_empty() {
            out.push_str("\nUnavailable:\n");
            for failure in &report.failures {
                out.push_str(&format!(
                    "- {}: {}\n",
                    failure.backend,
                    failure.reason.trim()
                ));
            }
        }
        out.push_str(&format!("\n({})", report.summary()));
        out
    }
}

#[async_trait]
impl Tool for WebSearchTool {
    fn name(&self) -> &str {
        "search"
    }

    fn description(&self) -> &str {
        "Search the web through the configured backends and return ranked results. Results that \
         several engines agree on rank higher. If a backend is unavailable it is listed at the \
         end rather than silently dropped."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "what to search for" },
                "limit": { "type": "integer", "description": "maximum results (default 8)" }
            },
            "required": ["query"]
        })
    }

    fn requirement(
        &self,
        args: &Value,
        _ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError> {
        let parsed: Args = parse_args(args)?;
        if parsed.query.trim().is_empty() {
            return Err(ToolError::Arguments("query is empty".to_string()));
        }
        Ok(Some(Requirement::new(
            Resource::NetworkHost {
                host: SEARCH_RESOURCE_HOST.to_string(),
            },
            Action::Connect,
            format!("search the web for {:?}", parsed.query),
        )))
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        let _ = ctx; // search does not touch the host
        let parsed: Args = parse_args(&args)?;
        let limit = parsed.limit.unwrap_or(8).clamp(1, 25);

        if self.backends.is_empty() {
            return Ok(ToolOutcome::failed(
                "no search backends are configured; set search.backends in the config",
            ));
        }

        let query = SearchQuery::new(parsed.query.clone()).with_limit(limit);
        let report = fanout(&self.backends, &self.client, &query, SEARCH_TIMEOUT).await;

        let rendered = Self::render(&report, limit);
        if report.results.is_empty() {
            // A failed outcome, because the model needs to decide what to do next — rephrase, try
            // another source, or tell the user that search is unavailable.
            return Ok(ToolOutcome::failed(rendered));
        }
        Ok(ToolOutcome::ok(rendered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_search::{BackendKind, SearchError, SearchResult};

    /// A backend that returns whatever it was told to.
    struct Scripted {
        id: String,
        results: Vec<SearchResult>,
        error: Option<String>,
    }

    impl Scripted {
        fn answering(id: &str, titles: &[(&str, &str)]) -> Self {
            Self {
                id: id.to_string(),
                results: titles
                    .iter()
                    .enumerate()
                    .map(|(rank, (title, url))| SearchResult {
                        title: title.to_string(),
                        url: url.to_string(),
                        snippet: format!("snippet for {title}"),
                        rank,
                    })
                    .collect(),
                error: None,
            }
        }

        fn failing(id: &str, reason: &str) -> Self {
            Self {
                id: id.to_string(),
                results: Vec::new(),
                error: Some(reason.to_string()),
            }
        }
    }

    #[async_trait]
    impl SearchBackend for Scripted {
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
            match &self.error {
                Some(reason) => Err(SearchError::NotConfigured(reason.clone())),
                None => Ok(self.results.clone()),
            }
        }
    }

    fn tool(backends: Vec<Arc<dyn SearchBackend>>) -> WebSearchTool {
        WebSearchTool::new(backends, reqwest::Client::new())
    }

    fn ctx() -> ToolContext {
        ToolContext::new(Arc::new(crate::testing::FakeHost::unix()))
    }

    #[tokio::test]
    async fn results_are_rendered_with_their_urls() {
        let backend = Arc::new(Scripted::answering(
            "stub",
            &[
                ("Rust Programming Language", "https://rust-lang.org/"),
                ("The Book", "https://doc.rust-lang.org/book/"),
            ],
        ));

        let outcome = tool(vec![backend])
            .call(json!({"query": "rust"}), &ctx())
            .await
            .unwrap();

        assert!(outcome.ok, "{}", outcome.content);
        assert!(outcome.content.contains("1. Rust Programming Language"));
        assert!(outcome.content.contains("https://rust-lang.org/"));
        assert!(outcome.content.contains("2. The Book"));
    }

    #[tokio::test]
    async fn a_backend_that_fails_is_reported_alongside_the_results() {
        // The point of the whole report shape: a partial answer has to look partial.
        let server = Arc::new(Scripted::answering(
            "alpha",
            &[("One", "https://one.example")],
        ));
        let broken = Arc::new(Scripted::failing("beta", "connection refused"));

        let outcome = tool(vec![server, broken])
            .call(json!({"query": "anything"}), &ctx())
            .await
            .unwrap();

        assert!(outcome.ok);
        assert!(outcome.content.contains("https://one.example"));
        assert!(outcome.content.contains("Unavailable:"));
        assert!(outcome.content.contains("beta: connection refused"));
        assert!(outcome.content.contains("unavailable: beta"));
    }

    #[tokio::test]
    async fn no_results_anywhere_is_a_failure_the_model_reads() {
        let broken = Arc::new(Scripted::failing("beta", "served a bot check"));
        let outcome = tool(vec![broken])
            .call(json!({"query": "anything"}), &ctx())
            .await
            .unwrap();

        assert!(!outcome.ok);
        assert!(outcome.content.contains("No results."));
        assert!(
            outcome.content.contains("served a bot check"),
            "the reason is the useful part: {}",
            outcome.content
        );
    }

    #[tokio::test]
    async fn no_backends_configured_says_so_rather_than_returning_nothing() {
        let outcome = tool(vec![])
            .call(json!({"query": "anything"}), &ctx())
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("no search backends"),
            "{}",
            outcome.content
        );
    }

    #[test]
    fn searching_asks_for_a_connect_grant_on_the_search_resource() {
        let requirement = tool(vec![])
            .requirement(&json!({"query": "rust"}), &ctx())
            .unwrap()
            .expect("searching has an external effect");
        assert_eq!(requirement.action, Action::Connect);
        match requirement.resource {
            Resource::NetworkHost { host } => assert_eq!(host, SEARCH_RESOURCE_HOST),
            other => panic!("expected a network grant, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_query_is_refused() {
        let err = tool(vec![])
            .requirement(&json!({"query": "  "}), &ctx())
            .unwrap_err();
        assert!(err.to_string().contains("query is empty"), "{err}");
    }

    #[tokio::test]
    async fn duplicate_urls_from_two_engines_are_fused_and_agreement_is_shown() {
        let a = Arc::new(Scripted::answering(
            "alpha",
            &[
                ("Rust", "https://rust-lang.org/"),
                ("Other", "https://other.example"),
            ],
        ));
        let b = Arc::new(Scripted::answering(
            "beta",
            &[("Rust", "https://rust-lang.org/")],
        ));

        let outcome = tool(vec![a, b])
            .call(json!({"query": "rust"}), &ctx())
            .await
            .unwrap();

        assert!(outcome.content.contains("https://rust-lang.org/"));
        assert!(
            outcome.content.contains("[alpha, beta agree]"),
            "agreement is the signal worth surfacing: {}",
            outcome.content
        );
    }
}
