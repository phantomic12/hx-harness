//! The backend trait and the registry built from configuration.

use crate::aggregate::{fanout, SearchReport, DEFAULT_BACKEND_TIMEOUT};
use crate::backends::{
    DuckDuckGoBackend, MarginaliaBackend, MojeekBackend, SearxngBackend, WikipediaBackend,
};
use crate::types::{SearchQuery, SearchResult};
use async_trait::async_trait;
use hx_core::config::SearchConfig;
use hx_core::error::{HxError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Every backend name `search.backends` accepts, in one place so the "unknown backend" error
/// cannot drift out of step with what the registry actually builds.
pub const KNOWN_BACKENDS: &str = "searxng, duckduckgo (alias: ddg), mojeek, marginalia, wikipedia";

/// Which family a backend belongs to. Useful for status output and for grouping sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// A SearXNG instance — fronts ~70 engines in one API.
    Searxng,
    /// Direct keyless scrapers.
    Keyless,
    /// Bring-your-own-key APIs.
    Keyed,
    /// Test double.
    Stub,
}

#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("backend returned HTTP {status}")]
    Http { status: u16 },

    #[error("could not parse the response: {reason}")]
    Parse { reason: String },

    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("{0}")]
    NotConfigured(String),
}

/// One search source.
///
/// Takes the HTTP client by reference rather than owning one, so the daemon shares a single
/// connection pool and TLS session cache across every backend.
#[async_trait]
pub trait SearchBackend: Send + Sync {
    fn id(&self) -> &str;

    fn kind(&self) -> BackendKind;

    /// Whether this backend needs a credential. Lets `hx doctor` flag a missing key rather than
    /// letting it surface as a mysterious empty result set later.
    fn requires_key(&self) -> bool {
        false
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        query: &SearchQuery,
    ) -> std::result::Result<Vec<SearchResult>, SearchError>;
}

/// The configured set of backends, in priority order.
pub struct BackendRegistry {
    backends: Vec<Arc<dyn SearchBackend>>,
    client: reqwest::Client,
    timeout: Duration,
}

impl std::fmt::Debug for BackendRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn SearchBackend` is not `Debug`, and printing a backend's internals would risk
        // leaking a key. Ids and configuration shape are what diagnostics actually need.
        f.debug_struct("BackendRegistry")
            .field("backends", &self.ids())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl BackendRegistry {
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            backends: Vec::new(),
            client,
            timeout: DEFAULT_BACKEND_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the backends named in `search.backends`, in the order given.
    ///
    /// An unrecognised name or a keyed backend with no credential is a configuration error, not
    /// a skip. Silently dropping a backend the user asked for produces the worst outcome: search
    /// that looks configured and quietly returns less.
    pub fn from_config(cfg: &SearchConfig, client: reqwest::Client) -> Result<Self> {
        let mut registry = Self::new(client);

        for name in &cfg.backends {
            let backend: Arc<dyn SearchBackend> = match name.as_str() {
                "searxng" => {
                    let base = cfg.searxng_url.clone().ok_or_else(|| {
                        HxError::Config(
                            "search.backends lists 'searxng' but search.searxng_url is unset"
                                .to_string(),
                        )
                    })?;
                    Arc::new(SearxngBackend::new(base))
                }
                "duckduckgo" | "ddg" => Arc::new(DuckDuckGoBackend::new()),
                "mojeek" => Arc::new(MojeekBackend::new()),
                "marginalia" => Arc::new(MarginaliaBackend::new()),
                "wikipedia" => Arc::new(WikipediaBackend::new()),
                other => {
                    return Err(HxError::Config(format!(
                        "unknown search backend '{other}'; known backends: {KNOWN_BACKENDS}"
                    )))
                }
            };
            registry.insert(backend);
        }

        Ok(registry)
    }

    pub fn insert(&mut self, backend: Arc<dyn SearchBackend>) {
        self.backends.push(backend);
    }

    pub fn ids(&self) -> Vec<String> {
        self.backends.iter().map(|b| b.id().to_string()).collect()
    }

    /// The backends themselves, for a tool that fans out its own way.
    ///
    /// `WebSearchTool` is the caller: it takes the backends at construction and decides its own
    /// fanout, so it needs handles rather than names.
    pub fn all(&self) -> Vec<Arc<dyn SearchBackend>> {
        self.backends.clone()
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// Query every configured backend.
    pub async fn search(&self, query: &SearchQuery) -> SearchReport {
        fanout(&self.backends, &self.client, query, self.timeout).await
    }

    /// Query only the first `fanout` backends — the cheap path for a quick lookup.
    pub async fn search_with_fanout(&self, query: &SearchQuery, fanout: usize) -> SearchReport {
        let slice = &self.backends[..fanout.min(self.backends.len())];
        let report = crate::aggregate::fanout(slice, &self.client, query, self.timeout).await;
        report
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(backends: &[&str], searxng: Option<&str>) -> SearchConfig {
        SearchConfig {
            backends: backends.iter().map(|s| (*s).to_string()).collect(),
            searxng_url: searxng.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn builds_the_named_backends_in_priority_order() {
        let r = BackendRegistry::from_config(
            &cfg(&["searxng", "duckduckgo"], Some("http://localhost:8888")),
            reqwest::Client::new(),
        )
        .unwrap();

        assert_eq!(r.ids(), vec!["searxng", "duckduckgo"]);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn every_keyless_backend_builds_with_no_configuration_at_all() {
        // The $0 promise, at the registry: the keyless set needs no URL and no credential, so a
        // config that names them and nothing else must build.
        let r = BackendRegistry::from_config(
            &cfg(
                &["searxng", "ddg", "mojeek", "marginalia", "wikipedia"],
                Some("http://localhost:8888"),
            ),
            reqwest::Client::new(),
        )
        .unwrap();

        assert_eq!(
            r.ids(),
            vec!["searxng", "duckduckgo", "mojeek", "marginalia", "wikipedia"]
        );
        assert!(
            r.backends.iter().all(|b| !b.requires_key()),
            "no default backend may require a credential"
        );
    }

    #[test]
    fn ddg_is_an_accepted_alias_for_duckduckgo() {
        // `search.backends` shipped with the short name in `default_backends()`, so the long
        // name alone would make the shipped default a configuration error.
        let r = BackendRegistry::from_config(&cfg(&["ddg"], None), reqwest::Client::new()).unwrap();
        assert_eq!(r.ids(), vec!["duckduckgo"]);
    }

    #[test]
    fn searxng_without_a_url_is_a_loud_configuration_error() {
        let err = BackendRegistry::from_config(&cfg(&["searxng"], None), reqwest::Client::new())
            .unwrap_err();
        assert!(err.to_string().contains("searxng_url is unset"), "{err}");
    }

    #[test]
    fn an_unknown_backend_name_is_rejected_with_the_known_list() {
        let err = BackendRegistry::from_config(&cfg(&["google"], None), reqwest::Client::new())
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown search backend 'google'"), "{msg}");
        assert!(msg.contains("searxng"), "must list valid options: {msg}");
    }

    #[test]
    fn an_empty_backend_list_is_allowed_but_reported_as_empty() {
        let r = BackendRegistry::from_config(&cfg(&[], None), reqwest::Client::new()).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn kinds_are_reported_for_status_output() {
        let r = BackendRegistry::from_config(
            &cfg(&["searxng", "duckduckgo"], Some("http://localhost:8888")),
            reqwest::Client::new(),
        )
        .unwrap();
        let kinds: Vec<BackendKind> = r.backends.iter().map(|b| b.kind()).collect();
        assert_eq!(kinds, vec![BackendKind::Searxng, BackendKind::Keyless]);
    }

    #[test]
    fn no_backend_requires_a_key_yet() {
        // Guards against a keyed backend being added without updating `hx doctor`.
        let r = BackendRegistry::from_config(
            &cfg(&["searxng", "duckduckgo"], Some("http://localhost:8888")),
            reqwest::Client::new(),
        )
        .unwrap();
        assert!(r.backends.iter().all(|b| !b.requires_key()));
    }
}
