//! The backend trait and the registry built from configuration.

use crate::aggregate::{fanout, SearchReport, DEFAULT_BACKEND_TIMEOUT};
use crate::backends::{
    BraveBackend, DuckDuckGoBackend, GoogleCseBackend, HnAlgoliaBackend, MarginaliaBackend,
    MojeekBackend, SearxngBackend, WikipediaBackend,
};
use crate::types::{SearchQuery, SearchResult};
use async_trait::async_trait;
use hx_core::config::SearchConfig;
use hx_core::error::{HxError, Result};
use hx_secrets::{Redactor, Secret, SecretStores};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Every backend name `search.backends` accepts, in one place so the "unknown backend" error
/// cannot drift out of step with what the registry actually builds.
///
/// The keyless names are the free set the milestone counts; `brave` and `google_cse` are keyed and
/// are therefore never defaults.
pub const KNOWN_BACKENDS: &str = "searxng, duckduckgo (alias: ddg), mojeek, marginalia, \
     wikipedia, hackernews (alias: hn), brave, google_cse";

/// The names that need neither a URL nor a credential — the "free backends" of M6's exit criteria.
///
/// Listed here so the milestone's count is a number the code knows rather than a number the docs
/// assert: `every_keyless_backend_is_counted` in `backend.rs` compares this list against what the
/// registry actually builds.
pub const KEYLESS_BACKENDS: &[&str] = &[
    "searxng",
    "duckduckgo",
    "mojeek",
    "marginalia",
    "wikipedia",
    "hackernews",
];

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

    /// The site refused the automated client — a bot wall, a challenge, or a 403/429/503.
    ///
    /// Added for the browser-backed [`Fetcher`](crate::research::Fetcher). A refusal is **not**
    /// a transport failure: the plain fetch was blocked by a wall, and that is the event a caller
    /// escalates on. It is also **not** an empty body — a caller that swallowed the wall into
    /// `Ok(Some(""))` would hand the model a page that was never served. `reason` is a
    /// credential-free sentence built from a rung's [`Disposition`], never the page body.
    #[error("fetch refused: {reason}")]
    Refused { reason: String },

    #[error("could not parse the response: {reason}")]
    Parse { reason: String },

    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// A transport failure whose message had a credential taken out of it.
    ///
    /// `reqwest::Error`'s `Display` includes the request URL. For a backend that passes its key as a
    /// query parameter — Google PSE — the default `#[from]` conversion would therefore put a live
    /// credential into an error the model reads. Such a backend converts through
    /// [`SearchError::transport_redacted`] instead, and that method returns the ordinary
    /// [`SearchError::Transport`] when there was nothing to hide, so only the leaking case changes
    /// shape.
    #[error("transport error: {reason}")]
    TransportRedacted { reason: String },

    #[error("{0}")]
    NotConfigured(String),
}

impl SearchError {
    /// A transport failure with `secret`'s value masked out of its message.
    ///
    /// Uses the crate's own [`Redactor`] rather than a hand-rolled `replace`, so a value is masked
    /// exactly the way it is masked everywhere else in the harness.
    pub fn transport_redacted(err: reqwest::Error, secret: &Secret) -> Self {
        let mut redactor = Redactor::new();
        redactor.register(secret.expose());
        let redaction = redactor.redact(&err.to_string());

        if !redaction.changed() {
            return SearchError::Transport(err);
        }

        SearchError::TransportRedacted {
            reason: redaction.text,
        }
    }
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
    /// An unrecognised name, a keyed backend with no credential *reference* configured, or a
    /// reference that will not resolve is a configuration error, not a skip. Silently dropping a
    /// backend the user asked for produces the worst outcome: search that looks configured and
    /// quietly returns less.
    ///
    /// `secrets` resolves the references in `search.credentials` — `vault:…`, `env:…`. It is taken
    /// here rather than read from the environment directly so a deployment decides where its keys
    /// live, and so a test can install a fixed source with no vault and no environment at all.
    /// Resolution happens **once**, at construction: a long-running daemon that touches the vault
    /// per query is a daemon that can be made to read an unlocked vault from a stray request.
    pub fn from_config(
        cfg: &SearchConfig,
        client: reqwest::Client,
        secrets: &SecretStores,
    ) -> Result<Self> {
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
                "hackernews" | "hn" => Arc::new(HnAlgoliaBackend::new()),
                "brave" => {
                    let key = resolve_credential(cfg, secrets, "brave", "BRAVE_SEARCH_KEY")?;
                    Arc::new(BraveBackend::new(key))
                }
                "google_cse" => {
                    let key = resolve_credential(cfg, secrets, "google_cse", "GOOGLE_CSE_KEY")?;
                    // `cx` is not a credential: it names a search engine the operator configured
                    // and it appears in every result URL, so it is a plain config value.
                    let cx = cfg
                        .google_cse_cx
                        .as_deref()
                        .map(str::trim)
                        .filter(|cx| !cx.is_empty())
                        .ok_or_else(|| {
                            HxError::Config(
                                "search.backends lists 'google_cse' but search.google_cse_cx is \
                                 unset (the `cx` id of the Programmable Search engine)"
                                    .to_string(),
                            )
                        })?;
                    Arc::new(GoogleCseBackend::new(key, cx))
                }
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

/// Resolve the credential reference configured for `backend`.
///
/// Two failures, both loud and both naming the *reference*:
///
/// - No reference configured. The message names the backend, shows the shape to add, and says
///   "a reference, never a value" — because the wrong fix here is to paste the key into the config,
///   which is the mistake this shape exists to prevent.
/// - A reference that will not resolve. `SecretStores` already refuses to name a value; this wraps
///   its error so a deployment with several keyed backends knows which one failed to start.
///
/// `env_name` is only used to make the first message actionable.
fn resolve_credential(
    cfg: &SearchConfig,
    secrets: &SecretStores,
    backend: &str,
    env_name: &str,
) -> Result<Secret> {
    let reference = cfg.credentials.get(backend).ok_or_else(|| {
        HxError::Config(format!(
            "search.backends lists '{backend}' but search.credentials has no reference for it; \
             add e.g. `credentials: {{{backend}: \"env:{env_name}\"}}` — a reference, never a value"
        ))
    })?;

    secrets.resolve_str(reference).map_err(|err| {
        HxError::Config(format!(
            "could not resolve the '{backend}' search credential from reference \
             '{reference}': {err}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_secrets::FixedSecrets;

    fn cfg(backends: &[&str], searxng: Option<&str>) -> SearchConfig {
        SearchConfig {
            backends: backends.iter().map(|s| (*s).to_string()).collect(),
            searxng_url: searxng.map(str::to_string),
            ..Default::default()
        }
    }

    /// Build a registry the way the daemon does, but with **no secret sources at all**.
    ///
    /// That is the right default for these tests: it is what makes "a keyed backend with no
    /// credential configured" reachable without touching the process environment, and it is the
    /// shape a deployment that has not set up a vault actually has.
    fn registry(cfg: &SearchConfig) -> Result<BackendRegistry> {
        BackendRegistry::from_config(cfg, reqwest::Client::new(), &SecretStores::new())
    }

    /// The same, with one `vault:` reference resolvable from a fixed map — no vault, no environment.
    fn registry_with(cfg: &SearchConfig, name: &str, value: &str) -> Result<BackendRegistry> {
        let stores = SecretStores::new().with(Arc::new(FixedSecrets::vault().set(name, value)));
        BackendRegistry::from_config(cfg, reqwest::Client::new(), &stores)
    }

    #[test]
    fn builds_the_named_backends_in_priority_order() {
        let r = registry(&cfg(
            &["searxng", "duckduckgo"],
            Some("http://localhost:8888"),
        ))
        .unwrap();

        assert_eq!(r.ids(), vec!["searxng", "duckduckgo"]);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn every_keyless_backend_builds_with_no_configuration_at_all() {
        // The $0 promise, at the registry: the keyless set needs no URL and no credential, so a
        // config that names them and nothing else must build.
        let r = registry(&cfg(
            &[
                "searxng",
                "ddg",
                "mojeek",
                "marginalia",
                "wikipedia",
                "hackernews",
            ],
            Some("http://localhost:8888"),
        ))
        .unwrap();

        assert_eq!(
            r.ids(),
            vec![
                "searxng",
                "duckduckgo",
                "mojeek",
                "marginalia",
                "wikipedia",
                "hackernews"
            ]
        );
        assert!(
            r.backends.iter().all(|b| !b.requires_key()),
            "no default backend may require a credential"
        );
    }

    #[test]
    fn every_keyless_backend_is_counted() {
        // M6's exit criteria is "6 free backends in parallel". A count in a document is a claim;
        // this compares the crate's own list against what the registry builds, so adding a backend
        // without adding it here (or naming one here that does not build) fails the suite instead
        // of making the milestone's number quietly wrong.
        assert_eq!(
            KEYLESS_BACKENDS.len(),
            6,
            "the milestone's \"6 free backends\" has to be a number the code agrees with"
        );

        let r = registry(&cfg(KEYLESS_BACKENDS, Some("http://localhost:8888"))).unwrap();

        assert_eq!(r.ids(), KEYLESS_BACKENDS.to_vec());
        assert!(
            r.backends.iter().all(|b| !b.requires_key()),
            "a name on the keyless list that needs a credential is a lie about cost"
        );
        assert!(
            r.backends.iter().all(|b| b.kind() != BackendKind::Keyed),
            "a keyless backend must not report itself as keyed"
        );
    }

    #[test]
    fn hn_is_an_accepted_alias_for_hackernews() {
        let r = registry(&cfg(&["hn"], None)).unwrap();
        assert_eq!(r.ids(), vec!["hackernews"]);
    }

    #[test]
    fn ddg_is_an_accepted_alias_for_duckduckgo() {
        // `search.backends` shipped with the short name in `default_backends()`, so the long
        // name alone would make the shipped default a configuration error.
        let r = registry(&cfg(&["ddg"], None)).unwrap();
        assert_eq!(r.ids(), vec!["duckduckgo"]);
    }

    #[test]
    fn searxng_without_a_url_is_a_loud_configuration_error() {
        let err = registry(&cfg(&["searxng"], None)).unwrap_err();
        assert!(err.to_string().contains("searxng_url is unset"), "{err}");
    }

    #[test]
    fn an_unknown_backend_name_is_rejected_with_the_known_list() {
        let err = registry(&cfg(&["google"], None)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown search backend 'google'"), "{msg}");
        assert!(msg.contains("searxng"), "must list valid options: {msg}");
    }

    #[test]
    fn an_empty_backend_list_is_allowed_but_reported_as_empty() {
        let r = registry(&cfg(&[], None)).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn kinds_are_reported_for_status_output() {
        let r = registry(&cfg(
            &["searxng", "duckduckgo"],
            Some("http://localhost:8888"),
        ))
        .unwrap();
        let kinds: Vec<BackendKind> = r.backends.iter().map(|b| b.kind()).collect();
        assert_eq!(kinds, vec![BackendKind::Searxng, BackendKind::Keyless]);
    }

    // ---- keyed backends ----

    #[test]
    fn the_default_registry_contains_no_keyed_backend() {
        // The $0 promise has to hold at the *defaults*, not only in a hand-written config: a keyed
        // backend on by default would make a default run bill somebody.
        let default = SearchConfig::default();
        assert!(
            !default
                .backends
                .iter()
                .any(|b| b == "brave" || b == "google_cse"),
            "a keyed backend must never be a default: {:?}",
            default.backends
        );

        let r = registry(&default).unwrap();
        assert!(
            r.backends.iter().all(|b| !b.requires_key()),
            "the default registry must contain no backend that needs a credential: {:?}",
            r.ids()
        );
        assert!(
            r.backends.iter().all(|b| b.kind() != BackendKind::Keyed),
            "{:?}",
            r.ids()
        );
    }

    #[test]
    fn a_keyed_backend_reports_that_it_needs_a_key() {
        // `hx doctor` and `hx status` branch on this, so a keyed backend that answered `false`
        // would present itself as free and fail at the first query instead.
        let cfg = SearchConfig {
            backends: vec!["brave".into(), "google_cse".into()],
            credentials: [
                ("brave".to_string(), "vault:brave/search".to_string()),
                ("google_cse".to_string(), "vault:google/cse".to_string()),
            ]
            .into_iter()
            .collect(),
            google_cse_cx: Some("0123456789abcdef0".into()),
            ..Default::default()
        };

        // Both names resolve from one fixed source, so this needs no vault and no environment.
        let stores = SecretStores::new().with(Arc::new(
            FixedSecrets::vault()
                .set("brave/search", "BSA-sentinel")
                .set("google/cse", "GOOGLE-sentinel"),
        ));
        let r = BackendRegistry::from_config(&cfg, reqwest::Client::new(), &stores).unwrap();

        assert_eq!(r.ids(), vec!["brave", "google_cse"]);
        assert!(
            r.backends.iter().all(|b| b.requires_key()),
            "a keyed backend must say so: {:?}",
            r.ids()
        );
        assert!(
            r.backends.iter().all(|b| b.kind() == BackendKind::Keyed),
            "{:?}",
            r.ids()
        );
    }

    #[test]
    fn a_keyed_backend_with_no_credential_reference_is_a_loud_error() {
        // The failure mode this prevents: a search that looks configured, silently drops a backend,
        // and returns less than the operator asked for.
        let err = registry(&cfg(&["brave"], None)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'brave'"), "{msg}");
        assert!(
            msg.contains("credentials"),
            "the message must name the key to add: {msg}"
        );
        assert!(
            msg.contains("never a value"),
            "the wrong fix is pasting the key in; the message should say so: {msg}"
        );
    }

    #[test]
    fn a_credential_reference_that_cannot_resolve_names_the_reference_and_never_a_value() {
        // No secret sources at all, which is what a deployment without a vault has.
        let cfg = SearchConfig {
            backends: vec!["brave".into()],
            credentials: [("brave".to_string(), "vault:brave/search".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };

        let err = registry(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("vault:brave/search"), "{msg}");
        assert!(msg.contains("'brave'"), "which backend failed: {msg}");
    }

    #[test]
    fn a_resolved_keyed_backend_builds_and_its_credential_never_reaches_a_debug_line() {
        let cfg = SearchConfig {
            backends: vec!["brave".into()],
            credentials: [("brave".to_string(), "vault:brave/search".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };

        let r = registry_with(&cfg, "brave/search", "BSA-sentinel-value").unwrap();
        assert_eq!(r.ids(), vec!["brave"]);

        let printed = format!("{r:?}");
        assert!(!printed.contains("BSA-sentinel-value"), "{printed}");
        assert!(printed.contains("brave"), "{printed}");
    }

    #[test]
    fn a_missing_credential_value_is_an_error_and_does_not_fall_back_to_the_environment() {
        // The reference says `vault:`; an `env:` value with the same name must not satisfy it, or a
        // deployment that thinks it is using a vault is silently reading the environment instead.
        let name = "HX_TEST_BRAVE_KEY_THAT_MUST_NOT_BE_READ";
        std::env::set_var(name, "an-environment-value");
        let stores = SecretStores::new().with(Arc::new(hx_secrets::EnvSecrets));

        let cfg = SearchConfig {
            backends: vec!["brave".into()],
            credentials: [("brave".to_string(), format!("env:{name}"))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        // The `env:` reference *does* resolve, and the value is used — but the point of this test
        // is that resolution goes through the named store, so a `vault:` reference against these
        // stores fails even though the environment holds a same-named variable.
        let r = BackendRegistry::from_config(&cfg, reqwest::Client::new(), &stores).unwrap();
        assert_eq!(r.ids(), vec!["brave"]);

        let vault_cfg = SearchConfig {
            backends: vec!["brave".into()],
            credentials: [("brave".to_string(), "vault:brave/search".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let err = BackendRegistry::from_config(&vault_cfg, reqwest::Client::new(), &stores)
            .unwrap_err()
            .to_string();
        assert!(err.contains("vault:brave/search"), "{err}");
        assert!(
            !err.contains("an-environment-value"),
            "no value may reach an error: {err}"
        );

        std::env::remove_var(name);
    }

    #[test]
    fn google_cse_without_an_engine_id_is_a_loud_configuration_error() {
        // The key alone is not enough: `cx` names the engine to search.
        let cfg = SearchConfig {
            backends: vec!["google_cse".into()],
            credentials: [("google_cse".to_string(), "vault:google/cse".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };

        let err = registry_with(&cfg, "google/cse", "GOOGLE-sentinel").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("google_cse_cx"), "{msg}");
        assert!(!msg.contains("GOOGLE-sentinel"), "{msg}");
    }
}
