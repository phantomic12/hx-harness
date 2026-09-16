//! Error type shared across the workspace.

use thiserror::Error;

pub type Result<T, E = HxError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum HxError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("secret error: {0}")]
    Secret(String),

    #[error("provider error: {0}")]
    Provider(String),

    /// A provider rejected the credential.
    ///
    /// Separate from [`HxError::Secret`], which is about the vault, and from a generic
    /// [`HxError::Provider`], which is a transient-looking failure. The distinction is what the
    /// pool acts on: this one means *bench the credential and try another*, and a harness that
    /// cannot tell a dead key from a bad day retries the dead key until someone reads the logs.
    #[error("provider {provider} rejected the credential: {reason}")]
    ProviderAuth { provider: String, reason: String },

    /// A rate or spend limit refused the request. `scope` names what was exhausted so the
    /// caller can decide whether to wait, fail over, or surface it to the user.
    #[error("rate limited on {scope}; retry after {retry_after_ms}ms")]
    RateLimited { scope: String, retry_after_ms: u64 },

    /// The policy engine refused a capability. Carries a reason suitable for the audit log —
    /// a denial must always be explainable after the fact.
    #[error("capability denied: {0}")]
    Denied(String),

    #[error("remote host error: {0}")]
    Remote(String),

    #[error("sandbox error: {0}")]
    Sandbox(String),

    #[error("tool error: {0}")]
    Tool(String),

    #[error("search backend {backend} failed: {reason}")]
    Search { backend: String, reason: String },

    #[error("connector {connector} failed: {reason}")]
    Connector { connector: String, reason: String },

    #[error("no route to a model: {0}")]
    NoRoute(String),

    #[error("not found: {0}")]
    NotFound(String),

    /// A durable-store failure — SQLite, a migration, or a row that does not parse.
    ///
    /// Deliberately *not* retryable: the transient case (`SQLITE_BUSY`) is absorbed by the store's
    /// own busy timeout, so anything that reaches here is a real fault — a corrupt file, a schema
    /// from a newer build, a row whose JSON no longer parses — and retrying it forever is how a
    /// daemon turns a broken database into a busy loop.
    #[error("store error: {0}")]
    Store(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl HxError {
    /// True when retrying the identical request could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            HxError::RateLimited { .. } | HxError::Io(_) | HxError::Provider(_)
        )
    }

    /// True when the failure should invalidate the credential that produced it.
    ///
    /// Two ways to reach this: the vault itself failed to produce the key, or the provider looked
    /// at the key and refused it. Both mean the same thing to a pool — stop using this credential
    /// until a human fixes it — and both are *not* retryable.
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, HxError::Secret(_) | HxError::ProviderAuth { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_is_retryable() {
        let e = HxError::RateLimited {
            scope: "anthropic-main/a1:tpm".into(),
            retry_after_ms: 1_500,
        };
        assert!(e.is_retryable());
        assert!(!e.is_auth_failure());
        assert!(e.to_string().contains("1500ms"));
    }

    #[test]
    fn denied_is_not_retryable() {
        assert!(!HxError::Denied("no grant".into()).is_retryable());
    }

    #[test]
    fn a_rejected_credential_is_an_auth_failure_and_is_not_retryable() {
        let e = HxError::ProviderAuth {
            provider: "openrouter".into(),
            reason: "HTTP 401 — check the credential".into(),
        };
        assert!(e.is_auth_failure(), "this is what benches the credential");
        assert!(
            !e.is_retryable(),
            "retrying a key the provider just refused is a busy loop"
        );
        // The message names the provider and the reason, so the operator knows which key to fix.
        let text = e.to_string();
        assert!(
            text.contains("openrouter") && text.contains("401"),
            "{text}"
        );
    }

    #[test]
    fn a_transient_provider_error_is_retryable_and_is_not_an_auth_failure() {
        // The pair that used to be one variant: before `ProviderAuth` existed, a 401 and a 500 were
        // both `Provider`, so every route looked equally worth retrying.
        let e = HxError::Provider("upstream returned 500".into());
        assert!(e.is_retryable());
        assert!(!e.is_auth_failure());
    }
}
