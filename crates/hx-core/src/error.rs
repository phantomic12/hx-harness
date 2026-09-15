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
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, HxError::Secret(_))
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
}
