//! Role → callable model resolution for the eval runner.
//!
//! Mirrors the daemon's construction in `hx-server` (`AppState::build` in
//! `crates/hx-server/src/state.rs` assembling the router, provider registry,
//! and env secret stores, and `RouterModels::for_role` in
//! `crates/hx-server/src/chat.rs` binding a role via `RouterModel::new`).
//! The eval runner needs the same shape — a role name resolving to an
//! `Arc<dyn hx_agent::ModelCall>` the agent loop can drive — without owning
//! any daemon state.

use chrono::{DateTime, Utc};
use hx_agent::{ModelCall, RouterModel};
use hx_core::error::{HxError, Result};
use hx_provider::{ModelRouter, ProviderRegistry};
use hx_secrets::{EnvSecrets, SecretStores};
use std::sync::{Arc, Mutex};

/// The daemon's model-routing triple, owned by the eval runner.
pub struct RunnerModels {
    router: Arc<Mutex<ModelRouter>>,
    providers: Arc<ProviderRegistry>,
    secrets: Arc<SecretStores>,
}

impl RunnerModels {
    /// Build the routing table, provider registry, and env secret stores from
    /// the app config, the way `AppState::build` does.
    pub fn from_config(config: &hx_core::config::Config, now: DateTime<Utc>) -> Result<Self> {
        let router = ModelRouter::from_config(config, now)?;
        // A model call that takes minutes is a slow answer, not a failed one:
        // no timeout here, matching the daemon's separate provider client.
        let provider_client = reqwest::Client::builder()
            .user_agent(concat!("hx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                HxError::Config(format!("could not build the provider HTTP client: {e}"))
            })?;
        let providers = ProviderRegistry::from_config(config, provider_client)?;
        // Until a vault is unlocked this resolves `env:` references only.
        let secrets = SecretStores::new().with(Arc::new(EnvSecrets));
        Ok(Self {
            router: Arc::new(Mutex::new(router)),
            providers: Arc::new(providers),
            secrets: Arc::new(secrets),
        })
    }

    /// Bind a role to a callable model, the way `RouterModels::for_role` does.
    /// Unknown roles (or roles whose pool has no routes) return `Err`.
    pub fn for_role(&self, role: &str) -> Result<Arc<dyn ModelCall>> {
        Ok(Arc::new(RouterModel::new(
            role,
            Arc::clone(&self.router),
            Arc::clone(&self.providers),
            Arc::clone(&self.secrets),
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["dead-model"]
    credentials:
      - { id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }

pools:
  interactive: { members: ["local/dead-model"] }

roles:
  builder: interactive
"#;

    #[test]
    fn resolves_configured_role_and_rejects_unknown() {
        let config = hx_core::config::Config::from_yaml(CONFIG).expect("config parses");
        let models = RunnerModels::from_config(&config, Utc::now()).expect("runner models build");
        assert!(models.for_role("builder").is_ok());
        assert!(models.for_role("no-such-role").is_err());
    }
}
