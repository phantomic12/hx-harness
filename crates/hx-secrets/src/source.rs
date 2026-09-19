//! Where a key comes from: resolving a `store:name` reference into a [`Secret`].
//!
//! ## Why this is a trait and a registry
//!
//! The configuration refers to credentials, never to values: `credentials: [{ id: a1, secret:
//! "vault:anthropic/main" }]`. Something has to turn that reference into a key at the moment of a
//! call, and *what* that something is differs by deployment — a laptop with an unlocked vault, a
//! container with an environment variable from its orchestrator, a CI job with neither.
//!
//! So the store name in the reference chooses the source, and the sources are composed:
//! `vault:` goes to the vault, `env:` to the process environment. An unknown store is an error
//! that lists the stores that *are* configured, because the alternative — treating an unknown
//! prefix as "empty key" — is how a request goes out unauthenticated and is blamed on the model.
//!
//! ## The rules this module holds to
//!
//! - **A value never appears in a message.** Errors name the reference and the variable, never the
//!   secret, and [`Secret`]'s own `Debug` is redacted, so a `{:?}` in a log cannot leak one either.
//! - **Missing is an error, not a default.** An empty key is refused here rather than sent: a
//!   provider answering `401` costs a round trip and reads like a bug in the harness.
//! - **Fail closed.** No sources configured means every reference fails; there is no implicit
//!   "read the environment" fallback, because a deployment that thinks it is using a vault should
//!   not silently be reading `$OPENAI_API_KEY` instead.

use crate::vault::{Secret, Vault, VaultError};
use hx_core::config::SecretRef;
use hx_core::error::{HxError, Result};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Where the key for a reference comes from.
pub trait SecretSource: Send + Sync {
    /// The store name this source answers for — `vault`, `env`.
    fn store(&self) -> &str;

    /// Resolve `name` within this store.
    ///
    /// The error must name the reference and must not contain the value.
    fn get(&self, name: &str) -> Result<Secret>;
}

impl fmt::Debug for dyn SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the values: a source is a lookup table of credentials.
        f.debug_struct("SecretSource")
            .field("store", &self.store())
            .finish()
    }
}

/// The sources a deployment has, dispatched by the reference's store name.
#[derive(Default)]
pub struct SecretStores {
    sources: BTreeMap<String, Arc<dyn SecretSource>>,
}

impl SecretStores {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source. A later source with the same store name replaces the earlier one, so a caller
    /// can layer a test double over a real vault without ordering games.
    pub fn with(mut self, source: Arc<dyn SecretSource>) -> Self {
        self.sources.insert(source.store().to_string(), source);
        self
    }

    /// The store names this deployment can answer for, in a stable order.
    pub fn stores(&self) -> Vec<&str> {
        self.sources.keys().map(String::as_str).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Resolve a reference like `vault:anthropic/main`.
    pub fn resolve(&self, reference: &SecretRef) -> Result<Secret> {
        let source = self.sources.get(&reference.store).ok_or_else(|| {
            let known = if self.sources.is_empty() {
                "none are configured".to_string()
            } else {
                format!("configured stores: {}", self.stores().join(", "))
            };
            HxError::Secret(format!(
                "no source for secret store '{}' ({known}); the reference was '{}'",
                reference.store, reference
            ))
        })?;

        source.get(&reference.name)
    }

    /// Resolve a reference written the way the config writes it.
    pub fn resolve_str(&self, reference: &str) -> Result<Secret> {
        self.resolve(&SecretRef::parse(reference)?)
    }
}

impl fmt::Debug for SecretStores {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStores")
            .field("stores", &self.stores())
            .finish()
    }
}

/// Keys from the process environment — `env:OPENROUTER_API_KEY`.
///
/// The right source for a container whose orchestrator injects secrets, and the wrong one for a
/// laptop: anything that can read `/proc/<pid>/environ` can read these, which is why the reference
/// has to name the variable explicitly instead of the harness guessing at well-known names.
pub struct EnvSecrets;

impl EnvSecrets {
    /// Is an environment variable visible under this name?
    ///
    /// Exposed so `hx doctor` can report what *would* resolve, without ever reading a value into a
    /// report.
    pub fn has(name: &str) -> bool {
        std::env::var_os(name).is_some()
    }
}

impl SecretSource for EnvSecrets {
    fn store(&self) -> &str {
        "env"
    }

    fn get(&self, name: &str) -> Result<Secret> {
        match std::env::var(name) {
            Ok(value) if !value.trim().is_empty() => Ok(Secret::new(value)),
            // An empty variable is the same as an absent one: exporting an empty string is how a
            // deploy script silently disables a credential.
            Ok(_) => Err(HxError::Secret(format!(
                "environment variable '{name}' is set but empty; the reference 'env:{name}' would \
                 send an unauthenticated request"
            ))),
            Err(std::env::VarError::NotPresent) => Err(HxError::Secret(format!(
                "environment variable '{name}' is not set (reference 'env:{name}')"
            ))),
            Err(std::env::VarError::NotUnicode(_)) => Err(HxError::Secret(format!(
                "environment variable '{name}' is not valid UTF-8; a key must be text"
            ))),
        }
    }
}

/// Keys from an unlocked [`Vault`].
pub struct VaultSecrets {
    vault: Vault,
}

impl VaultSecrets {
    pub fn new(vault: Vault) -> Self {
        Self { vault }
    }

    /// How many names the vault holds, for a doctor report. Never the names themselves: a vault
    /// that lists its contents to a status endpoint is a vault that leaks its shape.
    pub fn len(&self) -> usize {
        self.vault.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vault.is_empty()
    }
}

impl SecretSource for VaultSecrets {
    fn store(&self) -> &str {
        "vault"
    }

    fn get(&self, name: &str) -> Result<Secret> {
        self.vault.get(name).cloned().map_err(|err| match err {
            // The reference is named; the value is not, and never can be.
            VaultError::NotFound(_) => HxError::Secret(format!(
                "'vault:{name}' is not in the vault (the vault holds {} entries; \
                     `hx vault list` shows the names)",
                self.vault.len()
            )),
            other => HxError::Secret(format!("could not read 'vault:{name}': {other}")),
        })
    }
}

/// Keys from a fixed map.
///
/// Two real uses: tests, and a daemon that resolved its keys once at startup and holds them in
/// memory on purpose — a long-running process that touches the vault per call is a process that can
/// be made to read an unlocked vault from a stray request.
pub struct FixedSecrets {
    store: String,
    entries: BTreeMap<String, Secret>,
}

impl FixedSecrets {
    pub fn new(store: impl Into<String>) -> Self {
        Self {
            store: store.into(),
            entries: BTreeMap::new(),
        }
    }

    /// A map for the conventional `vault` store name, for tests that want a vault-shaped reference
    /// without building one.
    pub fn vault() -> Self {
        Self::new("vault")
    }

    pub fn set(mut self, name: impl Into<String>, value: impl Into<Secret>) -> Self {
        self.entries.insert(name.into(), value.into());
        self
    }
}

impl SecretSource for FixedSecrets {
    fn store(&self) -> &str {
        &self.store
    }

    fn get(&self, name: &str) -> Result<Secret> {
        self.entries.get(name).cloned().ok_or_else(|| {
            HxError::Secret(format!(
                "'{}:{name}' has no value in this build",
                self.store
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::KdfParams;

    fn reference(text: &str) -> SecretRef {
        SecretRef::parse(text).expect("a valid reference")
    }

    fn vault_with(name: &str, value: &str) -> Vault {
        let mut vault = Vault::create("test passphrase", KdfParams::for_tests()).unwrap();
        vault.put(name, value);
        vault
    }

    #[test]
    fn a_fixed_source_hands_back_the_value_it_was_given() {
        let stores = SecretStores::new().with(Arc::new(
            FixedSecrets::vault().set("openrouter/main", "sk-or-v1-abc"),
        ));

        let secret = stores.resolve(&reference("vault:openrouter/main")).unwrap();
        assert_eq!(secret.expose(), "sk-or-v1-abc");
    }

    #[test]
    fn a_missing_name_names_the_reference_and_not_a_value() {
        let stores = SecretStores::new().with(Arc::new(
            FixedSecrets::vault().set("openrouter/main", "sk-or-v1-secret-value"),
        ));

        let err = stores
            .resolve(&reference("vault:openrouter/other"))
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("openrouter/other"), "{text}");
        assert!(
            !text.contains("sk-or-v1-secret-value"),
            "an error must not carry a key: {text}"
        );
    }

    #[test]
    fn an_unknown_store_lists_the_stores_that_are_configured() {
        let stores = SecretStores::new()
            .with(Arc::new(EnvSecrets))
            .with(Arc::new(FixedSecrets::vault()));

        let err = stores.resolve(&reference("keychain:github")).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("keychain"), "{text}");
        assert!(
            text.contains("env") && text.contains("vault"),
            "the message should say what *would* work: {text}"
        );
        assert_eq!(stores.stores(), vec!["env", "vault"], "stable order");
    }

    #[test]
    fn with_no_sources_at_all_every_reference_fails_closed() {
        let stores = SecretStores::new();
        assert!(stores.is_empty());

        let err = stores.resolve(&reference("vault:anything")).unwrap_err();
        assert!(err.to_string().contains("none are configured"), "{err}");
    }

    #[test]
    fn an_unparseable_reference_is_refused_before_a_source_is_consulted() {
        let stores = SecretStores::new().with(Arc::new(FixedSecrets::vault()));
        let err = stores.resolve_str("no-colon-here").unwrap_err();
        assert!(
            err.to_string().contains("invalid secret reference"),
            "{err}"
        );
    }

    #[test]
    fn a_real_vault_round_trips_through_the_source() {
        let stores = SecretStores::new().with(Arc::new(VaultSecrets::new(vault_with(
            "anthropic/main",
            "sk-ant-1",
        ))));

        assert_eq!(
            stores
                .resolve(&reference("vault:anthropic/main"))
                .unwrap()
                .expose(),
            "sk-ant-1"
        );

        // And a name that is not there reports the vault's size rather than its contents.
        let err = stores
            .resolve(&reference("vault:anthropic/missing"))
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("not in the vault"), "{text}");
        assert!(text.contains("holds 1 entries"), "{text}");
        assert!(!text.contains("sk-ant-1"), "{text}");
        assert!(
            !text.contains("anthropic/main"),
            "the names stay in the vault: {text}"
        );
    }

    #[test]
    fn env_reads_the_variable_it_is_told_to_and_refuses_an_empty_one() {
        // A name unlikely to exist anywhere; the test sets it explicitly.
        let name = "HX_TEST_SECRET_FOR_SOURCE_TESTS";
        std::env::set_var(name, "from-the-environment");

        let stores = SecretStores::new().with(Arc::new(EnvSecrets));
        assert_eq!(
            stores.resolve_str(&format!("env:{name}")).unwrap().expose(),
            "from-the-environment"
        );

        std::env::set_var(name, "   ");
        let err = stores
            .resolve_str(&format!("env:{name}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("set but empty"), "{err}");

        std::env::remove_var(name);
        let err = stores
            .resolve_str(&format!("env:{name}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not set"), "{err}");
        assert!(
            !EnvSecrets::has(name),
            "the doctor check reads the same thing"
        );
    }

    #[test]
    fn a_vault_source_replaced_by_a_fixed_one_is_what_resolves() {
        // Layering, which is how a test double is installed over a real vault.
        let stores = SecretStores::new()
            .with(Arc::new(VaultSecrets::new(vault_with(
                "a",
                "from-the-vault",
            ))))
            .with(Arc::new(FixedSecrets::vault().set("a", "from-the-double")));

        assert_eq!(
            stores.resolve(&reference("vault:a")).unwrap().expose(),
            "from-the-double"
        );
    }

    #[test]
    fn the_debug_of_a_source_and_a_registry_never_prints_a_value() {
        let stores = SecretStores::new().with(Arc::new(
            FixedSecrets::vault().set("main", "sk-should-never-be-printed"),
        ));
        let source: Arc<dyn SecretSource> = Arc::new(FixedSecrets::vault().set("main", "sk-nope"));

        let printed = format!("{stores:?} {source:?}");
        assert!(!printed.contains("sk-"), "{printed}");
        assert!(printed.contains("vault"), "{printed}");
    }
}
