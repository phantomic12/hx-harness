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
use hx_core::api_auth::{ApiToken, API_TOKEN_ENV};
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

/// The daemon API's bearer token, resolved the one way every other credential is.
///
/// ## Why this lives here rather than in `hx-server`
///
/// Both the daemon and the `hx` CLI need the same answer to "what token is this deployment using",
/// and a second implementation in the CLI would be a second set of rules about what a `store:name`
/// reference means. This crate is the one that owns "where a key comes from", so the rule is stated
/// once, here, next to [`SecretStores`].
///
/// ## The rule, in full
///
/// 1. `config.api.token`, when it is set to something non-blank, wins. A value containing a `:` is a
///    `store:name` reference and is resolved through the configured sources; a value with no `:` is
///    a literal token.
/// 2. Otherwise `HX_API_TOKEN` in the process environment, which is the form a container or a CI job
///    uses. An **empty** variable counts as absent — an empty token is not a token, and treating it
///    as one would be a credential every caller could guess.
/// 3. Otherwise `None`: no token, which is legal only on a loopback bind.
///
/// ## What it refuses, and why the message never quotes the value
///
/// A reference naming a store that is not configured is an error rather than a literal. A literal
/// token can contain a `:`, and the value at this point is *exactly* the thing that must not be
/// printed — so the refusal names the configured stores and the environment variable to use
/// instead, and never the value it refused. A reference that names a configured store but a missing
/// entry fails with that source's own message, which names the reference and never the secret.
pub fn resolve_api_token(
    config: &hx_core::config::Config,
    secrets: &SecretStores,
) -> hx_core::error::Result<Option<ApiToken>> {
    if let Some(configured) = config
        .api
        .token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !configured.contains(':') {
            return Ok(Some(ApiToken::new(configured)));
        }

        let reference = SecretRef::parse(configured)?;
        if !secrets.stores().contains(&reference.store.as_str()) {
            let known = if secrets.is_empty() {
                "none are configured".to_string()
            } else {
                format!("configured stores: {}", secrets.stores().join(", "))
            };
            return Err(HxError::Config(format!(
                "`api.token` is written as a `store:name` reference but '{}' is not a store this \
                 deployment has ({known}). Use one of those, or — if this is a literal token that \
                 happens to contain a colon — set it in {} instead.",
                reference.store, API_TOKEN_ENV
            )));
        }

        let secret = secrets.resolve(&reference).map_err(|err| {
            HxError::Config(format!(
                "`api.token` could not be resolved: {err}. The daemon refuses to start rather than \
                 serving an API whose token it cannot check."
            ))
        })?;
        return Ok(Some(ApiToken::new(secret.expose())));
    }

    Ok(env_api_token())
}

/// `HX_API_TOKEN`, if it is set to something non-blank.
fn env_api_token() -> Option<ApiToken> {
    std::env::var(API_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(ApiToken::new)
}

/// The password `POST /v1/login` checks against, resolved the same way as the bearer token.
///
/// ## The rule
///
/// 1. `config.api.admin_password`, when it is set to something non-blank, wins. A value
///    containing a `:` is a `store:name` reference and is resolved through the configured
///    sources; a value with no `:` is a literal password.
/// 2. Otherwise `None`: no password is configured, and the login route refuses every attempt.
///    There is deliberately no environment-variable fallback here — unlike the bearer token,
///    which a container must be able to inject, a login password with no configured value
///    means the operator never set one, and guessing at one from the environment would be
///    inventing a credential the operator never chose.
///
/// ## What it refuses
///
/// A reference naming a store that is not configured is an error rather than a literal, for the
/// same reason as [`resolve_api_token`]: the value at this point is exactly the thing that must
/// not be printed, so the refusal names the configured stores and never the value it refused.
/// The login handler treats that error as a failed login rather than a 500, so the response
/// cannot be used to learn anything about the configuration.
pub fn resolve_admin_password(
    config: &hx_core::config::Config,
    secrets: &SecretStores,
) -> hx_core::error::Result<Option<ApiToken>> {
    let Some(configured) = config
        .api
        .admin_password
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    if !configured.contains(':') {
        return Ok(Some(ApiToken::new(configured)));
    }

    let reference = SecretRef::parse(configured)?;
    if !secrets.stores().contains(&reference.store.as_str()) {
        let known = if secrets.is_empty() {
            "none are configured".to_string()
        } else {
            format!("configured stores: {}", secrets.stores().join(", "))
        };
        return Err(HxError::Config(format!(
            "`api.admin_password` is written as a `store:name` reference but '{}' is not a store this \
             deployment has ({known}). Use one of those, or — if this is a literal password that \
             happens to contain a colon — set it in a store and reference it instead.",
            reference.store
        )));
    }

    let secret = secrets.resolve(&reference).map_err(|err| {
        HxError::Config(format!(
            "`api.admin_password` could not be resolved: {err}. The login route refuses every \
             attempt rather than checking against a password it cannot read."
        ))
    })?;
    Ok(Some(ApiToken::new(secret.expose())))
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

    // -- the API token -------------------------------------------------------

    /// The sentinel is the value the leak tests search for. It is deliberately *not* key-shaped, so
    /// the read-side redaction that masks `sk-…` in a file display cannot hide it from an assertion
    /// and make a leak test pass for the wrong reason.
    const API_SENTINEL: &str = "hx-api-token-1f4e7c9a-must-not-be-printed";

    fn config_with_token(token: Option<&str>) -> hx_core::config::Config {
        let yaml = match token {
            Some(value) => format!("api:\n  token: \"{value}\"\n"),
            None => "roles: {}\n".to_string(),
        };
        hx_core::config::Config::from_yaml(&yaml).expect("config parses")
    }

    #[test]
    fn a_literal_token_in_the_config_is_used_as_written() {
        // No `:` means no reference, so this is the value itself. A token like this is what a
        // machine-local daemon uses when it has no vault and no orchestrator.
        let config = config_with_token(Some(API_SENTINEL));
        let stores = SecretStores::new().with(Arc::new(EnvSecrets));

        let token = resolve_api_token(&config, &stores)
            .expect("a literal resolves")
            .expect("a token is configured");
        assert!(token.matches(API_SENTINEL));
        assert!(!token.matches("something-else"));
    }

    #[test]
    fn a_store_reference_in_the_config_is_resolved_through_the_sources() {
        // The point of the reference form: the value lives in the vault and the config holds a name.
        let config = config_with_token(Some("vault:api/daemon"));
        let stores = SecretStores::new().with(Arc::new(
            FixedSecrets::vault().set("api/daemon", API_SENTINEL),
        ));

        let token = resolve_api_token(&config, &stores)
            .expect("resolves")
            .expect("configured");
        assert!(token.matches(API_SENTINEL));
    }

    #[test]
    fn an_env_reference_resolves_to_the_variable_it_names() {
        // `env:NAME` is the form a container writes, and it must go through `EnvSecrets` rather
        // than a second reader here — otherwise the "set but empty" rule would differ between this
        // path and every other credential.
        std::env::set_var("HX_TEST_API_TOKEN_VARIABLE", API_SENTINEL);
        let config = config_with_token(Some("env:HX_TEST_API_TOKEN_VARIABLE"));
        let stores = SecretStores::new().with(Arc::new(EnvSecrets));

        let token = resolve_api_token(&config, &stores)
            .expect("resolves")
            .expect("configured");
        assert!(token.matches(API_SENTINEL));

        // And the same variable set to blank is refused, exactly as it is for a provider key.
        std::env::set_var("HX_TEST_API_TOKEN_VARIABLE", "   ");
        let err = resolve_api_token(&config, &stores).unwrap_err().to_string();
        assert!(err.contains("set but empty"), "{err}");
        assert!(!err.contains(API_SENTINEL), "{err}");

        std::env::remove_var("HX_TEST_API_TOKEN_VARIABLE");
    }

    #[test]
    fn a_reference_naming_an_unconfigured_store_is_refused_without_quoting_the_value() {
        // The trap: a literal token may contain a colon, and a message that echoed the reference
        // back would be printing a credential. This one names the stores that *would* work.
        let colon_literal = format!("literal:with-a-colon-{API_SENTINEL}");
        let config = config_with_token(Some(&colon_literal));
        let stores = SecretStores::new().with(Arc::new(EnvSecrets));

        let err = resolve_api_token(&config, &stores).unwrap_err().to_string();
        assert!(
            !err.contains(API_SENTINEL),
            "the refusal must not carry the value: {err}"
        );
        assert!(err.contains("literal"), "it names the store: {err}");
        assert!(
            err.contains(API_TOKEN_ENV),
            "and the way to use a colon-containing literal: {err}"
        );
        assert!(err.contains("env"), "listing the configured stores: {err}");
    }

    #[test]
    fn a_blank_config_token_falls_through_to_the_environment() {
        // One test owns `HX_API_TOKEN` for the whole binary: tests run in parallel threads, and two
        // of them mutating the same variable would make both flaky rather than wrong.
        std::env::remove_var(API_TOKEN_ENV);

        // Absent everywhere: no token, which is what a loopback daemon with no auth configured
        // looks like — and the reason `require_token_for_bind` is a separate question.
        let config = config_with_token(None);
        let stores = SecretStores::new().with(Arc::new(EnvSecrets));
        assert!(resolve_api_token(&config, &stores)
            .expect("no token is not an error")
            .is_none());

        // A blank config value is absent, not an empty token: it must not shadow the environment.
        let blank = config_with_token(Some("   "));
        assert!(resolve_api_token(&blank, &stores)
            .expect("absent")
            .is_none());

        // The environment supplies one, and it is used when the config names nothing.
        std::env::set_var(API_TOKEN_ENV, API_SENTINEL);
        let token = resolve_api_token(&config, &stores)
            .expect("resolves")
            .expect("the environment supplied one");
        assert!(token.matches(API_SENTINEL));

        // An empty variable counts as absent rather than as an empty token every caller could
        // guess — the same rule the audit chain's key follows.
        std::env::set_var(API_TOKEN_ENV, "");
        assert!(resolve_api_token(&config, &stores)
            .expect("absent")
            .is_none());

        // And the config wins over the environment, so "which token is this daemon checking" is
        // answerable from the config alone.
        std::env::set_var(API_TOKEN_ENV, "from-the-environment");
        let configured = config_with_token(Some(API_SENTINEL));
        let token = resolve_api_token(&configured, &stores)
            .expect("resolves")
            .expect("configured");
        assert!(token.matches(API_SENTINEL));
        assert!(!token.matches("from-the-environment"));

        std::env::remove_var(API_TOKEN_ENV);
    }

    #[test]
    fn a_config_that_names_an_unresolvable_token_is_an_error_and_not_a_daemon_without_one() {
        // Fail closed at startup: a `vault:` reference against a deployment with no vault source
        // must not quietly degrade into "no token configured", which would leave a non-loopback
        // daemon unprotected while its config says otherwise.
        let config = config_with_token(Some("vault:api/daemon"));
        let stores = SecretStores::new().with(Arc::new(EnvSecrets));

        let err = resolve_api_token(&config, &stores).unwrap_err().to_string();
        assert!(err.contains("api.token"), "{err}");
        assert!(!err.contains(API_SENTINEL), "{err}");
    }
}
