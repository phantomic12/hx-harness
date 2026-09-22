//! Secret storage and outbound redaction.
//!
//! Two jobs, both about making it hard for a credential to end up somewhere it shouldn't:
//!
//! 1. [`vault`] — an encrypted-at-rest store. Never roll your own crypto: this is
//!    Argon2id (memory-hard KDF) into XChaCha20-Poly1305 (AEAD), which is the boring,
//!    audited composition.
//! 2. [`redact`] — a last line of defence on the way *out* to a model or a chat platform.
//!    A key that leaks into `stdout` (or a stack trace, or a `git remote -v`) must get masked
//!    before it reaches a transcript that will be sent to a third party.
//!
//! The second one matters more than people expect, and most harnesses skip it.

pub mod redact;
pub mod source;
pub mod vault;

pub use redact::{Redaction, Redactor};
pub use source::{
    resolve_admin_password, resolve_api_token, EnvSecrets, FixedSecrets, SecretSource,
    SecretStores, VaultSecrets,
};
pub use vault::{KdfParams, Secret, Vault, VaultError};
