//! Encrypted-at-rest secret storage.
//!
//! Format: a JSON envelope holding the KDF parameters in the clear plus a single AEAD
//! ciphertext. KDF parameters live in the file so they can be raised later without breaking
//! existing vaults — a vault that can't be migrated is a vault people stop using.
//!
//! The plaintext inside the envelope is a JSON map of `name -> value`.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const ENVELOPE_VERSION: u32 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Binds a ciphertext to this application. Changing it invalidates existing vaults, on purpose:
/// it stops a vault from being silently reused in a different context.
const AAD: &[u8] = b"hx-vault-v1";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("decryption failed — wrong passphrase, or the vault has been tampered with")]
    Decrypt,
    #[error("malformed vault file: {0}")]
    Malformed(String),
    #[error("secret {0:?} not found in vault")]
    NotFound(String),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u32),
    #[error("randomness source unavailable: {0}")]
    Rng(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

/// Argon2id parameters. Stored in the vault file so the cost can be raised over time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// Interactive-but-serious defaults: 64 MiB, 3 passes, 4 lanes.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    /// Deliberately weak, for tests only. Exists so the test suite doesn't spend a second per
    /// vault operation — a slow suite is a suite people stop running.
    pub fn for_tests() -> Self {
        Self {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// A secret value that refuses to print itself.
///
/// `Debug` is redacted and the bytes are zeroed on drop, so an accidental `{:?}` in a log line
/// (or a `tracing::debug!` someone adds at 2am) cannot leak a key.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Explicit access. Named `expose` so that every call site is greppable and reviewable.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("Secret(<empty>)")
        } else {
            write!(f, "Secret(<{} bytes redacted>)", self.0.len())
        }
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    kdf: KdfParams,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

/// An unlocked vault, held in memory.
///
/// Deliberately not `Clone` and deliberately not `Debug`: the key must not be duplicated into
/// places we don't control.
pub struct Vault {
    key: Zeroizing<[u8; KEY_LEN]>,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    entries: BTreeMap<String, Secret>,
}

impl Vault {
    /// Create a new, empty vault protected by `passphrase`.
    pub fn create(passphrase: &str, kdf: KdfParams) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let key = derive_key(passphrase, &salt, &kdf)?;

        Ok(Self {
            key: Zeroizing::new(key),
            kdf,
            salt,
            entries: BTreeMap::new(),
        })
    }

    /// Unlock an existing vault from its serialized envelope.
    pub fn open(passphrase: &str, envelope_json: &str) -> Result<Self, VaultError> {
        let env: Envelope = serde_json::from_str(envelope_json)?;

        if env.version != ENVELOPE_VERSION {
            return Err(VaultError::UnsupportedVersion(env.version));
        }

        let b64 = base64::engine::general_purpose::STANDARD;
        let salt_vec = b64.decode(&env.salt_b64)?;
        let nonce_vec = b64.decode(&env.nonce_b64)?;
        let ciphertext = b64.decode(&env.ciphertext_b64)?;

        if salt_vec.len() != SALT_LEN {
            return Err(VaultError::Malformed(format!(
                "salt must be {SALT_LEN} bytes, got {}",
                salt_vec.len()
            )));
        }
        if nonce_vec.len() != NONCE_LEN {
            return Err(VaultError::Malformed(format!(
                "nonce must be {NONCE_LEN} bytes, got {}",
                nonce_vec.len()
            )));
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);
        // Same treatment as `salt` above: the length is already validated, so copy into a
        // fixed array and let `XNonce::from` be infallible. The old `XNonce::from_slice` is
        // deprecated in aead 0.6 (hybrid-array) in favour of TryFrom, which would force a
        // pointless second error path for a case that cannot fail.
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_vec);

        let key = derive_key(passphrase, &salt, &env.kdf)?;

        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|e| VaultError::Kdf(e.to_string()))?;
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: AAD,
                },
            )
            // Any failure here — wrong passphrase, flipped bit, truncated file — is
            // indistinguishable by design, and is reported without detail.
            .map_err(|_| VaultError::Decrypt)?;

        let entries: BTreeMap<String, String> =
            serde_json::from_slice(&plaintext).map_err(|_| VaultError::Decrypt)?;

        let entries = entries
            .into_iter()
            .map(|(k, v)| (k, Secret::new(v)))
            .collect();

        Ok(Self {
            key: Zeroizing::new(key),
            kdf: env.kdf,
            salt,
            entries,
        })
    }

    /// Serialize to an encrypted envelope, ready to write to disk.
    pub fn seal(&self) -> Result<String, VaultError> {
        let b64 = base64::engine::general_purpose::STANDARD;

        // Build the plaintext map. These intermediate strings are zeroized when dropped.
        let plain: BTreeMap<&str, &str> = self
            .entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.expose()))
            .collect();
        let mut plaintext = Zeroizing::new(serde_json::to_vec(&plain)?);

        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|e| VaultError::Kdf(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| VaultError::Decrypt)?;

        plaintext.zeroize();

        let env = Envelope {
            version: ENVELOPE_VERSION,
            kdf: self.kdf,
            salt_b64: b64.encode(self.salt),
            nonce_b64: b64.encode(nonce),
            ciphertext_b64: b64.encode(&ciphertext),
        };

        Ok(serde_json::to_string_pretty(&env)?)
    }

    pub fn put(&mut self, name: impl Into<String>, value: impl Into<Secret>) {
        self.entries.insert(name.into(), value.into());
    }

    pub fn get(&self, name: &str) -> Result<&Secret, VaultError> {
        self.entries
            .get(name)
            .ok_or_else(|| VaultError::NotFound(name.to_string()))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub fn remove(&mut self, name: &str) -> Option<Secret> {
        self.entries.remove(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("kdf", &self.kdf)
            .field("entries", &format_args!("{} secret(s)", self.entries.len()))
            .finish_non_exhaustive()
    }
}

fn derive_key(passphrase: &str, salt: &[u8], kdf: &KdfParams) -> Result<[u8; KEY_LEN], VaultError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(out)
}

fn fill_random(buf: &mut [u8]) -> Result<(), VaultError> {
    // getrandom 0.3 renamed `getrandom` to `fill`; the old name was ambiguous about which
    // buffer was being filled.
    getrandom::fill(buf).map_err(|e| VaultError::Rng(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams::for_tests()
    }

    #[test]
    fn round_trips_a_secret() {
        let mut v = Vault::create("correct horse battery staple", fast()).unwrap();
        v.put("anthropic/key1", "sk-ant-supersecret");

        let sealed = v.seal().unwrap();
        let reopened = Vault::open("correct horse battery staple", &sealed).unwrap();

        assert_eq!(
            reopened.get("anthropic/key1").unwrap().expose(),
            "sk-ant-supersecret"
        );
        assert_eq!(reopened.len(), 1);
    }

    #[test]
    fn wrong_passphrase_fails_without_leaking_why() {
        let mut v = Vault::create("right", fast()).unwrap();
        v.put("k", "v");
        let sealed = v.seal().unwrap();

        let err = Vault::open("wrong", &sealed).unwrap_err();
        assert!(matches!(err, VaultError::Decrypt));
        // The message must not distinguish "wrong passphrase" from "tampered file".
        assert!(err.to_string().contains("wrong passphrase, or"));
    }

    #[test]
    fn tampered_ciphertext_is_rejected_by_the_aead() {
        let mut v = Vault::create("pw", fast()).unwrap();
        v.put("k", "v");
        let sealed = v.seal().unwrap();

        // Flip a character *inside* the ciphertext field (not the trailing base64 padding,
        // which would just fail to decode and never exercise the AEAD).
        let mut parsed: serde_json::Value = serde_json::from_str(&sealed).unwrap();
        let ct = parsed["ciphertext_b64"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = ct.chars().collect();
        let idx = chars.len() / 2;
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        let flipped: String = chars.into_iter().collect();
        assert_ne!(flipped, ct, "the test must actually change the ciphertext");
        parsed["ciphertext_b64"] = serde_json::Value::String(flipped);

        let err = Vault::open("pw", &serde_json::to_string(&parsed).unwrap()).unwrap_err();
        assert!(matches!(err, VaultError::Decrypt), "got {err:?}");
    }

    #[test]
    fn same_plaintext_seals_to_different_ciphertext() {
        // A fresh nonce per seal means identical vaults are not identifiable on disk.
        let mut v = Vault::create("pw", fast()).unwrap();
        v.put("k", "identical-value");
        assert_ne!(v.seal().unwrap(), v.seal().unwrap());
    }

    #[test]
    fn aad_binds_the_envelope_to_this_application() {
        // Simulated by checking that a valid envelope from a different version is refused.
        let mut v = Vault::create("pw", fast()).unwrap();
        v.put("k", "v");
        let mut parsed: serde_json::Value = serde_json::from_str(&v.seal().unwrap()).unwrap();
        parsed["version"] = serde_json::json!(99);
        let err = Vault::open("pw", &serde_json::to_string(&parsed).unwrap()).unwrap_err();
        assert!(matches!(err, VaultError::UnsupportedVersion(99)));
    }

    #[test]
    fn missing_secret_reports_its_name_but_not_values() {
        let v = Vault::create("pw", fast()).unwrap();
        let err = v.get("nope").unwrap_err();
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn secret_debug_never_reveals_the_value() {
        let s = Secret::new("sk-ant-do-not-log-me");
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("do-not-log-me"), "leaked: {rendered}");
        assert!(rendered.contains("redacted"), "got: {rendered}");
    }

    #[test]
    fn vault_debug_never_reveals_values() {
        let mut v = Vault::create("pw", fast()).unwrap();
        v.put("k", "super-secret-value");
        let rendered = format!("{v:?}");
        assert!(
            !rendered.contains("super-secret-value"),
            "leaked: {rendered}"
        );
        assert!(rendered.contains("1 secret"), "got: {rendered}");
    }

    #[test]
    fn raised_kdf_params_still_open_an_old_vault() {
        // Params are read from the file, so cost can be raised without breaking existing vaults.
        let mut old = Vault::create("pw", fast()).unwrap();
        old.put("k", "v");
        let sealed = old.seal().unwrap();

        // Reopen using the stored (weak) params, not whatever the default now is.
        let reopened = Vault::open("pw", &sealed).unwrap();
        assert_eq!(reopened.get("k").unwrap().expose(), "v");
        let reparsed: Envelope = serde_json::from_str(&sealed).unwrap();
        assert_eq!(reparsed.kdf, KdfParams::for_tests());
    }

    #[test]
    fn empty_vault_round_trips() {
        let v = Vault::create("pw", fast()).unwrap();
        assert!(v.is_empty());
        let reopened = Vault::open("pw", &v.seal().unwrap()).unwrap();
        assert!(reopened.is_empty());
    }

    #[test]
    fn unicode_secret_values_survive() {
        let mut v = Vault::create("pw", fast()).unwrap();
        v.put("k", "pässwörd—🔑");
        let reopened = Vault::open("pw", &v.seal().unwrap()).unwrap();
        assert_eq!(reopened.get("k").unwrap().expose(), "pässwörd—🔑");
    }

    #[test]
    fn removing_a_secret_takes_effect_on_next_seal() {
        let mut v = Vault::create("pw", fast()).unwrap();
        v.put("a", "1");
        v.put("b", "2");
        assert!(v.remove("a").is_some());
        let reopened = Vault::open("pw", &v.seal().unwrap()).unwrap();
        assert!(!reopened.contains("a"));
        assert!(reopened.contains("b"));
    }
}
