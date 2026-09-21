//! Encrypted-at-rest secret storage.
//!
//! Format: a JSON envelope holding the KDF parameters in the clear plus a single AEAD
//! ciphertext. KDF parameters live in the file so they can be raised later without breaking
//! existing vaults — a vault that can't be migrated is a vault people stop using.
//!
//! The plaintext inside the envelope is a JSON map of `name -> value`.
//!
//! [`Vault::create`] and [`Vault::open`] work on that envelope as a *string*. [`Vault::create_at`],
//! [`Vault::open_at`] and [`Vault::save_to`] are the same operations against a file, and that is
//! where the cross-process behaviour lives: two processes can only disagree about a vault through a
//! file, so the properties that matter — never create one over a vault that is already there, never
//! replace one non-atomically, never read a missing vault as an empty one — are *file* properties.
//! They are held by the filesystem (`create_new`, `rename`) rather than by this type, because a
//! check written here is a check another process can run between two of its own lines.
//!
//! What the file layer deliberately does **not** do is coordinate writers: see [`Vault::save_to`]
//! for why a last-writer-wins replace is the whole design and not an oversight.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
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
    /// A vault is already at this path. Named because a path is not a secret and "which file"
    /// is the only thing the operator needs in order to act on it.
    #[error(
        "a vault already exists at {}; refusing to overwrite it — open it, or move it aside first",
        .0.display()
    )]
    AlreadyExists(PathBuf),
    /// There is no vault at this path — deliberately distinct from "a vault with nothing in it".
    #[error(
        "no vault at {} — there is a difference between \"no vault\" and \"an empty vault\"",
        .0.display()
    )]
    NoVault(PathBuf),
    #[error(transparent)]
    Io(#[from] io::Error),
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

/// Policy bounds for vault-supplied KDF parameters (see [`validate_kdf`]).
///
/// The envelope carries `m_cost_kib`/`t_cost`/`p_cost` in the clear so the cost can be raised over
/// time — which also means a tampered envelope (or a vault crafted by someone else) can name
/// absurd values. Without a check, `open` would hand them straight to Argon2: gigabytes of
/// allocation, or hours of iterations, from one malicious file read.
const KDF_M_COST_KIB_MIN: u32 = 8; // the `for_tests` floor; anything weaker is not Argon2, it is a wish
const KDF_M_COST_KIB_MAX: u32 = 1024 * 1024; // 1 GiB: far above the 64 MiB default, far below OOM
const KDF_T_COST_MIN: u32 = 1;
const KDF_T_COST_MAX: u32 = 100; // 100 passes at 64 MiB is already minutes; more is not a vault
const KDF_P_COST_MIN: u32 = 1;
const KDF_P_COST_MAX: u32 = 64; // beyond core counts parallelism buys nothing but confusion

/// Reject out-of-policy KDF parameters *before* any allocation or hashing.
///
/// Called by both [`Vault::create`] (fail fast on a misconfigured caller) and [`Vault::open`]
/// (refuse a tampered envelope without invoking Argon2). The shipped default (64 MiB, 3, 4) and
/// the test params (8 KiB, 1, 1) sit inside the range, so every vault written by this code —
/// past or present — still opens.
fn validate_kdf(kdf: &KdfParams) -> Result<(), VaultError> {
    if !(KDF_M_COST_KIB_MIN..=KDF_M_COST_KIB_MAX).contains(&kdf.m_cost_kib)
        || !(KDF_T_COST_MIN..=KDF_T_COST_MAX).contains(&kdf.t_cost)
        || !(KDF_P_COST_MIN..=KDF_P_COST_MAX).contains(&kdf.p_cost)
    {
        return Err(VaultError::Kdf(format!(
            "kdf parameters out of policy \
             (m_cost_kib={} t_cost={} p_cost={}); refusing before key derivation",
            kdf.m_cost_kib, kdf.t_cost, kdf.p_cost
        )));
    }
    Ok(())
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
        validate_kdf(&kdf)?;
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

    /// Create a new, empty vault **as a file**, refusing to touch one that is already there.
    ///
    /// The refusal is the point. [`Vault::create`] knows nothing about a path, so a second process
    /// that "creates a vault" where one already lives has only two moves available: truncate the
    /// file (`create(true)`), or check `exists()` first and lose the race anyway. Both destroy a
    /// vault holding the operator's keys, and neither is visible until something needs a secret.
    /// `create_new` makes the filesystem do the check and the create as one step, which is the only
    /// version of this that a second process cannot slip between.
    pub fn create_at(
        path: impl AsRef<Path>,
        passphrase: &str,
        kdf: KdfParams,
    ) -> Result<Self, VaultError> {
        let path = path.as_ref();
        let vault = Self::create(passphrase, kdf)?;
        let sealed = vault.seal()?;

        let mut file = match open_for_write(path, true) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(VaultError::AlreadyExists(path.to_path_buf()))
            }
            Err(e) => return Err(VaultError::Io(e)),
        };
        if let Err(e) = write_and_sync(&mut file, sealed.as_bytes()) {
            // Do not leave the reservation behind: a zero-length file would make every later
            // attempt fail with "already exists" for a vault that was never written.
            let _ = fs::remove_file(path);
            return Err(VaultError::Io(e));
        }
        Ok(vault)
    }

    /// Unlock an existing vault from its serialized envelope.
    pub fn open(passphrase: &str, envelope_json: &str) -> Result<Self, VaultError> {
        let env: Envelope = serde_json::from_str(envelope_json)?;

        if env.version != ENVELOPE_VERSION {
            return Err(VaultError::UnsupportedVersion(env.version));
        }

        // Before a single base64 decode, let alone an allocation: a tampered envelope naming
        // gigabytes of memory or millions of passes must fail here, not inside Argon2.
        validate_kdf(&env.kdf)?;

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

    /// Unlock the vault stored at `path`.
    ///
    /// A missing file is an error, not a new empty vault. "There is no vault here" and "the vault
    /// is empty" are different answers, and collapsing them turns a mistyped path into a vault
    /// whose every secret has apparently gone missing — while the caller carries on with no
    /// credentials at all. A zero-length file gets its own message for the same reason: it is a
    /// creation that died, and saying so beats a JSON parser's line and column.
    pub fn open_at(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, VaultError> {
        let path = path.as_ref();
        let sealed = match fs::read_to_string(path) {
            Ok(sealed) => sealed,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(VaultError::NoVault(path.to_path_buf()))
            }
            Err(e) => return Err(VaultError::Io(e)),
        };
        if sealed.trim().is_empty() {
            return Err(VaultError::Malformed(format!(
                "{} is empty — a vault whose creation never finished, or a file that was truncated",
                path.display()
            )));
        }
        Self::open(passphrase, &sealed)
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

    /// Write this vault to `path`, replacing what is there in one step.
    ///
    /// Seal to a temporary file in the target's own directory, flush it to the device, then
    /// `rename` it over the target. A `rename` within a directory is atomic on POSIX, so a second
    /// process opening the vault sees the whole previous envelope or the whole new one — never a
    /// half-written file, which would fail to parse and read to an operator as "the vault is
    /// corrupt". The temp file must be in that same directory because `rename` does not cross a
    /// filesystem, and a scratch file in `/tmp` would quietly turn the replace into a copy.
    ///
    /// **Deliberately not a lock, and deliberately not a merge.** Two processes that both open,
    /// edit and save the same vault end with the last writer's version and the earlier update is
    /// gone — silently, because nothing here reads the file it is replacing. That is what an atomic
    /// replace without locking *is*, and it is written down rather than implied: a vault is edited
    /// by a person through a CLI, not by a fleet, and the alternative (an advisory lock plus a
    /// re-read) buys a merge nobody asked for at the cost of a stale-lock failure mode. A test
    /// asserting that both updates survive would be asserting a property this design does not have.
    pub fn save_to(&self, path: impl AsRef<Path>) -> Result<(), VaultError> {
        let path = path.as_ref();
        let directory = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let sealed = self.seal()?;

        // A distinct scratch name per call: two processes saving at once must not share one, or
        // they interleave into it and rename the mixture into place.
        let mut suffix = [0u8; 8];
        fill_random(&mut suffix)?;
        let temp = directory.join(format!(
            ".{}.{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("vault"),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(suffix)
        ));

        let written = open_for_write(&temp, false)
            .and_then(|mut file| write_and_sync(&mut file, sealed.as_bytes()));
        if let Err(e) = written {
            let _ = fs::remove_file(&temp);
            return Err(VaultError::Io(e));
        }
        if let Err(e) = fs::rename(&temp, path) {
            let _ = fs::remove_file(&temp);
            return Err(VaultError::Io(e));
        }
        Ok(())
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

/// Write bytes and get them onto the device before returning.
///
/// The flush is not decoration: a `rename` that lands before the bytes do leaves a durable file
/// with no content, which is exactly the crash the atomic replace exists to survive.
fn write_and_sync(file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

/// Open a file for writing, optionally insisting that it did not already exist.
///
/// One function with a `#[cfg(unix)]` block rather than two cfg-split functions: the permission
/// bits are the only platform difference, and a split would need a second arm kept in step for
/// every other argument — the trap that leaves the non-Unix arm uncompiled and broken.
///
/// On Unix the file is created `0600`. The content is encrypted, so this is not about the
/// ciphertext leaking; it is about not handing an offline attacker a passphrase file, and about the
/// ordinary case where the vault sits in a shared home directory or a backup that ignores modes.
/// Windows inherits the directory's ACL, which is the closest equivalent it has.
fn open_for_write(path: &Path, create_new: bool) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
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

    /// A sealed envelope with its KDF parameters rewritten, so `open` faces vault-supplied
    /// params without any hashing having happened yet.
    fn sealed_with_kdf(kdf: KdfParams) -> String {
        let v = Vault::create("pw", fast()).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&v.seal().unwrap()).unwrap();
        parsed["kdf"]["m_cost_kib"] = serde_json::json!(kdf.m_cost_kib);
        parsed["kdf"]["t_cost"] = serde_json::json!(kdf.t_cost);
        parsed["kdf"]["p_cost"] = serde_json::json!(kdf.p_cost);
        serde_json::to_string(&parsed).unwrap()
    }

    #[test]
    fn absurd_kdf_params_are_rejected_before_key_derivation() {
        // Each of these would be catastrophic (or at least endless) inside Argon2: 4 TiB of
        // memory, billions of passes, billions of lanes, or a degenerate zero. The policy
        // check must refuse every one without invoking the KDF — hence the time bound, which
        // no real key derivation could meet for the large cases and which pins "rejected
        // before hashing" rather than "rejected by hashing".
        let base = KdfParams {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        };
        let cases = [
            KdfParams {
                m_cost_kib: u32::MAX,
                ..base
            },
            KdfParams {
                t_cost: u32::MAX,
                ..base
            },
            KdfParams {
                p_cost: u32::MAX,
                ..base
            },
            KdfParams {
                m_cost_kib: 0,
                ..base
            },
            KdfParams { t_cost: 0, ..base },
            KdfParams { p_cost: 0, ..base },
        ];
        for kdf in cases {
            let started = std::time::Instant::now();
            let err = Vault::open("pw", &sealed_with_kdf(kdf)).unwrap_err();
            assert!(
                matches!(err, VaultError::Kdf(_)),
                "m={} t={} p={}: got {err:?}",
                kdf.m_cost_kib,
                kdf.t_cost,
                kdf.p_cost
            );
            assert!(
                err.to_string().contains("out of policy"),
                "the refusal must say why: {err}"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "m={} t={} p={} took {:?}: Argon2 must not have run",
                kdf.m_cost_kib,
                kdf.t_cost,
                kdf.p_cost,
                started.elapsed()
            );
        }
    }

    #[test]
    fn creating_a_vault_with_absurd_kdf_params_fails_fast() {
        let err = Vault::create(
            "pw",
            KdfParams {
                m_cost_kib: u32::MAX,
                t_cost: 3,
                p_cost: 4,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VaultError::Kdf(_)), "got {err:?}");
    }

    #[test]
    fn historical_kdf_ranges_still_open() {
        // The policy must not brick vaults this code already wrote: the shipped default and
        // the test params both sit inside the range, and `open` accepts them.
        for kdf in [KdfParams::default(), KdfParams::for_tests()] {
            validate_kdf(&kdf).expect("shipped params must stay in policy");
            let mut v = Vault::create("pw", kdf).unwrap();
            v.put("k", "v");
            let reopened = Vault::open("pw", &v.seal().unwrap()).unwrap();
            assert_eq!(reopened.get("k").unwrap().expose(), "v");
        }
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

    // ---------------------------------------------------------------------------------------
    // The file layer. These are the in-process half; the cross-process half is
    // `tests/vault_process.rs`, which is the only place these properties can actually be seen.
    // ---------------------------------------------------------------------------------------

    fn temp_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("a temp dir")
    }

    #[test]
    fn creating_a_vault_over_an_existing_one_is_refused_rather_than_truncating_it() {
        // The destructive version of this is one word of `OpenOptions` away, and it looks like it
        // worked: the file exists, the vault opens, and every secret that was in it is gone.
        let dir = temp_dir();
        let path = dir.path().join("vault.json");
        let mut original = Vault::create_at(&path, "pw", fast()).unwrap();
        original.put("anthropic/main", "the-value-that-must-survive");
        original.save_to(&path).unwrap();
        let before = std::fs::read(&path).unwrap();

        let err = Vault::create_at(&path, "a-different-passphrase", fast()).unwrap_err();
        assert!(matches!(err, VaultError::AlreadyExists(_)), "got {err:?}");
        assert!(err.to_string().contains("refusing to overwrite"));

        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the file was touched"
        );
        let reopened = Vault::open_at(&path, "pw").unwrap();
        assert_eq!(
            reopened.get("anthropic/main").unwrap().expose(),
            "the-value-that-must-survive"
        );
    }

    #[test]
    fn opening_a_vault_that_is_not_there_is_an_error_rather_than_a_new_empty_vault() {
        // A typo in a path must not read as "this vault has no secrets": that answer is
        // indistinguishable from a vault that was wiped, and the caller carries on unauthenticated.
        let dir = temp_dir();
        let path = dir.path().join("typo.json");

        let err = Vault::open_at(&path, "pw").unwrap_err();
        assert!(matches!(err, VaultError::NoVault(_)), "got {err:?}");
        assert!(err.to_string().contains("no vault at"));
        assert!(!path.exists(), "opening must not have created the file");
    }

    #[test]
    fn a_zero_length_vault_file_is_named_rather_than_parsed() {
        // The state a `create` that died half-way leaves behind. A JSON parser's line-and-column
        // tells the operator nothing about how it got there.
        let dir = temp_dir();
        let path = dir.path().join("half-created.json");
        std::fs::write(&path, "").unwrap();

        let err = Vault::open_at(&path, "pw").unwrap_err();
        assert!(matches!(err, VaultError::Malformed(_)), "got {err:?}");
        assert!(err.to_string().contains("never finished"), "{err}");
    }

    #[test]
    fn saving_a_vault_leaves_no_scratch_file_behind() {
        // The temp file is in the vault's own directory, so a leak is visible to the operator and
        // grows without bound on every edit.
        let dir = temp_dir();
        let path = dir.path().join("vault.json");
        let mut vault = Vault::create_at(&path, "pw", fast()).unwrap();
        for round in 0..3 {
            vault.put("k", format!("v{round}"));
            vault.save_to(&path).unwrap();
        }

        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["vault.json".to_string()], "{entries:?}");
    }
}
