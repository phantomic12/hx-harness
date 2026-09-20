//! Per-session browser profiles — the isolation boundary the pool is built on.
//!
//! ## The property this module holds
//!
//! **Two sessions never share a profile directory, a cookie jar or a browser storage area.** Every
//! path a browser is pointed at is derived from the session id alone, under a single pool root, and
//! the derivation is injective: distinct session ids produce distinct directories, and a session id
//! can never name a path outside the root.
//!
//! That is a *security* property rather than housekeeping. A browser profile **is** the session's
//! identity on the web — its cookies, its `localStorage`, its logged-in accounts. Two concurrent
//! fetches sharing one profile is one task reading another task's authenticated session, and it is
//! the failure mode that makes a browser pool unsafe to run in parallel at all. So the containment
//! is asserted by the tests below rather than assumed from the shape of a `format!` call.
//!
//! ## Why the session id is validated rather than trusted
//!
//! A session id arrives from a store, a CLI flag or an HTTP request, so it is caller-supplied
//! input. `Path::join` will happily resolve `../..` and happily accept an absolute path, so an
//! unvalidated id is a directory-escape: `PoolRoot::session("../other")` would hand a browser the
//! profile of a different session, or of something that is not a session at all. The rule here is a
//! **whitelist** (`[a-z0-9._-]`, not a leading dot, not a Windows device name) because a whitelist
//! fails closed on the spellings nobody thought of, and a blacklist of `..` and `/` does not.
//!
//! Uppercase is refused too, and that is deliberate: on a case-insensitive filesystem — the default
//! on macOS and Windows — `Session_A` and `session_a` resolve to the *same* directory, so a
//! case-preserving whitelist would be a shared profile on half the platforms hx ships to. Refusing
//! the collision outright is the only version of the rule that means the same thing everywhere.
//!
//! ## What is deliberately NOT done
//!
//! - **No cleanup.** A profile directory outlives the fetch that created it, because that is the
//!   point: a cleared challenge or a login is worth keeping for the session's next fetch. Reaping
//!   profiles is a policy question (how long does a session live?) that belongs to whoever owns the
//!   session store, not to this module. `PoolRoot` therefore has no `Drop` that deletes anything —
//!   silently deleting a directory a browser is still writing to would be worse than leaving it.
//! - **No locking.** Two processes sharing one pool root is not a configuration this module
//!   defends against; a profile is per-process state. The concurrency it *does* hold is the one
//!   that matters inside a daemon: many sessions, one process, no shared path.

use hx_core::ids::SessionId;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The file a session's cookies are handed between rungs in.
///
/// The browser rungs keep their own storage inside the profile directory; this file exists for the
/// non-browser rung, which has no cookie jar of its own. It lives *inside* the session directory so
/// that a cookie cleared for one session cannot be read by another — the whole point of the module.
pub const COOKIE_FILE: &str = "cookies.txt";

/// The longest session id accepted, in bytes. A directory name has to fit a filesystem limit
/// (255 bytes on ext4, and a shorter effective limit on some Windows paths); refusing early names
/// the problem instead of letting `create_dir_all` report `ENAMETOOLONG`.
const MAX_SESSION_ID_BYTES: usize = 128;

/// Something that stopped a session profile from being created.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// The session id cannot be used as a directory name. Carries the id *and* the rule it broke,
    /// because "invalid session id" alone leaves an operator with no way to fix it.
    #[error("session id {id:?} cannot name a profile directory: {reason}")]
    UnsafeSessionId { id: String, reason: &'static str },

    #[error("could not create {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// The directory every session profile lives under.
///
/// One root per pool. It is created on construction, so a failure to make it is reported once, at
/// startup, rather than on the first fetch.
#[derive(Clone, Debug)]
pub struct PoolRoot {
    root: PathBuf,
}

impl PoolRoot {
    /// Adopt `root` as the pool root, creating it if it does not exist.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ProfileError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|source| ProfileError::Io {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    /// The profile for a session, creating the directory on first use.
    ///
    /// Idempotent by construction: the directory is derived from the id, not generated, so calling
    /// this twice for one session returns the same path and a browser can resume where it left off.
    /// The id is validated first — see the module docs for why it is not trusted.
    pub fn session(&self, id: &SessionId) -> Result<SessionProfile, ProfileError> {
        let name = safe_dir_name(id)?;
        let dir = self.root.join(name);
        std::fs::create_dir_all(&dir).map_err(|source| ProfileError::Io {
            path: dir.clone(),
            source,
        })?;
        Ok(SessionProfile {
            session: id.clone(),
            dir,
        })
    }
}

/// One session's isolated browser profile.
///
/// Handed to a rung as part of a fetch request. A rung that keeps state — cookies, storage, a
/// browser's user-data directory — must write it under [`SessionProfile::dir`] and nowhere else.
#[derive(Clone, Debug)]
pub struct SessionProfile {
    session: SessionId,
    dir: PathBuf,
}

impl SessionProfile {
    pub fn session_id(&self) -> &SessionId {
        &self.session
    }

    /// The profile directory. Unique to this session, contained by the pool root.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The sub-directory a browser should use for `--user-data-dir`.
    ///
    /// Separate from the session directory itself so the cookie hand-off file (and anything else
    /// this crate writes) cannot be mistaken for part of a browser's own storage layout.
    pub fn user_data_dir(&self) -> PathBuf {
        self.dir.join("user-data")
    }

    /// Where a browser should keep `localStorage`, IndexedDB and its cache.
    pub fn storage_dir(&self) -> PathBuf {
        self.dir.join("storage")
    }

    /// The cookie hand-off file for this session.
    pub fn cookie_file(&self) -> PathBuf {
        self.dir.join(COOKIE_FILE)
    }

    /// The cookies this session has cleared, as a `Cookie:` header value, or `None` if it has none.
    ///
    /// Format: one `name=value` pair per line; blank lines and `#` comments are ignored; a line
    /// without `=` is skipped rather than guessed at. A malformed file therefore degrades to
    /// "fewer cookies", never to a request carrying something the file did not say.
    ///
    /// The result is a **credential**: it must go into a request header and nowhere else. Nothing
    /// in this crate logs it, and the rung that reads it is tested not to put it in an error.
    pub fn read_cookies(&self) -> Option<String> {
        let raw = std::fs::read_to_string(self.cookie_file()).ok()?;
        let pairs: Vec<&str> = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter(|line| line.contains('='))
            .collect();
        if pairs.is_empty() {
            return None;
        }
        Some(pairs.join("; "))
    }

    /// Record cookies for this session, appending to whatever the session already has.
    ///
    /// Appending rather than replacing is what makes a hand-off work: the interactive rung adds the
    /// cookie a person earned without discarding one an earlier fetch earned. A repeated name wins
    /// with its *later* value, which is the rule HTTP itself uses for duplicate cookies.
    pub fn write_cookies(&self, cookies: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.cookie_file())?;
        // Written with a leading comment naming the writer, so a human reading the profile later
        // knows where the line came from.
        writeln!(file, "# written by hx-browser")?;
        for line in cookies.lines() {
            let line = line.trim();
            if !line.is_empty() && line.contains('=') {
                writeln!(file, "{line}")?;
            }
        }
        file.flush()
    }
}

/// Validate a session id and return the directory name it maps to.
///
/// Split out so the rule is one function with one set of tests, rather than a `format!` call at the
/// point of use that a later edit could quietly change.
fn safe_dir_name(id: &SessionId) -> Result<&str, ProfileError> {
    let raw = id.as_str();

    let refuse = |reason: &'static str| ProfileError::UnsafeSessionId {
        id: raw.to_string(),
        reason,
    };

    if raw.is_empty() {
        return Err(refuse("it is empty"));
    }
    if raw.len() > MAX_SESSION_ID_BYTES {
        return Err(refuse("it is longer than 128 bytes"));
    }
    if raw == "." || raw == ".." {
        return Err(refuse("it names a directory relative to its parent"));
    }
    if raw.starts_with('.') {
        return Err(refuse(
            "it starts with a dot, which names a hidden or relative path",
        ));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        return Err(refuse(
            "it is not made only of lowercase letters, digits, '-', '_' and '.'",
        ));
    }
    if is_windows_device_name(raw) {
        return Err(refuse(
            "it is a reserved device name on Windows, where no directory can be created",
        ));
    }

    Ok(raw)
}

/// The reserved MS-DOS device names, which Windows still resolves even with an extension and in
/// every directory. Creating one fails with a confusing error, so it is refused by name here.
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    matches!(stem, "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && stem[3..].chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> (tempfile::TempDir, PoolRoot) {
        let temp = tempfile::tempdir().expect("a temp directory");
        let root = PoolRoot::new(temp.path().join("pool")).expect("a pool root");
        (temp, root)
    }

    fn id(raw: &str) -> SessionId {
        SessionId::from_raw(raw)
    }

    #[test]
    fn two_sessions_never_share_a_profile_directory() {
        // The property the whole module exists for. If a refactor ever derives the directory from
        // something other than the session id, this fails rather than leaking a cookie jar.
        let (_temp, root) = root();
        let a = root.session(&id("ses_aaa")).unwrap();
        let b = root.session(&id("ses_bbb")).unwrap();

        assert_ne!(a.dir(), b.dir());
        assert_ne!(a.cookie_file(), b.cookie_file());
        assert_ne!(a.user_data_dir(), b.user_data_dir());
        assert_ne!(a.storage_dir(), b.storage_dir());
        assert!(
            !b.dir().starts_with(a.dir()) && !a.dir().starts_with(b.dir()),
            "neither profile may be nested inside the other: {} vs {}",
            a.dir().display(),
            b.dir().display()
        );
    }

    #[test]
    fn a_cookie_written_for_one_session_is_invisible_to_another() {
        // Real files on a real filesystem: the strongest form of "these are not the same place".
        let (_temp, root) = root();
        let a = root.session(&id("ses_aaa")).unwrap();
        let b = root.session(&id("ses_bbb")).unwrap();

        a.write_cookies("cf_clearance=a-token-a").unwrap();

        assert_eq!(
            a.read_cookies().as_deref(),
            Some("cf_clearance=a-token-a"),
            "the session that earned the cookie must see it"
        );
        assert_eq!(
            b.read_cookies(),
            None,
            "the other session must not see it, and must not see an empty string either"
        );
        assert!(
            !b.cookie_file().exists(),
            "the other session's cookie file must not have been created at all"
        );
    }

    #[test]
    fn a_session_id_that_escapes_the_pool_root_is_refused() {
        // Every spelling that would resolve outside the root. A whitelist is used precisely so this
        // list does not have to be exhaustive to be safe.
        let (_temp, root) = root();
        for raw in [
            "../other",
            "..",
            ".",
            "",
            "a/b",
            "a\\b",
            "/absolute",
            "sub/../../escape",
            ".hidden",
            "a b",
            "café",
            "a:b",
        ] {
            let err = root.session(&id(raw)).expect_err(raw);
            assert!(
                matches!(err, ProfileError::UnsafeSessionId { .. }),
                "{raw:?} produced {err:?}"
            );
        }
    }

    #[test]
    fn an_uppercase_session_id_is_refused_because_a_case_insensitive_filesystem_would_share_it() {
        // On macOS and Windows `Session_A` and `session_a` are one directory. Accepting uppercase
        // would mean two sessions sharing a profile on half the platforms hx ships to.
        let (_temp, root) = root();
        let err = root
            .session(&id("ses_AAA"))
            .expect_err("uppercase is refused");
        assert!(
            err.to_string().contains("lowercase"),
            "the refusal must name the rule: {err}"
        );
    }

    #[test]
    fn a_windows_device_name_is_refused_rather_than_failing_at_create() {
        let (_temp, root) = root();
        for raw in ["con", "nul", "com1", "lpt9", "aux"] {
            assert!(
                root.session(&id(raw)).is_err(),
                "{raw} cannot be a directory on Windows"
            );
        }
        // The near-misses are ordinary names and must stay usable.
        for raw in ["console", "null", "com", "lpt", "com10"] {
            assert!(
                root.session(&id(raw)).is_ok(),
                "{raw} is not a reserved name and must be accepted"
            );
        }
    }

    #[test]
    fn the_same_session_id_always_resolves_to_the_same_profile() {
        // What makes a cleared challenge or a login worth keeping: the next fetch for this session
        // must land in the same profile, not a fresh one.
        let (_temp, root) = root();
        let first = root.session(&id("ses_same")).unwrap();
        let second = root.session(&id("ses_same")).unwrap();
        assert_eq!(first.dir(), second.dir());
        assert_eq!(first.session_id(), second.session_id());
    }

    #[test]
    fn every_session_directory_is_contained_by_the_pool_root() {
        // Canonicalised, so a symlink or a `..` that survived validation would show up here.
        let (_temp, root) = root();
        let canonical_root = root.path().canonicalize().unwrap();
        for raw in ["ses_a", "ses_b", "a.b-c_d", "0"] {
            let profile = root.session(&id(raw)).unwrap();
            let canonical = profile.dir().canonicalize().unwrap();
            assert!(
                canonical.starts_with(&canonical_root),
                "{} escaped {}",
                canonical.display(),
                canonical_root.display()
            );
            assert!(profile.dir().is_dir());
        }
    }

    #[test]
    fn concurrent_sessions_get_disjoint_directories() {
        // The pool runs sessions in parallel; a derivation that collapsed under concurrency would
        // hand two tasks the same profile. Created from several threads at once, for real.
        let (_temp, root) = root();
        let mut handles = Vec::new();
        for n in 0..8 {
            let root = root.clone();
            handles.push(std::thread::spawn(move || {
                root.session(&SessionId::from_raw(format!("ses_{n}")))
                    .unwrap()
            }));
        }
        let dirs: Vec<PathBuf> = handles
            .into_iter()
            .map(|h| h.join().expect("no thread panicked").dir().to_path_buf())
            .collect();

        assert_eq!(dirs.len(), 8);
        let mut unique = dirs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            8,
            "every concurrent session needs its own path"
        );
    }

    #[test]
    fn a_cookie_file_that_is_malformed_yields_fewer_cookies_rather_than_a_guess() {
        let (_temp, root) = root();
        let profile = root.session(&id("ses_cookies")).unwrap();
        std::fs::write(
            profile.cookie_file(),
            "# a comment\n\na=1\nnot-a-pair\nb=2\n",
        )
        .unwrap();

        assert_eq!(
            profile.read_cookies().as_deref(),
            Some("a=1; b=2"),
            "comments, blanks and unparseable lines are skipped, not guessed at"
        );
    }

    #[test]
    fn writing_cookies_appends_so_a_later_hand_off_does_not_discard_an_earlier_one() {
        let (_temp, root) = root();
        let profile = root.session(&id("ses_append")).unwrap();
        profile.write_cookies("first=1").unwrap();
        profile.write_cookies("second=2").unwrap();

        let cookies = profile.read_cookies().unwrap();
        assert!(cookies.contains("first=1"), "{cookies}");
        assert!(cookies.contains("second=2"), "{cookies}");
    }
}
