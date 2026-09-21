//! A small on-disk cache for fetched URLs, keyed by the URL with its query stripped.
//!
//! ## What this is not
//!
//! This is **not an HTTP cache implementation**, and it does not pretend to be one. It speaks none
//! of `Vary`, `no-store`, `must-revalidate`, `Age`, `stale-while-revalidate` or the heuristic
//! freshness of RFC 9111 §4.2.2, and it holds no per-`Vary`-key variants. What it does is the one
//! thing the search extraction ladder actually needs: it holds the body of a URL it has already
//! fetched, and on a repeat fetch it *asks the origin whether that copy is still good* — with
//! `If-None-Match` / `If-Modified-Since` — rather than downloading the page again. A caller that
//! needs a real shared or browser-grade cache should use one; a second fetch of a result page is
//! both slow and rude to the origin, and that is the whole problem this solves.
//!
//! ## Why the key digests the query instead of dropping it
//!
//! [`cache_key`] is what a repeat fetch looks up: the URL with its fragment removed and, when a
//! query is present, a hexadecimal digest of the complete query-carrying URL appended. The shape
//! answers two requirements that pull in opposite directions:
//!
//! - A query string can carry a **credential** (`…?X-Amz-Signature=…`, `…?token=…`, `…?key=…`),
//!   and the key is what becomes a filename, a `Debug` line and a log field. The query's
//!   plaintext never reaches a filename, a log, or the serialized entry on disk — only the
//!   digest does — and `a_token_in_the_query_never_reaches_a_key_or_a_filename` asserts it
//!   against a real fetch.
//! - Two URLs that differ only in their query are **different entries**. Collapsing them meant a
//!   fresh first response (`Cache-Control: max-age`) was served for a URL the origin was never
//!   asked for: content fetched under one credential cited as another request's answer.
//!   `two_query_variants_of_one_path_hold_distinct_bodies_while_fresh` pins the fix.
//!
//! The fragment is still dropped without a trace: it is never sent to the origin, so it is not
//! part of the resource's identity and two URLs differing only in `#…` share one entry.
//!
//! The on-disk entry document deliberately does **not** store the full URL or its query string.
//! An earlier design stored the full URL so the document would "name its own resource", but that
//! field was never read and caused live query credentials to sit on disk in plaintext. The
//! query-stripped [`cache_key`] already names the resource and matches the filename; dropping the
//! URL field keeps credentials out of the cache directory entirely.
//!
//! ## Freshness
//!
//! An entry is reusable without a request only while it is fresh **by its own headers**:
//! `Cache-Control: max-age=N`, or `Expires` measured against the origin's `Date`. With neither, the
//! entry is **revalidated rather than assumed fresh** — the cache has no basis to invent a lifetime,
//! and inventing one is how a cache serves a stale page while claiming it was checked.
//!
//! ## Bounds
//!
//! A hostile or merely enormous site must not be able to fill the disk, so there are two caps: a
//! maximum number of entries and a maximum body size per entry.
//!
//! - Over the entry cap, entries are evicted oldest-first. **"Oldest" means `stored_at` as the
//!   injected clock recorded it, not the file's mtime.** mtime is set by whatever last wrote or
//!   copied the directory, so a restore, an `rsync` or a checkout would reorder eviction by an
//!   accident of the filesystem rather than by age.
//! - Over the body cap, the body is **aborted mid-stream, never stored, and never returned** —
//!   and whatever was filed for the key is dropped. A truncated entry would be a lie about what
//!   the origin said, and returning the full body would need the unbounded allocation the cap
//!   exists to prevent. The caller learns the page was too large ([`CacheOutcome::TooLarge`])
//!   and skips it rather than citing a fragment.
//!
//! ## On disk
//!
//! Under a caller-supplied root, one JSON document per entry — `key`, `etag`,
//! `last_modified`, `stored_at`, `max_age`, `body` — so a cache problem is diagnosable by reading
//! one file rather than by attaching a debugger. The filename is the sanitized key (every
//! non-alphanumeric folded to `_`, cut to 120 characters) **plus a FNV-1a 64-bit suffix over the
//! key**, because two different keys can sanitize to the same name and would otherwise silently
//! share an entry. The `key` field is re-checked on read, so even a hash collision degrades to a
//! miss rather than to a wrong body.
//!
//! FNV-1a rather than `sha2`: the suffix only has to keep two *filenames* apart, it is not an
//! integrity check and nothing trusts it as one, and `sha2` is in the workspace but **not** in this
//! crate's manifest — adding it would be a new dependency for a filename component. A
//! `DefaultHasher` would be shorter to write and is explicitly allowed to differ between Rust
//! versions, which would move every entry to a new filename on a toolchain upgrade.
//!
//! ## The clock
//!
//! Freshness is read from an injected [`Clock`], so a test can age an entry by advancing a counter
//! instead of sleeping. Nothing here reads the wall clock except [`SystemClock`].

use crate::backend::SearchError;
use futures::StreamExt as _;
use reqwest::header::{
    CACHE_CONTROL, DATE, ETAG, EXPIRES, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// Seconds in a day, named so the date arithmetic below reads as arithmetic rather than as a
/// magic number.
const SECS_PER_DAY: u64 = 86_400;

/// A clock, injected so no test sleeps.
///
/// Freshness is the only thing in this module that needs to know what time it is, and it is exactly
/// the thing a test must be able to move. Taking the clock as a trait object rather than calling
/// `SystemTime::now()` inside the cache is what makes "a stale entry is revalidated" a test that
/// runs in microseconds instead of one that sleeps for a `max-age`.
pub trait Clock: Send + Sync {
    fn now_secs(&self) -> u64;
}

/// The real clock: seconds since the Unix epoch.
///
/// A system clock set before 1970 reports `0` rather than panicking. A cache whose entries all look
/// maximally old is a cache that revalidates everything, which is the safe failure; a panic in the
/// middle of a search would not be.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0)
    }
}

/// The key an entry is filed under: the URL with its fragment removed, plus — when a query is
/// present — a hexadecimal digest of the complete query-carrying URL.
///
/// WHY a digest rather than the query: the key is what becomes a filename, a log field and the
/// `key` field of the entry on disk, and a query can carry a live credential (`?token=…`). The
/// digest lets the query influence *identity* — `…?token=A` and `…?token=B` are different
/// entries, so a fresh first response can never be served for a URL the origin was never asked
/// for — without the credential's plaintext ever reaching a filename, a log or the serialized
/// entry.
///
/// WHY the digest covers the complete canonical URL rather than just the query string: path and
/// query together name the resource, and one rule ("same canonical URL, same key") cannot drift
/// the way two half-rules can.
///
/// The fragment is dropped before digesting: it is never sent to the origin, so two URLs that
/// differ only in `#…` are the same entry. A string that is not an absolute URL is split by hand
/// on the same rule, so a relative path still keys consistently instead of collapsing every such
/// input onto one entry.
pub fn cache_key(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut parsed) => {
            parsed.set_fragment(None);
            let canonical = parsed.to_string();
            let has_query = parsed.query().is_some();
            parsed.set_query(None);
            let base = parsed.to_string();
            if has_query {
                format!("{base}#{:016x}", fnv1a(&canonical))
            } else {
                base
            }
        }
        Err(_) => {
            let without_fragment = url.split('#').next().unwrap_or(url);
            match without_fragment.split_once('?') {
                Some((base, _)) => format!("{base}#{:016x}", fnv1a(without_fragment)),
                None => without_fragment.to_string(),
            }
        }
    }
}

/// What a [`UrlCache::fetch`] did, kept apart so a caller cannot mistake one for another.
///
/// `Miss304` exists because a `304` with nothing stored is a **miss**, and collapsing it into
/// `Fetched` with an empty body would hand the caller an empty document that looks like a page the
/// origin returned. The variants carry the body rather than an `Option<String>`, and
/// [`CacheOutcome::body`] returns `None` — not `Some("")` — for `Miss304`, so the distinction is in
/// the type rather than in a convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheOutcome {
    /// Served from the stored copy. No request was made.
    Fresh(String),
    /// The origin answered `304`; the stored body was reused rather than downloaded again.
    Revalidated(String),
    /// The origin answered with a body (a `200`), stored if it fit the caps.
    Fetched(String),
    /// The origin answered with a body over the cache's `max_body_bytes`. The body was aborted
    /// mid-stream and never assembled: returning it would need the unbounded allocation the cap
    /// exists to prevent, and storing a truncation would lie about what the origin said. Nothing
    /// is stored — and whatever was previously filed for the key is dropped, because it is now
    /// known to be superseded by a response the cache refused to keep.
    TooLarge,
    /// The origin answered `304` and nothing was stored to reuse. A miss, reported as one.
    Miss304,
}

impl CacheOutcome {
    /// The body, when there is one.
    ///
    /// `None` for [`CacheOutcome::TooLarge`] and [`CacheOutcome::Miss304`], deliberately: a
    /// caller that unwraps the body of a miss gets a compile error rather than an empty string
    /// that renders as an empty page.
    pub fn body(&self) -> Option<&str> {
        match self {
            CacheOutcome::Fresh(body)
            | CacheOutcome::Revalidated(body)
            | CacheOutcome::Fetched(body) => Some(body),
            CacheOutcome::TooLarge | CacheOutcome::Miss304 => None,
        }
    }

    /// Whether the network was asked at all. `Fresh` is the only outcome that answered from disk
    /// alone.
    pub fn made_a_request(&self) -> bool {
        !matches!(self, CacheOutcome::Fresh(_))
    }
}

/// One cache entry, as it is stored on disk.
///
/// Deliberately does not store the full URL: `key` already names the resource — the query folded
/// into a digest rather than stored in plaintext — and matches the filename. The earlier
/// justification — *"Stored so the entry names its own resource"* — was not load-bearing because no read path ever inspected `Entry::url`, and
/// storing it wrote live query credentials (`?token=...`) to disk in plaintext. Dropping the
/// field keeps credentials off disk entirely.
///
/// Existing entries on disk written with a `url` field deserialize cleanly because Serde
/// ignores unknown fields by default; `an_entry_stored_in_the_legacy_format_with_a_url_field_is_read_successfully`
/// pins this compatibility.
#[derive(Serialize, Deserialize)]
struct Entry {
    /// The query-stripped key this entry is filed under. Re-checked on read.
    key: String,
    etag: Option<String>,
    last_modified: Option<String>,
    /// When this entry was stored, on the cache's clock. This is what "oldest" means for eviction.
    stored_at: u64,
    /// Lifetime in seconds from `stored_at`, from `Cache-Control: max-age` or `Expires`. `None`
    /// means "not fresh by its own headers", which is revalidated rather than assumed fresh.
    max_age: Option<u64>,
    body: String,
}

/// A bounded, on-disk cache of fetched URL bodies.
///
/// Takes the HTTP client by reference on every call rather than owning one, matching
/// [`crate::SearchBackend`]: the daemon shares a single connection pool and TLS session cache.
pub struct UrlCache {
    root: PathBuf,
    max_entries: usize,
    max_body_bytes: usize,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for UrlCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No URLs, and therefore no credentials, are reachable from here.
        f.debug_struct("UrlCache")
            .field("root", &self.root)
            .field("max_entries", &self.max_entries)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

impl UrlCache {
    /// A cache under `root` with the real clock.
    ///
    /// The filesystem is not touched here: the directory is created on the first write, so a cache
    /// configured but never used leaves nothing behind.
    pub fn new(root: impl Into<PathBuf>, max_entries: usize, max_body_bytes: usize) -> Self {
        Self::with_clock(root, max_entries, max_body_bytes, Arc::new(SystemClock))
    }

    /// The same, with the clock supplied. The injection point the tests use.
    pub fn with_clock(
        root: impl Into<PathBuf>,
        max_entries: usize,
        max_body_bytes: usize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            root: root.into(),
            max_entries,
            max_body_bytes,
            clock,
        }
    }

    /// The root this cache writes under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether a usable entry is filed for `url`.
    ///
    /// Reads the document rather than checking that a path exists, so a corrupt or
    /// collision-shared file reads as absent, which is what [`Self::fetch`] would do with it.
    pub fn contains(&self, url: &str) -> bool {
        let key = cache_key(url);
        read_entry(&self.entry_path(&key))
            .map(|entry| entry.key == key)
            .unwrap_or(false)
    }

    /// Fetch `url`, using and updating the cache.
    ///
    /// The order of decisions is the whole behaviour:
    ///
    /// 1. A stored entry that is **fresh** is returned with no request at all.
    /// 2. A stored entry that is **not fresh** is revalidated with `If-None-Match` (from the stored
    ///    `ETag`) and/or `If-Modified-Since` (from the stored `Last-Modified`). A `304` reuses the
    ///    stored body.
    /// 3. No entry — or a revalidation answered with a body — is a plain fetch. A `200` body is
    ///    stored if it fits the caps.
    /// 4. A `304` with nothing stored is [`CacheOutcome::Miss304`]. It is reported as a miss
    ///    because that is what it is: there is no body to hand over, and handing over an empty one
    ///    would look like a page the origin returned.
    ///
    /// A transport failure or a non-success status is a [`SearchError`] — the crate's own error
    /// rather than a parallel type, because a failure to reach an origin is the same class of
    /// failure a backend reports and a second error type is surface every caller must convert.
    ///
    /// Transport failures strip the request URL via [`reqwest::Error::without_url`].
    /// `reqwest::Error`'s `Display` and `Debug` implementations append the URL, which on a
    /// credential-bearing query string would leak live tokens into errors read by the model.
    /// Unlike search backends that mask known keys with [`SearchError::transport_redacted`],
    /// the cache has no `&Secret` to mask against because it cannot know which query parameter
    /// is secret. Dropping the URL entirely is the correct answer: the caller already holds the
    /// URL it passed to `fetch` and does not need it repeated in an error string.
    ///
    /// **A cache that cannot write is not a failed fetch.** If the directory cannot be created or
    /// the document cannot be written, the fetched body is still returned; only the caching is lost.
    /// The one thing that is never done is returning a body the origin did not send.
    pub async fn fetch(
        &self,
        client: &reqwest::Client,
        url: &str,
    ) -> Result<CacheOutcome, SearchError> {
        let key = cache_key(url);
        let stored = self.load(&key);

        let mut request = client.get(url);
        if let Some(entry) = &stored {
            if self.is_fresh(entry) {
                return Ok(CacheOutcome::Fresh(entry.body.clone()));
            }
            // Revalidate against whatever the origin gave us last time. Both validators go out
            // when both are known: a server that only understands `Last-Modified` would otherwise
            // re-send the whole body, which is the cost this cache exists to avoid.
            if let Some(etag) = &entry.etag {
                request = request.header(IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = &entry.last_modified {
                request = request.header(IF_MODIFIED_SINCE, last_modified);
            }
        }

        let response = request.send().await.map_err(transport_error)?;
        let status = response.status();

        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(match stored {
                Some(entry) => CacheOutcome::Revalidated(entry.body),
                // The origin says "unchanged" about a document we have never held. There is
                // nothing to reuse and nothing was sent, so this is a miss and is reported as one.
                None => CacheOutcome::Miss304,
            });
        }

        if !status.is_success() {
            return Err(SearchError::Http {
                status: status.as_u16(),
            });
        }

        // Read the headers into owned values before the body consumes the response.
        let etag = header_string(response.headers(), ETAG);
        let last_modified = header_string(response.headers(), LAST_MODIFIED);
        let cache_control = header_string(response.headers(), CACHE_CONTROL);
        let date = header_string(response.headers(), DATE);
        let expires = header_string(response.headers(), EXPIRES);
        let now = self.clock.now_secs();

        // Bounded read: an over-cap body aborts mid-stream and is never assembled, so a hostile
        // page cannot force an arbitrarily large allocation behind a missing or dishonest
        // `Content-Length`.
        let Some(body) = read_bounded_text(response, self.max_body_bytes)
            .await
            .map_err(transport_error)?
        else {
            // Over the cap: store nothing, and drop whatever was filed for the key — the copy
            // that was there is now known to be superseded by a response the cache refused to
            // keep. No body is returned: there is no bounded value to hand over that would still
            // be what the origin said.
            self.remove(&key);
            return Ok(CacheOutcome::TooLarge);
        };

        self.store(&Entry {
            key,
            etag,
            last_modified,
            stored_at: now,
            max_age: lifetime_secs(
                cache_control.as_deref(),
                date.as_deref(),
                expires.as_deref(),
                now,
            ),
            body: body.clone(),
        });

        Ok(CacheOutcome::Fetched(body))
    }

    /// Whether the entry may be reused without asking the origin.
    ///
    /// `None` for `max_age` is not fresh, and neither is an elapsed lifetime: absent a header that
    /// says how long the copy is good for, the answer is "ask", not "assume".
    fn is_fresh(&self, entry: &Entry) -> bool {
        match entry.max_age {
            Some(max_age) => self.clock.now_secs() < entry.stored_at.saturating_add(max_age),
            None => false,
        }
    }

    /// Read the entry filed for `key`, if there is a usable one.
    ///
    /// A missing file, unreadable bytes, malformed JSON or a document filed under a different key
    /// (the residual hash-collision case) all read as **absent**. A cache must never turn a hit
    /// into a failure: the caller can always fall back to the network, and it cannot fall back from
    /// an error it was handed instead of a body.
    fn load(&self, key: &str) -> Option<Entry> {
        let entry = read_entry(&self.entry_path(key))?;
        (entry.key == key).then_some(entry)
    }

    /// Write `entry`, subject to both caps.
    ///
    /// A body over `max_body_bytes`, or a cap of zero entries, stores nothing — and drops whatever
    /// was filed for the key, because the copy that *was* there is now known to be superseded by
    /// the response just fetched, and leaving it would let a later revalidation serve it.
    fn store(&self, entry: &Entry) {
        if self.max_entries == 0 || entry.body.len() > self.max_body_bytes {
            self.remove(&entry.key);
            return;
        }

        if std::fs::create_dir_all(&self.root).is_err() {
            return;
        }

        let Ok(json) = serde_json::to_string_pretty(entry) else {
            return;
        };

        // Write-then-rename, so a process that dies mid-write leaves no half-parsed entry for the
        // next run to trip over. The temporary name is unique per write — process id plus a
        // process-wide atomic counter — because concurrent fetches for the same key in one daemon
        // would otherwise truncate and rename the *same* path under each other, interleaving JSON
        // or filing another writer's body under this key. Created exclusively (`create_new`, with
        // a fresh suffix on the residual collision), fsynced before the rename, and atomically
        // renamed over the entry, so a reader only ever sees a complete document or nothing. The
        // name keeps the `.json` extension off itself so the eviction scan cannot mistake it for
        // an entry.
        for _ in 0..8 {
            let temporary = self.unique_tmp_path(&entry.key);
            let written = (|| -> std::io::Result<()> {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                file.write_all(json.as_bytes())?;
                file.sync_all()?;
                drop(file);
                std::fs::rename(&temporary, self.entry_path(&entry.key))
            })();
            match written {
                Ok(()) => break,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => {
                    let _ = std::fs::remove_file(&temporary);
                    return;
                }
            }
        }

        self.evict_to_cap();
    }

    /// A temporary path for one [`Self::store`] call: the entry filename plus the process id and
    /// a per-write atomic suffix, so no two concurrent writers in this daemon share a path.
    fn unique_tmp_path(&self, key: &str) -> PathBuf {
        static TMP_SUFFIX: AtomicU64 = AtomicU64::new(0);
        let n = TMP_SUFFIX.fetch_add(1, Ordering::Relaxed);
        self.root.join(format!(
            "{}.{}.{}.tmp",
            entry_file_name(key),
            std::process::id(),
            n
        ))
    }

    /// Drop the oldest entries until the cap holds.
    ///
    /// Ordering is by `stored_at` — the clock the entry was written with — and never by mtime, for
    /// the reason the module doc gives. The whole directory is read to decide this, which is
    /// acceptable because the cap is small by construction; a cache that needed to evict cheaply
    /// would keep an index, and an index is a second thing that can disagree with the directory.
    fn evict_to_cap(&self) {
        let mut entries = self.entries_on_disk();
        if entries.len() <= self.max_entries {
            return;
        }

        entries.sort_by_key(|(_, stored_at)| *stored_at);
        let excess = entries.len() - self.max_entries;
        for (path, _) in entries.into_iter().take(excess) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Every entry document under the root, with the time it was stored.
    ///
    /// Only `.json` files are considered, so an unrelated file in a caller-supplied root is left
    /// alone rather than evicted. An unreadable document is skipped: it cannot be ordered, and
    /// deleting something whose age is unknown is not eviction.
    fn entries_on_disk(&self) -> Vec<(PathBuf, u64)> {
        let Ok(read) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };

        read.flatten()
            .filter(|item| item.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .filter_map(|item| {
                let path = item.path();
                read_entry(&path).map(|entry| (path, entry.stored_at))
            })
            .collect()
    }

    /// Where the entry for `key` lives.
    fn entry_path(&self, key: &str) -> PathBuf {
        self.root.join(entry_file_name(key))
    }

    /// Forget whatever is filed for `key`.
    fn remove(&self, key: &str) {
        let _ = std::fs::remove_file(self.entry_path(key));
    }
}

/// The filename for `key`: a sanitized prefix plus a FNV-1a suffix.
///
/// The prefix is for a person reading a directory listing; the suffix is what makes the name
/// unique, because `a/b?x=1` and `a-b?x=1` sanitize to the same prefix and would otherwise share a
/// file and silently share an entry.
fn entry_file_name(key: &str) -> String {
    let mut prefix: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(120)
        .collect();
    if prefix.is_empty() {
        prefix.push('_');
    }
    format!("{prefix}_{:016x}.json", fnv1a(key))
}

/// FNV-1a, 64-bit, over the bytes of `input`.
///
/// Used only to keep two keys' filenames apart. It is not a security primitive, it is not treated
/// as one, and nothing verifies anything with it — the `key` field in the document is the check
/// that matters. Also used by `research`'s browser-backed fetcher to derive a profile session id
/// from a URL without ever putting the URL (or a token in it) on the filesystem.
pub(crate) fn fnv1a(input: &str) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Read and parse an entry document. `None` for anything that is not a valid entry.
fn read_entry(path: &Path) -> Option<Entry> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// A header value as an owned `String`, when it is present and is valid ASCII text.
fn header_string(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// How long a response may be reused, in seconds, from its own headers.
///
/// `max-age` wins when present, because it is the directive that was written for this. Otherwise
/// `Expires` is measured against the origin's own `Date` — not against the local clock, because a
/// skew between the two would silently stretch or collapse a lifetime. With neither, the answer is
/// `None`: not fresh, therefore revalidated.
///
/// The obsolete date formats (RFC 850, `asctime`) are not parsed, so a response that uses one is
/// treated as having no expiry and is revalidated. That is the safe direction and it is said here
/// rather than left to be discovered.
fn lifetime_secs(
    cache_control: Option<&str>,
    date: Option<&str>,
    expires: Option<&str>,
    now: u64,
) -> Option<u64> {
    if let Some(seconds) = cache_control.and_then(max_age_secs) {
        return Some(seconds);
    }

    let expires_at = expires.and_then(parse_http_date)?;
    let reference = date.and_then(parse_http_date).unwrap_or(now);
    Some(expires_at.saturating_sub(reference))
}

/// The `max-age` directive of a `Cache-Control` header, if it has one.
///
/// The other directives are deliberately not interpreted: this is not an HTTP cache (see the module
/// doc), and half-implementing `no-store` would be worse than not claiming it.
fn max_age_secs(cache_control: &str) -> Option<u64> {
    cache_control
        .split(',')
        .map(str::trim)
        .find_map(|directive| directive.strip_prefix("max-age="))
        .and_then(|value| value.trim().parse().ok())
}

/// An IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) as seconds since the Unix epoch.
///
/// Only the format RFC 7231 names as preferred is understood. Anything else is `None`, which the
/// caller turns into "no expiry" rather than into a guess.
fn parse_http_date(value: &str) -> Option<u64> {
    let (_, rest) = value.split_once(", ")?;
    let mut parts = rest.split(' ');

    let day: u64 = parts.next()?.parse().ok()?;
    let month = month_from(parts.next()?)?;
    let year: u64 = parts.next()?.parse().ok()?;
    let (hour, minute, second) = parse_clock(parts.next()?)?;
    if !parts.next()?.eq_ignore_ascii_case("GMT") || parts.next().is_some() {
        return None;
    }

    let days = days_from_civil(year, month, day);
    Some(days * SECS_PER_DAY + hour * 3_600 + minute * 60 + second)
}

/// The hour, minute and second of an `HH:MM:SS` field.
fn parse_clock(value: &str) -> Option<(u64, u64, u64)> {
    let mut fields = value.split(':');
    let hour: u64 = fields.next()?.parse().ok()?;
    let minute: u64 = fields.next()?.parse().ok()?;
    let second: u64 = fields.next()?.parse().ok()?;
    if fields.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

/// The 1-based month number of an English three-letter month name.
fn month_from(name: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    MONTHS
        .iter()
        .position(|month| month.eq_ignore_ascii_case(name))
        .map(|index| index as u64 + 1)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
///
/// Hand-rolled because the crate has no date library and this is the only date arithmetic in it.
/// The algorithm is exact for the whole proleptic Gregorian range, including the pre-1970 dates the
/// `Expires` header can technically carry.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = year as i64;
    let month = month as i64;
    let day = day as i64;

    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400;
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    (era * 146_097 + day_of_era - 719_468) as u64
}

/// Read a response body bounded by `limit` bytes — the one reader both the cached and the
/// uncached research paths use.
///
/// WHY one reader: the limit has to hold wherever a body is read, and two copies of "read then
/// check the length" already drifted once. The uncached path checked `Content-Length` up front,
/// which a missing or dishonest header bypasses, and both paths buffered the full body with
/// `text()` before comparing. This consumes `bytes_stream()` chunk by chunk and aborts past the
/// limit, so an oversized body is never assembled into a `String`.
///
/// Returns `Ok(Some(body))` when the whole body fit in `limit` bytes, `Ok(None)` when it did
/// not — the caller skips rather than truncates, because a truncated page would cite a document
/// the origin never published — and `Err` on a transport failure, with the request URL still
/// attached for the caller to strip (each path has its own credential rule).
///
/// The bytes are decoded as UTF-8 lossily, matching what `text()` produced for the ASCII and
/// UTF-8 pages this cache serves. The accumulator never holds more than `limit` bytes: the check
/// runs before each chunk is appended, so even one hostile chunk cannot push it over.
pub(crate) async fn read_bounded_text(
    response: reqwest::Response,
    limit: usize,
) -> Result<Option<String>, reqwest::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        if buf.len().saturating_add(bytes.len()) > limit {
            return Ok(None);
        }
        buf.extend_from_slice(&bytes);
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// A transport error with the request URL removed via [`reqwest::Error::without_url`].
///
/// `reqwest::Error`'s `Display` and `Debug` implementations append the request URL, so an error
/// on a URL carrying a query token (`?token=...`, `?key=...`) writes a live credential into
/// an error string that the model reads.
///
/// Unlike search backends (e.g. Google PSE) which mask a known key via
/// [`SearchError::transport_redacted`], the cache cannot know which query parameter is a secret,
/// so masking against a `&Secret` is not available to it. Dropping the URL entirely is the correct
/// answer: the caller already holds the URL it passed to `fetch` and does not need it repeated
/// in the transport error.
fn transport_error(err: reqwest::Error) -> SearchError {
    SearchError::Transport(err.without_url())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // -----------------------------------------------------------------------------------------
    // The injected clock
    // -----------------------------------------------------------------------------------------

    /// A clock a test moves by hand. This is why nothing in this file sleeps.
    #[derive(Clone)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn starting_at(secs: u64) -> Self {
            Self(Arc::new(AtomicU64::new(secs)))
        }

        fn advance(&self, secs: u64) {
            self.0.fetch_add(secs, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    // -----------------------------------------------------------------------------------------
    // The origin: a real HTTP/1.1 server on a real loopback socket
    // -----------------------------------------------------------------------------------------

    /// One scripted response.
    #[derive(Clone)]
    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
        /// When true, the body goes out as `Transfer-Encoding: chunked` with no `Content-Length`
        /// at all — the shape a missing-length hostile page takes.
        chunked: bool,
    }

    impl Reply {
        /// A `200` carrying an `ETag` and no freshness header — the ordinary case, which is *not*
        /// fresh and therefore has to be revalidated.
        fn ok(etag: &str, body: &str) -> Self {
            Self {
                status: 200,
                headers: vec![("etag".to_string(), etag.to_string())],
                body: body.to_string(),
                chunked: false,
            }
        }

        /// A `200` with no validator and no freshness header at all.
        fn plain(body: &str) -> Self {
            Self {
                status: 200,
                headers: Vec::new(),
                body: body.to_string(),
                chunked: false,
            }
        }

        /// A `200` with no `Content-Length`, framed as `Transfer-Encoding: chunked` — the shape
        /// whose missing length used to bypass the body cap's early check.
        fn chunked_ok(body: &str) -> Self {
            Self {
                status: 200,
                headers: Vec::new(),
                body: body.to_string(),
                chunked: true,
            }
        }

        /// A `200` that says how long it may be reused.
        fn ok_with_max_age(etag: &str, body: &str, max_age: u64) -> Self {
            Self {
                status: 200,
                headers: vec![
                    ("etag".to_string(), etag.to_string()),
                    (
                        "cache-control".to_string(),
                        format!("public, max-age={max_age}"),
                    ),
                ],
                body: body.to_string(),
                chunked: false,
            }
        }

        /// A `200` whose only validator is a `Last-Modified`.
        fn ok_with_last_modified(last_modified: &str, body: &str) -> Self {
            Self {
                status: 200,
                headers: vec![("last-modified".to_string(), last_modified.to_string())],
                body: body.to_string(),
                chunked: false,
            }
        }

        fn not_modified() -> Self {
            Self {
                status: 304,
                headers: Vec::new(),
                body: String::new(),
                chunked: false,
            }
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
            for (name, value) in &self.headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            let bytes = if self.chunked {
                // No `Content-Length`: chunked framing only, in small pieces so the body arrives
                // as several stream chunks rather than one.
                head.push_str("transfer-encoding: chunked\r\n");
                head.push_str("connection: close\r\n\r\n");
                let mut bytes = head.into_bytes();
                for piece in self.body.as_bytes().chunks(512) {
                    bytes.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                    bytes.extend_from_slice(piece);
                    bytes.extend_from_slice(b"\r\n");
                }
                bytes.extend_from_slice(b"0\r\n\r\n");
                bytes
            } else {
                head.push_str(&format!("content-length: {}\r\n", self.body.len()));
                head.push_str("connection: close\r\n\r\n");
                let mut bytes = head.into_bytes();
                bytes.extend_from_slice(self.body.as_bytes());
                bytes
            };
            bytes
        }
    }

    /// A scripted origin on a real socket.
    ///
    /// It **fails loudly**: a request it was not scripted for is answered `500` and counted, and
    /// every test calls [`Origin::assert_fully_scripted`]. A double that answered politely when it
    /// ran out of script would let a cache that made one request too many pass.
    ///
    /// Every response says `connection: close`, so one request is one connection and
    /// [`Origin::connection_count`] is a request count — which is what makes "a fresh entry makes
    /// no request" an assertion rather than a hope.
    struct Origin {
        base: String,
        connections: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
        unscripted: Arc<AtomicUsize>,
        _handle: tokio::task::JoinHandle<()>,
    }

    impl Origin {
        async fn serve(script: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
            let addr = listener.local_addr().expect("a bound address");

            let connections = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let unscripted = Arc::new(AtomicUsize::new(0));

            let remaining = Arc::new(Mutex::new(VecDeque::from(script)));
            let (counted, recorded, refused, script) = (
                connections.clone(),
                requests.clone(),
                unscripted.clone(),
                remaining.clone(),
            );

            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    counted.fetch_add(1, Ordering::SeqCst);

                    // Read the head *before* taking the lock: a `MutexGuard` held across an await
                    // makes the spawned future non-`Send`.
                    let head = read_head(&mut socket).await;
                    recorded.lock().unwrap().push(head);

                    let (reply, scripted) = match script.lock().unwrap().pop_front() {
                        Some(reply) => (reply, true),
                        None => (
                            Reply {
                                status: 500,
                                headers: Vec::new(),
                                body:
                                    "the origin was asked for a reply it was not scripted to give"
                                        .to_string(),
                                chunked: false,
                            },
                            false,
                        ),
                    };
                    if !scripted {
                        refused.fetch_add(1, Ordering::SeqCst);
                    }

                    let _ = socket.write_all(&reply.to_bytes()).await;
                    let _ = socket.flush().await;
                }
            });

            Self {
                base: format!("http://{addr}"),
                connections,
                requests,
                unscripted,
                _handle: handle,
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.base)
        }

        fn connection_count(&self) -> usize {
            self.connections.load(Ordering::SeqCst)
        }

        /// The request heads seen so far, in order. The socket ordering is what makes this safe to
        /// read without waiting: the origin records a head before it writes the response, so by the
        /// time a client holds a response the head is already here.
        fn request_heads(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        fn assert_fully_scripted(&self) {
            assert_eq!(
                self.unscripted.load(Ordering::SeqCst),
                0,
                "the origin was asked for more requests than it was scripted for"
            );
        }
    }

    /// Read a request head, up to the blank line. These are `GET`s, so there is no body to read.
    async fn read_head(socket: &mut TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        while let Ok(read) = socket.read(&mut chunk).await {
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buffer).to_string()
    }

    fn reason(status: u16) -> &'static str {
        match status {
            200 => "OK",
            304 => "Not Modified",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Status",
        }
    }

    // -----------------------------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------------------------

    /// A real directory under the system temp dir. `tempfile` is deliberately not a dependency of
    /// this crate, so the test makes its own and cleans it up.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hx-search-cache-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp directory");
        dir
    }

    fn entry_file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|read| {
                read.flatten()
                    .map(|item| item.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    // -----------------------------------------------------------------------------------------
    // The key
    // -----------------------------------------------------------------------------------------

    #[test]
    fn a_key_digests_the_query_and_drops_the_fragment_but_keeps_the_path() {
        // The key is what a repeat fetch looks up *and* what becomes a filename, so both halves
        // matter: the path has to survive, the fragment has to go, and the query must influence
        // identity without appearing in plaintext.
        let key = cache_key("https://example.com/a/b?token=xyz#section");
        assert!(
            key.starts_with("https://example.com/a/b#"),
            "the path stays and the query becomes a digest suffix: {key}"
        );
        assert!(
            !key.contains("xyz") && !key.contains("token"),
            "a credential must not reach the key: {key}"
        );
        assert_eq!(
            cache_key("https://example.com/a/b"),
            "https://example.com/a/b"
        );
        assert_eq!(
            cache_key("https://example.com/a/b#section"),
            "https://example.com/a/b"
        );
    }

    #[test]
    fn two_urls_that_differ_only_in_their_query_get_distinct_entries() {
        // The collision this replaces: a fresh first response used to be served for a URL the
        // origin was never asked for. The digest keeps query values out of the key while keeping
        // the entries apart.
        let first = cache_key("https://example.com/search?page=1&q=x");
        let second = cache_key("https://example.com/search?page=2&q=x");
        assert_ne!(first, second, "different queries are different entries");
        for key in [&first, &second] {
            assert!(
                key.starts_with("https://example.com/search#"),
                "the path stays readable: {key}"
            );
            assert!(
                !key.contains("page=1") && !key.contains("page=2"),
                "query plaintext must not reach the key: {key}"
            );
        }
        // Determinism: the same URL always keys the same way.
        assert_eq!(first, cache_key("https://example.com/search?page=1&q=x"));
    }

    #[test]
    fn a_relative_input_is_keyed_by_hand_rather_than_collapsing_to_nothing() {
        // `Url::parse` refuses a relative path, and a fallback that returned an empty key would put
        // every such input in one entry.
        let key = cache_key("/a/b?token=xyz");
        assert!(
            key.starts_with("/a/b#"),
            "the path stays and the query becomes a digest suffix: {key}"
        );
        assert!(!key.contains("xyz"), "{key}");
        assert_eq!(cache_key("/a/b"), "/a/b");
    }

    // -----------------------------------------------------------------------------------------
    // Revalidation, over a real socket
    // -----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_stored_entry_is_revalidated_with_if_none_match() {
        // The assertion is on the wire, not on the cache's bookkeeping: the header has to have
        // actually left the client. A response with no freshness header is not fresh, so a repeat
        // fetch has to ask the origin rather than trust its own copy.
        let origin = Origin::serve(vec![Reply::ok("\"v1\"", "first"), Reply::not_modified()]).await;
        let dir = temp_dir("revalidate");
        let cache = UrlCache::new(&dir, 8, 4096);
        let url = origin.url("/page");

        let first = cache.fetch(&client(), &url).await.unwrap();
        assert_eq!(first, CacheOutcome::Fetched("first".to_string()));

        let second = cache.fetch(&client(), &url).await.unwrap();
        assert_eq!(second, CacheOutcome::Revalidated("first".to_string()));

        let heads = origin.request_heads();
        assert_eq!(heads.len(), 2, "{heads:?}");
        assert!(
            heads[1]
                .to_ascii_lowercase()
                .contains("if-none-match: \"v1\""),
            "the conditional header has to reach the origin: {}",
            heads[1]
        );

        assert_eq!(origin.connection_count(), 2);
        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_last_modified_only_entry_revalidates_with_if_modified_since() {
        // `ETag` is not the only validator an origin offers, and a cache that only understood
        // `ETag` would re-download every page from a server that speaks `Last-Modified`.
        let origin = Origin::serve(vec![
            Reply::ok_with_last_modified("Sun, 06 Nov 1994 08:49:37 GMT", "first"),
            Reply::not_modified(),
        ])
        .await;
        let dir = temp_dir("last-modified");
        let cache = UrlCache::new(&dir, 8, 4096);
        let url = origin.url("/page");

        cache.fetch(&client(), &url).await.unwrap();
        let second = cache.fetch(&client(), &url).await.unwrap();
        assert_eq!(second, CacheOutcome::Revalidated("first".to_string()));

        let heads = origin.request_heads();
        assert!(
            heads[1]
                .to_ascii_lowercase()
                .contains("if-modified-since: sun, 06 nov 1994 08:49:37 gmt"),
            "{}",
            heads[1]
        );
        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_304_revalidation_returns_the_stored_body() {
        // The `304` itself carries no body — that is the point of a `304` — so a cache that handed
        // the response through would give the caller an empty page.
        let origin = Origin::serve(vec![Reply::ok("\"v1\"", "first"), Reply::not_modified()]).await;
        let dir = temp_dir("stored-body");
        let cache = UrlCache::new(&dir, 8, 4096);
        let url = origin.url("/page");

        cache.fetch(&client(), &url).await.unwrap();
        let second = cache.fetch(&client(), &url).await.unwrap();

        assert_eq!(second, CacheOutcome::Revalidated("first".to_string()));
        assert_eq!(
            second.body(),
            Some("first"),
            "the stored body is the answer"
        );
        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_304_with_nothing_stored_is_reported_as_a_miss_and_never_as_an_empty_body() {
        // The distinct-miss case. A `304` about a document the cache has never held leaves it with
        // nothing to return, and an empty body would be indistinguishable from a page the origin
        // actually sent.
        let origin = Origin::serve(vec![Reply::not_modified()]).await;
        let dir = temp_dir("miss-304");
        let cache = UrlCache::new(&dir, 8, 4096);
        let url = origin.url("/page");

        let outcome = cache.fetch(&client(), &url).await.unwrap();

        assert_eq!(outcome, CacheOutcome::Miss304);
        assert_eq!(
            outcome.body(),
            None,
            "a miss must not be handed over as an empty body: {outcome:?}"
        );
        assert_ne!(outcome.body(), Some(""));
        assert!(
            !cache.contains(&url),
            "nothing may be stored from a 304 alone"
        );
        assert!(
            entry_file_names(&dir).is_empty(),
            "{:?}",
            entry_file_names(&dir)
        );

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_entry_with_no_validator_is_not_assumed_fresh_and_sends_no_conditional_header() {
        // A `200` with neither an `ETag` nor a `Last-Modified` gives the cache nothing to
        // revalidate with. It must still go back to the origin, and it must not invent a
        // conditional header that would make the origin's answer meaningless.
        let origin = Origin::serve(vec![Reply::plain("first"), Reply::plain("second")]).await;
        let dir = temp_dir("no-validator");
        let cache = UrlCache::new(&dir, 8, 4096);
        let url = origin.url("/page");

        let first = cache.fetch(&client(), &url).await.unwrap();
        let second = cache.fetch(&client(), &url).await.unwrap();

        assert_eq!(first, CacheOutcome::Fetched("first".to_string()));
        assert_eq!(second, CacheOutcome::Fetched("second".to_string()));

        let heads = origin.request_heads();
        assert_eq!(heads.len(), 2);
        assert!(
            !heads[1].to_ascii_lowercase().contains("if-none-match")
                && !heads[1].to_ascii_lowercase().contains("if-modified-since"),
            "there is nothing to revalidate with, so no conditional header may be sent: {}",
            heads[1]
        );
        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------------------------
    // Freshness, on the injected clock
    // -----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_fresh_entry_is_served_with_no_request_made() {
        // The origin is scripted for exactly one reply, so a second request would be answered
        // `500` and counted as unscripted — the double fails loudly rather than covering for the
        // cache. The clock moves by less than `max-age`, and nothing sleeps.
        let origin = Origin::serve(vec![Reply::ok_with_max_age("\"v1\"", "first", 60)]).await;
        let dir = temp_dir("fresh");
        let clock = TestClock::starting_at(1_000_000);
        let cache = UrlCache::with_clock(&dir, 8, 4096, Arc::new(clock.clone()));
        let url = origin.url("/page");

        let first = cache.fetch(&client(), &url).await.unwrap();
        assert_eq!(first, CacheOutcome::Fetched("first".to_string()));

        clock.advance(10);

        let second = cache.fetch(&client(), &url).await.unwrap();
        assert_eq!(second, CacheOutcome::Fresh("first".to_string()));
        assert!(!second.made_a_request());
        assert_eq!(
            origin.connection_count(),
            1,
            "a fresh entry must not touch the network at all"
        );
        assert_eq!(origin.request_heads().len(), 1);

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_stale_entry_is_revalidated_rather_than_served() {
        // The clock passes `max-age` with no sleep involved. Serving the stale copy would be the
        // silent-staleness failure this whole module exists to avoid.
        let origin = Origin::serve(vec![
            Reply::ok_with_max_age("\"v1\"", "first", 60),
            Reply::not_modified(),
        ])
        .await;
        let dir = temp_dir("stale");
        let clock = TestClock::starting_at(1_000_000);
        let cache = UrlCache::with_clock(&dir, 8, 4096, Arc::new(clock.clone()));
        let url = origin.url("/page");

        cache.fetch(&client(), &url).await.unwrap();

        clock.advance(61);

        let second = cache.fetch(&client(), &url).await.unwrap();
        assert_eq!(
            second,
            CacheOutcome::Revalidated("first".to_string()),
            "an elapsed max-age has to go back to the origin"
        );
        assert_eq!(origin.connection_count(), 2);

        let heads = origin.request_heads();
        assert!(
            heads[1]
                .to_ascii_lowercase()
                .contains("if-none-match: \"v1\""),
            "{}",
            heads[1]
        );
        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn two_query_variants_of_one_path_hold_distinct_bodies_while_fresh() {
        // The regression entries collapsing by query caused: with `max-age` the first response is
        // fresh, and the second query variant must still go to the origin for its own body —
        // never be served the first variant's. Afterwards the first variant must still be fresh.
        let origin = Origin::serve(vec![
            Reply::ok_with_max_age("\"a\"", "body-for-A", 60),
            Reply::ok_with_max_age("\"b\"", "body-for-B", 60),
        ])
        .await;
        let dir = temp_dir("query-distinct");
        let clock = TestClock::starting_at(1_000_000);
        let cache = UrlCache::with_clock(&dir, 8, 4096, Arc::new(clock));
        let url_a = origin.url("/page?token=A");
        let url_b = origin.url("/page?token=B");

        let first = cache.fetch(&client(), &url_a).await.unwrap();
        assert_eq!(first, CacheOutcome::Fetched("body-for-A".to_string()));

        let second = cache.fetch(&client(), &url_b).await.unwrap();
        assert_eq!(
            second,
            CacheOutcome::Fetched("body-for-B".to_string()),
            "a fresh entry for ?token=A must never answer ?token=B"
        );
        assert_eq!(origin.connection_count(), 2);

        let again = cache.fetch(&client(), &url_a).await.unwrap();
        assert_eq!(again, CacheOutcome::Fresh("body-for-A".to_string()));
        assert_eq!(origin.connection_count(), 2);

        assert!(cache.contains(&url_a));
        assert!(cache.contains(&url_b));
        assert_eq!(entry_file_names(&dir).len(), 2);

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------------------------
    // Bounds
    // -----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn the_entry_cap_evicts_the_oldest_entry_first() {
        // "Oldest" is `stored_at` on the injected clock, and the assertion names *which* key went:
        // an eviction that removed the newest entry would keep the cache full of stale copies.
        let origin = Origin::serve(vec![
            Reply::ok("\"a\"", "aaa"),
            Reply::ok("\"b\"", "bbb"),
            Reply::ok("\"c\"", "ccc"),
        ])
        .await;
        let dir = temp_dir("evict");
        let clock = TestClock::starting_at(1_000);
        let cache = UrlCache::with_clock(&dir, 2, 4096, Arc::new(clock.clone()));

        let oldest = origin.url("/oldest");
        let middle = origin.url("/middle");
        let newest = origin.url("/newest");

        cache.fetch(&client(), &oldest).await.unwrap();
        clock.advance(10);
        cache.fetch(&client(), &middle).await.unwrap();
        clock.advance(10);
        cache.fetch(&client(), &newest).await.unwrap();

        assert!(
            !cache.contains(&oldest),
            "the entry stored first is the one the cap must evict"
        );
        assert!(cache.contains(&middle));
        assert!(cache.contains(&newest));
        assert_eq!(entry_file_names(&dir).len(), 2);

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_oversized_body_is_aborted_mid_stream_never_stored_and_never_built() {
        // The cap bounds allocation, not just the directory: the body is aborted once the limit
        // is passed, so no oversized `String` is ever assembled — and therefore none is stored
        // and none is returned. The caller learns `TooLarge` and skips the page.
        let body = "x".repeat(200);
        let origin = Origin::serve(vec![
            Reply::ok("\"big\"", &body),
            Reply::ok("\"big\"", &body),
        ])
        .await;
        let dir = temp_dir("oversized");
        let cache = UrlCache::new(&dir, 8, 100);
        let url = origin.url("/page");

        let outcome = cache.fetch(&client(), &url).await.unwrap();

        assert_eq!(outcome, CacheOutcome::TooLarge);
        assert_eq!(
            outcome.body(),
            None,
            "there is no bounded body to hand over"
        );
        assert!(outcome.made_a_request());
        assert!(
            !cache.contains(&url),
            "a body over the cap must not be stored at all"
        );
        assert!(
            entry_file_names(&dir).is_empty(),
            "{:?}",
            entry_file_names(&dir)
        );

        // And a second fetch proves it: with nothing filed, the origin is asked again.
        let again = cache.fetch(&client(), &url).await.unwrap();
        assert_eq!(again, CacheOutcome::TooLarge);
        assert_eq!(origin.connection_count(), 2);

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_chunked_body_without_content_length_over_the_cap_is_aborted_not_buffered() {
        // No `Content-Length` anywhere on the wire: the cap can only hold if the body is measured
        // while it streams. The 4 KiB body arrives as eight 512-byte chunks against a 1 KiB cap.
        let body = "y".repeat(4096);
        let origin = Origin::serve(vec![Reply::chunked_ok(&body)]).await;
        let dir = temp_dir("chunked-too-large");
        let cache = UrlCache::new(&dir, 8, 1024);
        let url = origin.url("/stream");

        let outcome = cache.fetch(&client(), &url).await.unwrap();

        assert_eq!(outcome, CacheOutcome::TooLarge);
        assert_eq!(outcome.body(), None);
        assert!(
            !cache.contains(&url),
            "an aborted body must not be stored at all"
        );
        assert!(
            entry_file_names(&dir).is_empty(),
            "{:?}",
            entry_file_names(&dir)
        );

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_chunked_body_without_content_length_within_the_cap_is_assembled_exactly() {
        // The other half: chunked framing must still assemble a small body byte-for-byte, across
        // chunk boundaries, and file it like any other response.
        let body = "z".repeat(700);
        let origin = Origin::serve(vec![Reply::chunked_ok(&body)]).await;
        let dir = temp_dir("chunked-small");
        let cache = UrlCache::new(&dir, 8, 1024);
        let url = origin.url("/stream");

        let outcome = cache.fetch(&client(), &url).await.unwrap();

        assert_eq!(outcome, CacheOutcome::Fetched(body.clone()));
        assert!(cache.contains(&url));
        assert_eq!(entry_file_names(&dir).len(), 1);

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------------------------
    // The credential
    // -----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_token_in_the_query_never_reaches_a_key_or_a_filename() {
        // The reason the key drops the query. This runs a real fetch, so the directory it inspects
        // is one the cache actually wrote.
        let token = "signed-token-9f3a2b7c";
        let origin = Origin::serve(vec![Reply::ok("\"v1\"", "body")]).await;
        let dir = temp_dir("token");
        let cache = UrlCache::new(&dir, 8, 4096);

        let plain = origin.url("/page");
        let url = format!("{plain}?token={token}&page=2");

        let key = cache_key(&url);
        assert!(
            key.starts_with(&plain),
            "the key still names the path: {key}"
        );
        assert!(
            !key.contains(token),
            "the key is what becomes a filename and a log field: {key}"
        );

        cache.fetch(&client(), &url).await.unwrap();

        let names = entry_file_names(&dir);
        assert_eq!(
            names.len(),
            1,
            "the entry has to exist for this to prove anything"
        );
        for name in &names {
            assert!(
                !name.contains(token),
                "a credential must not reach a filename: {name}"
            );
            assert!(!name.contains("token"), "{name}");

            let content = std::fs::read_to_string(dir.join(name)).unwrap();
            assert!(
                !content.contains(token),
                "a credential must not reach the serialized entry on disk: {content}"
            );
            assert!(
                !content.contains("\"url\""),
                "Entry::url was dropped so the serialized entry has no url field: {content}"
            );
        }

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_transport_error_does_not_contain_the_token_on_display_or_debug() {
        // A transport failure on a URL carrying a query token must not leak the token into
        // an error string the model reads. reqwest::Error appends the URL on both Display
        // and Debug; without_url() strips it.
        let token = "signed-token-9f3a2b7c";
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
        let addr = listener.local_addr().expect("a bound address");
        // Drop the listener so TCP connection attempts to this port are immediately refused.
        drop(listener);

        let dir = temp_dir("transport-token");
        let cache = UrlCache::new(&dir, 8, 4096);
        let url = format!("http://{addr}/page?token={token}&other=val");

        // The control: reqwest's raw error genuinely contains the token, proving that the hazard
        // is real and that the test cannot pass vacuously.
        let raw_err = client()
            .get(&url)
            .send()
            .await
            .expect_err("connection is refused");
        assert!(
            raw_err.to_string().contains(token),
            "the premise of this test is that raw reqwest errors print the URL: {raw_err}"
        );
        assert!(
            format!("{raw_err:?}").contains(token),
            "raw reqwest Debug also prints the URL: {raw_err:?}"
        );

        let err = cache
            .fetch(&client(), &url)
            .await
            .expect_err("fetch must fail");
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert!(
            !display.contains(token),
            "transport error Display must not leak the token: {display}"
        );
        assert!(
            !display.contains("token="),
            "transport error Display must not contain query parameters: {display}"
        );
        assert!(
            !debug.contains(token),
            "transport error Debug must not leak the token: {debug}"
        );
        assert!(
            !debug.contains("token="),
            "transport error Debug must not contain query parameters: {debug}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_transport_error_on_a_token_free_url_still_produces_a_useful_message() {
        // The control: stripping the URL must not blank the error or discard the failure reason.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
        let addr = listener.local_addr().expect("a bound address");
        drop(listener);

        let dir = temp_dir("transport-control");
        let cache = UrlCache::new(&dir, 8, 4096);
        let url = format!("http://{addr}/page");

        let err = cache
            .fetch(&client(), &url)
            .await
            .expect_err("fetch must fail");
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert!(
            display.contains("transport error"),
            "SearchError::Transport prefix must be present: {display}"
        );
        assert!(
            display.contains("error sending request") || display.contains("connect"),
            "underlying transport cause must be preserved: {display}"
        );
        assert!(
            !debug.is_empty() && debug.contains("Transport"),
            "Debug output must be informative: {debug}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_entry_stored_in_the_legacy_format_with_a_url_field_is_read_successfully() {
        // Compatibility: entries written before Entry::url was dropped must deserialize cleanly
        // rather than failing or being discarded as corrupt.
        let dir = temp_dir("legacy-entry");
        let clock = TestClock::starting_at(1_000_000);
        let cache = UrlCache::with_clock(&dir, 8, 4096, Arc::new(clock.clone()));

        let url = "http://example.com/legacy-page?token=old-secret-12345";
        let key = cache_key(url);

        let legacy_json = serde_json::json!({
            "key": key,
            "url": url,
            "etag": "\"legacy-v1\"",
            "last_modified": "Sun, 06 Nov 1994 08:49:37 GMT",
            "stored_at": 1_000_000,
            "max_age": 300,
            "body": "legacy cached body"
        });

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            cache.entry_path(&key),
            serde_json::to_string_pretty(&legacy_json).unwrap(),
        )
        .unwrap();

        assert!(cache.contains(url));

        // A fetch while fresh returns the body directly with no network request.
        let outcome = cache.fetch(&client(), url).await.unwrap();
        assert_eq!(
            outcome,
            CacheOutcome::Fresh("legacy cached body".to_string())
        );
        assert_eq!(outcome.body(), Some("legacy cached body"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------------------------
    // Robustness
    // -----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_corrupt_entry_file_is_a_miss_rather_than_a_failure() {
        // A cache can always fall back to the network, and it cannot fall back from an error it
        // was handed instead of a body. A half-written file from a killed process is the realistic
        // way this happens.
        let origin = Origin::serve(vec![Reply::ok("\"v1\"", "fetched anyway")]).await;
        let dir = temp_dir("corrupt");
        let cache = UrlCache::new(&dir, 8, 4096);
        let url = origin.url("/page");

        let key = cache_key(&url);
        std::fs::write(cache.entry_path(&key), b"{ this is not an entry").unwrap();
        assert!(!cache.contains(&url));

        let outcome = cache.fetch(&client(), &url).await.unwrap();
        assert_eq!(outcome, CacheOutcome::Fetched("fetched anyway".to_string()));

        origin.assert_fully_scripted();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_writes_for_one_key_leave_a_single_complete_entry() {
        // The race `store` used to have: every writer for one key truncated and renamed the same
        // `<name>.<pid>.tmp` path, so writers released at once could interleave JSON or file one
        // writer's body under another's rename. Sixteen threads store distinct bodies behind a
        // barrier; afterwards the directory must hold exactly the entry file — no orphan temps —
        // parsing cleanly with the right key and one writer's complete body, never a splice.
        use std::sync::Barrier;

        const WRITERS: usize = 16;
        let dir = temp_dir("concurrent-writers");
        let cache = Arc::new(UrlCache::new(&dir, 64, 4096));
        let url = "http://example.com/shared?round=1";
        let key = cache_key(url);
        let barrier = Arc::new(Barrier::new(WRITERS));

        let handles: Vec<_> = (0..WRITERS)
            .map(|i| {
                let (cache, barrier) = (Arc::clone(&cache), Arc::clone(&barrier));
                let key = key.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    cache.store(&Entry {
                        key,
                        etag: None,
                        last_modified: None,
                        stored_at: 1_000 + i as u64,
                        max_age: None,
                        body: format!("complete-body-from-writer-{i:02}"),
                    })
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("a writer thread must not panic");
        }

        let names = entry_file_names(&dir);
        assert_eq!(
            names.len(),
            1,
            "one entry file and no orphan temp files: {names:?}"
        );
        let text = std::fs::read_to_string(dir.join(&names[0])).unwrap();
        let stored: serde_json::Value =
            serde_json::from_str(&text).expect("concurrent writes must leave a parseable document");
        assert_eq!(stored["key"], key);
        let body = stored["body"].as_str().expect("a body field");
        assert!(
            (0..WRITERS).any(|i| body == format!("complete-body-from-writer-{i:02}")),
            "the stored body is one writer's complete body, not a splice: {body}"
        );
        assert!(
            cache.contains(url),
            "the entry reads back through the cache's own read path"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------------------------
    // Freshness headers, as values
    // -----------------------------------------------------------------------------------------

    #[test]
    fn an_expires_header_is_understood_when_cache_control_is_absent() {
        // A real IMF-fixdate and its epoch, so this cannot agree with itself: 1994-11-06 08:49:37
        // UTC is 784111777 seconds after the epoch.
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            lifetime_secs(
                None,
                Some("Sun, 06 Nov 1994 08:49:37 GMT"),
                Some("Sun, 06 Nov 1994 08:50:37 GMT"),
                0
            ),
            Some(60)
        );

        // `max-age` is the directive written for this and wins when both are present.
        assert_eq!(
            lifetime_secs(
                Some("public, max-age=300"),
                Some("Sun, 06 Nov 1994 08:49:37 GMT"),
                Some("Sun, 06 Nov 1994 08:50:37 GMT"),
                0
            ),
            Some(300)
        );

        // Absent both, the entry is not fresh — it is revalidated.
        assert_eq!(lifetime_secs(None, None, None, 0), None);
    }

    #[test]
    fn a_date_that_is_not_an_imf_fixdate_yields_no_lifetime_rather_than_a_guess() {
        // The obsolete formats are not parsed, so a response using one is revalidated. The safe
        // direction, and stated in the doc comment rather than left to be discovered.
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), None);
        assert_eq!(parse_http_date(""), None);
        assert_eq!(parse_http_date("Sun, 06 Foo 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 UTC"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 25:49:37 GMT"), None);

        assert_eq!(lifetime_secs(None, None, Some("not a date"), 0), None);
    }
}
