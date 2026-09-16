//! `known_hosts` — the file that decides which SSH host keys are trusted.
//!
//! This is the piece that makes the SSH transport no *less* safe than the `ssh` binary it
//! replaces. Without it, `check_server_key` has to answer a question it cannot answer, and
//! "accept anything" is a silent man-in-the-middle.
//!
//! ## What is implemented
//!
//! The OpenSSH format, parsed here rather than delegated, because two of its features change the
//! *verdict* and `russh`'s helper ignores both:
//!
//! - **`@revoked`** — a key marked revoked for a host is a hard rejection. Treating that line as
//!   merely "not a match" would downgrade a known-bad key to an unknown host, and trust-on-first-
//!   use would happily re-record it.
//! - **`@cert-authority`** — an authority that may sign host certificates. We do not verify
//!   certificates yet, so such a line grants nothing; it is never read as "this host is known".
//!
//! Also handled: hashed host fields (`|1|salt|hmac`, OpenSSH's default on Debian/Ubuntu, and the
//! reason a naive parser sees an empty file where a pinned key actually lives), comma-separated
//! host lists, `*`/`?` globs, `!` negation, and `[host]:port` for a non-default port.
//!
//! ## Verdict precedence
//!
//! `@revoked` beats everything. Trust beats a mismatch *if* both exist, which is what makes a
//! key rotation work: an operator who appends the new key before removing the old one still
//! connects. Anything else left over is a mismatch, and a mismatch is not a warning — it is the
//! attack this file exists to detect.
//!
//! ## What is deliberately not verified here
//!
//! Host certificates (`@cert-authority`). Until that lands, a server presenting a certificate is
//! refused by the caller rather than accepted on the strength of a CA line.

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use hx_core::error::{HxError, Result};
use russh::keys::{parse_public_key_base64, PublicKey};
use sha1::Sha1;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// What a `known_hosts` file says about a host key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// The offered key is the one recorded for this host.
    Trusted,
    /// The host is known, but with a different key of the same type. This is the
    /// man-in-the-middle case, or a server that was reinstalled.
    Changed {
        /// 1-based line number of the entry that disagrees.
        line: usize,
        /// The recorded key blob, so an operator can compare it against `ssh-keyscan`.
        recorded: String,
    },
    /// A `@revoked` entry records exactly this key for this host.
    Revoked {
        /// 1-based line number of the revoking entry.
        line: usize,
    },
    /// Nothing recorded for this host, or only for a different key type.
    ///
    /// A different type is *unknown*, not *changed*: `ssh` accepts a host offering an algorithm
    /// it has no entry for and records it on first use, and so do we. Treating it as a mismatch
    /// would make the first ed25519 connection to an RSA-only known_hosts fail.
    Unknown,
}

/// A `known_hosts` file at a specific path.
///
/// The path is explicit so tests never touch the real `~/.ssh/known_hosts`, and so a daemon can
/// point at its own trust store instead of inheriting the user's shell history of TOFU decisions.
#[derive(Clone, Debug)]
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    /// Use the file at `path`.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The conventional location: `~/.ssh/known_hosts` (`%USERPROFILE%` on Windows).
    ///
    /// Errors rather than silently falling back to an empty store: a policy that cannot find the
    /// trust store must say so, not behave as though nothing were pinned.
    pub fn user_default() -> Result<Self> {
        let home = home_dir().ok_or_else(|| {
            HxError::Remote(
                "cannot locate ~/.ssh/known_hosts: no HOME (or USERPROFILE) is set".to_string(),
            )
        })?;
        Ok(Self::at(known_hosts_under(&home)))
    }

    /// Where this store lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Compare an offered key against the file.
    ///
    /// A missing file is [`HostKeyVerdict::Unknown`], not an error: every user has a first host.
    pub fn lookup(&self, host: &str, port: u16, offered: &PublicKey) -> Result<HostKeyVerdict> {
        let contents = match fs::read_to_string(&self.path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(HostKeyVerdict::Unknown)
            }
            Err(err) => {
                return Err(HxError::Remote(format!(
                    "could not read {}: {err}",
                    self.path.display()
                )))
            }
        };

        Ok(evaluate(&contents, &host_field(host, port), offered))
    }

    /// Append a key to the file, creating it (and its directory) if needed.
    ///
    /// Refuses a file that group or world can write: a trust store another local user can edit is
    /// not a trust store. Appending is the only write — nothing in this file is ever rewritten,
    /// because rewriting a trust file is how a bug turns into a silent key substitution.
    pub fn record(&self, host: &str, port: u16, key: &PublicKey) -> Result<()> {
        let openssh = key.to_openssh().map_err(|err| {
            HxError::Remote(format!("could not serialise the server's host key: {err}"))
        })?;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                create_private_dir(parent)?;
            }
        }

        let mut file = open_private_append(&self.path)?;

        // `ssh` will not append to a file that does not end in a newline without adding one first;
        // without this an append lands on the last line and corrupts both entries.
        let mut ends_with_newline = true;
        let mut last = [0u8; 1];
        if file.seek(SeekFrom::End(-1)).is_ok() && file.read_exact(&mut last).is_ok() {
            ends_with_newline = last[0] == b'\n';
        }
        file.seek(SeekFrom::End(0))?;

        let mut line = String::new();
        if !ends_with_newline {
            line.push('\n');
        }
        line.push_str(&host_field(host, port));
        line.push(' ');
        line.push_str(&openssh);
        line.push('\n');

        file.write_all(line.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

/// The field `ssh` writes for a host: bare `host` on port 22, `[host]:port` otherwise.
///
/// Getting this wrong in the other direction — always writing the bare form — produces a file
/// that `ssh` itself no longer matches.
pub fn host_field(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// `~/.ssh/known_hosts` under a given home directory.
fn known_hosts_under(home: &Path) -> PathBuf {
    home.join(".ssh").join("known_hosts")
}

fn home_dir() -> Option<PathBuf> {
    // `std::env::home_dir` is deprecated for being wrong on Windows, and `HOME` is not set there.
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// One parsed line. Borrowed fields keep parsing allocation-free.
#[derive(Debug)]
struct Entry<'a> {
    line: usize,
    marker: Option<Marker>,
    patterns: Vec<&'a str>,
    /// The base64 blob. The type field next to it is not read: the blob names its own algorithm,
    /// and trusting the two to agree is how a mismatched pair slips through.
    key_blob: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Marker {
    Revoked,
    CertAuthority,
}

/// Parse one line. `None` for a blank line, a comment, or anything malformed.
///
/// Malformed lines are skipped rather than fatal, exactly as `ssh` does: one bad line (a hand
/// edit, a merge conflict marker) must not take a machine out of the trust store.
fn parse_line(raw: &str, line: usize) -> Option<Entry<'_>> {
    // `.trim()` also disposes of the `\r` in a file written on Windows.
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let mut fields = trimmed.split_whitespace();
    let first = fields.next()?;

    let (marker, host_field) = match first.strip_prefix('@') {
        Some(name) => (Some(marker_from(name)?), fields.next()?),
        None => (None, first),
    };

    // The key type, then the blob. The type is consumed and discarded.
    let _key_type = fields.next()?;
    let key_blob = fields.next()?;

    let patterns = host_field
        .split(',')
        .filter(|pattern| !pattern.is_empty())
        .collect::<Vec<_>>();

    Some(Entry {
        line,
        marker,
        patterns,
        key_blob,
    })
}

fn marker_from(name: &str) -> Option<Marker> {
    match name {
        "revoked" => Some(Marker::Revoked),
        "cert-authority" => Some(Marker::CertAuthority),
        // An unrecognised marker is not a hostname, and guessing at its meaning is worse than
        // dropping the line.
        _ => None,
    }
}

/// Decide the verdict for `target` against the whole file, without touching the filesystem.
fn evaluate(contents: &str, target: &str, offered: &PublicKey) -> HostKeyVerdict {
    let mut trusted = false;
    let mut changed: Option<HostKeyVerdict> = None;

    for (index, raw) in contents.lines().enumerate() {
        let Some(entry) = parse_line(raw, index + 1) else {
            continue;
        };
        if !entry_matches_host(&entry, target) {
            continue;
        }
        let Some(key) = parse_public_key_base64(entry.key_blob).ok() else {
            // An unparseable key pins nothing. Refusing the host instead would be worse: the file
            // is often shared with a different `ssh` build, and we still have the next entry.
            continue;
        };
        let same_algorithm = key.algorithm() == offered.algorithm();

        match entry.marker {
            // Revocation is absolute, so it returns instead of being remembered: nothing later in
            // the file can un-revoke it, and nothing earlier can be read as trust for it.
            Some(Marker::Revoked) => {
                if same_algorithm && key == *offered {
                    return HostKeyVerdict::Revoked { line: entry.line };
                }
            }
            // An authority is not a host key. See the module docs.
            Some(Marker::CertAuthority) => {}
            None => {
                if same_algorithm {
                    if key == *offered {
                        trusted = true;
                    } else if changed.is_none() {
                        changed = Some(HostKeyVerdict::Changed {
                            line: entry.line,
                            recorded: entry.key_blob.to_string(),
                        });
                    }
                }
            }
        }
    }

    // Trust first: a host listed twice (rotation, or one entry per algorithm) is trusted as soon
    // as one entry matches.
    if trusted {
        HostKeyVerdict::Trusted
    } else if let Some(changed) = changed {
        changed
    } else {
        HostKeyVerdict::Unknown
    }
}

/// Does this entry's host list cover `target`?
///
/// Negation is checked first and wins outright, matching `ssh`'s `match_pattern_list`: an entry
/// `!bad.example.com,*.example.com` must not be read as trust for `bad.example.com`.
fn entry_matches_host(entry: &Entry<'_>, target: &str) -> bool {
    let mut matched = false;
    for pattern in &entry.patterns {
        if let Some(negated) = pattern.strip_prefix('!') {
            if pattern_matches(negated, target) {
                return false;
            }
        } else if pattern_matches(pattern, target) {
            matched = true;
        }
    }
    matched
}

fn pattern_matches(pattern: &str, target: &str) -> bool {
    match pattern.strip_prefix("|1|") {
        Some(hashed) => hashed_pattern_matches(hashed, target),
        None => glob_match(pattern, target),
    }
}

/// `|1|base64(salt)|base64(hmac-sha1(salt, host))` — OpenSSH's hash-known-hosts form.
///
/// HMAC-SHA1 is not a choice being made here; it is the format on disk.
fn hashed_pattern_matches(hashed: &str, target: &str) -> bool {
    let mut parts = hashed.split('|');
    let (Some(salt), Some(expected)) = (parts.next(), parts.next()) else {
        return false;
    };
    let (Some(salt), Some(expected)) = (decode_b64(salt), decode_b64(expected)) else {
        return false;
    };

    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(target.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

fn decode_b64(input: &str) -> Option<Vec<u8>> {
    // `ssh` writes padded base64, but a hand-edited unpadded value should still be honoured
    // rather than silently read as "host unknown".
    base64::engine::general_purpose::STANDARD
        .decode(input.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input.as_bytes()))
        .ok()
}

/// `*` and `?` globs, no character classes — which is what `known_hosts` uses.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();

    let (mut p, mut t) = (0usize, 0usize);
    // Where the last `*` was, and how much of `text` it had consumed, so a failed match can
    // backtrack instead of giving up on the first mismatch.
    let mut star: Option<(usize, usize)> = None;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .map_err(|err| HxError::Remote(format!("could not create {}: {err}", path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `.ssh` is the user's own trust material; 0700 is what `ssh` creates it with.
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
            HxError::Remote(format!("could not restrict {}: {err}", path.display()))
        })?;
    }

    Ok(())
}

fn open_private_append(path: &Path) -> Result<File> {
    if let Ok(metadata) = fs::metadata(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(HxError::Remote(format!(
                    "{} is writable by other users; refusing to record a host key in a file \
                     someone else can edit (fix with: chmod 600 {})",
                    path.display(),
                    path.display()
                )));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
        }
    }

    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options
        .open(path)
        .map_err(|err| HxError::Remote(format!("could not open {}: {err}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real keys. `ED25519_A` and `RSA_A` came out of `ssh-keygen`; `ED25519_B` is OpenSSH's own
    /// test key, the one the hashed fixture below was built from. A hand-built blob would only
    /// prove that this parser agrees with itself.
    const ED25519_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILZs0NPMDY3wMHo5EX9Fh6AwmQzQyf9AkTL2z+0UvKRT";
    const ED25519_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const RSA_A: &str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCn5F+GtUt2HeghAccScpFlvjZ+akJKCF67TAozbdU7\
vB3OOSfLz+YroF58jgg3aiGlRNZjo7txiX4B5x6b89o5n1pjIjEFW5RxvF4+FyVE8CxN1SankpaAh7oUBTKnKBNij7Qik/NgocQnW7A\
x/gQiyDqqSIGOziY12E+KMTGhvSjX/7jgKTWx54jkHsQpoLKtUguVJvqP+YSqj6MXyHzzxIxRR4j3eRXpvEOVKiBMkZl1VyvX1tiSWsB\
Kckfd8YiV4C0LzA8KoiS3t2wIXpy/Z/qOzMgbg3lXUzXyW5bccUsIV1iR96LF7D9MToFM9Iap0bAuaW27tsO2kP6qII1P";

    fn ed(blob: &str) -> PublicKey {
        parse_public_key_base64(blob).expect("fixture key parses")
    }

    fn rsa(blob: &str) -> PublicKey {
        parse_public_key_base64(blob).expect("fixture key parses")
    }

    fn known_hosts_line(host: &str, port: u16, algorithm: &str, blob: &str) -> String {
        format!("{} {algorithm} {blob}\n", host_field(host, port))
    }

    #[test]
    fn a_recorded_key_is_trusted() {
        let file = known_hosts_line("buildbox", 22, "ssh-ed25519", ED25519_A);
        let verdict = evaluate(&file, "buildbox", &ed(ED25519_A));
        assert_eq!(verdict, HostKeyVerdict::Trusted);
    }

    #[test]
    fn a_changed_key_is_reported_with_the_line_that_disagrees() {
        let file = format!(
            "# a comment\n\n{}",
            known_hosts_line("buildbox", 22, "ssh-ed25519", ED25519_A)
        );
        let verdict = evaluate(&file, "buildbox", &ed(ED25519_B));

        let HostKeyVerdict::Changed { line, recorded } = verdict else {
            panic!("expected a change, got {verdict:?}");
        };
        assert_eq!(line, 3, "the third line of the file");
        assert_eq!(
            recorded, ED25519_A,
            "so it can be compared against ssh-keyscan"
        );
    }

    #[test]
    fn the_same_host_with_a_different_key_type_is_unknown_not_changed() {
        // A host that gained an ed25519 key after being pinned with RSA is a first use of that
        // algorithm, not a substitution. Reporting it as a change would break the rotation.
        let file = known_hosts_line("buildbox", 22, "ssh-rsa", RSA_A);
        let verdict = evaluate(&file, "buildbox", &ed(ED25519_A));
        assert_eq!(verdict, HostKeyVerdict::Unknown);
    }

    #[test]
    fn trust_wins_over_a_stale_entry_for_the_same_host() {
        // Key rotation: the old line has not been cleaned up yet, but the new key is present.
        let file = format!(
            "{}{}",
            known_hosts_line("buildbox", 22, "ssh-ed25519", ED25519_A),
            known_hosts_line("buildbox", 22, "ssh-ed25519", ED25519_B)
        );
        assert_eq!(
            evaluate(&file, "buildbox", &ed(ED25519_B)),
            HostKeyVerdict::Trusted
        );
    }

    #[test]
    fn a_revoked_key_is_rejected_even_when_an_earlier_line_trusts_it() {
        // Ordering must not matter here: accepting first and checking revocation later is how a
        // revoked key gets used.
        let file = format!(
            "{}{}",
            known_hosts_line("buildbox", 22, "ssh-ed25519", ED25519_A),
            format_args!("@revoked buildbox ssh-ed25519 {ED25519_A}\n")
        );
        let verdict = evaluate(&file, "buildbox", &ed(ED25519_A));
        assert!(
            matches!(verdict, HostKeyVerdict::Revoked { .. }),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_revoked_key_for_a_different_key_is_not_a_revocation() {
        let file = format!("@revoked buildbox ssh-ed25519 {ED25519_A}\n");
        let verdict = evaluate(&file, "buildbox", &ed(ED25519_B));
        assert_eq!(verdict, HostKeyVerdict::Unknown);
    }

    #[test]
    fn a_cert_authority_line_never_reads_as_trust() {
        let file = format!("@cert-authority *.example.com ssh-rsa {RSA_A}\n");
        assert_eq!(
            evaluate(&file, "buildbox.example.com", &rsa(RSA_A)),
            HostKeyVerdict::Unknown
        );
    }

    #[test]
    fn a_hashed_host_field_matches() {
        // The exact pair `ssh` writes for example.com with HashKnownHosts: salt and HMAC-SHA1.
        let file = format!(
            "|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 {ED25519_B}\n"
        );
        let verdict = evaluate(&file, "example.com", &ed(ED25519_B));
        assert_eq!(verdict, HostKeyVerdict::Trusted);
    }

    #[test]
    fn a_hashed_host_field_for_another_host_does_not_match() {
        let file = format!(
            "|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 {ED25519_B}\n"
        );
        // Without this the fix would be worse than the bug: a hashed file would look empty, a
        // changed key would read as a first connection, and trust-on-first-use would re-pin it.
        assert_eq!(
            evaluate(&file, "elsewhere.example", &ed(ED25519_B)),
            HostKeyVerdict::Unknown
        );
    }

    #[test]
    fn a_hashed_field_is_produced_the_way_ssh_produces_it() {
        // Proves the fixture above is a real hashed entry and not a coincidence of this parser.
        let salt = base64::engine::general_purpose::STANDARD
            .decode("O33ESRMWPVkMYIwJ1Uw+n877jTo=")
            .unwrap();
        let mut mac = Hmac::<Sha1>::new_from_slice(&salt).unwrap();
        mac.update(b"example.com");
        let digest = mac.finalize().into_bytes();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(digest),
            "nuuC5vEqXlEZ/8BXQR7m619W6Ak="
        );
    }

    #[test]
    fn a_port_other_than_22_uses_the_bracketed_form() {
        let file = known_hosts_line("buildbox", 2222, "ssh-ed25519", ED25519_A);
        assert!(file.starts_with("[buildbox]:2222 "), "{file}");
        assert_eq!(
            evaluate(&file, "[buildbox]:2222", &ed(ED25519_A)),
            HostKeyVerdict::Trusted
        );
        // The bare form must not match the same host on a different port: that would pin an
        // unrelated service on the same box.
        assert_eq!(
            evaluate(&file, "buildbox", &ed(ED25519_A)),
            HostKeyVerdict::Unknown
        );
    }

    #[test]
    fn a_comma_separated_host_list_matches_every_member() {
        let file = format!("buildbox,10.0.0.5 ssh-ed25519 {ED25519_A}\n");
        assert_eq!(
            evaluate(&file, "10.0.0.5", &ed(ED25519_A)),
            HostKeyVerdict::Trusted
        );
        assert_eq!(
            evaluate(&file, "otherbox", &ed(ED25519_A)),
            HostKeyVerdict::Unknown
        );
    }

    #[test]
    fn a_glob_matches_and_a_negation_overrides_it() {
        let file = format!("*.example.com ssh-ed25519 {ED25519_A}\n");
        assert_eq!(
            evaluate(&file, "host7.example.com", &ed(ED25519_A)),
            HostKeyVerdict::Trusted
        );
        assert_eq!(
            evaluate(&file, "host7.example.net", &ed(ED25519_A)),
            HostKeyVerdict::Unknown
        );

        let negated = format!("!bad.example.com,*.example.com ssh-ed25519 {ED25519_A}\n");
        assert_eq!(
            evaluate(&negated, "bad.example.com", &ed(ED25519_A)),
            HostKeyVerdict::Unknown,
            "an explicit negation is not a softer form of trust"
        );
        assert_eq!(
            evaluate(&negated, "good.example.com", &ed(ED25519_A)),
            HostKeyVerdict::Trusted
        );
    }

    #[test]
    fn comments_blanks_and_malformed_lines_are_skipped_not_fatal() {
        let file = format!(
            "# a comment\n\nnot-a-known-host-line\n<<<<<<< HEAD\ngarbage with fields but no key\n{}",
            known_hosts_line("buildbox", 22, "ssh-ed25519", ED25519_A)
        );
        assert_eq!(
            evaluate(&file, "buildbox", &ed(ED25519_A)),
            HostKeyVerdict::Trusted
        );
    }

    #[test]
    fn a_line_whose_key_does_not_parse_does_not_read_as_a_change() {
        // Pinning nothing must not manufacture a man-in-the-middle warning.
        let file = "buildbox ssh-ed25519 !!!not base64!!!\n";
        assert_eq!(
            evaluate(file, "buildbox", &ed(ED25519_A)),
            HostKeyVerdict::Unknown
        );
    }

    #[test]
    fn an_empty_file_is_a_first_use() {
        assert_eq!(
            evaluate("", "buildbox", &ed(ED25519_A)),
            HostKeyVerdict::Unknown
        );
    }

    #[test]
    fn recording_then_looking_up_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownHosts::at(dir.path().join("known_hosts"));
        let key = ed(ED25519_A);

        assert_eq!(
            store.lookup("buildbox", 22, &key).unwrap(),
            HostKeyVerdict::Unknown,
            "a missing file is a first use, not an error"
        );

        store.record("buildbox", 22, &key).unwrap();
        assert_eq!(
            store.lookup("buildbox", 22, &key).unwrap(),
            HostKeyVerdict::Trusted
        );

        let contents = fs::read_to_string(store.path()).unwrap();
        assert!(contents.starts_with("buildbox ssh-ed25519 "), "{contents}");
        assert!(contents.ends_with('\n'), "{contents}");
    }

    #[test]
    fn recording_keeps_the_file_readable_by_ssh() {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownHosts::at(dir.path().join("nested").join(".ssh/known_hosts"));

        store.record("buildbox", 2222, &ed(ED25519_A)).unwrap();
        store.record("otherbox", 22, &rsa(RSA_A)).unwrap();

        let contents = fs::read_to_string(store.path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "{contents}");
        assert!(
            lines[0].starts_with("[buildbox]:2222 ssh-ed25519 "),
            "{contents}"
        );
        assert!(lines[1].starts_with("otherbox ssh-rsa "), "{contents}");

        // Both are re-read as trusted, which is the only proof the file is still a known_hosts.
        assert_eq!(
            store.lookup("buildbox", 2222, &ed(ED25519_A)).unwrap(),
            HostKeyVerdict::Trusted
        );
        assert_eq!(
            store.lookup("otherbox", 22, &rsa(RSA_A)).unwrap(),
            HostKeyVerdict::Trusted
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_new_store_is_created_private_and_a_loose_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let store = KnownHosts::at(&path);
        store.record("buildbox", 22, &ed(ED25519_A)).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "a trust store another user can edit");

        // A file another local user can write is not a trust store: appending to it would let
        // them substitute a key that this code would then treat as pinned.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let err = store.record("otherbox", 22, &rsa(RSA_A)).unwrap_err();
        assert!(err.to_string().contains("writable by other users"), "{err}");
    }

    #[test]
    fn recording_appends_rather_than_replacing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let store = KnownHosts::at(&path);

        store.record("one", 22, &ed(ED25519_A)).unwrap();
        let first = fs::read_to_string(&path).unwrap();
        store.record("two", 22, &ed(ED25519_B)).unwrap();

        let second = fs::read_to_string(&path).unwrap();
        assert!(second.starts_with(&first), "the first entry must survive");
        assert_eq!(second.lines().count(), 2);
    }

    #[test]
    fn recording_repairs_a_file_with_no_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        // A file that ends mid-line is what an interrupted write leaves behind; appending
        // blindly would fuse two entries into one unusable line.
        fs::write(&path, format!("buildbox ssh-ed25519 {ED25519_A}")).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();

        let store = KnownHosts::at(&path);
        store.record("otherbox", 22, &ed(ED25519_B)).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2, "{contents}");
        assert_eq!(
            store.lookup("buildbox", 22, &ed(ED25519_A)).unwrap(),
            HostKeyVerdict::Trusted
        );
        assert_eq!(
            store.lookup("otherbox", 22, &ed(ED25519_B)).unwrap(),
            HostKeyVerdict::Trusted
        );
    }

    #[test]
    fn the_default_store_lives_under_dot_ssh() {
        let path = known_hosts_under(Path::new("/home/someone"));
        assert_eq!(path, PathBuf::from("/home/someone/.ssh/known_hosts"));
    }

    #[test]
    fn glob_matching_handles_backtracking() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("host?", "host7"));
        assert!(!glob_match("host?", "host77"));
        assert!(glob_match("*.example.com", "a.b.example.com"));
        assert!(!glob_match("*.example.com", "a.b.example.net"));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("a*b*c", "aXbYd"));
        assert!(
            glob_match("[literal", "[literal"),
            "only * and ? are special"
        );
    }
}
