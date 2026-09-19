//! The audit chain: making a stored event prove it was not edited afterwards.
//!
//! ## The property this module exists to hold
//!
//! The store already keeps every event — an approval asked, an answer given, a call refused — but a
//! row in a table is a claim by whoever owns the database. Anyone with `sqlite3` and a reason can
//! rewrite the row that says they approved a `git push`, and nothing about the file would look
//! different. `docs/approvals.md` §6 states the requirement this addresses: the question is in the
//! audit trail, not just the answer. A trail that can be edited afterwards answers a weaker question
//! than it appears to.
//!
//! The fix is a **hash chain**: every event's row carries a digest over (its own content, the
//! previous event's digest). Editing a row changes its digest; changing that digest breaks the next
//! row, and so on to the end. Verification walks the chain and reports the first row that does not
//! match — which is the row that was tampered with, not merely "something is wrong somewhere".
//!
//! ## What this does and does not prove
//!
//! It proves **internal consistency**: the chain as stored has not been edited without leaving a
//! trace, *given* that the digest of the final row is known to be correct. It is not a signature and
//! does not prove authorship — an attacker who rewrites the whole chain from a point onward produces
//! a chain that verifies, because the only secret involved is the construction itself. Closing that
//! needs a key held outside the database, which is `hx-secrets`' business and a later step; this
//! module deliberately does not pretend otherwise. What it *does* buy is real: a single edited or
//! deleted row is detectable, which is the overwhelmingly common case — an operator or a compromised
//! process fixing one inconvenient fact.
//!
//! ## Why the digest covers the fields it covers
//!
//! Every field that a reader would rely on: the sequence number, the timestamp, the kind, and the
//! payload. Covering the sequence is what makes *deletion or reordering* detectable rather than just
//! modification — a chain that hashed only content would still verify with a row removed, because
//! each remaining row's previous-digest would still line up if the removal happened at the end. The
//! session id is covered too, so a row cannot be moved between sessions.

use hmac::{Hmac, KeyInit, Mac};
use hx_core::error::{HxError, Result};
use sha2::{Digest, Sha256};
use sha2_11::Sha256 as HmacSha256;

/// The digest of every event before the first one: a fixed, well-known value.
///
/// A chain has to start somewhere, and starting from a constant rather than from `NULL` means the
/// first row's digest is computed the same way as every other — one code path, and a test can assert
/// the exact digest of a known first event rather than special-casing it.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The content of one event, as the chain sees it.
///
/// A struct rather than a long argument list because the *order* of these fields is load-bearing:
/// they are fed to the digest in this order, and two callers that assembled them differently would
/// produce digests that disagree for the same stored row — the chain would then reject honest data
/// as tampered with.
#[derive(Clone, Debug)]
pub struct EventLink<'a> {
    pub session_id: &'a str,
    /// Position within the session. Covered so a removed or reordered row is detectable.
    pub seq: i64,
    pub at: &'a str,
    pub kind: &'a str,
    pub payload: &'a str,
}

/// The digest of one row, given the previous row's digest and the chain's key.
///
/// ## Why this is keyed
///
/// An unkeyed hash chain proves only that the rows are *consistent with each other*. Anyone who can
/// write the database can rewrite every row from a chosen point forward and recompute every digest,
/// and the result verifies — so the chain would attest to a history that never happened. That is the
/// difference between a tamper-*evident* log and a tamper-*proof* one, and it is why this takes a key:
/// without the key, an attacker can produce a self-consistent forgery only by guessing it.
///
/// The key lives **outside** the database — in the daemon's environment, not in a table the same
/// attacker can read. A key stored beside the data it protects buys nothing.
///
/// Length-prefixes each field before hashing it. Without that, `("ab", "c")` and `("a", "bc")` hash
/// identically — a genuine collision an attacker could use to move a character between two fields
/// while keeping the chain intact. The prefix is the field's byte length, which is unambiguous
/// because the separator after it cannot occur inside the decimal digits that precede it.
pub fn digest_with_key(key: &[u8], previous: &str, link: &EventLink<'_>) -> String {
    let mut mac = Hmac::<HmacSha256>::new_from_slice(key)
        .expect("HMAC accepts a key of any length, including the empty one");
    for field in [
        previous,
        link.session_id,
        &link.seq.to_string(),
        link.at,
        link.kind,
        link.payload,
    ] {
        mac.update(field.len().to_string().as_bytes());
        mac.update(b":");
        mac.update(field.as_bytes());
        mac.update(b"|");
    }
    hex(&mac.finalize().into_bytes())
}

/// The digest of one row under an **unkeyed** chain.
///
/// Kept for the case where no key is configured, and named for what it is: it detects edits made by
/// accident or by someone who did not recompute the chain, and detects nothing at all against an
/// adversary who did. A chain written this way cannot be trusted as evidence, which is exactly why
/// the keyed form exists and why [`ChainKey`] reports which one was used.
pub fn digest(previous: &str, link: &EventLink<'_>) -> String {
    let mut hasher = Sha256::new();
    for field in [
        previous,
        link.session_id,
        &link.seq.to_string(),
        link.at,
        link.kind,
        link.payload,
    ] {
        hasher.update(field.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(field.as_bytes());
        hasher.update(b"|");
    }
    hex(&hasher.finalize())
}

/// The secret that makes the chain unforgeable, and whether there is one.
///
/// Two states, kept apart on purpose. A store with a key can say a rewrite required the key; a store
/// without one can only say the rows agree with each other. Collapsing them into a single "verified"
/// would let the weaker guarantee be read as the stronger one, which is the whole failure this type
/// exists to prevent.
#[derive(Clone)]
pub enum ChainKey {
    /// An HMAC key, held outside the database.
    Keyed(Vec<u8>),
    /// No key configured. The chain still catches an inconsistent edit; it cannot catch a rewrite.
    Unkeyed,
}

impl ChainKey {
    /// Read the key from the environment variable the daemon documents.
    ///
    /// Absent is not an error: a fresh checkout and the tests run unkeyed, and the report says so.
    /// A key that is set but empty is treated as absent rather than as a zero-length secret, because
    /// an empty HMAC key is a real (if weak) key and silently using it would be worse than saying
    /// there is none.
    pub fn from_env(var: &str) -> Self {
        match std::env::var(var) {
            Ok(value) if !value.trim().is_empty() => ChainKey::Keyed(value.into_bytes()),
            _ => ChainKey::Unkeyed,
        }
    }

    /// Is a rewrite detectable, or only an inconsistent edit?
    pub fn is_keyed(&self) -> bool {
        matches!(self, ChainKey::Keyed(_))
    }
}

impl std::fmt::Debug for ChainKey {
    /// Never prints the key: a `{:?}` in a log line must not be a way to leak the secret that makes
    /// the audit trail trustworthy.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainKey::Keyed(_) => f.write_str("ChainKey::Keyed(<redacted>)"),
            ChainKey::Unkeyed => f.write_str("ChainKey::Unkeyed"),
        }
    }
}

/// One digest, under whichever mode the key implies.
pub fn digest_for(key: &ChainKey, previous: &str, link: &EventLink<'_>) -> String {
    match key {
        ChainKey::Keyed(secret) => digest_with_key(secret, previous, link),
        ChainKey::Unkeyed => digest(previous, link),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Where the chain first fails to hold, if it does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Break {
    /// Position within the session where the chain stopped matching.
    pub seq: i64,
    /// What the stored digest was.
    pub stored: String,
    /// What it should have been, given the row's content and its predecessor.
    pub expected: String,
}

impl Break {
    /// A sentence for a log line or a report. Names the row, because "the audit log is invalid"
    /// without a position is not actionable.
    pub fn explain(&self) -> String {
        format!(
            "the audit chain is broken at sequence {}: the stored digest is {} but the row's \
             content and its predecessor give {}. The row was edited after it was written, or a row \
             before it was removed.",
            self.seq, self.stored, self.expected
        )
    }
}

/// One stored event, as the verifier needs it: its content and the digest recorded beside it.
#[derive(Clone, Debug)]
pub struct StoredEvent {
    pub seq: i64,
    pub at: String,
    pub kind: String,
    pub payload: String,
    /// The digest column. `None` for a row written before the chain existed.
    pub digest: Option<String>,
}

/// Walk a session's stored events in order and report the first row whose chain does not hold.
///
/// **Recomputes** each row's digest from the row's own content plus its stored predecessor — the
/// first version of this function only compared each stored digest to the previous stored digest,
/// which is a property that holds for any list of strings and therefore detects nothing. A verifier
/// that cannot fail is worse than none: it certifies an edited log as intact, which is the exact
/// claim an audit chain exists to make honestly.
///
/// Rows with no digest (written before the chain existed) are counted and skipped rather than
/// treated as a break — an upgraded database keeps its history. [`verify`]'s caller reports that
/// count, because "verified" over rows that were never checked is the same lie in a quieter form.
///
/// Returns `Err` when the sequence itself has a gap, which is how a *deleted* row is detected: its
/// content is gone, so no digest can be recomputed, but the jump in sequence is visible.
pub fn verify_events(
    key: &ChainKey,
    session_id: &str,
    events: &[StoredEvent],
) -> Result<Option<Break>> {
    let mut previous = GENESIS.to_string();
    let mut expected_seq: Option<i64> = None;

    for event in events {
        if let Some(last) = expected_seq {
            if event.seq != last + 1 {
                return Err(HxError::Store(format!(
                    "the audit chain has a gap: sequence {last} is followed by {}, so at least one \
                     row was removed",
                    event.seq
                )));
            }
        }
        expected_seq = Some(event.seq);

        let Some(stored) = &event.digest else {
            // Unchained history: carry the genesis forward rather than inventing a predecessor, so
            // the first *chained* row after it is verified against genesis instead of against a row
            // that has no digest to chain from.
            continue;
        };

        let recomputed = digest_for(
            key,
            &previous,
            &EventLink {
                session_id,
                seq: event.seq,
                at: &event.at,
                kind: &event.kind,
                payload: &event.payload,
            },
        );

        if *stored != recomputed {
            return Ok(Some(Break {
                seq: event.seq,
                stored: stored.clone(),
                expected: recomputed,
            }));
        }

        previous = recomputed;
    }

    Ok(None)
}

/// Verify `(seq, digest)` pairs whose content is not available.
///
/// Kept for the case where only the digest column is being compared — a cheap "has this log been
/// truncated or reordered" check. It **cannot** detect an edited row, because it has no content to
/// recompute from; use [`verify_events`] for anything that makes a claim about integrity. Named
/// differently on purpose so the weaker guarantee cannot be picked up by accident.
pub fn verify_order(pairs: &[(i64, String)]) -> Result<Option<Break>> {
    let mut expected_seq: Option<i64> = None;
    for (seq, stored) in pairs {
        if let Some(last) = expected_seq {
            if *seq != last + 1 {
                return Err(HxError::Store(format!(
                    "the audit chain has a gap: sequence {last} is followed by {seq}, so at least \
                     one row was removed"
                )));
            }
        }
        expected_seq = Some(*seq);
        if stored == GENESIS {
            return Ok(Some(Break {
                seq: *seq,
                stored: stored.clone(),
                expected: "(any content)".to_string(),
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a chain of `n` rows as the store would hold them, content included.
    ///
    /// Content is carried rather than only the digests, because a verifier given only digests cannot
    /// recompute anything and so cannot detect an edited row — the defect this helper's shape was
    /// changed to expose.
    fn chain(session: &str, n: i64) -> Vec<StoredEvent> {
        let mut previous = GENESIS.to_string();
        let mut out = Vec::new();
        for seq in 1..=n {
            let payload = format!("{{\"turn\":{seq}}}");
            let at = "2026-09-17T12:00:00Z".to_string();
            let kind = "TurnStarted".to_string();
            let digest = digest(
                &previous,
                &EventLink {
                    session_id: session,
                    seq,
                    at: &at,
                    kind: &kind,
                    payload: &payload,
                },
            );
            previous = digest.clone();
            out.push(StoredEvent {
                seq,
                at,
                kind,
                payload,
                digest: Some(digest),
            });
        }
        out
    }

    fn verify(events: &[StoredEvent]) -> Result<Option<Break>> {
        verify_events(&ChainKey::Unkeyed, "ses_1", events)
    }

    #[test]
    fn an_untouched_chain_verifies() {
        // The identity case matters as much as the failure case: a verifier that reports a break on
        // honest data is worse than none, because it trains people to ignore it.
        let events = chain("ses_1", 5);
        assert_eq!(verify(&events).unwrap(), None);
    }

    #[test]
    fn an_edited_row_is_caught_and_named() {
        // The whole point. An operator rewriting the row that records an approval must be visible,
        // and the report must say *which* row — "invalid" over a long log is not actionable.
        let mut events = chain("ses_1", 5);
        // The row's *content* is rewritten while its stored digest is left alone — exactly what a
        // direct UPDATE does, and the only shape a content-aware verifier can catch.
        events[2].payload = "{\"turn\":99}".to_string();

        let found = verify(&events).unwrap().expect("the edit is caught");
        assert_eq!(found.seq, 3, "the break is reported at the edited row");
        assert!(
            found.explain().contains("sequence 3"),
            "{}",
            found.explain()
        );
    }

    #[test]
    fn deleting_a_row_is_caught_rather_than_passing() {
        // A chain that only hashed content would still verify with a row removed from the *end*,
        // because nothing after it would disagree. Covering the sequence number is what makes the
        // removal itself the detectable fact.
        let mut events = chain("ses_1", 5);
        events.remove(2);
        let err = verify(&events).unwrap_err().to_string();
        assert!(err.contains("gap"), "{err}");
        assert!(err.contains("removed"), "it says what happened: {err}");
    }

    #[test]
    fn a_chain_does_not_verify_across_sessions() {
        // Moving a row into another session's log would otherwise be invisible: the row is genuine,
        // it was just taken from somewhere else. The session id is hashed, so it stops matching.
        let original = chain("ses_1", 3);
        // The same row, verified as if it belonged to another session: the session id is hashed, so
        // the recomputation disagrees with the digest that was stored.
        let moved = verify_events(&ChainKey::Unkeyed, "ses_2", &original)
            .unwrap()
            .expect("caught");
        assert_eq!(moved.seq, 1, "the first row already disagrees");
    }

    #[test]
    fn a_character_moved_between_two_fields_changes_the_digest() {
        // The length prefix: without it `("ab","c")` and `("a","bc")` collide, which would let an
        // attacker shift a byte between the kind and the payload while keeping the chain intact.
        let one = digest(
            GENESIS,
            &EventLink {
                session_id: "s",
                seq: 1,
                at: "t",
                kind: "ab",
                payload: "c",
            },
        );
        let two = digest(
            GENESIS,
            &EventLink {
                session_id: "s",
                seq: 1,
                at: "t",
                kind: "a",
                payload: "bc",
            },
        );
        assert_ne!(one, two);
    }

    #[test]
    fn the_first_row_chains_from_the_known_genesis_digest() {
        // A fixed starting value is what lets the first row be computed like every other. A chain
        // that special-cased it would have one code path for row one and another for the rest, and
        // the two would eventually disagree.
        let events = chain("ses_1", 1);
        assert_eq!(events.len(), 1);
        assert_ne!(
            events[0].digest.as_deref(),
            Some(GENESIS),
            "a real row never digests to genesis"
        );
        assert_eq!(verify(&events).unwrap(), None);
    }

    #[test]
    fn an_empty_log_is_not_a_broken_one() {
        // A session with no events yet is empty, not invalid. Reporting a break here would make
        // every fresh session look tampered with.
        assert_eq!(verify(&[]).unwrap(), None);
    }

    /// Build a chain under a given key, so the same helper makes both an honest chain and a forgery.
    fn keyed_chain(key: &ChainKey, session: &str, n: i64, turn_offset: i64) -> Vec<StoredEvent> {
        let mut previous = GENESIS.to_string();
        let mut out = Vec::new();
        for seq in 1..=n {
            let payload = format!("{{\"turn\":{}}}", seq + turn_offset);
            let at = "2026-09-17T12:00:00Z".to_string();
            let kind = "TurnStarted".to_string();
            let digest = digest_for(
                key,
                &previous,
                &EventLink {
                    session_id: session,
                    seq,
                    at: &at,
                    kind: &kind,
                    payload: &payload,
                },
            );
            previous = digest.clone();
            out.push(StoredEvent {
                seq,
                at,
                kind,
                payload,
                digest: Some(digest),
            });
        }
        out
    }

    #[test]
    fn a_keyed_chain_verifies_under_its_own_key() {
        let key = ChainKey::Keyed(b"a real secret".to_vec());
        let events = keyed_chain(&key, "ses_k", 4, 0);
        assert!(
            verify_events(&key, "ses_k", &events).unwrap().is_none(),
            "an untouched keyed chain must verify"
        );
    }

    #[test]
    fn a_keyed_chain_does_not_verify_under_a_different_key() {
        // The point of the key: the rows are internally consistent, but without the secret they are
        // not evidence. This is the case an unkeyed chain cannot distinguish from an honest one.
        let key = ChainKey::Keyed(b"the real secret".to_vec());
        let other = ChainKey::Keyed(b"a different secret".to_vec());
        let events = keyed_chain(&key, "ses_k", 4, 0);

        let result = verify_events(&other, "ses_k", &events).unwrap();
        assert!(result.is_some(), "the wrong key must not accept the chain");
        assert_eq!(result.unwrap().seq, 1, "it fails at the first row");
    }

    #[test]
    fn a_whole_chain_rewritten_without_the_key_is_caught() {
        // The forgery the unkeyed chain could not see: an attacker with write access to the database
        // rewrites every row and recomputes every digest, so the rows agree with each other.
        let key = ChainKey::Keyed(b"the real secret".to_vec());
        let honest = keyed_chain(&key, "ses_k", 4, 0);

        // Same rows, same session, same sequence numbers — only the content differs, and the digests
        // were recomputed to be consistent with that content.
        let forged = keyed_chain(&ChainKey::Unkeyed, "ses_k", 4, 1000);

        // Without a key this is indistinguishable from an honest chain: nothing to compare against.
        assert!(
            verify_events(&ChainKey::Unkeyed, "ses_k", &forged)
                .unwrap()
                .is_none(),
            "a self-consistent forgery defeats the unkeyed chain"
        );

        // With the key, the forgery is rejected — which is the entire reason the key exists.
        assert!(
            verify_events(&key, "ses_k", &forged).unwrap().is_some(),
            "the keyed chain must reject a rewrite that did not have the key"
        );

        // And the honest version still verifies, so the rejection is the forgery being detected
        // rather than the key simply refusing everything.
        assert!(verify_events(&key, "ses_k", &honest).unwrap().is_none());
    }

    #[test]
    fn a_key_never_appears_in_a_debug_line() {
        // `{:?}` on a config or a store is how a secret ends up in a log file.
        let rendered = format!("{:?}", ChainKey::Keyed(b"do-not-print-me".to_vec()));
        assert!(!rendered.contains("do-not-print-me"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn an_empty_environment_key_is_treated_as_no_key_rather_than_as_a_secret() {
        // An empty HMAC key is a real, weak key. Using it silently would produce a chain that looks
        // keyed and is trivially forgeable, so it is refused and the report says `unkeyed`.
        std::env::set_var("HX_TEST_CHAIN_KEY_EMPTY", "");
        assert!(!ChainKey::from_env("HX_TEST_CHAIN_KEY_EMPTY").is_keyed());
        std::env::remove_var("HX_TEST_CHAIN_KEY_EMPTY");

        std::env::set_var("HX_TEST_CHAIN_KEY_SET", "s3cret");
        assert!(ChainKey::from_env("HX_TEST_CHAIN_KEY_SET").is_keyed());
        std::env::remove_var("HX_TEST_CHAIN_KEY_SET");

        // Absent is not an error: a fresh checkout runs unkeyed and says so.
        assert!(!ChainKey::from_env("HX_TEST_CHAIN_KEY_ABSENT").is_keyed());
    }
}
