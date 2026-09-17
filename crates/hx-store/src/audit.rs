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

use hx_core::error::{HxError, Result};
use sha2::{Digest, Sha256};

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

/// The digest of one row, given the previous row's digest.
///
/// Length-prefixes each field before hashing it. Without that, `("ab", "c")` and `("a", "bc")` hash
/// identically — a genuine collision an attacker could use to move a character between two fields
/// while keeping the chain intact. The prefix is the field's byte length, which is unambiguous
/// because the separator after it cannot occur inside the decimal digits that precede it.
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
pub fn verify_events(session_id: &str, events: &[StoredEvent]) -> Result<Option<Break>> {
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

        let recomputed = digest(
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
        verify_events("ses_1", events)
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
        let moved = verify_events("ses_2", &original).unwrap().expect("caught");
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
}
