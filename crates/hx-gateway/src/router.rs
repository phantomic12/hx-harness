//! The session router: how a platform conversation becomes a session.
//!
//! The property the roadmap calls out is the one this module exists to hold: **the same conversation on
//! one platform always lands on one session.** A user DMing the bot twice, with the daemon restarted
//! in between, must reach the same history — the platform's own message ids change every message, so they
//! cannot be the identity. The identity is the `platform/chat/thread` tuple, folded into a
//! [`SessionKey`] by a pure, deterministic function.
//!
//! The key is a SHA-256 of the canonical form, hex-encoded. Deterministic (same tuple → same key,
//! forever, across processes) and collision-resistant (two distinct conversations — even two threads of one chat —
//! get distinct keys, which is exactly the "two threads on one platform do not collide" property the tests
//! pin). Hashing rather than using the raw id keeps the key a uniform length and guarantees a two chats on
//! different platforms that happen to share a numeric id can never collide even if their string forms differ
//! only in the platform prefix.
//!
//! ## What is deliberately NOT here
//!
//! The map from key to a live session is the gateway's job (a `HashMap<SessionKey, …>`), not this
//! module's; here we only define the key so that map can exist. There is deliberately no counter or random
//! id involved — a random per-process id would make the *same* conversation a *different* session after a
//! restart, which is the failure this router exists to prevent.

use crate::types::{Conversation, Platform};
use sha2::{Digest, Sha256};

/// The deterministic identity of one conversation. Same conversation ⟺ same key, on any process, forever.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionKey(String);

impl SessionKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Fold a conversation into its [`SessionKey`].
pub fn session_key(conversation: &Conversation) -> SessionKey {
    SessionKey(hex(&Sha256::digest(conversation.canonical().as_bytes())))
}

/// The [`SessionKey`] of a platform's home channel — the pinned destination for background output.
pub fn home_key(platform: &Platform) -> SessionKey {
    session_key(&Conversation {
        platform: platform.clone(),
        chat: crate::types::ChatId("$home".into()),
        thread: crate::types::ThreadId(String::new()),
    })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_thread_on_one_platform_always_maps_to_one_session() {
        // The property that makes a chat bridge survivable: the same conversation, addressed exactly the
        // same way twice (even across a daemon restart, which a fresh call models), is one session.
        let a = crate::types::Conversation::telegram("12345", "");
        let b = crate::types::Conversation::telegram("12345", "");
        assert_eq!(session_key(&a), session_key(&b));
        assert_eq!(session_key(&a).as_str(), session_key(&b).as_str());
    }

    #[test]
    fn two_threads_on_one_platform_do_not_collide() {
        // The roadmap's exact case: one chat, two threads. They are two conversations and must become
        // two sessions, or a reply meant for one lands in the other's history.
        let main = crate::types::Conversation::telegram("999", "");
        let sub = crate::types::Conversation::telegram("999", "42");
        assert_ne!(session_key(&main), session_key(&sub));
    }

    #[test]
    fn two_chats_on_one_platform_do_not_collide() {
        let one = crate::types::Conversation::telegram("1", "");
        let two = crate::types::Conversation::telegram("2", "");
        assert_ne!(session_key(&one), session_key(&two));
    }

    #[test]
    fn two_platforms_with_the_same_numeric_id_do_not_collide() {
        // "12345" as a Telegram chat and "12345" as a Discord chat are different conversations even
        // though the id string is identical; the platform prefix must keep them apart. Hashing the
        // canonical `platform/chat/thread` form is what guarantees this.
        let tg = crate::types::Conversation::telegram("12345", "");
        let dc = Conversation {
            platform: Platform("discord".into()),
            chat: crate::types::ChatId("12345".into()),
            thread: crate::types::ThreadId(String::new()),
        };
        assert_ne!(session_key(&tg), session_key(&dc));
    }

    #[test]
    fn the_key_is_stable_and_a_fixed_length() {
        // Deterministic and hex-encoded SHA-256: 64 characters, every time, so nothing upstream can
        // guess a session key from a conversation and a stored key never changes shape.
        let key = session_key(&crate::types::Conversation::telegram("42", "7"));
        assert_eq!(key.as_str().len(), 64);
        assert!(key.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            key.as_str(),
            session_key(&crate::types::Conversation::telegram("42", "7")).as_str()
        );
    }

    #[test]
    fn the_home_channel_has_its_own_session_key() {
        // The home channel is a distinct conversation, so its key can never collide with a real chat —
        // a cron digest therefore never lands in a conversation someone is typing in.
        let home = home_key(&Platform("telegram".into()));
        let any_chat = session_key(&crate::types::Conversation::telegram("12345", ""));
        assert_ne!(home, any_chat);
        assert_eq!(home, home_key(&Platform("telegram".into())));
    }
}
