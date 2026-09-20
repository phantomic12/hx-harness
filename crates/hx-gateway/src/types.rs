//! The shared vocabulary of a connector: what a platform conversation is, what a message is,
//! and what a delivery target is.
//!
//! None of this is Telegram-specific. A `platform` is just a name; a `chat` and `thread` are
//! opaque platform ids that only make sense to that platform's connector. Defining them here — and not in
//! the connector — is what lets a second, third and seventh connector implement the same [`Connector`]
//! trait without inventing their own message shapes that the router then has to reconcile.
//!
//! [`Connector`]: crate::Connector
//!
//! ## Untrusted input
//!
//! A [`ChatId`], a [`ThreadId`] and an [`Inbound`] message all come from the platform, which is an
//! **untrusted input surface**. A human (or a bot, or a compromised account) can put anything in a
//! message. Nothing here interprets a message as an instruction; `text` is data to be treated exactly the
//! way a tool result is — fed to the model as data, never executed as a command. The values are kept as
//! opaque strings precisely so nobody upstream mistakes a platform id for a path or a command.

use hx_core::approval::{ApprovalRequest, RiskClass};
use serde::{Deserialize, Serialize};

/// A chat platform a connector speaks. The string is the connector's own name (`telegram`,
/// `discord`, …), so a new connector is just a new value — there is no central enum to grow.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Platform(pub String);

impl Platform {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Platform {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A chat on a platform — a DM, a group, a server channel. Opaque to every platform but its own.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChatId(pub String);

impl ChatId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ChatId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for ChatId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A thread within a chat. Many platforms have no threads at all; for those the empty string is the
/// single thread, which is what makes one chat on Telegram one conversation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ThreadId(pub String);

impl ThreadId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ThreadId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The empty thread — the single conversation of a platform that has no threading.
pub fn main_thread() -> ThreadId {
    ThreadId(String::new())
}

/// A specific conversation on a specific platform: `platform/chat/thread`.
///
/// This is what the session router keys on. Two messages that share a [`Conversation`] belong to the
/// same session, on any platform — the whole point of the router is that this tuple, not the platform's
/// own id, is the identity that outlives a client disconnect.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Conversation {
    pub platform: Platform,
    pub chat: ChatId,
    pub thread: ThreadId,
}

impl Conversation {
    /// The `/`-joined form used as the deterministic input to a [`SessionKey`].
    pub fn canonical(&self) -> String {
        format!("{}/{}/{}", self.platform, self.chat, self.thread)
    }

    pub fn telegram(chat_id: impl Into<String>, thread_id: impl Into<String>) -> Self {
        Self {
            platform: Platform("telegram".into()),
            chat: ChatId(chat_id.into()),
            thread: ThreadId(thread_id.into()),
        }
    }
}

impl std::fmt::Display for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.platform, self.chat)
    }
}

/// A target a connector can send to. Either a conversation (a live chat thread) or the configured
/// **home channel** (the pinned destination for background output such as a cron digest, so that output
/// never interleaves with a conversation the user is actually watching).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// A live conversation's own thread. A reply to a message goes here.
    Conversation(Conversation),
    /// The home channel, where background output goes so it does not interleave with chat.
    Home,
}

/// A message a connector has received from the platform.
///
/// This is **untrusted data**. The `text` is handed to a model the way a tool result is — read as
/// data, never executed and never treated as an instruction. A connector that received a message that looks
/// like a command must still deliver it to the gateway as data and let the *gateway* decide what it means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A chat message from a human in a conversation.
    Message {
        conversation: Conversation,
        text: String,
    },
    /// The answer a human gave to a previously posted approval prompt.
    ApprovalAnswer {
        conversation: Conversation,
        approval_id: String,
        /// The answer, already mapped to a legal choice (an [`ApprovalRequest`] option label).
        answer: String,
    },
}

/// What a connector must be able to deliver and ask. Kept as one concrete request rather than
/// free-form text because a chat bridge must render the *same* question a terminal does — the whole
/// [`ApprovalRequest`] — so a phone and a terminal cannot disagree about what was asked.
#[derive(Clone, Debug)]
pub struct ApprovalTask {
    pub request: ApprovalRequest,
    /// The strongest [`RiskClass`] this channel may authorise. A chat bridge is a weaker signal than
    /// a terminal: a phone tap must never approve a `Destructive` action. The ceiling is enforced by
    /// [`crate::answer::AnswerAuthority`] before any answer is honoured, never by the connector.
    pub ceiling: RiskClass,
}
