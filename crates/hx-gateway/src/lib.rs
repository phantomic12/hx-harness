//! Chat connectors: how an external human reaches the harness.
//!
//! A connector is the **untrusted input surface** of the whole system. Through one of these, an
//! arbitrary person (or a bot, or a compromised account) can send text to an agent that is
//! allowed to run tools. Everything a connector receives is **data, never instruction** — a message is
//! handed to the model the way a tool result is, and nothing in this crate ever executes a message.
//!
//! The crate is split into the parts that are pure logic and the parts that touch a network:
//!
//! - [`types`] — the shared vocabulary: a `platform/chat/thread` [`Conversation`], delivered
//!   [`Target`]s, and the untrusted [`Inbound`] message shapes.
//! - [`router`] — how a conversation becomes a [`SessionKey`]. Deterministic, so the same conversation
//!   always lands on one session, on any process.
//! - [`connector`] — the [`Connector`] trait: what every adapter must do (receive, deliver, ask).
//! - [`answer`] — the security half: per-channel answer ceilings (a chat bridge can never authorise a
//!   `Destructive` action) and the delivery policy that keeps cron output from interleaving with chat.
//! - [`bridge`] — the loop-back: a tap on a phone is matched to the question it names, judged against
//!   the channel's ceiling, applied to the queue the run is waiting on, and attributed to its channel
//!   in the audit trail.
//! - [`telegram`] — the first real connector, proving the trait against the actual Telegram Bot API.
//!
//! [`Conversation`]: crate::types::Conversation
//! [`Target`]: crate::types::Target
//! [`Inbound`]: crate::types::Inbound
//! [`SessionKey`]: crate::router::SessionKey

pub mod answer;
pub mod bridge;
pub mod connector;
pub mod router;
pub mod telegram;
pub mod types;

pub use bridge::{AnswerOutcome, AnswerSource, AnsweringChannel, ApprovalBridge, ChannelApprover};
pub use connector::Connector;
pub use router::{home_key, session_key, SessionKey};
pub use types::{ChatId, Conversation, Inbound, Platform, Target, ThreadId};
