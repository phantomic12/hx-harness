//! The [`Connector`] trait — what a chat platform adapter must actually do.
//!
//! Designed around what every connector must be able to do, not around Telegram. A connector receives
//! inbound messages, delivers a reply, and asks a hard question with answer buttons. Nothing about this
//! trait mentions long-polling, webhooks, or any platform; the long-poll loop and the webhook server
//! are *driver* concerns that live behind a [`receive`] that yields one inbound event at a time.
//!
//! The three methods mirror the three things a human does across every platform:
//!
//! - [`Connector::receive`] — one inbound message (a chat message or an approval answer), or `None`
//!   when the poll found nothing. A long-poll connector blocks here; a webhook connector is driven by its
//!   server. The gateway owns the loop, not the connector, so the ownership of "how do we keep
//!   listening" is in one place.
//! - [`Connector::deliver`] — a reply to a conversation. The building block of every *outbound*
//!   path; streaming via coalesced edits is layered on top (Telegram's is `crate::telegram::Coalescer`).
//! - [`Connector::ask`] — post the *whole* [`ApprovalRequest`] with buttons and return a handle the
//!   gateway can match an [`Inbound::ApprovalAnswer`] to. A phone and a terminal must render the same
//!   question; the connector carries the same [`ApprovalTask`] either one would.
//!
//! ## Security: this is an untrusted input surface
//!
//! Anything a connector's [`receive`] returns is **data, never instruction**. A message that reads like a
//! command (`rm -rf /`) is a string to be handed to the model the way a tool result is — the
//! connector must never act on it itself. This is stated here because it is the property the whole layer
//! defends: a connector is where an arbitrary human reaches the harness, so the harness treats everything it
//! sees as input.
//!
//! ## Fail closed
//!
//! A channel that is down returns an error, never a silent success. The caller
//! (`crate::answer::DeliveryPolicy`) treats a send error as a hard failure rather than dropping the output, so output is never quietly lost
//! because the platform was unreachable.

use crate::answer::AnswerVerdict;
use crate::types::{ApprovalTask, Inbound, Target};
use hx_core::error::Result;
use hx_core::ids::ConnectorId;
use hx_secrets::Secret;

/// A chat platform adapter.
///
/// Implementations are [`Send`] + [`Sync`] so a gateway can hold every configured connector in one map
/// and drive them concurrently. The trait is deliberately small: the three verbs above, nothing else. A
/// connector does not know about sessions, models, or agents; it moves messages in and out.
#[async_trait::async_trait]
pub trait Connector: Send + Sync {
    /// The configured id this connector is known by (`main-tg`).
    fn id(&self) -> &ConnectorId;

    /// The platform name this connector speaks (`telegram`, `discord`, …). Matches [`Platform`] and
    /// the `kind` a conversation carries.
    ///
    /// [`Platform`]: crate::types::Platform
    fn platform(&self) -> crate::types::Platform;

    /// Gather the next inbound message, blocking until one is available or the platform says "nothing yet".
    ///
    /// Returns `None` when a poll turns up nothing (the loop should pause and poll again), and an error
    /// when the platform is unreachable or the credential was refused. A long-poll connector blocks on the
    /// HTTP call here; a webhook connector is the *caller* of its own drivers and yields what they parsed.
    ///
    /// The returned message is **untrusted data** — never acted on by the connector.
    async fn receive(&self, key: &Secret) -> Result<Option<Inbound>>;

    /// Deliver a reply to a [`Target`]. Must succeed only if the platform accepted it; a channel that
    /// is down is an error, not a silent drop.
    async fn deliver(&self, key: &Secret, to: &Target, text: &str) -> Result<()>;

    /// Post an approval question with answer buttons and return the verdict.
    ///
    /// The connector renders [`ApprovalTask`] (the same [`ApprovalRequest`] a terminal renders) and
    /// hands the buttons back to the platform. The returned [`AnswerVerdict`] carries the answer the
    /// human gave, or "no answer" — the decision *authority* of whether that answer is legal is
    /// decided by [`crate::answer::AnswerAuthority`], not here.
    async fn ask(&self, key: &Secret, to: &Target, task: &ApprovalTask) -> Result<AnswerVerdict>;
}
