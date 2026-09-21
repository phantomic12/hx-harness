//! The generic webhook connector — the other half of M5.
//!
//! Telegram is a **pull** connector: the harness polls `getUpdates`, so the connector owns the loop
//! and the harness calls [`receive`]. A generic webhook is a **push** connector: a remote chat
//! platform `POST`s inbound events to the daemon's HTTP surface, and the connector is a channel *from*
//! that route to the harness. This module is that channel.
//!
//! The shape is deliberately tiny because the trait says it must be. [`WebhookConnector`] holds a
//! [`ConnectorId`], an optional `outbound_url`, and a `tokio::sync::mpsc` receiver that the
//! webhook route fills. It implements [`Connector`] by:
//!
//! - [`receive`] — await one message off the channel. It returns `Ok(None)` when the channel is
//!   closed (nobody can push any more), and each inbound event is an `Inbound` the route parsed.
//!   Because a webhook is push-driven, this is the *caller* of the driver, not the poller: the
//!   routing of a real HTTP request into this connector is the `POST` handler in `hx-server`.
//! - [`deliver`] / [`ask`] — `POST` the outbound body to `outbound_url`, or **fail closed** if
//!   none is configured. A webhook-only channel may not support replies, and dropping output silently would
//!   mean a user asked a question and got nothing — an error is the honest report.
//!
//! ## Untrusted input
//!
//! Everything that arrives on the channel is **data, never instruction**. A webhook is the most exposed of
//! the integration surfaces — a remote platform, authenticated only by a bearer token — so the route must
//! verify the token and parse strictly, and this connector must hand what it gets up as `Inbound` without
//! ever acting on it. The [`parse`] function in this module is the mapping, pure and tested.
//!
//! [`receive`]: crate::Connector::receive

use crate::answer::AnswerVerdict;
use crate::connector::Connector;
use crate::types::{ApprovalTask, ChatId, Conversation, Inbound, Platform, Target, ThreadId};
use hx_core::error::{HxError, Result};
use hx_core::ids::ConnectorId;
use hx_secrets::Secret;
use serde::Deserialize;

/// The `kind` a webhook connector reports in a [`Platform`]. A generic webhook's events are all
/// attributed to the same platform name, exactly as a chat platform's are to its own name — the session
/// router keys on this, so two webhook connectors behind the same id share one set of conversations.
pub fn platform() -> Platform {
    Platform("webhook".into())
}

/// The small envelope a webhook `POST` must carry.
///
/// This is the *generic* contract: a platform pushes a message, naming where it came from. It is kept
/// JSON-shaped and minimal because it is the boundary a third-party platform implements — a platform that wants
/// `text`, `chat` and `thread` more naturally already fits here, and a platform that needs more than a text
/// message is not this connector's business.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookEnvelope {
    /// The chat this message belongs to — the conversation id in the remote platform's terms.
    pub chat: String,
    /// The thread within that chat; the empty string is the single conversation of a non-threaded one.
    #[serde(default)]
    pub thread: Option<String>,
    /// The message text. **Data, never instruction** — nothing here interprets it.
    pub text: String,
}

/// Parse a verified envelope into an [`Inbound::Message`].
///
/// The `thread` is `None`-collapsed to the empty [`ThreadId`], the same flattening Telegram's
/// connector applies to a chat without a thread, so one webhook chat is one conversation on every platform.
pub fn parse(envelope: WebhookEnvelope, id: &ConnectorId) -> Inbound {
    Inbound::Message {
        conversation: Conversation {
            // The connector's id is its platform name for the purposes of a conversation, so the same
            // remote platform pushed to two different connector ids lands in two different session spaces.
            platform: Platform(id.to_string().replace("con_", "webhook:")),
            chat: ChatId(envelope.chat),
            thread: ThreadId(envelope.thread.unwrap_or_default()),
        },
        text: envelope.text,
    }
}

/// The JSON body of an outbound `POST` to `outbound_url`.
fn outbound_body(conversation: &Conversation, text: &str) -> serde_json::Value {
    serde_json::json!({
        "chat": conversation.chat.as_str(),
        "thread": conversation.thread.as_str(),
        "text": text,
    })
}

/// The generic webhook connector.
///
/// The receiver is the *only* thing that feeds [`receive`]; the webhook route in `hx-server` holds
/// the sender end. This connector never talks to the platform to gather input — it is driven entirely by the
/// route pushing what it parsed.
pub struct WebhookConnector {
    id: ConnectorId,
    outbound_url: Option<String>,
    client: reqwest::Client,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Inbound>>,
}

impl WebhookConnector {
    /// Build a connector bound to `rx`. The route is given the matching sender from the returned pair.
    pub fn new(
        id: ConnectorId,
        outbound_url: Option<String>,
        client: reqwest::Client,
        rx: tokio::sync::mpsc::UnboundedReceiver<Inbound>,
    ) -> Self {
        Self {
            id,
            outbound_url,
            client,
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    fn unreachable(&self, err: reqwest::Error) -> HxError {
        // The outbound URL may carry a credential; the same discipline as Telegram's connector, which
        // formats transport errors through `without_url()` so a URL that names a secret never reaches a log
        // line, an error message, or — because a failed `ask` denies a run with its reason — a transcript.
        HxError::Connector {
            connector: self.id.to_string(),
            reason: format!("could not reach the webhook outbound endpoint: {}", err.without_url()),
        }
    }

    async fn post_outbound(&self, key: &Secret, conversation: &Conversation, text: &str) -> Result<()> {
        let Some(url) = self.outbound_url.as_deref() else {
            // Fail closed: a webhook-only channel with no outbound endpoint cannot reply, and dropping the
            // output would be a silent loss. An error is the honest report.
            return Err(HxError::Connector {
                connector: self.id.to_string(),
                reason: "no outbound_url is configured, so this webhook channel cannot deliver a reply".into(),
            });
        };

        let body = outbound_body(conversation, text);
        let response = self
            .client
            .post(url)
            .bearer_auth(key.expose())
            .json(&body)
            .send()
            .await
            .map_err(|err| self.unreachable(err))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|err| format!("<unreadable body: {}>", err.without_url()));
        if !status.is_success() {
            return Err(HxError::Connector {
                connector: self.id.to_string(),
                reason: format!("webhook outbound POST returned {status}: {text}"),
            });
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Connector for WebhookConnector {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    fn platform(&self) -> Platform {
        platform()
    }

    async fn receive(&self, _key: &Secret) -> Result<Option<Inbound>> {
        // A webhook connector is push-driven: it yields exactly what the route pushed. `None` when the
        // channel is closed means no more pushes can ever arrive, which is how the receive loop knows to stop
        // rather than poll forever.
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(inbound) => Ok(Some(inbound)),
            None => Ok(None),
        }
    }

    async fn deliver(&self, key: &Secret, to: &Target, text: &str) -> Result<()> {
        let conversation = match to {
            Target::Conversation(c) => c,
            Target::Home => {
                return Err(HxError::Connector {
                    connector: self.id.to_string(),
                    reason: "a webhook can only deliver to an explicit conversation".into(),
                })
            }
        };
        self.post_outbound(key, conversation, text).await
    }

    async fn ask(&self, key: &Secret, to: &Target, task: &ApprovalTask) -> Result<AnswerVerdict> {
        let conversation = match to {
            Target::Conversation(c) => c,
            Target::Home => {
                return Err(HxError::Connector {
                    connector: self.id.to_string(),
                    reason: "approvals can only be asked in an explicit conversation".into(),
                })
            }
        };
        self.post_outbound(key, conversation, &task.request.render()).await?;
        // The prompt was posted; the answer arrives later through `receive` (pushed by the platform) and
        // is joined to the waiting run by `crate::bridge`. Returning `NoAnswer` here is the honest report of
        // what this call did — it asked, and nobody has answered yet.
        Ok(AnswerVerdict::NoAnswer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_envelope_without_a_thread_is_the_single_conversation() {
        let envelope = WebhookEnvelope {
            chat: "777".into(),
            thread: None,
            text: "hello".into(),
        };
        let inbound = parse(envelope, &ConnectorId::from("con_main-web"));
        match inbound {
            Inbound::Message { conversation, text } => {
                // The connector's id (a `con_` id) becomes `webhook:<name>` as its platform, and
                // the same remote platform pushed to two ids lands in two different session spaces.
                assert_eq!(conversation.platform.as_str(), "webhook:main-web");
                assert_eq!(conversation.chat.as_str(), "777");
                assert_eq!(conversation.thread.as_str(), "");
                assert_eq!(text, "hello");
            }
            other => panic!("expected a message, got {other:?}"),
        }
    }

    #[test]
    fn an_envelope_with_a_thread_keeps_it() {
        let envelope = WebhookEnvelope {
            chat: "9".into(),
            thread: Some("42".into()),
            text: "hi".into(),
        };
        let inbound = parse(envelope, &ConnectorId::from("con_main-web"));
        match inbound {
            Inbound::Message { conversation, .. } => assert_eq!(conversation.thread.as_str(), "42"),
            other => panic!("expected a message, got {other:?}"),
        }
    }

    #[test]
    fn the_thread_is_dropped_from_an_outbound_body_when_there_is_none() {
        let body = outbound_body(
            &Conversation {
                platform: Platform("webhook".into()),
                chat: ChatId("5".into()),
                thread: ThreadId(String::new()),
            },
            "hi",
        );
        assert_eq!(body["chat"], "5");
        assert_eq!(body["thread"], "");
        assert_eq!(body["text"], "hi");
    }

    #[test]
    fn a_receive_from_a_closed_channel_is_none_not_an_error() {
        // No route is holding the sender: the channel is closed, which means no more pushes can ever arrive.
        // The loop must stop, so that is `None`, not a failure.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        drop(tx);
        let con = WebhookConnector::new(
            ConnectorId::from("main-web"),
            None,
            reqwest::Client::new(),
            rx,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let received = rt.block_on(con.receive(&Secret::new(""))).unwrap();
        assert!(received.is_none());
    }
}
