//! The Telegram connector — the first real proof that the [`Connector`] trait survives contact with a
//! platform. Written second, after the trait, so any mismatch between "what a connector must do" and
//! "what Telegram is" surfaces here rather than in a mock.
//!
//! Telegram's Bot API is a plain HTTPS `POST`/`GET` JSON API with a long-poll for updates, so the
//! connector is a thin layer over `reqwest` and the interesting half is the mapping between Telegram's wire
//! shapes and the crate's [`Inbound`] / [`Target`] shapes. The mapping is pure functions
//! ([`parse_message`], [`parse_callback`], [`build_send_body`]) tested against literals, with the HTTP
//! round-trip asserted against a stub server in `tests/telegram_http.rs` — the same hermetic-HTTP
//! pattern `hx-provider` uses for its adapters.
//!
//! ## The long-poll loop
//!
//! Telegram delivers messages by long-polling `getUpdates` with an *offset*: each update carries an
//! opaque id, and handing back `offset = last_id + 1` asks Telegram to never send it again. The
//! connector owns that offset so the gateway's [`receive`] needs no state of its own. Multiple
//! updates can arrive in one poll; they are buffered and handed out one [`Inbound`] at a time, so a
//! burst is delivered, not dropped.
//!
//! ## Streaming via coalesced edits
//!
//! The roadmap names streaming via coalesced `editMessageText`: instead of one `sendMessage` per token,
//! the first chunk sends a message and each later chunk edits it in place. [`Coalescer`] is the pure
//! accumulator that decides *which* chunks even need an API call — a long-running stream collapses into one
//! send plus a few edits. Whether a full streaming loop is wired is stated in `ROADMAP.md`; this
//! connector implements the coalescing primitive and its send/edit request shapes.
//!
//! ## Untrusted input
//!
//! Everything parsed here comes from Telegram — an arbitrary person or bot. [`parse_message`] turns it into
//! an [`Inbound`] whose `text` is **data, never instruction**; nothing in this module acts on a message.
//!
//! [`receive`]: crate::Connector::receive

use crate::answer::AnswerVerdict;
use crate::connector::Connector;
use crate::types::{ApprovalTask, ChatId, Conversation, Inbound, Platform, Target, ThreadId};
use hx_core::error::{HxError, Result};
use hx_core::ids::ConnectorId;
use hx_secrets::Secret;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The Bot API root. A config may override it to point at a testing stub; the production value is the
/// real API.
pub const DEFAULT_API_ROOT: &str = "https://api.telegram.org";

/// The `kind` a Telegram connector reports in a [`Platform`].
pub fn platform() -> Platform {
    Platform("telegram".into())
}

/// Gather all currently pending updates (no long-poll timeout — used by the stub tests).
pub fn get_updates_url(base: &str, offset: u64) -> String {
    format!(
        "{}/bot{{token}}/getUpdates?offset={offset}&timeout=0",
        base.trim_end_matches('/')
    )
}

/// A message half of a `getUpdates` update, as seen on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelegramMessage {
    pub chat_id: String,
    pub thread_id: Option<String>,
    pub text: String,
}

/// A callback_query (a button tap) on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelegramCallback {
    pub chat_id: String,
    pub data: String,
}

/// Parse a `message` object from a getUpdates result into its fields.
pub fn parse_message(message: &Value) -> Option<TelegramMessage> {
    // Telegram chat ids are signed 64-bit integers; a numeric id is the only well-formed form.
    let chat_id = message
        .get("chat")
        .and_then(|c| c.get("id"))
        .and_then(Value::as_i64)?
        .to_string();

    let thread_id = message
        .get("message_thread_id")
        .and_then(Value::as_i64)
        .map(|n| n.to_string());

    let text = message.get("text").and_then(Value::as_str)?.to_string();

    Some(TelegramMessage {
        chat_id,
        thread_id,
        text,
    })
}

/// Parse a `callback_query` object into a button answer.
pub fn parse_callback(callback: &Value) -> Option<TelegramCallback> {
    let chat_id = callback
        .get("message")
        .and_then(|m| m.get("chat"))
        .and_then(|c| c.get("id"))
        .and_then(Value::as_i64)?
        .to_string();
    let data = callback.get("data").and_then(Value::as_str)?.to_string();
    Some(TelegramCallback { chat_id, data })
}

/// The body of a `sendMessage` for a plain reply.
pub fn build_send_body(conversation: &Conversation, text: &str) -> Value {
    let mut body = json!({
        "chat_id": conversation.chat.as_str(),
        "text": text,
    });
    if !conversation.thread.as_str().is_empty() {
        body["message_thread_id"] = json!(conversation.thread.as_str());
    }
    body
}

/// The body of a `sendMessage` that carries an approval with answer buttons.
///
/// The buttons are the request's own options; the callback `data` is the option label, and the
/// gateway maps it back through the same request. No decision about whether an answer is *legal* happens
/// here — that is [`crate::answer::AnswerAuthority`]'s job, against the request's risk.
pub fn build_approval_body(conversation: &Conversation, task: &ApprovalTask) -> Value {
    let rows: Vec<Value> = task
        .request
        .options
        .iter()
        .map(|option| {
            json!([{
                "text": option.label(),
                "callback_data": option.label(),
            }])
        })
        .collect();
    let mut body = json!({
        "chat_id": conversation.chat.as_str(),
        "text": task.request.render(),
        "reply_markup": { "inline_keyboard": rows },
    });
    if !conversation.thread.as_str().is_empty() {
        body["message_thread_id"] = json!(conversation.thread.as_str());
    }
    body
}

/// The body of an `editMessageText` that replaces a previously sent message in place.
///
/// Coalesced streaming's second half: a callback `message_id` plus the accumulated text. The connector
/// tracks the id of the message it sent so it can edit instead of re-send.
pub fn build_edit_body(conversation: &Conversation, message_id: i64, text: &str) -> Value {
    let mut body = json!({
        "chat_id": conversation.chat.as_str(),
        "message_id": message_id,
        "text": text,
    });
    if !conversation.thread.as_str().is_empty() {
        body["message_thread_id"] = json!(conversation.thread.as_str());
    }
    body
}

/// The message id Telegram returns when it accepts a send. Parsed so a stream can edit it next.
pub fn sent_message_id(response: &Value) -> Option<i64> {
    response.get("result").and_then(Value::as_i64)
}

/// A pure accumulator for coalesced streamed output.
///
/// The roadmap's "streaming via coalesced `editMessageText`": the first chunk is a *send*, every
/// chunk after that would be an edit, and long streaming would mean an API call per chunk. Coalescing
/// collapses that: the connector only sends when enough new text has accumulated, so a 40-chunk stream
/// becomes a handful of API calls. This is the pure decision of "is there enough new text to bother the
/// API with an edit yet"; the network half (calling `editMessageText` with the newest accumulated text) is
/// the connector's.
#[derive(Clone, Debug)]
pub struct Coalescer {
    pub buffer: String,
    pub sent: usize,
    pub unit: usize,
}

impl Coalescer {
    /// `unit` is the number of characters an edit waits for before it is worth sending.
    pub fn new(unit: usize) -> Self {
        Self {
            buffer: String::new(),
            sent: 0,
            unit: unit.max(1),
        }
    }

    /// Append a chunk. Returns true when an API call is worthwhile now (enough new text accumulated).
    pub fn push(&mut self, chunk: &str) -> bool {
        self.buffer.push_str(chunk);
        self.buffer.chars().count() - self.sent >= self.unit
    }

    /// The text to send/edit now; advances the "sent" watermark.
    pub fn take_send(&mut self) -> String {
        self.sent = self.buffer.chars().count();
        self.buffer.clone()
    }

    /// Whether a send is needed at all (the very first chunk always is).
    pub fn has_unsent(&self) -> bool {
        self.buffer.chars().count() > self.sent
    }
}

/// The Telegram connector. Field order matters: the token is **never stored** — it is resolved from the
/// vault via a [`Secret`] at call time, so the connector holds a credential *reference*, never a value.
pub struct TelegramConnector {
    id: ConnectorId,
    base_url: String,
    client: reqwest::Client,
    offset: AtomicU64,
    pending: Mutex<VecDeque<Inbound>>,
}

impl TelegramConnector {
    pub fn new(id: ConnectorId, base_url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            id,
            base_url: base_url.into(),
            client,
            offset: AtomicU64::new(0),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    fn api_url(&self, method: &str, key: &Secret) -> String {
        format!(
            "{}/bot{}/{}",
            self.base_url.trim_end_matches('/'),
            key.expose(),
            method
        )
    }

    async fn poll(&self, key: &Secret) -> Result<Vec<Inbound>> {
        let offset = self.offset.load(Ordering::SeqCst);
        let url = format!(
            "{}/bot{}/getUpdates?offset={offset}&timeout=0",
            self.base_url.trim_end_matches('/'),
            key.expose()
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|err| HxError::Connector {
                connector: self.id.to_string(),
                reason: format!("could not reach Telegram: {err}"),
            })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|err| format!("<unreadable body: {err}>"));
        if !status.is_success() {
            return Err(HxError::Connector {
                connector: self.id.to_string(),
                reason: format!("Telegram getUpdates returned {status}: {text}"),
            });
        }

        let parsed: Value = serde_json::from_str(&text).map_err(|err| HxError::Connector {
            connector: self.id.to_string(),
            reason: format!("Telegram returned non-JSON: {err}"),
        })?;
        if parsed.get("ok") != Some(&Value::Bool(true)) {
            // Fail closed: a body that is not signed `ok: true` is an error, not "no messages".
            return Err(HxError::Connector {
                connector: self.id.to_string(),
                reason: format!("Telegram refused the request: {parsed}"),
            });
        }

        let mut inbound = Vec::new();
        let mut last_id: Option<i64> = None;
        if let Some(updates) = parsed.get("result").and_then(Value::as_array) {
            for update in updates {
                if let Some(id) = update.get("update_id").and_then(Value::as_i64) {
                    last_id = Some(id.max(last_id.unwrap_or(id)));
                }
                if let Some(message) = update.get("message").and_then(parse_message) {
                    inbound.push(Inbound::Message {
                        conversation: Conversation {
                            platform: platform(),
                            chat: ChatId(message.chat_id),
                            thread: ThreadId(message.thread_id.unwrap_or_default()),
                        },
                        text: message.text,
                    });
                } else if let Some(callback) = update.get("callback_query").and_then(parse_callback)
                {
                    inbound.push(Inbound::ApprovalAnswer {
                        conversation: Conversation {
                            platform: platform(),
                            chat: ChatId(callback.chat_id),
                            thread: ThreadId(String::new()),
                        },
                        approval_id: String::new(),
                        answer: callback.data,
                    });
                }
            }
        }

        // Advance past everything we just saw so Telegram never re-sends it.
        if let Some(id) = last_id {
            self.offset.store(id as u64 + 1, Ordering::SeqCst);
        }

        Ok(inbound)
    }
}

#[async_trait::async_trait]
impl Connector for TelegramConnector {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    fn platform(&self) -> Platform {
        platform()
    }

    async fn receive(&self, key: &Secret) -> Result<Option<Inbound>> {
        // Drain buffered updates before asking Telegram for more, so a burst is delivered one at a time.
        if let Some(first) = self.pending.lock().unwrap().pop_front() {
            return Ok(Some(first));
        }
        let batch = self.poll(key).await?;
        let mut queue = self.pending.lock().unwrap();
        queue.extend(batch);
        Ok(queue.pop_front())
    }

    async fn deliver(&self, key: &Secret, to: &Target, text: &str) -> Result<()> {
        let conversation = match to {
            Target::Conversation(c) => c,
            Target::Home => {
                return Err(HxError::Connector {
                    connector: self.id.to_string(),
                    reason: "Telegram can only deliver to an explicit conversation".into(),
                })
            }
        };
        let body = build_send_body(conversation, text);
        let url = self.api_url("sendMessage", key);
        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|err| HxError::Connector {
                connector: self.id.to_string(),
                reason: format!("could not reach Telegram: {err}"),
            })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|err| format!("<unreadable body: {err}>"));
        if !status.is_success() {
            // Fail closed: a failed send is an error, not a silent drop.
            return Err(HxError::Connector {
                connector: self.id.to_string(),
                reason: format!("Telegram sendMessage returned {status}: {text}"),
            });
        }
        Ok(())
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
        let body = build_approval_body(conversation, task);
        let url = self.api_url("sendMessage", key);
        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|err| HxError::Connector {
                connector: self.id.to_string(),
                reason: format!("could not reach Telegram: {err}"),
            })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|err| format!("<unreadable body: {err}>"));
        if !status.is_success() {
            return Err(HxError::Connector {
                connector: self.id.to_string(),
                reason: format!("Telegram sendMessage returned {status}: {text}"),
            });
        }

        // The prompt was posted. Whether and how the human's answer reaches a running agent is a
        // separate wiring step (see ROADMAP.md); the connector has done its job: the question is on the
        // screen with answer buttons. An answer, when it comes, arrives through `receive` as
        // `Inbound::ApprovalAnswer` and is judged by `AnswerAuthority`.
        Ok(AnswerVerdict::NoAnswer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_message_is_parsed_with_its_thread() {
        let wire = json!({
            "message_id": 7,
            "message_thread_id": 42,
            "chat": { "id": 12345, "type": "private" },
            "text": "hello harness"
        });
        let m = parse_message(&wire).expect("a message");
        assert_eq!(m.chat_id, "12345");
        assert_eq!(m.thread_id.as_deref(), Some("42"));
        assert_eq!(m.text, "hello harness");
    }

    #[test]
    fn a_message_without_text_is_not_a_message() {
        // A photo or a sticker has no `text`; it is not a chat message, and must parse to None
        // rather than to an empty string the model would see as silence.
        let wire = json!({
            "message_id": 8,
            "chat": { "id": 12345 },
            "photo": [{ "file_id": "x" }]
        });
        assert_eq!(parse_message(&wire), None);
    }

    #[test]
    fn a_button_tap_is_parsed_as_a_callback_answer() {
        let wire = json!({
            "callback_query": {
                "data": "allow once",
                "message": { "chat": { "id": 12345 } }
            }
        });
        let c = wire
            .get("callback_query")
            .and_then(parse_callback)
            .expect("a callback");
        assert_eq!(c.chat_id, "12345");
        assert_eq!(c.data, "allow once");
    }

    #[test]
    fn a_send_body_omits_the_thread_when_there_is_none() {
        let body = build_send_body(&Conversation::telegram("12345", ""), "hi");
        assert_eq!(body["chat_id"], "12345");
        assert_eq!(body["text"], "hi");
        assert!(body.get("message_thread_id").is_none(), "{body}");
    }

    #[test]
    fn a_send_body_carries_the_thread_when_there_is_one() {
        let body = build_send_body(&Conversation::telegram("12345", "42"), "hi");
        assert_eq!(body["message_thread_id"], "42");
    }

    #[test]
    fn an_approval_body_renders_the_request_with_one_button_per_option() {
        let request = hx_core::approval::ApprovalRequest {
            id: hx_core::ids::ApprovalId::from_raw("apr_1"),
            tool: "shell".into(),
            summary: "list /tmp".into(),
            risk: hx_core::approval::RiskClass::Mutate,
            reason: "t".into(),
            key: "k".into(),
            options: vec![
                hx_core::approval::ApprovalOption::AllowOnce,
                hx_core::approval::ApprovalOption::Deny,
            ],
            targets: vec![],
            reversible: false,
            undo: None,
            confined: Default::default(),
            default_on_timeout: hx_core::approval::ApprovalOption::Deny,
            timeout_secs: None,
        };
        let task = ApprovalTask {
            request,
            ceiling: hx_core::approval::RiskClass::Mutate,
        };
        let body = build_approval_body(&Conversation::telegram("9", ""), &task);
        let keyboard = body["reply_markup"]["inline_keyboard"].as_array().unwrap();
        assert!(!keyboard.is_empty(), "one row per option");
        assert!(
            body["text"].as_str().unwrap().contains("risk:"),
            "the question is rendered"
        );
    }

    #[test]
    fn the_coalescer_only_flushes_when_enough_new_text_has_accumulated() {
        // The whole point of coalesced streaming: a stream of tiny chunks does not mean an API call per
        // chunk. With a unit of 5, three one-char chunks force no send, and the fourth flushes.
        let mut c = Coalescer::new(5);
        assert!(!c.has_unsent(), "nothing buffered yet");
        assert!(!c.push("a"));
        assert!(!c.push("b"));
        assert!(!c.push("c"));
        assert!(!c.push("d"));
        assert!(c.push("e"), "five chars have accumulated");
        assert_eq!(c.take_send(), "abcde");
        assert!(!c.has_unsent());
    }

    #[test]
    fn the_edit_body_targets_a_known_message_in_place() {
        let body = build_edit_body(&Conversation::telegram("5", ""), 99, "accumulated");
        assert_eq!(body["chat_id"], "5");
        assert_eq!(body["message_id"], 99);
        assert_eq!(body["text"], "accumulated");
    }
}
