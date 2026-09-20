//! The Telegram streaming driver against a **real** Bot API.
//!
//! The hermetic suite next door (`telegram_http.rs`) proves the driver against a scripted stub: the URL
//! shape, the coalescing, the `429`/`retry_after` policy, the benign no-op, the fallback, and the bound
//! on the number of writes. What a stub cannot prove is that the real API agrees with any of it. Three
//! things are pinned here and nowhere else:
//!
//! - **A real `sendMessage` answers with a Message object**, so `sent_message_id` reads a real id and
//!   the edit path is reachable at all. A stub that flattened `result` would hide the defect that
//!   reading it as an integer once was, and that defect made every streamed answer a single post.
//! - **The real API really does answer a repeated identical edit with `message is not modified`.** The
//!   driver's treatment of that case rests on the documented phrase, so it is asserted against the API
//!   rather than against a literal written by the same hand as the code. It is also what proves the text
//!   is on the screen: an edit to *different* text is accepted, so only the no-op is evidence that the
//!   visible text is already the one expected. Both live text assertions below use it for that reason.
//! - **A real transport failure and a real refusal carry no token.** The token authenticates in the
//!   request *path*, and `reqwest`'s `Display` includes the URL it failed on — the live failure paths are
//!   exactly where that leak would print the credential.
//!
//! ```console
//! $ HX_TELEGRAM_TEST_TOKEN=… HX_TELEGRAM_TEST_CHAT_ID=… \
//!   cargo test -p hx-gateway --test telegram_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The chat must be one the bot can post to; `HX_TELEGRAM_TEST_THREAD_ID` targets a topic in a forum.
//! `HX_TELEGRAM_TEST_BASE_URL` points at a gateway instead of `api.telegram.org`. Every message this
//! suite sends is deleted again, so a run leaves the chat as it found it — with one exception: a run
//! whose final delivery had to *replace* the streamed message leaves the short streamed one behind,
//! because the replacement overwrites the only id the driver reports. The token never appears in output.

use hx_core::ids::ConnectorId;
use hx_gateway::connector::Connector;
use hx_gateway::telegram::{TelegramConnector, DEFAULT_API_ROOT};
use hx_gateway::telegram_stream::{
    classify, is_not_modified, ApiVerdict, FinalDelivery, StreamOutcome, StreamPlan,
};
use hx_gateway::{Conversation, Target};
use hx_secrets::Secret;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// The live bot this suite drives.
struct Bot {
    base_url: String,
    token: Secret,
    chat: String,
    thread: String,
    client: reqwest::Client,
}

fn bot() -> Option<Bot> {
    let token = std::env::var("HX_TELEGRAM_TEST_TOKEN").ok()?;
    let chat = std::env::var("HX_TELEGRAM_TEST_CHAT_ID").ok()?;
    let thread = std::env::var("HX_TELEGRAM_TEST_THREAD_ID").unwrap_or_default();
    let base_url =
        std::env::var("HX_TELEGRAM_TEST_BASE_URL").unwrap_or_else(|_| DEFAULT_API_ROOT.to_string());
    Some(Bot {
        base_url,
        token: Secret::new(token),
        chat,
        thread,
        client: reqwest::Client::builder().build().ok()?,
    })
}

macro_rules! skip_without_a_bot {
    () => {
        match bot() {
            Some(bot) => bot,
            None => {
                eprintln!(
                    "skipped: set HX_TELEGRAM_TEST_TOKEN and HX_TELEGRAM_TEST_CHAT_ID to run this \
                     against a real bot"
                );
                return;
            }
        }
    };
}

impl Bot {
    fn conversation(&self) -> Conversation {
        Conversation::telegram(self.chat.clone(), self.thread.clone())
    }

    fn connector(&self) -> Arc<TelegramConnector> {
        Arc::new(TelegramConnector::new(
            ConnectorId::from("live-tg"),
            self.base_url.clone(),
            self.client.clone(),
        ))
    }

    /// One raw Bot API call, for the two things the connector deliberately does not expose: reading
    /// back what the API says about an edit, and deleting the messages this suite sends.
    ///
    /// The URL is built here because the token authenticates in its path — and it is never printed.
    async fn call(&self, method: &str, body: &Value) -> (u16, Value) {
        let url = format!(
            "{}/bot{}/{}",
            self.base_url.trim_end_matches('/'),
            self.token.expose(),
            method
        );
        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .expect("the Bot API must answer this probe");
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Delete a message this suite sent, so a live run leaves the chat as it found it.
    async fn delete(&self, message_id: i64) {
        let body = json!({ "chat_id": self.chat, "message_id": message_id });
        let _ = self.call("deleteMessage", &body).await;
    }

    /// Whether the API says `message_id` already holds exactly `text`.
    ///
    /// Only a `message is not modified` answer proves it. An *accepted* edit means the previous text
    /// differed, which is evidence against what this is used to assert — so this returns false and says
    /// so, rather than passing on any `2xx`.
    async fn holds_text(&self, message_id: i64, text: &str) -> bool {
        let body = json!({
            "chat_id": self.chat,
            "message_id": message_id,
            "text": text,
        });
        let (status, parsed) = self.call("editMessageText", &body).await;
        let description = parsed
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if is_not_modified(status, description) {
            return true;
        }
        eprintln!(
            "probe: message {message_id} does not hold the text this suite expects \
             (status {status}, description {description:?})"
        );
        false
    }
}

/// Drive `chunks` through the real driver and return what it did, with the stream closed at the end.
///
/// The chunks are sent one at a time with a yield between them, which is the shape a model actually
/// produces and the only shape in which the message is seen to grow *while* the answer is still
/// arriving. The sender is dropped before awaiting, which is how a turn ends — including when the model
/// fails mid-answer, the case where the partial text matters most.
async fn stream(
    bot: &Bot,
    plan: StreamPlan,
    chunks: &[String],
) -> hx_core::error::Result<StreamOutcome> {
    let con = bot.connector();
    let token = bot.token.clone();
    let conversation = bot.conversation();
    let (tx, mut rx) = mpsc::channel::<String>(1);
    let driver = tokio::spawn(async move {
        con.stream_answer(&token, &Target::Conversation(conversation), plan, &mut rx)
            .await
    });

    for chunk in chunks {
        tx.send(chunk.clone())
            .await
            .expect("the driver keeps reading");
        tokio::task::yield_now().await;
    }
    drop(tx);
    driver.await.expect("the driver task")
}

#[ignore = "requires a real Telegram bot token and a chat it can post to"]
#[tokio::test]
async fn a_real_chat_shows_a_growing_message_that_ends_holding_the_whole_answer() {
    let bot = skip_without_a_bot!();

    let answer =
        "The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs.";
    let unit = 25;
    let chunks: Vec<String> = answer.chars().map(|c| c.to_string()).collect();

    let outcome = stream(
        &bot,
        StreamPlan {
            unit,
            ..StreamPlan::default()
        },
        &chunks,
    )
    .await
    .expect("a real stream");

    eprintln!(
        "live stream: chunks={} chars={} writes={} skipped={} failed={} delivery={:?}",
        outcome.chunks,
        outcome.chars,
        outcome.writes,
        outcome.skipped,
        outcome.failed_writes,
        outcome.delivery
    );

    assert_eq!(
        outcome.chunks,
        chunks.len(),
        "every chunk was taken off the stream"
    );
    assert_eq!(outcome.chars, answer.chars().count());

    // The assertion a stub that flattened `result` could never make: a real `sendMessage` answers with
    // a Message *object*, and without the id it carries nothing can ever be edited in place.
    let message_id = outcome.message_id.expect(
        "a real sendMessage must report the message id, or no streamed answer can ever grow",
    );
    assert_ne!(outcome.delivery, FinalDelivery::NothingToSend);

    // A bound on the *count*, never a duration: a real per-chat edit rate can cost a write its retries
    // (the driver honours `retry_after`), but the number of calls is still bounded by characters.
    assert!(
        outcome.writes <= 2 + (outcome.chars / unit) as u32,
        "{} writes for {} characters at a unit of {unit}",
        outcome.writes,
        outcome.chars
    );

    // And the whole answer is what is on the screen — proven by the API itself, not by the driver's own
    // bookkeeping: an edit to the same text is the one thing the API refuses as already done.
    assert!(
        bot.holds_text(message_id, answer).await,
        "the answer is not what the message holds after the stream ended"
    );

    bot.delete(message_id).await;
}

#[ignore = "requires a real Telegram bot token and a chat it can post to"]
#[tokio::test]
async fn a_real_stream_cut_short_still_leaves_the_partial_answer_on_the_screen() {
    let bot = skip_without_a_bot!();

    // The model failing mid-answer, told through the channel closing. A short answer and a small unit,
    // so the message has grown at least once before the stream ends.
    let answer = "The quick brown fox jumps over the lazy dog and then keeps running for a while.";
    let unit = 20;
    let partial: String = answer.chars().take(45).collect();
    let chunks: Vec<String> = partial.chars().map(|c| c.to_string()).collect();

    let outcome = stream(
        &bot,
        StreamPlan {
            unit,
            ..StreamPlan::default()
        },
        &chunks,
    )
    .await
    .expect("a real stream");

    eprintln!(
        "live cut short: chunks={} chars={} writes={} delivery={:?}",
        outcome.chunks, outcome.chars, outcome.writes, outcome.delivery
    );

    let message_id = outcome
        .message_id
        .expect("the first chunk creates the message");
    assert_eq!(outcome.chars, partial.chars().count());
    assert!(
        outcome.writes >= 2,
        "the message must have grown before the stream was cut: {} writes",
        outcome.writes
    );
    assert!(
        bot.holds_text(message_id, &partial).await,
        "the {} characters that arrived are not on the screen",
        partial.chars().count()
    );

    bot.delete(message_id).await;
}

#[ignore = "requires a real Telegram bot token and a chat it can post to"]
#[tokio::test]
async fn the_real_api_answers_a_repeated_identical_edit_with_message_is_not_modified() {
    let bot = skip_without_a_bot!();

    let (status, parsed) = bot
        .call(
            "sendMessage",
            &json!({ "chat_id": bot.chat, "text": "hx live suite: first draft." }),
        )
        .await;
    assert_eq!(status, 200, "the probe message must be posted: {parsed}");
    let message_id = parsed
        .get("result")
        .and_then(|result| result.get("message_id"))
        .and_then(Value::as_i64)
        .expect("a real sendMessage answers with a Message object carrying message_id");

    // The control: an edit that *changes* the text is accepted. Without it, a no-op answer below would
    // be indistinguishable from an API that accepts every edit.
    let changed = json!({
        "chat_id": bot.chat,
        "message_id": message_id,
        "text": "hx live suite: second draft.",
    });
    let (status, parsed) = bot.call("editMessageText", &changed).await;
    assert_eq!(
        status, 200,
        "an edit that changes the text must be accepted: {parsed}"
    );
    assert_eq!(
        classify(status, &parsed.to_string(), None),
        ApiVerdict::Accepted
    );

    // The same edit, byte for byte identical. This is the phrase the driver's benign-no-op case rests
    // on, asserted against the API rather than against a literal of our own.
    let (status, parsed) = bot.call("editMessageText", &changed).await;
    let description = parsed
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    eprintln!("live not-modified: status {status} description {description:?}");
    assert!(
        is_not_modified(status, description),
        "the real API no longer answers an identical edit with `message is not modified` (status \
         {status}, description {description:?}); the driver's benign-no-op case rests on that phrase"
    );
    assert_eq!(
        classify(status, &parsed.to_string(), None),
        ApiVerdict::NotModified
    );

    bot.delete(message_id).await;
}

#[ignore = "requires network access to the real Bot API; needs no token"]
#[tokio::test]
async fn a_real_transport_failure_and_a_real_refusal_carry_no_token() {
    // No bot and no chat: this is about what the live failure paths print, and the token is in the URL
    // they are built from. The value is deliberately shaped like a bot token and is not one.
    let token = Secret::new("123456789:NOT-A-REAL-TOKEN-FOR-THE-LIVE-SUITE");
    let client = reqwest::Client::builder().build().expect("an HTTP client");
    let to = Target::Conversation(Conversation::telegram("1", ""));

    // A real transport failure: the real API host, a port nothing listens on. `reqwest`'s `Display`
    // carries the URL it failed on, so this is precisely the path that leaked the credential once.
    let unreachable = TelegramConnector::new(
        ConnectorId::from("live-tg"),
        "https://api.telegram.org:1",
        client.clone(),
    );
    let err = tokio::time::timeout(
        Duration::from_secs(60),
        unreachable.deliver(&token, &to, "x"),
    )
    .await
    .expect("a refused connection must answer rather than hang")
    .expect_err("nothing listens on port 1 of the real API host");
    let message = err.to_string();
    assert!(message.contains("could not reach"), "{message}");
    assert!(
        !message.contains(token.expose()),
        "the token must never appear in an error, and this one is built from a URL: {message}"
    );

    // A real refusal from the real API: a malformed token in the path is answered by the API itself.
    let refused = TelegramConnector::new(ConnectorId::from("live-tg"), DEFAULT_API_ROOT, client);
    let err = tokio::time::timeout(Duration::from_secs(60), refused.deliver(&token, &to, "x"))
        .await
        .expect("the real API must answer")
        .expect_err("a malformed token is refused");
    let message = err.to_string();
    assert!(
        !message.contains(token.expose()),
        "the token must never appear in an error: {message}"
    );
}
