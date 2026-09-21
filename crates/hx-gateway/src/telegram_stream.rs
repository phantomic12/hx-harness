//! The live streaming half of the Telegram connector: a model's token stream driving coalesced
//! `editMessageText` updates.
//!
//! [`crate::telegram`] carries the coalescing *primitive* and the send/edit request shapes. This
//! module is the driver that wires a real token stream to them, and it exists because the two halves
//! are useless apart: a `Coalescer` nobody calls and an `editMessageText` body nobody sends leaves the
//! user staring at nothing until the answer is complete.
//!
//! ## The property this module exists to hold
//!
//! The visible message grows while the answer is generated, the number of API calls is bounded by
//! *characters*, not by tokens, and **the token stream is never slowed by the network**. Those three
//! are in tension and the design is the resolution:
//!
//! - **The first chunk writes immediately.** An empty screen while a model thinks is the worst of both
//!   worlds: no progress signal and no answer. So the first non-empty chunk is sent as a message
//!   regardless of the coalescing unit.
//! - **Every later write waits for the unit.** With the default of 120 characters, a 4000-character
//!   answer costs at most 34 writes; a token-per-edit driver would cost thousands and be rate-limited
//!   into uselessness.
//! - **At most one write is ever in flight, and the token loop never awaits it.** A flush that arrives
//!   while a write is running is *skipped*, not queued: the newer text is carried by the next write, so
//!   nothing is lost, and the loop goes straight back to draining the model. Awaiting the write inline
//!   is the rejected alternative — it is the one line that turns a slow edit into a slow generation.
//!
//! ## The Bot API's real edge cases, each handled rather than hoped about
//!
//! - **`429` with `retry_after`.** Telegram names the delay in the body
//!   (`parameters.retry_after`); the standard `Retry-After` header is read as a fallback. The delay is
//!   honoured — inside the write's own task, so the model keeps generating while the display waits. The
//!   wait is capped ([`StreamPlan::max_retry_delay`]) and the attempt count is bounded
//!   ([`StreamPlan::max_attempts`]): honouring a one-hour `retry_after` literally would wedge the run,
//!   which the roadmap forbids for the same reason a down channel must fail closed.
//! - **`message is not modified`.** Telegram answers a repeated identical edit with a `400` whose
//!   description says so. That is a benign no-op, not an error, and it must not consume the retry
//!   budget. It is matched on the documented phrase, *not* on the status: a `400` also means "message to
//!   edit not found", "chat not found" and "message text is empty", and treating those as success would
//!   silently lose the answer.
//! - **A failure mid-answer.** A write that fails after its budget is recorded, and the visible text is
//!   known to be stale. The partial text is never dropped: whatever the coalescer holds is delivered by
//!   the final step below.
//! - **A final write that always lands.** When the stream ends, the accumulated text is put on the
//!   screen by an edit if the message still exists, and otherwise by a fresh `sendMessage`. A duplicate
//!   message is a worse *looking* outcome than a missing one and a much better one to be in: the failure
//!   mode this whole module exists to prevent is a user left with nothing. Only if both calls fail is
//!   this an error — and then it is a loud one, not a silent success.
//!
//! ## Deliberately NOT done
//!
//! - **No `sendChatAction` "typing…" indicator.** It cannot be cleared (it expires on its own), so a run
//!   that dies leaves a stuck "typing…" — the exact symptom named above. The first chunk's message *is*
//!   the progress signal, and it is one the user can read.
//! - **No truncation at Telegram's 4096-character message limit.** The API's own error is surfaced
//!   instead. Silently dropping the tail of an answer is the failure this module exists to prevent, so
//!   a long answer fails loudly rather than arriving short.
//! - **No time-based flush.** A timer would either fire needlessly (an extra call per idle moment) or
//!   need its own cancellation; the character unit plus the guaranteed final write already covers both
//!   "shows movement" and "shows everything".
//! - **No retry of a *failed* mid-stream write by re-arming the coalescer.** A channel that is down must
//!   not be hammered, so a failed write does not reset the watermark; the final write is what recovers
//!   the text.
//!
//! ## The honest trade-off
//!
//! Coalescing bounds the *number* of writes, and the bound is `characters / unit + 1`, so the *rate* of
//! writes follows generation speed. A very fast model can therefore still outrun Telegram's per-chat
//! edit rate (community-observed at roughly one edit per second; the Bot API does not document a
//! number). When it does, the `429` path above is what keeps the run correct: the display falls behind
//! while the generation does not, because the wait happens in the write's task and never in the token
//! loop. Bounded call counts and an always-live message are genuinely in tension at high generation
//! speed; this is the resolution, not a hidden one.
//!
//! ## Layering
//!
//! The driver takes a channel of text chunks rather than a `hx-provider` stream. `hx-gateway` must not
//! depend on `hx-provider` (the wiring lives in `hx-server`, which holds both), and a connector that
//! knew about `StreamDelta` would be a connector coupled to one vendor's stream shape. The model side
//! holds the `Sender`, so "the stream ended" is the channel closing — including when the model *fails*
//! mid-answer, which is exactly when the partial text matters most.

use crate::connector::Connector;
use crate::telegram::{
    build_edit_body, build_send_body, sent_message_id, Coalescer, TelegramConnector,
};
use crate::types::Target;
use hx_core::error::{HxError, Result};
use hx_secrets::Secret;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Characters an edit waits for before it is worth an API call.
///
/// 120 is chosen against the two things that matter: a short answer still produces visible movement
/// within a token or two of arriving, and a 4000-character answer costs at most 34 writes rather than
/// one per token. A smaller unit buys nothing (the user cannot read faster than the model types) and
/// costs API calls that a per-chat edit rate will eventually refuse.
pub const DEFAULT_UNIT: usize = 120;

/// Attempts per write, including the first. Bounded because a persistently throttled channel must not
/// be able to wedge a run — and small because a long answer issues few writes, so losing one is
/// recoverable by the guaranteed final write rather than needing a determined retry.
pub const MAX_ATTEMPTS: u32 = 3;

/// Backoff for a transient failure that named no delay of its own (a 5xx, a dropped connection).
/// Short: a blip is worth one quick retry, and anything longer is what the final write is for.
pub const TRANSIENT_BACKOFF: Duration = Duration::from_millis(250);

/// The longest `retry_after` this driver will actually wait out.
///
/// Telegram's own throttles are seconds; a value beyond this is a channel telling us to go away for a
/// while, and sleeping on it would hold the run open. Past the cap the write is treated as failed *for
/// now* and the guaranteed final write recovers the text — the run stays alive and the user still gets
/// an answer, which is the property that matters.
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);

/// A single Bot API call must not be able to hang forever: `reqwest`'s default is no timeout at all, and
/// a wedged socket would otherwise hold the final write open indefinitely. 30s is far above any normal
/// Bot API latency and below any run deadline worth having.
pub const API_TIMEOUT: Duration = Duration::from_secs(30);

/// How much of an API's error body is kept in a verdict. Enough to identify the failure, short enough
/// that a proxy's HTML error page cannot fill a log.
const DETAIL_LIMIT: usize = 300;

/// The knobs a streaming run is driven with. A `Copy` value so a spawned write owns its own policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPlan {
    /// Characters of new text an edit waits for. See [`DEFAULT_UNIT`].
    pub unit: usize,
    /// Attempts per write, including the first. See [`MAX_ATTEMPTS`].
    pub max_attempts: u32,
    /// Backoff for a transient failure that named no delay. See [`TRANSIENT_BACKOFF`].
    pub transient_backoff: Duration,
    /// The longest throttle delay actually waited out. See [`MAX_RETRY_DELAY`].
    pub max_retry_delay: Duration,
}

impl Default for StreamPlan {
    fn default() -> Self {
        Self {
            unit: DEFAULT_UNIT,
            max_attempts: MAX_ATTEMPTS,
            transient_backoff: TRANSIENT_BACKOFF,
            max_retry_delay: MAX_RETRY_DELAY,
        }
    }
}

/// What one Bot API call said.
///
/// `Accepted` and `NotModified` are both success: the second means the text is already on the screen,
/// which is what an edit was for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiVerdict {
    /// The API took it.
    Accepted,
    /// `400` — the new text is identical to the current text. A benign no-op.
    NotModified,
    /// `429` — the API named how long to wait.
    Throttled { retry_after: Duration },
    /// A refusal that is not the benign case: the status and what the API said about it.
    Failed { status: u16, detail: String },
    /// The request never got an answer (a transport failure, or the timeout above).
    Unreachable { reason: String },
}

impl ApiVerdict {
    /// Whether the API considers the message up to date after this call.
    pub fn is_success(&self) -> bool {
        matches!(self, ApiVerdict::Accepted | ApiVerdict::NotModified)
    }

    /// A sentence naming what happened, built **without the request URL**.
    ///
    /// The token authenticates in that path, so anything derived from a URL is a credential in a log.
    pub fn describe(&self) -> String {
        match self {
            ApiVerdict::Accepted => "was accepted".into(),
            ApiVerdict::NotModified => "reported the text already up to date".into(),
            ApiVerdict::Throttled { retry_after } => {
                format!("was rate limited (retry after {retry_after:?})")
            }
            ApiVerdict::Failed { status, detail } => format!("returned {status}: {detail}"),
            ApiVerdict::Unreachable { reason } => format!("could not be reached: {reason}"),
        }
    }
}

/// What to do after an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextStep {
    /// The attempt settled it (accepted, the benign no-op, or a refusal that will not change).
    Done,
    /// Wait this long, then try again.
    RetryIn(Duration),
    /// The attempt budget is spent, or asking again cannot change the answer.
    GiveUp,
}

/// Decide the next step from a verdict and how many calls have already been spent.
///
/// Pure, so the retry policy is testable without a network and without sleeping. `attempt` is 1-based
/// and counts the call that produced `verdict`.
pub fn next_step(verdict: &ApiVerdict, attempt: u32, plan: &StreamPlan) -> NextStep {
    if verdict.is_success() {
        return NextStep::Done;
    }
    if attempt >= plan.max_attempts.max(1) {
        return NextStep::GiveUp;
    }
    match verdict {
        ApiVerdict::Throttled { retry_after } => {
            // Honour the delay the API named, up to the cap. Past it, stop waiting: the run must not
            // be held open, and the final write still gets the text there.
            if *retry_after > plan.max_retry_delay {
                NextStep::GiveUp
            } else {
                NextStep::RetryIn(*retry_after)
            }
        }
        // A 5xx or a transport failure may be a blip, so one short retry is worth it.
        ApiVerdict::Unreachable { .. } => NextStep::RetryIn(plan.transient_backoff),
        ApiVerdict::Failed { status, .. } if *status >= 500 => {
            NextStep::RetryIn(plan.transient_backoff)
        }
        // Every other refusal (a 4xx that is not "not modified") is a request Telegram has already
        // judged; repeating it only spends the budget and delays the final write.
        _ => NextStep::GiveUp,
    }
}

/// Classify one Bot API response.
///
/// A `2xx` is only a success when the body is signed `ok: true`, so a proxy's HTML page or a truncated
/// body cannot read as "the edit landed" — fail closed, the same way `receive` treats a missing `ok`.
pub fn classify(status: u16, body: &str, retry_after_header: Option<&str>) -> ApiVerdict {
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let ok = parsed
        .as_ref()
        .and_then(|value| value.get("ok"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let description = parsed
        .as_ref()
        .and_then(|value| value.get("description"))
        .and_then(Value::as_str)
        .unwrap_or("");

    if (200..300).contains(&status) && ok {
        return ApiVerdict::Accepted;
    }
    if is_not_modified(status, description) {
        return ApiVerdict::NotModified;
    }
    if status == 429 {
        return ApiVerdict::Throttled {
            retry_after: retry_after_of(body, retry_after_header)
                .unwrap_or(plan_default_throttle()),
        };
    }
    ApiVerdict::Failed {
        status,
        detail: detail_of(description, body),
    }
}

/// Whether this refusal is Telegram saying "the text is already exactly this".
///
/// Matched on the documented phrase and on `400`, never on `400` alone: the same status means "message
/// to edit not found" and "chat not found", and calling those a success would lose the answer.
pub fn is_not_modified(status: u16, description: &str) -> bool {
    status == 400
        && description
            .to_ascii_lowercase()
            .contains("message is not modified")
}

/// The delay a throttle named, read from the body before the header.
///
/// Telegram puts it in `parameters.retry_after`; the standard `Retry-After` header is the fallback, so a
/// proxy that rewrites the body still gets its delay honoured.
pub fn retry_after_of(body: &str, header: Option<&str>) -> Option<Duration> {
    if let Ok(parsed) = serde_json::from_str::<Value>(body) {
        if let Some(seconds) = parsed
            .get("parameters")
            .and_then(|parameters| parameters.get("retry_after"))
            .and_then(Value::as_u64)
        {
            return Some(Duration::from_secs(seconds));
        }
    }
    header?.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// A throttle that named no delay at all still means "not yet". One second is the smallest wait that is
/// still a wait; the attempt budget bounds the total.
fn plan_default_throttle() -> Duration {
    Duration::from_secs(1)
}

/// Keep a refusal's own words, capped. Never the request URL — the token is in it.
fn detail_of(description: &str, body: &str) -> String {
    let text = if description.is_empty() {
        body
    } else {
        description
    };
    if text.chars().count() <= DETAIL_LIMIT {
        return text.to_string();
    }
    let mut kept: String = text.chars().take(DETAIL_LIMIT).collect();
    kept.push('…');
    kept
}

/// How the answer ended up on the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalDelivery {
    /// An edit landed last: the message the stream created now holds the whole answer.
    Edited,
    /// An edit could not carry it, so the whole answer was posted as a new message. The streamed
    /// message may still be visible and short; a duplicate is the accepted cost of never leaving the
    /// user with nothing.
    Replaced,
    /// The full answer was already on the screen, so no further call was made.
    AlreadyVisible,
    /// The model produced no text. Nothing was ever sent, so there is no empty message to clean up.
    NothingToSend,
}

/// What a streaming run did, in numbers a test can assert on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamOutcome {
    /// The id of the message the answer is visible in, when one was created.
    pub message_id: Option<i64>,
    /// Chunks taken off the model's stream. Equal to what the model produced, however slow the network.
    pub chunks: usize,
    /// Bot API calls made, retries included.
    pub writes: u32,
    /// Flushes the coalescer asked for that were deliberately not written: another write was in flight,
    /// or there was no message to edit. This is coalescing working, not an error.
    pub skipped: u32,
    /// Writes that gave up after their budget.
    pub failed_writes: u32,
    /// Characters in the answer.
    pub chars: usize,
    /// How the whole text reached the user.
    pub delivery: FinalDelivery,
}

impl Default for StreamOutcome {
    fn default() -> Self {
        Self {
            message_id: None,
            chunks: 0,
            writes: 0,
            skipped: 0,
            failed_writes: 0,
            chars: 0,
            delivery: FinalDelivery::NothingToSend,
        }
    }
}

/// The result of one write, retries folded in.
struct Attempt {
    verdict: ApiVerdict,
    calls: u32,
    /// The parsed body of the last call, so a send can report the message it created.
    body: Option<Value>,
}

/// Fold a finished write into the run's bookkeeping.
///
/// A joined panic is a failed write, not a lost one: the task's work is gone, so the visible text is
/// stale and the final write must recover it.
fn absorb(
    joined: std::result::Result<Attempt, tokio::task::JoinError>,
    outcome: &mut StreamOutcome,
    last_write_failed: &mut bool,
) {
    let attempt = match joined {
        Ok(attempt) => attempt,
        Err(_) => {
            outcome.writes += 1;
            outcome.failed_writes += 1;
            *last_write_failed = true;
            return;
        }
    };
    outcome.writes += attempt.calls;
    if attempt.verdict.is_success() {
        *last_write_failed = false;
        // Only the first write creates the message; later writes are edits of it and must not
        // overwrite the id with nothing.
        if outcome.message_id.is_none() {
            outcome.message_id = attempt.body.as_ref().and_then(sent_message_id);
        }
    } else {
        outcome.failed_writes += 1;
        *last_write_failed = true;
    }
}

impl TelegramConnector {
    /// Drive a stream of answer chunks into one Telegram message, growing it as the answer arrives.
    ///
    /// Takes `self` as an `Arc` because a write must run *concurrently* with the token loop, and a
    /// concurrent task needs to own what it borrows. Awaiting the write inline instead is the rejected
    /// alternative — see this module's doc.
    ///
    /// Returns when the channel closes, which is how a model's turn ends — including when the model
    /// *fails* mid-answer, which is precisely when the partial text must not be lost.
    ///
    /// This is an inherent method rather than a fourth [`Connector`] verb on purpose: a platform with no
    /// edit primitive has nothing to stream into, and forcing every connector to implement a streaming
    /// method would make Discord and Slack implement a lie. The trait stays three verbs.
    pub async fn stream_answer(
        self: &Arc<Self>,
        key: &Secret,
        to: &Target,
        plan: StreamPlan,
        chunks: &mut mpsc::Receiver<String>,
    ) -> Result<StreamOutcome> {
        let conversation = match to {
            Target::Conversation(conversation) => conversation.clone(),
            Target::Home => {
                return Err(HxError::Connector {
                    connector: self.id().to_string(),
                    reason: "streaming needs an explicit conversation, not the home channel".into(),
                })
            }
        };

        let mut outcome = StreamOutcome::default();
        let mut coalescer = Coalescer::new(plan.unit);
        let mut started = false;
        let mut last_write_failed = false;
        let mut in_flight: Option<JoinHandle<Attempt>> = None;

        while let Some(chunk) = chunks.recv().await {
            outcome.chunks += 1;

            // The first non-empty chunk writes regardless of the unit: the user should see the answer
            // begin. After that, only enough new text justifies a call.
            let enough = coalescer.push(&chunk);
            if !(enough || (!started && coalescer.has_unsent())) {
                continue;
            }

            // Reap a finished write without waiting for it: `is_finished` is a poll, not a block.
            if in_flight
                .as_ref()
                .is_some_and(|handle| handle.is_finished())
            {
                let joined = in_flight.take().expect("just checked").await;
                absorb(joined, &mut outcome, &mut last_write_failed);
            }
            if in_flight.is_some() {
                // A write is running. Skipping here is the whole reason a slow edit cannot slow the
                // model: the text is not lost, it is carried by the next write.
                outcome.skipped += 1;
                continue;
            }
            if started && outcome.message_id.is_none() {
                // The first send failed, or was accepted without a message id to edit. Re-sending on
                // every flush would put several copies of the answer on the screen and would hammer a
                // channel that is already failing; the guaranteed final write is what gets the text
                // there instead.
                outcome.skipped += 1;
                continue;
            }

            let text = coalescer.take_send();
            let body = match outcome.message_id {
                Some(id) => build_edit_body(&conversation, id, &text),
                None => build_send_body(&conversation, &text),
            };
            let method = if outcome.message_id.is_some() {
                "editMessageText"
            } else {
                "sendMessage"
            };
            in_flight = Some(self.spawn_write(method, body, plan, key));
            started = true;
        }

        // Join the last write before the final one. There is nothing left to generate, so waiting costs
        // the model nothing — and it is required: a stale edit still in flight could land *after* the
        // final write and put short text back on the screen.
        if let Some(handle) = in_flight.take() {
            let joined = handle.await;
            absorb(joined, &mut outcome, &mut last_write_failed);
        }

        let final_text = coalescer.buffer.clone();
        outcome.chars = final_text.chars().count();
        if final_text.is_empty() {
            // Nothing was ever sent, so there is no empty message and no stuck indicator to clear.
            outcome.delivery = FinalDelivery::NothingToSend;
            return Ok(outcome);
        }

        // A final write is needed unless the visible text is provably the whole answer: no unsent text,
        // the last attempt succeeded, and there is a message holding it.
        if !coalescer.has_unsent() && !last_write_failed && outcome.message_id.is_some() {
            outcome.delivery = FinalDelivery::AlreadyVisible;
            return Ok(outcome);
        }

        // The guaranteed final delivery. An edit first (it keeps one message and one scroll position),
        // then a fresh message. The failure mode being designed out is a user left with nothing.
        let mut edit_failure: Option<ApiVerdict> = None;
        if let Some(id) = outcome.message_id {
            let body = build_edit_body(&conversation, id, &final_text);
            let url = self.api_url("editMessageText", key);
            let attempt = self.attempt(&url, &body, plan).await;
            outcome.writes += attempt.calls;
            match attempt.verdict {
                ApiVerdict::Accepted | ApiVerdict::NotModified => {
                    outcome.delivery = FinalDelivery::Edited;
                    return Ok(outcome);
                }
                other => {
                    outcome.failed_writes += 1;
                    edit_failure = Some(other);
                }
            }
        }

        let body = build_send_body(&conversation, &final_text);
        let url = self.api_url("sendMessage", key);
        let attempt = self.attempt(&url, &body, plan).await;
        outcome.writes += attempt.calls;
        match attempt.verdict {
            ApiVerdict::Accepted | ApiVerdict::NotModified => {
                if let Some(id) = attempt.body.as_ref().and_then(sent_message_id) {
                    outcome.message_id = Some(id);
                }
                outcome.delivery = FinalDelivery::Replaced;
                Ok(outcome)
            }
            other => {
                // The run has no answer to show. The call count goes into the message so an operator can
                // see how hard it was tried before concluding the channel is down.
                Err(HxError::Connector {
                    connector: self.id().to_string(),
                    reason: format!(
                        "the answer could not be put on the screen, so the user has none: \
                         editMessageText {}; sendMessage {} ({} API call(s) this run). Both are \
                         reported because which one failed changes what an operator does next.",
                        edit_failure
                            .as_ref()
                            .map(ApiVerdict::describe)
                            .unwrap_or_else(|| "was not attempted (no message to edit)".into()),
                        other.describe(),
                        outcome.writes
                    ),
                })
            }
        }
    }

    /// Hand one write to its own task so it cannot hold the token loop.
    fn spawn_write(
        self: &Arc<Self>,
        method: &str,
        body: Value,
        plan: StreamPlan,
        key: &Secret,
    ) -> JoinHandle<Attempt> {
        // The URL is built here, where the token is available, so the task holds a string and never the
        // credential itself.
        let url = self.api_url(method, key);
        let this = Arc::clone(self);
        tokio::spawn(async move { this.attempt(&url, &body, plan).await })
    }

    /// One write, retried according to [`next_step`] until it settles or the budget is spent.
    async fn attempt(&self, url: &str, body: &Value, plan: StreamPlan) -> Attempt {
        let mut calls = 0;
        loop {
            calls += 1;
            let (verdict, parsed) = self.one_call(url, body).await;
            match next_step(&verdict, calls, &plan) {
                NextStep::Done | NextStep::GiveUp => {
                    return Attempt {
                        verdict,
                        calls,
                        body: parsed,
                    }
                }
                NextStep::RetryIn(delay) => tokio::time::sleep(delay).await,
            }
        }
    }

    /// One Bot API call, under a timeout, classified rather than raised.
    async fn one_call(&self, url: &str, body: &Value) -> (ApiVerdict, Option<Value>) {
        let request = self.http().post(url).json(body).send();
        match tokio::time::timeout(API_TIMEOUT, request).await {
            Err(_) => (
                ApiVerdict::Unreachable {
                    reason: format!("no answer within {API_TIMEOUT:?}"),
                },
                None,
            ),
            // `without_url` is load-bearing, not tidiness: the token authenticates in the request path
            // and reqwest's Display includes that URL, so an error built from this one would print the
            // credential.
            Ok(Err(err)) => (
                ApiVerdict::Unreachable {
                    reason: err.without_url().to_string(),
                },
                None,
            ),
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let text = response
                    .text()
                    .await
                    .unwrap_or_else(|err| format!("<unreadable body: {}>", err.without_url()));
                // `without_url` for the same reason as the transport error above: the URL carries
                // `/bot<token>/`, and this string is classified into verdicts surfaced to callers.
                let verdict = classify(status, &text, retry_after.as_deref());
                let parsed = serde_json::from_str::<Value>(&text).ok();
                (verdict, parsed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> StreamPlan {
        StreamPlan::default()
    }

    #[test]
    fn a_repeated_identical_edit_is_a_benign_no_op_rather_than_an_error() {
        // Telegram answers a second identical edit with a 400. Treating it as a failure would mark the
        // visible text stale and trigger a pointless replacement message at the end of every stream
        // that happened to land on the same text twice.
        let body = r#"{"ok":false,"error_code":400,"description":"Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content and reply markup of the message"}"#;
        let verdict = classify(400, body, None);
        assert_eq!(verdict, ApiVerdict::NotModified);
        assert!(
            verdict.is_success(),
            "the text is on the screen, which is the point"
        );
        assert_eq!(next_step(&verdict, 1, &plan()), NextStep::Done);
    }

    #[test]
    fn a_bad_request_that_is_not_the_identical_edit_case_is_a_real_failure() {
        // The control for the test above. A 400 also means "message to edit not found" and "chat not
        // found"; calling those a benign no-op would report a successful stream while the user sees a
        // message that never grew.
        for description in [
            "Bad Request: message to edit not found",
            "Bad Request: chat not found",
            "Bad Request: message text is empty",
        ] {
            let body = format!(r#"{{"ok":false,"error_code":400,"description":"{description}"}}"#);
            let verdict = classify(400, &body, None);
            assert!(
                matches!(verdict, ApiVerdict::Failed { status: 400, .. }),
                "{description} must be a failure, got {verdict:?}"
            );
            assert!(!verdict.is_success());
        }
    }

    #[test]
    fn the_throttle_delay_is_read_from_the_body_before_the_header() {
        // Telegram names it in `parameters.retry_after`; the standard header is the fallback for a proxy
        // that rewrites the body. The body wins because it is the API's own field.
        let body = r#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}"#;
        assert_eq!(
            retry_after_of(body, Some("3")),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            retry_after_of("not json", Some("3")),
            Some(Duration::from_secs(3))
        );
        assert_eq!(retry_after_of("not json", None), None);
    }

    #[test]
    fn a_throttled_write_waits_the_delay_the_api_named() {
        let verdict = ApiVerdict::Throttled {
            retry_after: Duration::from_secs(4),
        };
        assert_eq!(
            next_step(&verdict, 1, &plan()),
            NextStep::RetryIn(Duration::from_secs(4)),
            "hammering a rate-limited API is what earns a longer ban"
        );
    }

    #[test]
    fn the_retry_budget_is_bounded_so_a_throttled_channel_cannot_wedge_a_run() {
        // A channel that keeps answering 429 must not be retried forever: the run would never finish and
        // the user would never see the answer.
        let verdict = ApiVerdict::Throttled {
            retry_after: Duration::from_millis(1),
        };
        let plan = plan();
        assert_eq!(
            next_step(&verdict, 1, &plan),
            NextStep::RetryIn(Duration::from_millis(1))
        );
        assert_eq!(
            next_step(&verdict, 2, &plan),
            NextStep::RetryIn(Duration::from_millis(1))
        );
        assert_eq!(
            next_step(&verdict, plan.max_attempts, &plan),
            NextStep::GiveUp,
            "the last attempt is the last"
        );
    }

    #[test]
    fn a_throttle_longer_than_the_cap_gives_up_rather_than_holding_the_run_open() {
        // Honouring a long `retry_after` literally would park the run; the final write is what recovers
        // the text instead. This is the documented limit of "honour the delay".
        let verdict = ApiVerdict::Throttled {
            retry_after: MAX_RETRY_DELAY + Duration::from_secs(1),
        };
        assert_eq!(next_step(&verdict, 1, &plan()), NextStep::GiveUp);
        let just_inside = ApiVerdict::Throttled {
            retry_after: MAX_RETRY_DELAY,
        };
        assert_eq!(
            next_step(&just_inside, 1, &plan()),
            NextStep::RetryIn(MAX_RETRY_DELAY),
            "the cap itself is still honoured"
        );
    }

    #[test]
    fn a_client_error_is_not_retried_because_asking_again_cannot_change_it() {
        let verdict = ApiVerdict::Failed {
            status: 403,
            detail: "Forbidden: bot was blocked by the user".into(),
        };
        assert_eq!(next_step(&verdict, 1, &plan()), NextStep::GiveUp);
    }

    #[test]
    fn a_transport_failure_and_a_server_error_are_retried_briefly() {
        // Both may be a blip. The backoff is short and fixed, so a burst of retries cannot build up.
        let unreachable = ApiVerdict::Unreachable {
            reason: "connection reset".into(),
        };
        assert_eq!(
            next_step(&unreachable, 1, &plan()),
            NextStep::RetryIn(TRANSIENT_BACKOFF)
        );
        let server_error = ApiVerdict::Failed {
            status: 502,
            detail: "Bad Gateway".into(),
        };
        assert_eq!(
            next_step(&server_error, 1, &plan()),
            NextStep::RetryIn(TRANSIENT_BACKOFF)
        );
    }

    #[test]
    fn a_2xx_without_an_ok_flag_is_not_a_success() {
        // Fail closed, the way `receive` treats a missing `ok`: a proxy's HTML page or a truncated body
        // must not read as "the edit landed".
        let verdict = classify(200, "<html>upstream is unwell</html>", None);
        assert!(matches!(verdict, ApiVerdict::Failed { status: 200, .. }));
        assert!(!verdict.is_success());
    }

    #[test]
    fn a_verdict_never_renders_a_request_url() {
        // The token is in the path, so a sentence built from a URL is a credential in a log.
        let verdict = ApiVerdict::Unreachable {
            reason: "error sending request".into(),
        };
        let described = verdict.describe();
        assert!(described.contains("could not be reached"), "{described}");
        assert!(!described.contains("http"), "{described}");
    }

    #[test]
    fn a_verdict_keeps_a_long_refusal_short() {
        let verdict = classify(500, &"x".repeat(5000), None);
        match verdict {
            ApiVerdict::Failed { detail, .. } => {
                assert!(
                    detail.chars().count() <= DETAIL_LIMIT + 1,
                    "a proxy's error page must not fill a log: {} chars",
                    detail.chars().count()
                );
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn a_throttle_that_names_no_delay_still_waits() {
        // A bare 429 means "not yet" even when nothing says how long; waiting zero would be hammering.
        let verdict = classify(429, r#"{"ok":false,"error_code":429}"#, None);
        match verdict {
            ApiVerdict::Throttled { retry_after } => {
                assert!(retry_after >= Duration::from_secs(1), "{retry_after:?}");
            }
            other => panic!("expected a throttle, got {other:?}"),
        }
    }
}
