//! Transcript compaction: choosing what of a long conversation to hand the model next turn.
//!
//! ## The property this module exists to hold
//!
//! A run appends to the same `Vec<Message>` every turn and hands it to the provider verbatim. Left
//! alone, a long session's transcript grows without bound until the model's context window is
//! exhausted and the provider refuses the request with an error that reads like a network fault
//! rather than what it is. This module is the thing that keeps a long conversation sendable.
//!
//! The **audit trail is sacred and is never touched here**. The store keeps the whole transcript —
//! that is the record a human audits. Compaction is purely about what the *model* is handed: we
//! return a shrunken `Vec<Message>` for the request, and the loop's own `transcript` that feeds
//! the store is left exactly as it was. A reader must never worry that compaction deleted a line
//! of the record, because it structurally cannot.
//!
//! The policy is a pure function — `(transcript, threshold) -> what to send` — so it is testable
//! with no provider in the loop. It has three parts:
//!
//! - **Keep the head.** The first messages — the system prompt and the original goal — are the
//!   reason the conversation started, and dropping them would orphan every later turn.
//! - **Keep the tail.** The most recent messages carry the current state: the last prompt, the
//!   exchanges that led here, the latest answer or tool results. A model asked to continue on an
//!   empty memory of its own last move cannot.
//! - **Replace the middle with an explicit marker.** The elision is *said*, not hidden: an
//!   assistant-role message states how many messages were elided and that the store keeps the full
//!   record. The alternative — silently dropping the middle — was rejected because it makes the
//!   transcript look continuous when it is not, and a model that thinks it remembers the whole
//!   conversation will act on a false memory. A dedicated `Part` variant was also rejected: it
//!   would have to flow through every adapter, the TUI and the renders, while an assistant text
//!   message is a shape every layer already understands. The assistant role (rather than user) is
//!   chosen because a recap of what the conversation did is a summary *of* the assistant's work;
//!   consecutive assistant messages are valid in the one adapter this crate ships (OpenAI-compatible).
//!
//! ## What it deliberately does not do yet
//!
//! It does not call a model to produce a real natural-language summary of the middle — that would
//! turn a pure policy into a provider call (and a recursive one, since compaction would need a
//! model call to decide a smaller prompt). It keeps a fixed head/tail rather than reasoning about
//! which turns a given task still needs, and it does not compress images or truncate individual
//! tool results (that is the tool's `truncated` flag, decided at run time). Those are later
//! refinements; the job here is the structural one: never send the unbounded whole.
//!
//! ## Token counting is an estimate
//!
//! There is no tokenizer in the tree. Counting uses [`hx_core::message::approximate_tokens`] — the
//! same 4-chars-per-token heuristic the provider crate uses to *reserve* capacity before a call —
//! so the decision is in the right ballpark but not exact. The threshold is a config knob on the
//! *conversation* estimate (the growing part), not on system-prompt or tool-schema tokens, which are
//! constant across a run and notional next to the real provider figures. The estimate covers only
//! the message transcript, not the (constant) tool schemas and system prompt; the provider's window
//! is the ceiling, and `compact_at_tokens` says where *we* start shrinking what we send.

use hx_core::message::{approximate_tokens, Message, Part, Role};

/// How many leading messages are always kept, however long the conversation.
///
/// Two is a deliberate choice rather than one: the first message is usually the system prompt and
/// the second the original user goal. Together they pin the task. A real head needs both; one
/// would, for a session whose first entry is the goal and whose system prompt lives elsewhere,
/// risk dropping the instruction that colours every turn.
const KEEP_HEAD: usize = 2;

/// How many trailing messages are always kept, however long the conversation.
///
/// Sized to hold the recent active work: the last prompt, the current turn's tool exchange and
/// the latest answer. Twelve lets several tool round-trips survive intact so the model can see
/// how it got to where it is. Anything larger eats into the context budget the threshold exists
/// to protect; anything smaller risks a model that cannot see its own last move.
const KEEP_TAIL: usize = 12;

/// Result of deciding what to send, with the numbers a caller or a log line might want.
#[derive(Clone, Debug, PartialEq)]
pub struct Compacted {
    /// The messages to hand the model.
    pub messages: Vec<Message>,
    /// Actually kept from the head of the conversation.
    pub head: usize,
    /// Actually kept from the tail.
    pub tail: usize,
    /// Original messages replaced by the marker.
    pub elided: usize,
}

/// Choose what of `transcript` to hand the model next, so it stays under `threshold` tokens.
///
/// Under the threshold this is the identity: the whole transcript is sent, because there is
/// nothing to fix. Over it, the head and tail are kept (each trimmed only as far as is needed to
/// avoid splitting a tool call from its result) and the middle is replaced by an explicit marker.
/// `threshold == 0` means "never compact" — a caller can disable the behaviour without removing
/// the plumbing.
///
/// The transcript passed in is never modified; the returned `Vec` is a freshly built request.
pub fn compact_at(transcript: &[Message], threshold: usize) -> Compacted {
    if threshold == 0 || approximate_tokens(transcript) <= threshold {
        return Compacted {
            messages: transcript.to_vec(),
            head: transcript.len(),
            tail: 0,
            elided: 0,
        };
    }

    let head_end = safe_head_end(transcript, KEEP_HEAD);
    let tail_start = safe_tail_start(transcript, KEEP_TAIL);

    // If the head and tail reach or overlap — the transcript is small but the estimate says
    // otherwise — keep the whole thing rather than manufacture an elision that loses a message we
    // said we would keep. A sane estimate never triggers this; a pathological one degrades to
    // "send it all" instead of guessing.
    if head_end >= tail_start {
        return Compacted {
            messages: transcript.to_vec(),
            head: transcript.len(),
            tail: 0,
            elided: 0,
        };
    }

    let head = &transcript[..head_end];
    let tail = &transcript[tail_start..];
    let mut messages = Vec::with_capacity(head_end + 1 + tail.len());
    messages.extend_from_slice(head);
    messages.push(marker(tail_start - head_end));
    messages.extend_from_slice(tail);

    Compacted {
        messages,
        head: head_end,
        tail: tail.len(),
        elided: tail_start - head_end,
    }
}

/// An explicit, visible statement that the middle of the conversation was elided.
///
/// The point of the marker is that the elision is *noticed*: a model that is quietly handed a
/// transcript with a hole in it will act as though nothing was skipped. The count included is the
/// number of messages the full (stored) transcript has that this request does not, so a reader
/// can see the scale of what was trimmed.
fn marker(elided: usize) -> Message {
    Message::new(
        Role::Assistant,
        vec![Part::Text {
            text: format!(
                "[The middle of this conversation — {elided} message(s) — was elided to fit the \
                 context window. The full transcript is retained in the session store. Continue \
                 from the current state below, and re-derive anything you need from the tools \
                 rather than assuming you remember what was trimmed.]"
            ),
        }],
    )
}

/// The largest prefix end whose slice is self-contained (no tool call without its result).
///
/// We want `want` messages as the head, but never at the cost of handing the model a tool call
/// whose result lives in the middle we are about to drop — a pair split across the boundary is the
/// one shape every provider rejects. Walk the end backwards over the rare cases where the head
/// would cut through a call/result pair (a head almost always ends on a system or user message,
/// but the guarantee is what we walk for).
fn safe_head_end(transcript: &[Message], want: usize) -> usize {
    let mut end = want.min(transcript.len());
    while end > 0 && !is_pair_safe(&transcript[..end]) {
        end -= 1;
    }
    end
}

/// The smallest suffix start whose slice is self-contained (no tool result without its call).
///
/// Mirror of [`safe_head_end`] for the tail: the tail must not open with a tool result whose call
/// was dropped into the middle, because a result that names a call the provider never saw is as
/// un-sendable as a call without a result. Walk the start forwards until the retained suffix is
/// whole.
fn safe_tail_start(transcript: &[Message], want_from_end: usize) -> usize {
    let mut start = transcript.len().saturating_sub(want_from_end);
    while start < transcript.len() && !is_pair_safe(&transcript[start..]) {
        start += 1;
    }
    start
}

/// True when every tool call in `messages` has its result in `messages`, and vice versa.
///
/// "Every call answered, every result's call present." Both directions matter: a call whose result
/// is outside the slice leaves the model waiting on an answer that will never come, and a result
/// whose call is outside the slice names a call the provider never saw. A slice that satisfies
/// both is a complete, self-contained stretch of the conversation.
fn is_pair_safe(messages: &[Message]) -> bool {
    let mut calls = std::collections::HashSet::new();
    let mut results = std::collections::HashSet::new();
    for message in messages {
        for part in &message.parts {
            match part {
                Part::ToolCall { id, .. } => {
                    calls.insert(id.clone());
                }
                Part::ToolResult { id, .. } => {
                    results.insert(id.clone());
                }
                _ => {}
            }
        }
    }
    calls == results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `--help`-style transcript is not big enough to warrant compaction; sending it as-is is
    /// the honest fast path and the assertion is that compaction does not edit what is already
    /// small. This matters because a compaction that shrank an under-threshold conversation would
    /// be trading quality for nothing.
    #[test]
    fn an_under_threshold_transcript_is_sent_unchanged() {
        let transcript = vec![
            Message::system("you are an agent"),
            Message::user("build it"),
            Message::assistant("on it"),
        ];
        // 4 chars/token on tiny messages still lands far under any sane threshold.
        let result = compact_at(&transcript, 1000);
        assert_eq!(result.messages, transcript, "the identity must hold");
        assert_eq!(result.elided, 0);
    }

    /// A conversation that grew past the threshold loses its *middle*, never its head or its most recent
    /// tail, and the marker says so. The elision being visible is the whole reason the marker exists — a
    /// model told nothing would assume the gap was a bug, so the marker is not decoration.
    #[test]
    fn an_over_threshold_transcript_keeps_head_tail_and_a_speaking_marker() {
        // Head: system + goal. Middle: forty filler turns. Tail: two closing lines that must survive.
        let goal = Message::user("build the whole thing");
        let mut transcript = vec![Message::system("be thorough"), goal.clone()];
        for i in 0..40 {
            transcript.push(Message::assistant(format!("step {i} done")));
        }
        let closing = vec![
            Message::assistant("nearly there"),
            Message::assistant("done"),
        ];
        transcript.extend(closing.clone());

        let result = compact_at(&transcript, 1);
        // 44 messages: head(2) + 40 filler + closing(2). Tail = the last KEEP_TAIL(12) messages,
        // which end with the two closing lines.
        assert_eq!(result.head, KEEP_HEAD, "the goal must survive");
        assert_eq!(result.tail, KEEP_TAIL, "the most recent window survives");
        assert_eq!(
            result.elided,
            44 - KEEP_HEAD - KEEP_TAIL,
            "the filler middle goes"
        );
        assert_eq!(result.messages.len(), KEEP_HEAD + 1 + KEEP_TAIL);

        // The head and the closing lines are literally the originals, and the marker openly owns the
        // elision, naming the count.
        assert_eq!(result.messages[..KEEP_HEAD], [transcript[0].clone(), goal]);
        assert_eq!(
            result.messages[result.messages.len() - closing.len()..],
            closing
        );
        let marker = result.messages[KEEP_HEAD].text();
        assert!(
            marker.contains("elided"),
            "the marker must say what happened: {marker}"
        );
        assert!(
            marker.contains(&result.elided.to_string()),
            "it must name the scale: {marker}"
        );
    }

    /// The estimate used to decide compaction is the same coarse heuristic the provider uses to
    /// reserve capacity, so a change to one side of the boundary cannot silently disagree with the
    /// other. This pins the seam rather than the exact number (which is a property of `hx-core`).
    #[test]
    fn the_decision_uses_the_same_estimate_as_the_provider_reservation() {
        // ~1000 tokens per long message (4 chars/token); enough of them (more than the head+tail
        // budget of 14) that the transcript can genuinely shrink. Choosing a threshold either side of the
        // ~20k total flips the decision.
        let mut under = vec![Message::system("go")];
        for _ in 0..20 {
            under.push(Message::user(format!("need: {}", "x".repeat(4000))));
        }
        // Total ~ 20k tokens.
        let whole = compact_at(&under, 100_000);
        assert_eq!(
            whole.messages.len(),
            under.len(),
            "under-threshold is the identity"
        );
        assert_eq!(whole.elided, 0);

        let shrunk = compact_at(&under, 100);
        assert!(
            shrunk.messages.len() < under.len(),
            "over-threshold must shrink, got {} of {}",
            shrunk.messages.len(),
            under.len()
        );
        assert!(shrunk.elided > 0, "something in the middle must be elided");
    }

    /// A tool call and its result are one inseparable pair in a transcript: splitting them across the
    /// compaction boundary produces a request most providers reject, and the downstream repair code
    /// (`Store::close_interrupted`) exists precisely because that shape is un-sendable. This pins the
    /// real guarantee: whenever compaction actually shrinks the transcript, the request it produces is
    /// still pair-safe — every retained call has its result, every retained result has its call. That
    /// is a property the request must hold regardless of which boundary cut, so it is tested on a
    /// transcript dense with pairs rather than on a hand-picked coordinate.
    #[test]
    fn compaction_never_splits_a_tool_call_from_its_result() {
        let mut transcript = vec![Message::system("be thorough"), Message::user("goal")];
        // A run of completed tool round-trips, then a long tail, so a middle is cut.
        for i in 0..30 {
            let id = hx_core::ids::ToolCallId::from_raw(format!("tc_{i}"));
            transcript.push(Message::new(
                Role::Assistant,
                vec![Part::ToolCall {
                    id: id.clone(),
                    name: "shell".into(),
                    arguments: serde_json::json!({"cmd": "x"}),
                }],
            ));
            transcript.push(Message::tool_result(id, true, "ok"));
        }
        for i in 0..20 {
            transcript.push(Message::assistant(format!("tail {i}")));
        }

        let result = compact_at(&transcript, 1);
        assert!(
            result.elided > 0,
            "a long over-threshold transcript must actually shrink"
        );
        assert!(
            is_pair_safe(&result.messages),
            "the compacted request must not split a call from its result"
        );
    }

    /// The head must back off, not end on a solo call. If the head window lands on an assistant
    /// message whose result is far away, keeping the head at the window size would hand the model a
    /// call it will never see answered. The only correct moves are to keep the pair or drop it as a
    /// unit — the head shrinks until the retained prefix is self-contained.
    #[test]
    fn a_head_that_would_end_on_a_solo_call_backs_off_to_a_whole_prefix() {
        let call_id = hx_core::ids::ToolCallId::from_raw("tc_h");
        let call = Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: call_id.clone(),
                name: "shell".into(),
                arguments: serde_json::json!({"cmd": "ls"}),
            }],
        );
        let result_msg = Message::tool_result(call_id, true, "hi");
        let mut transcript = vec![Message::system("be thorough"), call];
        // The call's result is far in the middle, so a head that kept both messages would end on the
        // call with its result out of reach.
        for _ in 0..20 {
            transcript.push(Message::assistant("filler"));
        }
        transcript.push(result_msg);
        transcript.push(Message::assistant("done"));

        let result = compact_at(&transcript, 1);
        assert!(
            result.elided > 0,
            "the transcript is long enough that compaction must shrink it"
        );
        assert!(
            is_pair_safe(&result.messages),
            "whatever the head kept, it must be self-contained"
        );
    }

    /// `compact_at(_, 0)` means "never compact": the plumbing stays in the loop but is switched
    /// off, so a deployment is not forced into a policy it did not ask for. The key default is
    /// non-zero exactly so silence means "compact", not "treat every transcript as too small".
    #[test]
    fn a_zero_threshold_disables_compaction_entirely() {
        let transcript = vec![Message::user("x".repeat(10_000))];
        let result = compact_at(&transcript, 0);
        assert_eq!(result.messages, transcript, "disabled must send everything");
        assert_eq!(result.elided, 0);
    }
}
