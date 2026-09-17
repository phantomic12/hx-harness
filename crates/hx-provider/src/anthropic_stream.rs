//! Reassembling Anthropic's event stream into the same `ChatResponse` a non-streaming call returns.
//!
//! ## Why this is not the OpenAI accumulator with different field names
//!
//! Anthropic streams *named* events, and the shape of a turn is carried by their order rather than by
//! a per-chunk delta: `message_start` opens it, each content block runs
//! `content_block_start` → `content_block_delta`* → `content_block_stop`, then one or more
//! `message_delta` carry cumulative usage, and `message_stop` closes it. Tool inputs are the part
//! that cannot be handled like text: the deltas are **partial JSON strings**
//! (`input_json_delta.partial_json`), and the docs are explicit that the object is only valid once
//! the block stops — so the fragments are accumulated as raw text and parsed at
//! `content_block_stop`, never per delta. Parsing a fragment would produce an error on almost every
//! tool call, and the failure would look like the model sending malformed arguments.
//!
//! ## What it tolerates, and why that is not laziness
//!
//! `ping` is documented as arbitrary and carries nothing. Unknown event types are explicitly
//! documented as possible as the API grows ("your code should handle unknown event types
//! gracefully"), so an unrecognised name is skipped rather than treated as an error — a harness that
//! broke on a new event name would break for reasons unrelated to anything it did.
//!
//! Usage is cumulative across `message_delta` events, so the last one seen wins rather than the
//! counts being summed; summing them would overstate the turn's cost.

use crate::provider::{ChatResponse, FinishReason, Usage};
use hx_core::error::{HxError, Result};
use hx_core::ids::ToolCallId;
use hx_core::message::{Message, Part, Role};
use serde_json::{json, Value};

use crate::provider::StreamDelta;

/// A content block being assembled.
#[derive(Clone, Debug, Default)]
struct Block {
    kind: String,
    /// Text of a `text` block, or the raw `partial_json` of a `tool_use` block.
    ///
    /// One field for both because they are the same operation — concatenate what arrives — and the
    /// only difference is whether the result is handed on as text or parsed as JSON at the stop.
    buffer: String,
    id: Option<String>,
    name: Option<String>,
}

/// The turn so far, built from the events seen.
#[derive(Clone, Debug, Default)]
pub struct StreamAccumulator {
    /// Text blocks, concatenated in order.
    pub text: String,
    /// Reasoning, when the vendor sends thinking blocks separately.
    pub reasoning: String,
    /// Finished tool calls, as `{id, name, input}` the way `parse_response` produces them.
    pub calls: Vec<Value>,
    /// The blocks currently open, by index. Anthropic indexes them explicitly, and an index is what
    /// tells a tool fragment which call it belongs to when a turn uses several.
    open: std::collections::BTreeMap<i64, Block>,
    /// The model that actually served the turn, from `message_start`.
    pub model: String,
    /// Cumulative usage; the last value seen wins.
    pub usage: Usage,
    /// Why the turn stopped, from `message_delta`.
    pub stop_reason: Option<String>,
    /// Set when the stream carried an `error` event: the turn failed mid-flight.
    pub error: Option<String>,
}

/// Fold one streamed event into the accumulator and report what it contributed.
///
/// Returns a `Result` because one thing here really can fail: a `tool_use` block whose accumulated
/// arguments do not parse as JSON. Reporting that as an error is deliberate — a tool call with
/// silently-empty arguments would run the wrong command, which is worse than stopping.
pub fn apply_event(
    acc: &mut StreamAccumulator,
    event_name: &str,
    data: &Value,
) -> Result<Vec<StreamDelta>> {
    let mut out = Vec::new();

    // The event name and the `type` field are documented as matching, but the data is what carries
    // the payload, so the dispatch is on whichever is present rather than assuming they agree.
    let kind = data
        .get("type")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
        .unwrap_or(event_name);

    match kind {
        "message_start" => {
            if let Some(model) = data
                .get("message")
                .and_then(|m| m.get("model"))
                .and_then(Value::as_str)
            {
                acc.model = model.to_string();
            }
            // A message_start may already report input tokens; the later message_delta reports the
            // fuller, cumulative figure and overwrites this.
            if let Some(usage) = data.get("message").and_then(|m| m.get("usage")) {
                acc.usage = read_usage(usage);
            }
        }

        "content_block_start" => {
            let index = data.get("index").and_then(Value::as_i64).unwrap_or(0);
            let block = data.get("content_block").cloned().unwrap_or(Value::Null);
            let block_kind = block
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            let mut entry = Block {
                kind: block_kind.clone(),
                ..Default::default()
            };
            match block_kind.as_str() {
                "text" => {
                    // A block that opens with text already in it is unusual but valid; taking it
                    // here means no leading characters are lost.
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            entry.buffer.push_str(text);
                            acc.text.push_str(text);
                            out.push(StreamDelta::Text(text.to_string()));
                        }
                    }
                }
                "tool_use" => {
                    entry.id = block.get("id").and_then(Value::as_str).map(str::to_string);
                    entry.name = block
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    // The docs note a `tool_use` start can arrive with a partial `input` already
                    // present; nothing here depends on it, and the deltas carry the rest.
                }
                "thinking" | "redacted_thinking" => {}
                // An unfamiliar block type is opened and ignored rather than rejected: the API may
                // add block types, and refusing to run for an unrecognised one would be a harness
                // failure caused by a vendor improvement.
                _ => {}
            }
            acc.open.insert(index, entry);
        }

        "content_block_delta" => {
            let index = data.get("index").and_then(Value::as_i64).unwrap_or(0);
            let delta = data.get("delta").cloned().unwrap_or(Value::Null);
            let delta_type = delta.get("type").and_then(Value::as_str).unwrap_or("");

            match delta_type {
                "text_delta" => {
                    if let Some(text) = delta.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            if let Some(block) = acc.open.get_mut(&index) {
                                block.buffer.push_str(text);
                            }
                            acc.text.push_str(text);
                            out.push(StreamDelta::Text(text.to_string()));
                        }
                    }
                }
                "thinking_delta" => {
                    if let Some(text) = delta.get("thinking").and_then(Value::as_str) {
                        if !text.is_empty() {
                            acc.reasoning.push_str(text);
                            out.push(StreamDelta::Reasoning(text.to_string()));
                        }
                    }
                }
                "input_json_delta" => {
                    // Accumulate the raw fragment. It is deliberately NOT parsed here: a partial JSON
                    // string is almost never valid on its own, so parsing per delta would fail on
                    // nearly every tool call and look like the model sending broken arguments.
                    if let Some(partial) = delta.get("partial_json").and_then(Value::as_str) {
                        if let Some(block) = acc.open.get_mut(&index) {
                            block.buffer.push_str(partial);
                        }
                    }
                }
                // A new delta type is ignored rather than fatal, for the same reason as an unknown
                // block type.
                _ => {}
            }
        }

        "content_block_stop" => {
            let index = data.get("index").and_then(Value::as_i64).unwrap_or(0);
            if let Some(block) = acc.open.remove(&index) {
                if block.kind == "tool_use" {
                    let id = block.id.clone().unwrap_or_else(|| format!("call_{index}"));
                    let name = block.name.clone().unwrap_or_default();
                    // The block has stopped, so the accumulated JSON is complete. An empty buffer
                    // means a call with no arguments, which is legitimate; anything else that does
                    // not parse is a real error and is reported rather than silently becoming null,
                    // because a tool call with silently-empty arguments would run the wrong thing.
                    let input = if block.buffer.trim().is_empty() {
                        json!({})
                    } else {
                        serde_json::from_str(&block.buffer).map_err(|err| {
                            HxError::Provider(format!(
                                "tool_use block {id} ({name}) finished with arguments that are not \
                                 valid JSON: {err}. The accumulated text was: {}",
                                truncate(&block.buffer)
                            ))
                        })?
                    };
                    acc.calls
                        .push(json!({ "id": id, "name": name, "input": input }));
                    out.push(StreamDelta::ToolCall {
                        id: id.clone(),
                        name,
                        arguments: acc
                            .calls
                            .last()
                            .and_then(|c| c.get("input"))
                            .cloned()
                            .unwrap_or(Value::Null),
                    });
                }
            }
        }

        "message_delta" => {
            // Cumulative, so the last one wins: summing these would overstate the turn's cost.
            if let Some(usage) = data.get("usage") {
                let reported = read_usage(usage);
                acc.usage = Usage {
                    input_tokens: if reported.input_tokens > 0 {
                        reported.input_tokens
                    } else {
                        acc.usage.input_tokens
                    },
                    output_tokens: if reported.output_tokens > 0 {
                        reported.output_tokens
                    } else {
                        acc.usage.output_tokens
                    },
                    ..acc.usage
                };
            }
            if let Some(reason) = data
                .get("delta")
                .and_then(|d| d.get("stop_reason"))
                .and_then(Value::as_str)
            {
                acc.stop_reason = Some(reason.to_string());
            }
        }

        "error" => {
            // Documented mid-stream failure (an overload is the usual one). Recorded so the caller
            // raises it rather than returning a short answer as if the model had finished.
            acc.error = Some(
                data.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("the provider sent an error event")
                    .to_string(),
            );
        }

        // `message_stop` ends the turn and carries nothing; `ping` is documented as carrying
        // nothing; anything else is a name this client does not know yet.
        _ => {}
    }

    Ok(out)
}

/// Take one complete SSE frame off `pending`, if there is one.
///
/// A frame ends at a blank line. `event:` and `data:` lines are read in any order, and the payload is
/// built from the `data:` lines joined with newlines, which is what the spec says a multi-line `data:`
/// field means. Returns `None` when no complete frame is buffered yet, leaving the partial text in
/// place for the next read — a frame split across two TCP segments must never be parsed in halves,
/// because half a JSON object is a parse error that reads like a provider fault.
pub fn take_sse_frame(pending: &mut String) -> Option<(String, Value)> {
    // Tolerate CRLF as well as LF: a proxy that terminates lines with CRLF would otherwise buffer
    // every event forever with no error at all.
    let find_terminator = |text: &str| -> Option<(usize, usize)> {
        if let Some(i) = text.find("\n\n") {
            return Some((i, 2));
        }
        if let Some(i) = text.find("\r\n\r\n") {
            return Some((i, 4));
        }
        None
    };

    let (index, width) = find_terminator(pending)?;
    let frame: String = pending.drain(..index + width).collect();
    parse_frame(&frame)
}

/// A frame at the end of a stream that never sent its terminating blank line.
pub fn take_trailing_frame(pending: &mut String) -> Option<(String, Value)> {
    let rest = std::mem::take(pending);
    parse_frame(&rest)
}

/// Parse one SSE frame's text into its event name and payload.
///
/// `None` when the frame carries no `data:` at all — a `ping` or a comment has nothing to apply.
fn parse_frame(frame: &str) -> Option<(String, Value)> {
    let mut event = String::new();
    let mut data = Vec::new();

    for line in frame.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with(':') {
            continue; // a comment, which is what a keepalive is
        }
        match line.split_once(':') {
            Some((field, value)) => {
                let value = value.strip_prefix(' ').unwrap_or(value);
                match field {
                    "event" => event = value.to_string(),
                    "data" => data.push(value.to_string()),
                    _ => {}
                }
            }
            None => continue,
        }
    }

    if data.is_empty() {
        return None;
    }
    let payload = data.join("\n");
    // A frame whose data is not JSON is skipped rather than fatal: the API documents that unknown
    // events may appear, and failing a run because a new one did would be a harness bug.
    let parsed = serde_json::from_str(&payload).ok()?;
    Some((event, parsed))
}

/// Read whichever usage field names the payload uses.
///
/// Anthropic reports `input_tokens`/`output_tokens`; the cache-related counters are added to the
/// stored totals so a turn's cost is not understated when caching is in play. A missing field is
/// zero rather than an error: usage is reporting, and a provider that omits it should not fail a run.
fn read_usage(value: &Value) -> Usage {
    let get = |name: &str| value.get(name).and_then(Value::as_u64).unwrap_or(0);
    Usage {
        input_tokens: get("input_tokens"),
        output_tokens: get("output_tokens"),
        cached_input_tokens: get("cache_read_input_tokens"),
        ..Default::default()
    }
}

/// Finish the accumulated turn into the same shape a non-streaming call returns.
///
/// Refuses an empty turn. A stream that produced no text and no tool calls is a failure, not an
/// empty success: returning a blank assistant message would have the loop continue against nothing
/// and look like the model refusing to answer.
pub fn finish_stream(acc: StreamAccumulator, requested_model: &str) -> Result<ChatResponse> {
    if let Some(message) = acc.error {
        return Err(HxError::Provider(message));
    }

    let mut parts: Vec<Part> = Vec::new();
    if !acc.text.is_empty() {
        parts.push(Part::text(&acc.text));
    }
    for call in &acc.calls {
        let id = call.get("id").and_then(Value::as_str).unwrap_or("call");
        let name = call.get("name").and_then(Value::as_str).unwrap_or("");
        parts.push(Part::ToolCall {
            id: ToolCallId::from_raw(id),
            name: name.to_string(),
            arguments: call.get("input").cloned().unwrap_or(Value::Null),
        });
    }

    if parts.is_empty() {
        return Err(HxError::Provider(
            "the streamed turn contained neither text nor a tool call, so there is no reply to \
             return"
                .to_string(),
        ));
    }

    let finish = match acc.stop_reason.as_deref() {
        Some("tool_use") => FinishReason::ToolUse,
        Some("max_tokens") => FinishReason::Length,
        // `end_turn`, `stop_sequence`, and a missing reason all mean the model finished on its own.
        // An unrecognised reason is treated the same way rather than being an error: the reply is
        // complete either way, and failing a run over a new stop reason name would be a harness bug.
        _ => FinishReason::Stop,
    };

    Ok(ChatResponse {
        message: Message::new(Role::Assistant, parts),
        usage: acc.usage,
        finish,
        model: if acc.model.is_empty() {
            requested_model.to_string()
        } else {
            acc.model
        },
        raw: None,
    })
}

fn truncate(text: &str) -> String {
    const LIMIT: usize = 400;
    if text.len() <= LIMIT {
        return text.to_string();
    }
    let mut end = LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a sequence of `(event_name, data)` pairs, as the adapter does for a real stream.
    fn feed(events: &[(&str, Value)]) -> (StreamAccumulator, Vec<StreamDelta>) {
        let mut acc = StreamAccumulator::default();
        let mut deltas = Vec::new();
        for (name, data) in events {
            deltas.extend(apply_event(&mut acc, name, data).expect("these events are well formed"));
        }
        (acc, deltas)
    }

    fn text_stream() -> Vec<(&'static str, Value)> {
        vec![
            (
                "message_start",
                json!({"type":"message_start","message":{"id":"msg_1","model":"claude-opus-5",
                       "usage":{"input_tokens":11,"output_tokens":1}}}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":", world"}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":0}),
            ),
            (
                "message_delta",
                json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},
                       "usage":{"output_tokens":7}}),
            ),
            ("message_stop", json!({"type":"message_stop"})),
        ]
    }

    #[test]
    fn a_text_turn_emits_deltas_in_order_and_builds_the_reply() {
        let (acc, deltas) = feed(&text_stream());
        let texts: Vec<String> = deltas
            .iter()
            .filter_map(|d| match d {
                StreamDelta::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, vec!["Hello".to_string(), ", world".to_string()]);

        let response = finish_stream(acc, "requested").unwrap();
        assert_eq!(response.message.text(), "Hello, world");
        assert_eq!(response.finish, FinishReason::Stop);
        assert_eq!(
            response.model, "claude-opus-5",
            "the serving model is reported"
        );
        assert_eq!(response.usage.input_tokens, 11);
        assert_eq!(
            response.usage.output_tokens, 7,
            "the later, fuller count wins"
        );
    }

    #[test]
    fn usage_is_not_summed_across_message_delta_events() {
        // The docs state these counts are cumulative. Adding them would overstate a turn's cost,
        // and the error would grow with the length of the reply — the kind of number nobody checks.
        let (_acc, _) = feed(&text_stream());
        let (acc, _) = feed(&[
            (
                "message_start",
                json!({"type":"message_start","message":{"model":"m","usage":{"input_tokens":10,"output_tokens":1}}}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":0}),
            ),
            (
                "message_delta",
                json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}),
            ),
            (
                "message_delta",
                json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9}}),
            ),
        ]);
        assert_eq!(
            acc.usage.output_tokens, 9,
            "the last cumulative value, not 5+9"
        );
    }

    #[test]
    fn a_tool_call_whose_arguments_arrive_in_fragments_is_assembled_once() {
        // The single most likely thing to get wrong. Anthropic sends `input_json_delta` with a
        // *partial JSON string*; parsing each fragment would fail on almost every call.
        let (acc, deltas) = feed(&[
            (
                "message_start",
                json!({"type":"message_start","message":{"model":"m","usage":{"input_tokens":9,"output_tokens":1}}}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":0,
                       "content_block":{"type":"tool_use","id":"toolu_1","name":"read_file","input":{}}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,
                       "delta":{"type":"input_json_delta","partial_json":"{\"pa"}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,
                       "delta":{"type":"input_json_delta","partial_json":"th\": \"Ca"}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,
                       "delta":{"type":"input_json_delta","partial_json":"rgo.toml\"}"}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":0}),
            ),
            (
                "message_delta",
                json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":12}}),
            ),
            ("message_stop", json!({"type":"message_stop"})),
        ]);

        assert_eq!(
            acc.calls.len(),
            1,
            "three fragments make one call, not three"
        );
        let call = &acc.calls[0];
        assert_eq!(call["id"], "toolu_1");
        assert_eq!(call["name"], "read_file");
        assert_eq!(call["input"]["path"], "Cargo.toml");

        // No delta is emitted until the block stops, because until then the arguments are not JSON.
        let tool_deltas = deltas
            .iter()
            .filter(|d| matches!(d, StreamDelta::ToolCall { .. }))
            .count();
        assert_eq!(tool_deltas, 1, "exactly one finished call");

        let response = finish_stream(acc, "requested").unwrap();
        assert_eq!(response.finish, FinishReason::ToolUse);
    }

    #[test]
    fn a_tool_call_with_no_arguments_is_an_empty_object_not_an_error() {
        // A call that takes nothing is legitimate; treating an empty buffer as malformed JSON would
        // refuse to run a perfectly valid tool.
        let (acc, _) = feed(&[
            (
                "content_block_start",
                json!({"type":"content_block_start","index":0,
                       "content_block":{"type":"tool_use","id":"toolu_2","name":"list_sessions","input":{}}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":0}),
            ),
        ]);
        assert_eq!(acc.calls[0]["input"], json!({}));
    }

    #[test]
    fn arguments_that_never_become_json_are_an_error_rather_than_empty_ones() {
        // The failure mode this guards: a call with silently-empty arguments runs the wrong thing.
        // Better to stop the run than to execute a tool with arguments nobody chose.
        let mut acc = StreamAccumulator::default();
        apply_event(
            &mut acc,
            "content_block_start",
            &json!({"type":"content_block_start","index":0,
                    "content_block":{"type":"tool_use","id":"toolu_3","name":"shell","input":{}}}),
        )
        .unwrap();
        apply_event(
            &mut acc,
            "content_block_delta",
            &json!({"type":"content_block_delta","index":0,
                    "delta":{"type":"input_json_delta","partial_json":"{\"command\": "}}),
        )
        .unwrap();

        let err = apply_event(
            &mut acc,
            "content_block_stop",
            &json!({"type":"content_block_stop","index":0}),
        )
        .expect_err("truncated JSON must not become a successful call");
        let message = format!("{err}");
        assert!(message.contains("not valid JSON"), "{message}");
        assert!(message.contains("toolu_3"), "names the call: {message}");
    }

    #[test]
    fn two_tool_calls_in_one_turn_stay_separate() {
        // An index is what tells one call's fragments from another's; ignoring it would interleave
        // two calls into one nonsense call.
        let (acc, _) = feed(&[
            (
                "content_block_start",
                json!({"type":"content_block_start","index":0,
                       "content_block":{"type":"tool_use","id":"a","name":"read_file","input":{}}}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":1,
                       "content_block":{"type":"tool_use","id":"b","name":"shell","input":{}}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,
                       "delta":{"type":"input_json_delta","partial_json":"{\"path\":\"A\"}"}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":1,
                       "delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":0}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":1}),
            ),
        ]);

        assert_eq!(acc.calls.len(), 2);
        assert_eq!(acc.calls[0]["id"], "a");
        assert_eq!(acc.calls[0]["input"]["path"], "A");
        assert_eq!(acc.calls[1]["id"], "b");
        assert_eq!(acc.calls[1]["input"]["command"], "ls");
    }

    #[test]
    fn ping_and_unknown_events_are_ignored_rather_than_fatal() {
        // The docs say pings are arbitrary and that new event types may appear, and that code
        // should handle unknown ones gracefully. Failing a run over an unfamiliar name would be a
        // harness failure caused by a vendor improvement.
        let mut acc = StreamAccumulator::default();
        for (name, data) in [
            ("ping", json!({"type":"ping"})),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"x"}}),
            ),
            (
                "some_future_event",
                json!({"type":"some_future_event","whatever":1}),
            ),
        ] {
            let deltas = apply_event(&mut acc, name, &data).expect("unknown events are not errors");
            assert!(deltas.is_empty(), "{name} contributed {deltas:?}");
        }
    }

    #[test]
    fn a_stream_error_event_is_raised_rather_than_returned_as_a_short_answer() {
        // An overload arrives mid-stream, after a 200. Returning the partial text as a finished
        // reply would look like the model chose to stop early.
        let (_acc, _) = feed(&text_stream());
        let (acc, _) = feed(&[
            (
                "message_start",
                json!({"type":"message_start","message":{"model":"m","usage":{"input_tokens":1,"output_tokens":1}}}),
            ),
            (
                "error",
                json!({"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}),
            ),
        ]);
        let err = finish_stream(acc, "requested").expect_err("an error event is not a reply");
        assert!(format!("{err}").contains("Overloaded"), "{err}");
    }

    #[test]
    fn an_empty_turn_is_an_error_rather_than_a_blank_reply() {
        let acc = StreamAccumulator::default();
        assert!(finish_stream(acc, "requested").is_err());
    }

    #[test]
    fn frames_are_assembled_across_split_reads_and_crlf_terminates_them() {
        // A frame split across two TCP reads must not be parsed in halves, and a proxy that
        // terminates lines with CRLF must not cause every event to buffer forever.
        let mut pending = String::new();
        pending.push_str("event: content_block_delta\ndata: {\"type\":\"content_bl");
        assert!(
            take_sse_frame(&mut pending).is_none(),
            "half a frame is not a frame"
        );

        pending.push_str(
            "ock_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
        );
        let (name, data) = take_sse_frame(&mut pending).expect("the frame completes");
        assert_eq!(name, "content_block_delta");
        assert_eq!(data["delta"]["text"], "hi");

        pending.push_str("event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n");
        let (name, _) = take_sse_frame(&mut pending).expect("CRLF terminates a frame too");
        assert_eq!(name, "message_stop");
    }

    #[test]
    fn a_trailing_frame_without_a_blank_line_is_still_applied() {
        // A stream that ends without the final blank line would otherwise lose its last event.
        let mut pending =
            String::from("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}");
        let (name, data) =
            take_trailing_frame(&mut pending).expect("the last frame is not dropped");
        assert_eq!(name, "message_delta");
        assert_eq!(data["delta"]["stop_reason"], "end_turn");
        assert!(pending.is_empty(), "the buffer is consumed");
    }

    #[test]
    fn a_keepalive_comment_carries_no_frame() {
        let mut pending = String::from(": keepalive\n\n");
        assert!(take_sse_frame(&mut pending).is_none());
    }
}
