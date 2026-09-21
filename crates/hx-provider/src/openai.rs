//! The OpenAI-compatible chat-completions adapter.
//!
//! One adapter, most of the market: OpenAI itself, Azure OpenAI, OpenRouter, Together, Groq,
//! Fireworks, DeepSeek, vLLM, llama.cpp's server, Ollama's compatibility endpoint, LiteLLM and
//! essentially every gateway. That is why it is the first one written.
//!
//! ## Shape
//!
//! The wire mapping lives in two pure functions — [`build_body`] and [`parse_response`] — and only
//! [`OpenAiCompatible::complete`] touches the network. Provider quirks that would otherwise leak
//! into the agent loop (arguments arrive as a JSON *string*, `finish_reason` has vendor-specific
//! spellings, usage has nested detail objects) are normalised here, once, where they can be
//! asserted against literals.
//!
//! ## What is deliberately not supported yet
//!
//! Image parts and tool-choice control. Each is a real feature rather than a hypothetical, and each
//! fails loudly instead of being silently dropped: an image part is an error naming the adapter, not a
//! message that quietly loses its picture. Streaming is **supported**: [`OpenAiCompatible::stream`]
//! upgrades the request to `stream: true` and replays the vendor's SSE chunks as
//! [`crate::StreamDelta`], folding unmerged tool-call fragments with the same rule
//! [`merge_tool_call_fragments`] uses for a single-shot body.

use crate::provider::{
    ChatRequest, ChatResponse, FinishReason, Provider, StreamDelta, ToolSpec, Usage,
};
use futures::StreamExt;
use hx_core::config::ProviderKind;
use hx_core::error::{HxError, Result};
use hx_core::ids::{ProviderId, ToolCallId};
use hx_core::message::{Message, Part, Role};
use hx_secrets::Secret;
use serde_json::{json, Value};
use std::time::Duration;

/// How much of an error body to keep. Provider error pages are sometimes HTML novels, and the
/// interesting part is always the first line.
const ERROR_BODY_LIMIT: usize = 512;

/// A `/v1/chat/completions` endpoint.
pub struct OpenAiCompatible {
    id: ProviderId,
    models: Vec<String>,
    base_url: String,
    client: reqwest::Client,
    /// Whether to send `Authorization: Bearer`. Local servers (llama.cpp, vLLM without auth) accept
    /// — and some reject — the header, so it is explicit rather than always-on.
    send_auth: bool,
}

impl OpenAiCompatible {
    /// `base_url` is the API root, e.g. `https://api.openai.com/v1`.
    pub fn new(
        id: ProviderId,
        base_url: impl Into<String>,
        models: Vec<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            id,
            models,
            base_url: base_url.into(),
            client,
            send_auth: true,
        }
    }

    /// For an endpoint that does not authenticate (a local llama.cpp server, typically).
    pub fn without_auth(mut self) -> Self {
        self.send_auth = false;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn complete_raw(&self, req: &ChatRequest, key: &Secret) -> Result<ChatResponse> {
        let url = chat_completions_url(&self.base_url);
        let body = build_body(req)?;

        let mut request = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body);

        if self.send_auth {
            request = request.bearer_auth(key.expose());
        }

        let response = request.send().await.map_err(|err| {
            // A transport failure is worth its own message: "the endpoint is unreachable" and "the
            // endpoint answered 500" are different problems for whoever is on call.
            if err.is_timeout() {
                HxError::Provider(format!(
                    "{}: request to {url} timed out after {:?}",
                    self.id, err
                ))
            } else {
                HxError::Provider(format!("{}: could not reach {url}: {err}", self.id))
            }
        })?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());

        let text = response
            .text()
            .await
            .unwrap_or_else(|err| format!("<the response body could not be read: {err}>"));

        if !status.is_success() {
            return Err(classify_error(
                &self.id,
                status.as_u16(),
                retry_after,
                &text,
            ));
        }

        let parsed: Value = serde_json::from_str(&text).map_err(|err| {
            HxError::Provider(format!(
                "{}: the response was not JSON ({err}); body: {}",
                self.id,
                truncate(&text)
            ))
        })?;

        parse_response(&parsed, &req.model)
    }
}

#[async_trait::async_trait]
impl Provider for OpenAiCompatible {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn kind(&self) -> ProviderKind {
        ProviderKind::Openai
    }

    fn models(&self) -> &[String] {
        &self.models
    }

    async fn complete(&self, req: ChatRequest, key: &Secret) -> Result<ChatResponse> {
        self.complete_raw(&req, key).await
    }

    async fn stream(
        &self,
        req: ChatRequest,
        key: &Secret,
        on_delta: &mut (dyn FnMut(StreamDelta) -> Result<()> + Send),
    ) -> Result<ChatResponse> {
        let url = chat_completions_url(&self.base_url);
        let body = stream_body(&req)?;

        let mut request = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body.to_string());

        if self.send_auth {
            request = request.bearer_auth(key.expose());
        }

        let response = request.send().await.map_err(|err| {
            if err.is_timeout() {
                HxError::Provider(format!(
                    "{}: request to {url} timed out after {:?}",
                    self.id, err
                ))
            } else {
                HxError::Provider(format!("{}: could not reach {url}: {err}", self.id))
            }
        })?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());

        if !status.is_success() {
            let text = response
                .text()
                .await
                .unwrap_or_else(|err| format!("<could not read: {err}>"));
            return Err(classify_error(
                &self.id,
                status.as_u16(),
                retry_after,
                &text,
            ));
        }

        // Every `data:` line is one chunk; `data: [DONE]` closes the stream. A chunk may be
        // split across TCP segments, so each chunk object is accumulated whole before being parsed.
        // Two details keep this loop honest rather than merely working against a local server:
        // bytes are decoded incrementally (a multi-byte character split across reads must not
        // become U+FFFD scars), and `done` propagates the terminal `[DONE]` marker out of the
        // inner framing loop — a proxy that holds the connection open past `[DONE]` would
        // otherwise hang this request until the 120 s timeout.
        let mut accumulator = StreamAccumulator::default();
        let mut decoder = crate::sse::Utf8StreamDecoder::new();
        let mut raw = String::new();
        let mut bytes = response.bytes_stream();
        let mut done = false;
        while !done {
            let Some(part) = bytes.next().await else {
                break;
            };
            let part = part.map_err(|err| {
                HxError::Provider(format!("{}: the stream was interrupted: {err}", self.id))
            })?;
            raw.push_str(&decoder.push(&part));
            while let Some(event) = take_sse_event(&mut raw) {
                if feed_event(&mut accumulator, &self.id, event, on_delta)? {
                    done = true;
                    break;
                }
            }
        }
        // Flush the decoder (a vendor should not end mid-character, but a truncated connection
        // might) and drain whatever framed or trailing events remain.
        raw.push_str(&decoder.finish());
        while let Some(event) = take_sse_event(&mut raw) {
            if feed_event(&mut accumulator, &self.id, event, on_delta)? {
                done = true;
                break;
            }
        }
        if !done {
            if let Some(event) = take_trailing_sse_event(&mut raw) {
                feed_event(&mut accumulator, &self.id, event, on_delta)?;
            }
        }

        let response = finish_stream(&self.id, &accumulator, &req.model)?;
        Ok(response)
    }
}

/// The request body for a streaming call: the non-streaming body with `stream: true`.
///
/// Built from [`build_body`] rather than duplicated, so the two paths cannot drift on message
/// shaping. Two deliberate differences beyond the stream flag: `stream_options.include_usage`
/// asks the vendor to send the terminal usage chunk — without it the stream carries no token
/// counts at all and `finish_stream` can only report zeros, which silently breaks cost
/// accounting and limiter reconciliation downstream.
fn stream_body(req: &ChatRequest) -> Result<Value> {
    let mut body = build_body(req)?;
    body["stream"] = Value::Bool(true);
    body["stream_options"] = json!({ "include_usage": true });
    Ok(body)
}

/// The accumulated, in-flight state of one streamed turn.
///
/// Pure by design: [`apply_chunk`] mutates this and returns the deltas to emit, so the
/// vendor's chunk shape is asserted against literals rather than only discovered across a socket.
#[derive(Default)]
pub struct StreamAccumulator {
    /// The text so far, concatenated in order. Not emitted here; the deltas carry the pieces.
    pub text: String,
    /// The reasoning/text-in-thinking so far, if the vendor sends it separately.
    pub reasoning: String,
    /// Tool-call fragments, in arrival order. Merged by [`merge_tool_call_fragments`] when a
    /// call finishes, using the same rule a single-shot body uses.
    pub calls: Vec<Value>,
    /// Whether the turn ended with a tool call.
    pub tool_use: bool,
    /// Token counts from the terminal usage chunk (`stream_options.include_usage` asks the
    /// vendor to send one). Stays zero when the vendor never sends usage rather than failing
    /// the turn — usage is reporting, and a provider that omits it should not fail a run.
    pub usage: Usage,
}

/// Parse a vendor chunk and return the deltas it contributes.
pub fn apply_chunk(acc: &mut StreamAccumulator, chunk: &Value) -> Vec<StreamDelta> {
    let mut out = Vec::new();
    // The terminal usage chunk carries `usage` and usually *no* choices at all, so it is read
    // before the early return below — otherwise `finish_stream` never sees any token counts.
    if let Some(usage) = chunk.get("usage") {
        acc.usage = merge_stream_usage(&acc.usage, usage);
    }
    let Some(choice) = chunk.get("choices").and_then(|c| c.get(0)) else {
        return out;
    };

    if let Some(content) = choice
        .get("delta")
        .and_then(|d| d.get("content"))
        .and_then(Value::as_str)
    {
        if !content.is_empty() {
            acc.text.push_str(content);
            out.push(StreamDelta::Text(content.to_string()));
        }
    }

    if let Some(reasoning) = choice
        .get("delta")
        .and_then(|d| d.get("reasoning_content"))
        .and_then(Value::as_str)
    {
        if !reasoning.is_empty() {
            acc.reasoning.push_str(reasoning);
            out.push(StreamDelta::Reasoning(reasoning.to_string()));
        }
    }

    // Tool-call fragments are accumulated, not emitted, then merged and emitted whole when the call
    // finishes. A fragment's `arguments` is itself a piece of the final JSON; the whole arguments
    // string is only valid after every fragment for that call has arrived.
    if let Some(calls) = choice
        .get("delta")
        .and_then(|d| d.get("tool_calls"))
        .and_then(Value::as_array)
    {
        acc.calls.extend(calls.iter().cloned());
    }

    if let Some(finish) = choice.get("finish_reason").and_then(Value::as_str) {
        if finish == "tool_calls" {
            acc.tool_use = true;
            for call in merge_tool_call_fragments(&acc.calls) {
                if call.id.is_empty() || call.name.is_empty() {
                    continue;
                }
                let arguments = match serde_json::from_str::<Value>(call.arguments.as_str()) {
                    Ok(value) => value,
                    Err(_) => json!({ "__malformed_arguments": call.arguments }),
                };
                out.push(StreamDelta::ToolCall {
                    id: call.id,
                    name: call.name,
                    arguments,
                });
            }
        }
    }

    out
}

/// Assemble the whole reply from a finished accumulator.
///
/// Reachable from every streaming path that does not go through the network, which is what makes the
/// provider layer's streamed turn *also* return a full [`ChatResponse`]: a live client gets the
/// deltas and the store still gets the transcript row.
fn finish_stream(
    id: &ProviderId,
    acc: &StreamAccumulator,
    requested_model: &str,
) -> Result<ChatResponse> {
    let mut parts = Vec::new();
    if !acc.text.is_empty() {
        parts.push(Part::text(acc.text.clone()));
    }
    if acc.tool_use {
        for call in merge_tool_call_fragments(&acc.calls) {
            let arguments = match serde_json::from_str::<Value>(call.arguments.as_str()) {
                Ok(value) => value,
                Err(_) => json!({ "__malformed_arguments": call.arguments }),
            };
            parts.push(Part::ToolCall {
                id: ToolCallId::from_raw(call.id),
                name: call.name,
                arguments,
            });
        }
    }
    if parts.is_empty() {
        return Err(HxError::Provider(format!(
            "{id}: the streamed turn produced neither text nor a tool call"
        )));
    }

    let finish = if acc.tool_use {
        FinishReason::ToolUse
    } else {
        FinishReason::Stop
    };

    Ok(ChatResponse {
        message: Message::new(Role::Assistant, parts),
        usage: acc.usage,
        finish,
        model: requested_model.to_string(),
        raw: None,
    })
}

/// Fold a streamed `usage` object into the running totals.
///
/// Field-by-field with "reported non-zero wins" rather than a wholesale overwrite: the usage
/// chunk is normally terminal and complete, but a vendor that sends partial usage objects
/// (prompt tokens on one chunk, completion tokens on another) must still end up with the full
/// picture instead of the last partial object clobbering the earlier fields.
fn merge_stream_usage(into: &Usage, reported: &Value) -> Usage {
    // Each field keeps the largest value seen: the usage chunk is normally terminal and
    // complete, but a vendor that splits usage across chunks (prompt tokens on one,
    // completion tokens on another) must still end with the full picture rather than the
    // last partial object clobbering earlier fields with zeros.
    let best = |old: u64, fresh: u64| old.max(fresh);
    let details = |obj: &str, field: &str| number(reported.get(obj).unwrap_or(&Value::Null), field);
    Usage {
        input_tokens: best(into.input_tokens, number(reported, "prompt_tokens")),
        output_tokens: best(into.output_tokens, number(reported, "completion_tokens")),
        // Detail objects nest the way the non-streaming response spells them
        // (`prompt_tokens_details.cached_tokens`); a flat `cached_tokens` is accepted too
        // because some gateways hoist it.
        cached_input_tokens: into
            .cached_input_tokens
            .max(number(reported, "cached_tokens"))
            .max(details("prompt_tokens_details", "cached_tokens")),
        reasoning_tokens: into
            .reasoning_tokens
            .max(number(reported, "reasoning_tokens"))
            .max(details("completion_tokens_details", "reasoning_tokens")),
    }
}

/// One framed SSE event from an OpenAI-compatible stream.
#[derive(Debug, PartialEq, Eq)]
enum SseEvent {
    /// A JSON payload to parse into a chunk.
    Data(String),
    /// The terminal `data: [DONE]` marker. The vendor will send nothing more after it, and the
    /// outer read loop must stop on it rather than wait for EOF — a proxy that holds the
    /// connection open past `[DONE]` would otherwise hang the request until the timeout.
    Done,
}

/// Apply one framed event: parse a data payload into deltas, or report terminal state.
///
/// Returns `true` when the stream is over (`[DONE]`), which the caller propagates to the outer
/// read loop. Keepalive comments arrive as empty data and are skipped, not parsed — asking
/// serde for the meaning of nothing is an error nobody needs.
fn feed_event(
    acc: &mut StreamAccumulator,
    id: &ProviderId,
    event: SseEvent,
    on_delta: &mut (dyn FnMut(StreamDelta) -> Result<()> + Send),
) -> Result<bool> {
    let line = match event {
        SseEvent::Done => return Ok(true),
        SseEvent::Data(line) => line,
    };
    if line.is_empty() {
        return Ok(false);
    }
    let chunk: Value = match serde_json::from_str(&line) {
        Ok(chunk) => chunk,
        Err(err) => {
            return Err(HxError::Provider(format!(
                "{id}: a streamed chunk was not JSON ({err}): {}",
                truncate(&line)
            )))
        }
    };
    for delta in apply_chunk(acc, &chunk) {
        on_delta(delta)?;
    }
    Ok(false)
}

/// Pull the next complete SSE event out of a buffer.
///
/// Events end at a blank line, spelled `\n\n` or `\r\n\r\n` — a proxy that terminates lines
/// with CRLF would otherwise buffer every event forever with no error at all. Within an event,
/// comment lines (`: keepalive`) are skipped and multiple `data:` lines are joined with newlines,
/// which is what the SSE spec says a multi-line data field means. A chunk split across TCP
/// segments has no blank line yet in the buffer, so this returns `None` and waits rather than
/// parsing halfway JSON; the buffer keeps the remainder for the next read.
fn take_sse_event(raw: &mut String) -> Option<SseEvent> {
    // `\r\n\r\n` contains no `\n\n`, so the two spellings need separate searches; the
    // earlier terminator wins when both are present.
    let lf = raw.find("\n\n");
    let crlf = raw.find("\r\n\r\n");
    let (sep, width) = match (lf, crlf) {
        (Some(a), Some(b)) if a < b => (a, 2),
        (Some(_), Some(b)) => (b, 4),
        (Some(a), None) => (a, 2),
        (None, Some(b)) => (b, 4),
        (None, None) => return None,
    };
    let frame: String = raw.drain(..sep + width).collect();
    Some(parse_sse_frame(&frame))
}

/// A final frame that never got its terminating blank line.
///
/// A stream that ends (or is cut) right after a data line with no trailing blank line would
/// otherwise lose its last event — often the usage chunk. `None` when the remainder carries no
/// `data:` at all, so trailing keepalive comments and empty tails stay silent.
fn take_trailing_sse_event(raw: &mut String) -> Option<SseEvent> {
    let rest = std::mem::take(raw);
    if rest.lines().any(|line| {
        let line = line.strip_suffix('\r').unwrap_or(line);
        line.starts_with("data:")
    }) {
        Some(parse_sse_frame(&rest))
    } else {
        None
    }
}

/// Read one framed event's text into its payload.
///
/// `data: [DONE]` (possibly padded with whitespace, as proxies do) is the terminal marker;
/// anything else joins its `data:` lines. Comment-only frames carry no data and become empty
/// payloads, which the caller skips.
fn parse_sse_frame(frame: &str) -> SseEvent {
    let mut data = Vec::new();
    for line in frame.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with(':') {
            continue; // a comment, which is what a keepalive is
        }
        if let Some((field, value)) = line.split_once(':') {
            if field == "data" {
                data.push(value.strip_prefix(' ').unwrap_or(value).to_string());
            }
        }
    }
    let payload = data.join("\n");
    if payload.trim() == "[DONE]" {
        SseEvent::Done
    } else {
        SseEvent::Data(payload)
    }
}

/// The chat-completions URL for an API root.
///
/// Tolerant of the shapes people actually paste into a config: with or without a trailing slash,
/// with or without the `/v1`, and with the full path already included (a common way to point at a
/// gateway that lives somewhere unexpected). Anything else would produce a 404 that looks like a
/// credential problem.
pub fn chat_completions_url(base: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    if trimmed.ends_with("/chat/completions") {
        return trimmed.to_string();
    }
    format!("{trimmed}/chat/completions")
}

/// Convert an internal request into the wire format.
pub fn build_body(req: &ChatRequest) -> Result<Value> {
    let mut messages: Vec<Value> = Vec::with_capacity(req.messages.len() + 1);

    if let Some(system) = &req.system {
        messages.push(json!({ "role": "system", "content": system }));
    }

    for message in &req.messages {
        match message.role {
            Role::System => messages.push(json!({
                "role": "system",
                "content": message.text(),
            })),
            Role::User => messages.push(json!({
                "role": "user",
                "content": text_content(message)?,
            })),
            Role::Assistant => {
                let mut calls: Vec<Value> = Vec::new();
                for part in message.tool_calls() {
                    if let Part::ToolCall {
                        id,
                        name,
                        arguments,
                        ..
                    } = part
                    {
                        calls.push(json!({
                            "id": id.as_str(),
                            "type": "function",
                            "function": {
                                "name": name,
                                // OpenAI wants the arguments as a JSON *string*, not an object.
                                // Sending the object is accepted by some gateways and rejected by
                                // others, which is a two-hour debugging session either way.
                                "arguments": serde_json::to_string(arguments)?,
                            },
                        }));
                    }
                }

                // An assistant turn that only calls tools has no text; `null` is what the API
                // expects there, and an empty string is not equivalent.
                let text = message.text();
                let content = if text.is_empty() {
                    Value::Null
                } else {
                    Value::String(text)
                };

                let mut entry = json!({ "role": "assistant", "content": content });
                if !calls.is_empty() {
                    entry["tool_calls"] = Value::Array(calls);
                }
                messages.push(entry);
            }
            Role::Tool => {
                // One message per result: the API pairs each tool message with one `tool_call_id`.
                for part in &message.parts {
                    if let Part::ToolResult { id, content, .. } = part {
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": id.as_str(),
                            "content": content,
                        }));
                    }
                }
            }
        }
    }

    let tools: Vec<Value> = req.tools.iter().map(tool_body).collect::<Vec<_>>();

    let mut body = json!({
        "model": req.model,
        "messages": messages,
        "max_tokens": req.max_tokens,
        // Explicit, because omitting it is not the same as asking for it: a proxy that defaults to
        // streaming will stream, and this adapter reads one JSON object and no more.
        "stream": false,
    });
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools);
    }
    if let Some(temperature) = req.temperature {
        body["temperature"] = json!(temperature);
    }
    // WHY: a clamped `reasoning_effort` that stops at `ChatRequest` still never reaches the wire,
    // which is the defect this field exists to close. The o-series/gpt-5 shape is `reasoning_effort`
    // as a lowercase string; a member whose pool entry rejects the kind never gets here because the
    // spawner only sets the field from effective (accepted) params.
    if let Some(effort) = req.reasoning_effort {
        let value = match effort {
            hx_core::pool::ReasoningEffort::Low => "low",
            hx_core::pool::ReasoningEffort::Medium => "medium",
            hx_core::pool::ReasoningEffort::High => "high",
        };
        body["reasoning_effort"] = json!(value);
    }

    Ok(body)
}

fn tool_body(spec: &ToolSpec) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.input_schema,
        }
    })
}

/// Text content, or an error for the parts this adapter cannot send.
///
/// Silently dropping an image would be the worst outcome: the model answers a question about a
/// picture it never received, and nothing in the transcript says so.
fn text_content(message: &Message) -> Result<String> {
    let mut out = String::new();
    for part in &message.parts {
        match part {
            Part::Text { text } => out.push_str(text),
            Part::ToolResult { content, .. } => out.push_str(content),
            Part::Image { .. } => {
                return Err(HxError::Provider(
                    "image inputs are not implemented in the OpenAI-compatible adapter yet"
                        .to_string(),
                ))
            }
            Part::ToolCall { .. } => {}
        }
    }
    Ok(out)
}

/// A tool call as the wire sends it, after fragments have been folded back together.
#[derive(Debug, PartialEq, Eq)]
struct RawCall {
    id: String,
    name: String,
    arguments: String,
}

/// Fold unmerged streaming fragments back into whole tool calls.
///
/// The OpenAI wire format sends a tool call as a *stream* of deltas: the first carries the id and the
/// name, the rest carry pieces of `function.arguments`. An endpoint that streams internally and then
/// hands the fragments over unmerged produces a `tool_calls` array whose entries after the first have
/// an empty id and name — read literally that is seven tool calls, six of them nameless with a
/// fragment of the JSON as their arguments, and the model is told its arguments were malformed when
/// they were complete all along. (Found the first time a real model was asked to call a tool through
/// litellm in front of the GLM proxy; no scripted test could have produced it.)
///
/// The rule is the one a stream accumulator uses: `index` decides when present, otherwise an entry
/// with a name starts a call and an entry with neither name nor id extends the previous one. A
/// well-formed response is left exactly as it was, because every entry in one carries its own id,
/// name and arguments.
fn merge_tool_call_fragments(calls: &[Value]) -> Vec<RawCall> {
    let mut merged: Vec<RawCall> = Vec::new();
    // `index` is optional and, when present, is the authority. Tracked separately so an entry with an
    // index can extend a call that is not the last one (interleaved parallel calls do that).
    let mut by_index: Vec<(u64, usize)> = Vec::new();

    for call in calls {
        let id = call.get("id").and_then(Value::as_str).unwrap_or("");
        let name = call
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let arguments = call
            .get("function")
            .and_then(|f| f.get("arguments"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let target = match call.get("index").and_then(Value::as_u64) {
            Some(index) => by_index
                .iter()
                .find(|(seen, _)| *seen == index)
                .map(|(_, at)| *at),
            None if name.is_empty() && id.is_empty() => merged.len().checked_sub(1),
            None => None,
        };

        match target {
            Some(at) => merged[at].arguments.push_str(arguments),
            None => {
                if let Some(index) = call.get("index").and_then(Value::as_u64) {
                    by_index.push((index, merged.len()));
                }
                merged.push(RawCall {
                    id: id.to_string(),
                    name: name.to_string(),
                    arguments: arguments.to_string(),
                });
            }
        }
    }

    merged
}

/// Normalise a chat-completions response.
pub fn parse_response(body: &Value, requested_model: &str) -> Result<ChatResponse> {
    let choice = body
        .get("choices")
        .and_then(|choices| choices.get(0))
        .ok_or_else(|| {
            HxError::Provider(format!(
                "the response contained no choices: {}",
                truncate(&body.to_string())
            ))
        })?;

    let message = choice.get("message").cloned().unwrap_or(Value::Null);

    let mut parts = Vec::new();

    if let Some(text) = message.get("content").and_then(Value::as_str) {
        if !text.is_empty() {
            parts.push(Part::text(text));
        }
    }

    if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
        for call in merge_tool_call_fragments(calls) {
            if call.id.is_empty() {
                return Err(HxError::Provider(
                    "a tool call arrived without an id".to_string(),
                ));
            }
            if call.name.is_empty() {
                return Err(HxError::Provider(format!(
                    "tool call {} arrived without a function name",
                    call.id
                )));
            }

            // Arguments arrive as a string. When it is not valid JSON the call is kept, carrying
            // the raw text, so the tool layer can tell the model what was wrong with its arguments
            // instead of the whole turn failing with a parse error the model never sees.
            let raw = call.arguments.as_str();
            let arguments = match serde_json::from_str::<Value>(raw) {
                Ok(value) => value,
                Err(_) => json!({ "__malformed_arguments": raw }),
            };

            parts.push(Part::ToolCall {
                id: ToolCallId::from_raw(call.id),
                name: call.name,
                arguments,
            });
        }
    }

    if parts.is_empty() {
        return Err(HxError::Provider(
            "the model returned neither text nor a tool call".to_string(),
        ));
    }

    let finish = match choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .unwrap_or("stop")
    {
        "stop" => FinishReason::Stop,
        "length" => FinishReason::Length,
        "tool_calls" | "function_call" => FinishReason::ToolUse,
        "content_filter" => FinishReason::ContentFilter,
        _ => FinishReason::Other,
    };

    let usage = body.get("usage").cloned().unwrap_or(Value::Null);
    let usage = Usage {
        input_tokens: number(&usage, "prompt_tokens"),
        output_tokens: number(&usage, "completion_tokens"),
        cached_input_tokens: number(
            usage.get("prompt_tokens_details").unwrap_or(&Value::Null),
            "cached_tokens",
        ),
        reasoning_tokens: number(
            usage
                .get("completion_tokens_details")
                .unwrap_or(&Value::Null),
            "reasoning_tokens",
        ),
    };

    Ok(ChatResponse {
        message: Message::new(Role::Assistant, parts),
        usage,
        finish,
        model: body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(requested_model)
            .to_string(),
        raw: Some(body.clone()),
    })
}

fn number(value: &Value, field: &str) -> u64 {
    value.get(field).and_then(Value::as_u64).unwrap_or(0)
}

/// Turn an HTTP failure into something the pool can act on.
///
/// The distinction matters upstream: a `429` is "wait and retry", a `401` is "this credential is
/// dead, bench it", a `500` is "the provider is having a bad day, try another", and a `400` is
/// "this request is wrong — another member would refuse it the same way". The last one is why
/// `hx_provider` uses `HxError::ProviderRejected` for a refused request rather than folding it into
/// `HxError::Provider` with the 5xx: a pool that cannot tell them apart re-draws a deterministic
/// failure across every member and turns one error into one per member. A request that was *clamped*
/// to what the member accepts does not reach here at all — that is what clamping is for.
pub fn classify_error(
    id: &ProviderId,
    status: u16,
    retry_after: Option<u64>,
    body: &str,
) -> HxError {
    let detail = truncate(body);
    match status {
        429 => HxError::RateLimited {
            scope: id.to_string(),
            // A provider that says how long to wait is worth believing; the default matches the
            // usual one-minute window rather than retrying immediately into another 429.
            retry_after_ms: retry_after.unwrap_or(60).saturating_mul(1000),
        },
        401 | 403 => HxError::ProviderAuth {
            provider: id.to_string(),
            reason: format!("HTTP {status} — the credential was refused: {detail}"),
        },
        404 => HxError::Provider(format!(
            "{id}: HTTP 404 — the model or the base URL is wrong: {detail}"
        )),
        400 | 422 => HxError::ProviderRejected {
            provider: id.to_string(),
            reason: format!("the request was rejected (HTTP {status}): {detail}"),
        },
        _ => HxError::Provider(format!("{id}: HTTP {status}: {detail}")),
    }
}

fn truncate(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= ERROR_BODY_LIMIT {
        return trimmed.to_string();
    }
    let head: String = trimmed.chars().take(ERROR_BODY_LIMIT).collect();
    format!(
        "{head}… ({} more characters)",
        trimmed.chars().count() - ERROR_BODY_LIMIT
    )
}

/// The default per-request timeout. Long enough for a slow reasoning model, short enough that a
/// hung connection does not hold a pool slot for the rest of the afternoon.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Build a client suitable for a provider endpoint.
pub fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(|err| HxError::Provider(format!("could not build an HTTP client: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::ids::ProviderId;

    fn id() -> ProviderId {
        ProviderId::from("openai-main")
    }

    fn tool(name: &str) -> ToolSpec {
        ToolSpec {
            name: name.to_string(),
            description: describe(),
            input_schema: json!({
                "type": "object",
                "properties": { "cmd": { "type": "string" } },
                "required": ["cmd"]
            }),
        }
    }

    fn describe() -> String {
        "run a shell command".to_string()
    }

    fn tool_call_message() -> Message {
        Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: ToolCallId::from_raw("call_1"),
                name: "shell".to_string(),
                arguments: json!({"cmd": "ls -la"}),
            }],
        )
    }

    // ---- URL joining -------------------------------------------------------------------------

    #[test]
    fn the_url_is_the_api_root_plus_the_path() {
        assert_eq!(
            chat_completions_url("https://api.openai.com/v1"),
            "https://api.openai.com/v1/chat/completions"
        );
        // Trailing slashes and full paths both come out right, because both get pasted into configs.
        assert_eq!(
            chat_completions_url("https://api.openai.com/v1/"),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            chat_completions_url("http://127.0.0.1:8080/v1/chat/completions"),
            "http://127.0.0.1:8080/v1/chat/completions"
        );
        assert_eq!(
            chat_completions_url("http://localhost:11434/v1"),
            "http://localhost:11434/v1/chat/completions"
        );
    }

    // ---- request construction ----------------------------------------------------------------

    #[test]
    fn a_system_prompt_goes_first() {
        let req = ChatRequest::new("gpt-5", vec![Message::user("hello")]).with_system("be terse");
        let body = build_body(&req).unwrap();

        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "be terse");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "hello");
    }

    #[test]
    fn tool_arguments_are_sent_as_a_json_string() {
        // The detail that breaks gateways in both directions if it is wrong.
        let req = ChatRequest::new("gpt-5", vec![tool_call_message()]);
        let body = build_body(&req).unwrap();

        let call = &body["messages"][0]["tool_calls"][0];
        assert_eq!(call["id"], "call_1");
        assert_eq!(call["type"], "function");
        assert_eq!(call["function"]["name"], "shell");
        assert_eq!(
            call["function"]["arguments"],
            serde_json::json!("{\"cmd\":\"ls -la\"}"),
            "arguments must be a string containing JSON, not an object"
        );

        // And an assistant turn with no text sends null, not "".
        assert!(body["messages"][0]["content"].is_null());
    }

    #[test]
    fn tool_results_become_one_message_each() {
        let message = Message::new(
            Role::Tool,
            vec![
                Part::ToolResult {
                    id: ToolCallId::from_raw("call_1"),
                    ok: true,
                    content: "total 0".to_string(),
                },
                Part::ToolResult {
                    id: ToolCallId::from_raw("call_2"),
                    ok: false,
                    content: "no such file".to_string(),
                },
            ],
        );
        let body = build_body(&ChatRequest::new("gpt-5", vec![message])).unwrap();

        let messages = body["messages"].as_array().unwrap();
        assert_eq!(
            messages.len(),
            2,
            "the API pairs one tool message per call id"
        );
        assert_eq!(messages[0]["role"], "tool");
        assert_eq!(messages[0]["tool_call_id"], "call_1");
        assert_eq!(messages[0]["content"], "total 0");
        assert_eq!(messages[1]["tool_call_id"], "call_2");
    }

    #[test]
    fn tools_are_sent_as_function_specs() {
        // No tools configured must mean no `tools` key at all: an empty array is rejected by some
        // gateways, and omitting the key is what "no tools" means.
        let bare = build_body(&ChatRequest::new("gpt-5", vec![Message::user("hi")])).unwrap();
        assert!(bare.get("tools").is_none(), "{bare}");

        let req =
            ChatRequest::new("gpt-5", vec![Message::user("hi")]).with_tools(vec![tool("shell")]);
        let body = build_body(&req).unwrap();
        let sent = &body["tools"][0];
        assert_eq!(sent["type"], "function");
        assert_eq!(sent["function"]["name"], "shell");
        assert_eq!(sent["function"]["description"], describe());
        assert_eq!(sent["function"]["parameters"]["required"][0], "cmd");
    }

    #[test]
    fn limits_and_temperature_are_carried_through() {
        let req = ChatRequest::new("gpt-5", vec![Message::user("hi")])
            .with_max_tokens(1234)
            .with_temperature(0.25);
        let body = build_body(&req).unwrap();
        assert_eq!(body["max_tokens"], 1234);
        assert_eq!(body["temperature"], 0.25);
        assert_eq!(body["model"], "gpt-5");
    }

    #[test]
    fn a_clamped_reasoning_effort_is_sent_and_an_unset_one_is_not() {
        // WHY both halves: the spawner sets this field from the member's effective params, and a
        // member that rejects the kind never gets it set — so "unset means absent on the wire" is
        // the clamp's enforcement, and "set means present" is the fix for the defect where the
        // clamp stopped at the spec and never reached the wire.
        use hx_core::pool::ReasoningEffort as Effort;
        let bare = build_body(&ChatRequest::new("gpt-5", vec![Message::user("hi")])).unwrap();
        assert!(bare.get("reasoning_effort").is_none(), "{bare}");

        let req =
            ChatRequest::new("gpt-5", vec![Message::user("hi")]).with_reasoning_effort(Effort::Low);
        let body = build_body(&req).unwrap();
        assert_eq!(body["reasoning_effort"], "low", "{body}");
    }

    #[test]
    fn an_image_part_is_refused_rather_than_dropped() {
        // The failure mode being avoided: the model answers about a picture it never received, and
        // nothing in the transcript says so.
        let message = Message::new(
            Role::User,
            vec![
                Part::text("what is this?"),
                Part::Image {
                    mime: "image/png".to_string(),
                    data_b64: "AAAA".to_string(),
                },
            ],
        );
        let err = build_body(&ChatRequest::new("gpt-5", vec![message])).unwrap_err();
        assert!(err.to_string().contains("image inputs"), "{err}");
    }

    // ---- response parsing ---------------------------------------------------------------------

    #[test]
    fn a_text_response_is_normalised() {
        let body = json!({
            "model": "gpt-5-2026-01-01",
            "choices": [{
                "message": { "role": "assistant", "content": "hello there" },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 3,
                "prompt_tokens_details": { "cached_tokens": 8 },
                "completion_tokens_details": { "reasoning_tokens": 1 }
            }
        });

        let response = parse_response(&body, "gpt-5").unwrap();
        assert_eq!(response.message.text(), "hello there");
        assert_eq!(response.message.role, Role::Assistant);
        assert_eq!(response.finish, FinishReason::Stop);
        assert_eq!(
            response.model, "gpt-5-2026-01-01",
            "the served model is reported"
        );
        assert_eq!(response.usage.input_tokens, 12);
        assert_eq!(response.usage.output_tokens, 3);
        assert_eq!(
            response.usage.cached_input_tokens, 8,
            "cached input tokens are the signal that context reuse works"
        );
        assert_eq!(response.usage.reasoning_tokens, 1);
    }

    #[test]
    fn the_served_model_falls_back_to_the_requested_one() {
        let body = json!({
            "choices": [{ "message": { "content": "hi" }, "finish_reason": "stop" }]
        });
        assert_eq!(parse_response(&body, "gpt-5").unwrap().model, "gpt-5");
    }

    #[test]
    fn tool_calls_are_parsed_into_arguments() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": { "name": "shell", "arguments": "{\"cmd\":\"pwd\"}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });

        let response = parse_response(&body, "gpt-5").unwrap();
        assert_eq!(response.finish, FinishReason::ToolUse);

        let call = response.message.tool_calls().next().unwrap();
        match call {
            Part::ToolCall {
                id,
                name,
                arguments,
            } => {
                assert_eq!(id.as_str(), "call_abc");
                assert_eq!(name, "shell");
                assert_eq!(arguments["cmd"], "pwd");
            }
            other => panic!("expected a tool call, got {other:?}"),
        }
    }

    #[test]
    fn malformed_tool_arguments_are_kept_for_the_tool_layer_to_report() {
        // The model, not this adapter, is what needs to learn that its arguments were invalid.
        // Failing the whole turn hides that from it.
        let body = json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "id": "call_1",
                        "function": { "name": "shell", "arguments": "{not json" }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });

        let response = parse_response(&body, "gpt-5").unwrap();
        let calls: Vec<&Part> = response.message.tool_calls().collect();
        match calls[0] {
            Part::ToolCall { arguments, .. } => {
                assert_eq!(arguments["__malformed_arguments"], "{not json");
            }
            other => panic!("expected a tool call, got {other:?}"),
        }
    }

    #[test]
    fn unmerged_stream_fragments_are_folded_back_into_one_call() {
        // Exactly what litellm returned for glm-prox/swe-2-high: the name on the first entry, the
        // arguments as six fragments after it, and empty ids on the fragments. Read literally, that
        // is seven tool calls — six of them nameless, with a piece of JSON as their "arguments".
        let fragments = json!([
            { "id": "read_file_0#abc", "type": "function",
              "function": { "arguments": "", "name": "read_file" } },
            { "id": "", "type": "function", "function": { "arguments": "{", "name": "" } },
            { "id": "", "type": "function", "function": { "arguments": "\"path\": \"", "name": "" } },
            { "id": "", "type": "function", "function": { "arguments": "Cargo", "name": "" } },
            { "id": "", "type": "function", "function": { "arguments": ".toml", "name": "" } },
            { "id": "", "type": "function", "function": { "arguments": "\"", "name": "" } },
            { "id": "", "type": "function", "function": { "arguments": "}", "name": "" } }
        ]);

        let merged = merge_tool_call_fragments(fragments.as_array().unwrap());
        assert_eq!(merged.len(), 1, "seven fragments are one call: {merged:?}");
        assert_eq!(merged[0].name, "read_file");
        assert_eq!(merged[0].id, "read_file_0#abc");
        assert_eq!(merged[0].arguments, "{\"path\": \"Cargo.toml\"}");

        // And the arguments then parse, which is the point: the model's call was well-formed all
        // along and the tool layer must not be told otherwise.
        let body = json!({
            "choices": [{
                "message": { "tool_calls": fragments },
                "finish_reason": "tool_calls"
            }]
        });
        let response = parse_response(&body, "swe-2-high").unwrap();
        let calls: Vec<&Part> = response.message.tool_calls().collect();
        assert_eq!(calls.len(), 1);
        match calls[0] {
            Part::ToolCall {
                id,
                name,
                arguments,
                ..
            } => {
                assert_eq!(id.as_str(), "read_file_0#abc");
                assert_eq!(name, "read_file");
                assert_eq!(arguments["path"], "Cargo.toml");
            }
            other => panic!("expected a tool call, got {other:?}"),
        }
    }

    #[test]
    fn parallel_calls_are_left_exactly_as_they_arrived() {
        // The merge rule must not touch the well-formed case: every entry carries its own id, name
        // and arguments.
        let calls = json!([
            { "id": "call_1", "function": { "name": "shell", "arguments": "{\"cmd\":\"ls\"}" } },
            { "id": "call_2", "function": { "name": "read_file", "arguments": "{\"path\":\"/x\"}" } }
        ]);

        let merged = merge_tool_call_fragments(calls.as_array().unwrap());
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].arguments, "{\"cmd\":\"ls\"}");
        assert_eq!(merged[1].arguments, "{\"path\":\"/x\"}");
    }

    #[test]
    fn fragments_merge_by_index_when_the_index_is_there() {
        // Interleaved parallel calls: index is the authority, not arrival order.
        let calls = json!([
            { "index": 0, "id": "a", "function": { "name": "shell", "arguments": "{\"cmd\":" } },
            { "index": 1, "id": "b", "function": { "name": "read_file", "arguments": "{\"path\":" } },
            { "index": 0, "function": { "arguments": "\"ls\"}", "name": "" } },
            { "index": 1, "function": { "arguments": "\"/x\"}", "name": "" } }
        ]);

        let merged = merge_tool_call_fragments(calls.as_array().unwrap());
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].name, "shell");
        assert_eq!(merged[0].arguments, "{\"cmd\":\"ls\"}");
        assert_eq!(merged[1].name, "read_file");
        assert_eq!(merged[1].arguments, "{\"path\":\"/x\"}");
    }

    #[test]
    fn a_lone_fragment_is_still_an_error_rather_than_a_silent_merge() {
        // Nothing to extend: an entry with no id and no name cannot become a call, and inventing one
        // would hide a malformed response behind a nameless tool call.
        let calls = json!([{ "function": { "arguments": "\"path\": \"x\"", "name": "" } }]);
        assert_eq!(
            merge_tool_call_fragments(calls.as_array().unwrap()).len(),
            1
        );

        let body = json!({
            "choices": [{
                "message": { "tool_calls": calls },
                "finish_reason": "tool_calls"
            }]
        });
        let err = parse_response(&body, "gpt-5").unwrap_err();
        assert!(format!("{err}").contains("without an id"), "{err}");
    }

    #[test]
    fn finish_reasons_are_normalised_across_spellings() {
        let cases = [
            ("stop", FinishReason::Stop),
            ("length", FinishReason::Length),
            ("tool_calls", FinishReason::ToolUse),
            ("function_call", FinishReason::ToolUse),
            ("content_filter", FinishReason::ContentFilter),
            ("something_new", FinishReason::Other),
        ];

        for (wire, expected) in cases {
            let body = json!({
                "choices": [{ "message": { "content": "x" }, "finish_reason": wire }]
            });
            assert_eq!(
                parse_response(&body, "m").unwrap().finish,
                expected,
                "finish_reason={wire}"
            );
        }
    }

    #[test]
    fn a_response_with_nothing_in_it_is_an_error() {
        let body = json!({
            "choices": [{ "message": { "role": "assistant", "content": "" }, "finish_reason": "stop" }]
        });
        let err = parse_response(&body, "gpt-5").unwrap_err();
        assert!(
            err.to_string().contains("neither text nor a tool call"),
            "{err}"
        );

        let err = parse_response(&json!({}), "gpt-5").unwrap_err();
        assert!(err.to_string().contains("no choices"), "{err}");
    }

    #[test]
    fn a_tool_call_without_an_id_or_a_name_is_rejected() {
        let no_id = json!({
            "choices": [{ "message": { "tool_calls": [{ "function": { "name": "shell" } }] } }]
        });
        assert!(parse_response(&no_id, "m")
            .unwrap_err()
            .to_string()
            .contains("without an id"));

        let no_name = json!({
            "choices": [{ "message": { "tool_calls": [{ "id": "c1", "function": {} }] } }]
        });
        assert!(parse_response(&no_name, "m")
            .unwrap_err()
            .to_string()
            .contains("without a function name"));
    }

    #[test]
    fn usage_missing_entirely_is_zero_rather_than_a_panic() {
        let body = json!({
            "choices": [{ "message": { "content": "x" }, "finish_reason": "stop" }]
        });
        let usage = parse_response(&body, "m").unwrap().usage;
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
    }

    // ---- failure classification ---------------------------------------------------------------

    #[test]
    fn a_429_becomes_a_retry_and_believes_retry_after() {
        let err = classify_error(&id(), 429, Some(3), "slow down");
        match err {
            HxError::RateLimited {
                scope,
                retry_after_ms,
            } => {
                assert_eq!(scope, "openai-main");
                assert_eq!(retry_after_ms, 3000);
            }
            other => panic!("expected a rate limit, got {other:?}"),
        }

        // Without the header there is still a sane default rather than an immediate retry.
        match classify_error(&id(), 429, None, "") {
            HxError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 60_000),
            other => panic!("expected a rate limit, got {other:?}"),
        }
    }

    #[test]
    fn an_auth_failure_is_named_as_one() {
        // The pool benches a credential on this, so it must not read like a generic 500 — and
        // `is_auth_failure` has to be true, which is what the router keys off.
        let err = classify_error(&id(), 401, None, "{\"error\":\"invalid api key\"}");
        assert!(err.is_auth_failure(), "{err:?}");
        assert!(
            !err.is_retryable(),
            "the same key will be refused again: {err:?}"
        );

        let message = err.to_string();
        assert!(message.contains("rejected the credential"), "{message}");
        assert!(
            message.contains("invalid api key"),
            "the body is the useful part: {message}"
        );

        assert!(classify_error(&id(), 403, None, "").is_auth_failure());
    }

    #[test]
    fn a_404_says_the_model_or_the_url_is_wrong() {
        let message = classify_error(&id(), 404, None, "model not found").to_string();
        assert!(
            message.contains("the model or the base URL is wrong"),
            "{message}"
        );
    }

    /// A `400` is a refused *request*, not a member that failed: the pool's own rule must read the
    /// two differently, because one is worth re-drawing onto another member and the other is not.
    #[test]
    fn a_refused_request_is_the_pools_rule_for_a_child_failure_not_a_member_death() {
        let rejected = classify_error(&id(), 400, None, "unknown parameter: reasoning_effort");
        assert!(
            matches!(rejected, HxError::ProviderRejected { .. }),
            "a 400 must not be spelled like a 500: {rejected:?}"
        );
        assert!(
            !hx_core::pool::member_death(&rejected),
            "every member refuses this request the same way, so re-drawing it makes N errors"
        );
        assert!(!rejected.is_retryable(), "{rejected:?}");
        let message = rejected.to_string();
        assert!(message.contains("rejected the request"), "{message}");
        assert!(
            message.contains("unknown parameter"),
            "the body is the useful part: {message}"
        );

        // `422` is the same decision in a different status, and the pair must not diverge.
        assert!(matches!(
            classify_error(&id(), 422, None, "unprocessable"),
            HxError::ProviderRejected { .. }
        ));

        // The control: a 500 is the member's failure, and the pool's rule says so — this is the
        // assertion that would pass if every status were folded into `Provider`.
        let down = classify_error(&id(), 500, None, "upstream on fire");
        assert!(hx_core::pool::member_death(&down), "{down:?}");
    }

    #[test]
    fn long_error_bodies_are_truncated() {
        let huge = "x".repeat(4000);
        let message = classify_error(&id(), 500, None, &huge).to_string();
        assert!(
            message.len() < 1000,
            "a 4 KB error page is not a log line: {}",
            message.len()
        );
        assert!(message.contains("more characters"), "{message}");
    }

    #[test]
    fn the_client_builds_with_a_timeout() {
        assert!(http_client().is_ok());
    }

    // ---- streaming ------------------------------------------------------------------------------

    #[test]
    fn a_stream_body_is_the_single_shot_body_with_stream_on() {
        let req = ChatRequest::new("gpt-5", vec![Message::user("hi")]);
        let streamed = stream_body(&req).unwrap();
        assert_eq!(streamed["stream"], true);
        assert_eq!(streamed["messages"][0]["content"], "hi");
        // And the single-shot body is the default, so an adapter that does not think about the flag
        // does not accidentally stream (the pitfall the repo paid for).
        assert_eq!(build_body(&req).unwrap()["stream"], false);
    }

    #[test]
    fn sse_events_are_split_on_a_blank_line_and_survive_a_split_chunk() {
        // The whole point of reassembling events before parsing: the vendor can hand half a chunk
        // in one TCP segment and the other half in the next, and parsing a half-JSON object would
        // error. Reassemble first, then parse.
        let mut raw = String::new();
        assert_eq!(take_sse_event(&mut raw), None, "nothing yet");

        raw.push_str("data: {\"a\":1}\n\n");
        assert_eq!(
            take_sse_event(&mut raw),
            Some(SseEvent::Data("{\"a\":1}".into()))
        );

        // A chunk split across segments has no blank line until the second segment arrives.
        raw.push_str("data: {\"b\":");
        assert_eq!(take_sse_event(&mut raw), None, "no terminator yet");
        raw.push_str("2}\n\n");
        assert_eq!(
            take_sse_event(&mut raw),
            Some(SseEvent::Data("{\"b\":2}".into()))
        );
        assert!(raw.is_empty(), "nothing left over: {raw:?}");
    }

    #[test]
    fn a_stream_that_splits_a_multibyte_char_decodes_cleanly() {
        // The failure mode behind the incremental decoder: an emoji split across two reads must
        // decode whole. Per-chunk `from_utf8_lossy` would scar both halves with U+FFFD and the
        // chunk would no longer parse as the JSON the vendor sent.
        let text = "data: {\"choices\":[{\"delta\":{\"content\":\"hi 🌍\"}}]}\n\n";
        let bytes = text.as_bytes();
        let cut = text.find('🌍').unwrap() + 2; // inside the four-byte emoji

        let mut decoder = crate::sse::Utf8StreamDecoder::new();
        let mut raw = String::new();
        raw.push_str(&decoder.push(&bytes[..cut]));
        raw.push_str(&decoder.push(&bytes[cut..]));
        raw.push_str(&decoder.finish());

        let event = take_sse_event(&mut raw).expect("one complete event");
        match event {
            SseEvent::Data(line) => {
                let chunk: serde_json::Value =
                    serde_json::from_str(&line).expect("the reassembled chunk parses");
                assert_eq!(
                    chunk["choices"][0]["delta"]["content"], "hi 🌍",
                    "no replacement scars"
                );
            }
            SseEvent::Done => panic!("expected a data event"),
        }
    }

    #[test]
    fn crlf_separators_terminate_events_like_lf_does() {
        // A proxy that terminates lines with CRLF must not cause every event to buffer forever
        // with no error at all.
        let mut raw = String::from("data: {\"a\":1}\r\n\r\n");
        assert_eq!(
            take_sse_event(&mut raw),
            Some(SseEvent::Data("{\"a\":1}".into()))
        );

        // Mixed in one buffer: the earlier terminator wins and the later event waits its turn.
        let mut mixed = String::from("data: {\"a\":1}\r\n\r\ndata: {\"b\":2}\n\n");
        assert_eq!(
            take_sse_event(&mut mixed),
            Some(SseEvent::Data("{\"a\":1}".into()))
        );
        assert_eq!(
            take_sse_event(&mut mixed),
            Some(SseEvent::Data("{\"b\":2}".into()))
        );
    }

    #[test]
    fn comments_are_skipped_and_multiline_data_is_joined() {
        // Keepalive comments carry nothing; multi-line data joins with newlines per the SSE spec.
        let mut raw = String::from(": keepalive\n\n");
        assert_eq!(
            take_sse_event(&mut raw),
            Some(SseEvent::Data(String::new()))
        );

        let mut multi = String::from("data: {\"a\":\ndata: 1}\n\n");
        assert_eq!(
            take_sse_event(&mut multi),
            Some(SseEvent::Data("{\"a\":\n1}".into()))
        );
    }

    #[test]
    fn a_done_event_is_terminal_even_with_padding() {
        // Proxies pad; the marker still ends the turn, and the caller propagates it to the outer
        // read loop so a connection held open past `[DONE]` does not hang the request.
        for frame in ["data: [DONE]\n\n", "data:  [DONE]  \r\n\r\n"] {
            let mut raw = String::from(frame);
            assert_eq!(take_sse_event(&mut raw), Some(SseEvent::Done), "{frame:?}");
        }

        let mut acc = StreamAccumulator::default();
        let mut deltas = 0;
        let mut on_delta = |_: StreamDelta| -> Result<()> {
            deltas += 1;
            Ok(())
        };
        assert!(
            feed_event(&mut acc, &id(), SseEvent::Done, &mut on_delta).unwrap(),
            "Done must report terminal state"
        );
        assert_eq!(deltas, 0, "the marker emits no delta");
    }

    #[test]
    fn a_trailing_frame_without_a_blank_line_is_still_applied() {
        // A stream cut right after a data line with no trailing blank line must not lose its
        // last event — that tail is often the usage chunk.
        let mut raw = String::from("data: {\"usage\":{\"prompt_tokens\":3}}\n");
        assert_eq!(take_sse_event(&mut raw), None, "no terminator yet");
        assert_eq!(
            take_trailing_sse_event(&mut raw),
            Some(SseEvent::Data("{\"usage\":{\"prompt_tokens\":3}}".into()))
        );

        // But a trailing keepalive comment or an empty tail stays silent.
        let mut comment = String::from(": keepalive\n");
        assert_eq!(take_trailing_sse_event(&mut comment), None);
        let mut empty = String::new();
        assert_eq!(take_trailing_sse_event(&mut empty), None);
    }

    #[test]
    fn a_stream_body_asks_the_vendor_for_usage() {
        // Without `stream_options.include_usage` the stream carries no token counts and
        // `finish_stream` can only report zeros.
        let req = ChatRequest::new("gpt-5", vec![Message::user("hi")]);
        let streamed = stream_body(&req).unwrap();
        assert_eq!(streamed["stream"], true);
        assert_eq!(streamed["stream_options"]["include_usage"], true);
        assert_eq!(streamed["messages"][0]["content"], "hi");
    }

    #[test]
    fn a_terminal_usage_chunk_is_reported_by_finish_stream() {
        // The usage chunk arrives last and carries no choices; it must still land in the
        // accumulator, or the turn reports zeros and cost accounting silently breaks.
        let mut acc = StreamAccumulator::default();
        let deltas = apply_chunk(
            &mut acc,
            &json!({"choices": [{"delta": {"content": "hi"}}]}),
        );
        assert_eq!(deltas.len(), 1);
        let usage_only = apply_chunk(
            &mut acc,
            &json!({
                "choices": [],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 3,
                    "prompt_tokens_details": { "cached_tokens": 8 },
                    "completion_tokens_details": { "reasoning_tokens": 1 }
                }
            }),
        );
        assert!(usage_only.is_empty(), "usage contributes no delta");

        let response = finish_stream(&id(), &acc, "gpt-5").unwrap();
        assert_eq!(response.message.text(), "hi");
        assert_eq!(response.usage.input_tokens, 12);
        assert_eq!(response.usage.output_tokens, 3);
        assert_eq!(response.usage.cached_input_tokens, 8);
        assert_eq!(response.usage.reasoning_tokens, 1);
    }

    #[test]
    fn partial_usage_chunks_combine_rather_than_clobber() {
        // A vendor that splits usage across chunks must still end with the full picture: a later
        // partial object must not zero fields an earlier one reported.
        let mut acc = StreamAccumulator::default();
        apply_chunk(&mut acc, &json!({"usage": {"prompt_tokens": 10}}));
        apply_chunk(&mut acc, &json!({"usage": {"completion_tokens": 4}}));
        assert_eq!(acc.usage.input_tokens, 10);
        assert_eq!(acc.usage.output_tokens, 4);
    }

    #[test]
    fn a_streamed_text_turn_emits_text_deltas_in_order_and_builds_the_reply() {
        // A live surface needs the pieces as they arrive; the store still needs the whole message.
        let mut acc = StreamAccumulator::default();
        let mut deltas = Vec::new();
        for piece in ["hello ", "there"] {
            deltas.extend(apply_chunk(
                &mut acc,
                &json!({"choices": [{"delta": {"content": piece}}]}),
            ));
        }
        assert_eq!(
            deltas,
            vec![
                StreamDelta::Text("hello ".into()),
                StreamDelta::Text("there".into())
            ]
        );
        assert_eq!(acc.text, "hello there");

        let response = finish_stream(&id(), &acc, "gpt-5").unwrap();
        assert_eq!(response.message.text(), "hello there");
        assert_eq!(response.finish, FinishReason::Stop);
    }

    #[test]
    fn a_proxy_that_streams_tool_deltas_in_a_non_streaming_body_is_merged() {
        // The real failure mode paid for with the single-shot path, replayed as streamed chunks:
        // an OpenAI-compatible proxy streams upstream and hands the deltas over as nameless
        // fragments. Read literally that is seven tool calls (one naked shell call plus six JSON
        // scraps); merged by the same rule, it is one `read_file` with `{"path":"Cargo.toml"}`.
        let chunks = [
            json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "read_file_0#abc", "type": "function", "function": {"name": "read_file", "arguments": ""}}]}}]}),
            json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{"}}]}}]}),
            json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "\"path\": \""}}]}}]}),
            json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "Cargo"}}]}}]}),
            json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": ".toml"}}]}}]}),
            json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "\""}}]}}]}),
            json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "}"}}]}}]}),
            json!({"choices": [{"delta": {}, "finish_reason": "tool_calls"}]}),
        ];

        let mut acc = StreamAccumulator::default();
        let mut deltas = Vec::new();
        for chunk in &chunks {
            deltas.extend(apply_chunk(&mut acc, chunk));
        }

        // One merged call, not seven: the fragments became `{"path": "Cargo.toml"}`.
        assert_eq!(deltas.len(), 1, "{deltas:?}");
        match &deltas[0] {
            StreamDelta::ToolCall {
                id,
                name,
                arguments,
            } => {
                assert_eq!(id, "read_file_0#abc");
                assert_eq!(name, "read_file");
                assert_eq!(arguments["path"], "Cargo.toml");
            }
            other => panic!("expected a merged tool call, got {other:?}"),
        }
        assert!(acc.tool_use);

        let response = finish_stream(&id(), &acc, "gpt-5").unwrap();
        assert_eq!(response.finish, FinishReason::ToolUse);
        let calls: Vec<&Part> = response.message.tool_calls().collect();
        match calls[0] {
            Part::ToolCall {
                name, arguments, ..
            } => {
                assert_eq!(name, "read_file");
                assert_eq!(arguments["path"], "Cargo.toml");
            }
            other => panic!("expected a tool call, got {other:?}"),
        }
    }

    #[test]
    fn a_stream_from_an_empty_turn_is_an_error_rather_than_a_blank_reply() {
        // A stream that produced nothing is not a valid turn: a reply with neither text nor a call
        // would be handed to the loop as a silent no-op.
        let acc = StreamAccumulator::default();
        let err = finish_stream(&id(), &acc, "gpt-5").unwrap_err();
        assert!(
            err.to_string().contains("neither text nor a tool call"),
            "{err}"
        );
    }
}
