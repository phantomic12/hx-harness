//! The Anthropic Messages API adapter.
//!
//! The second adapter, written because Anthropic's wire format is genuinely different from the
//! OpenAI-compatible one rather than a cosmetic variant. Claude speaks `POST /v1/messages` and asks
//! for a JSON dialect with its own rules, and getting any of them wrong produces responses that look like
//! model-quality bugs when they are really serialisation bugs. The mapping is two pure functions —
//! [`build_body`] and [`parse_response`] — with only [`AnthropicMessages::complete`] touching the
//! network, the same shape as the OpenAI adapter so both are asserted against literals.
//!
//! ## The differences that matter
//!
//! - The system prompt is a **top-level `system` field**, not a `system`-role message. There is no
//!   `system` role in the Messages API at all; a message with `role: "system"` is rejected.
//! - Messages alternate `user` and `assistant`. Tool results are `user`-role messages whose `content`
//!   is one or more `tool_result` blocks (there is no `tool` role).
//! - Tool definitions use `input_schema`, not `parameters`.
//! - A tool call comes back as a `tool_use` content block carrying `id`, `name` and `input`,
//!   where `input` is always a JSON **object** — not a JSON *string* like OpenAI's `arguments`.
//! - `max_tokens` is **required**; the request is invalid without it.
//! - The response reports `stop_reason` (`end_turn`, `tool_use`, `max_tokens`, …) instead of
//!   `finish_reason`.
//! - Auth is the `x-api-key` header (plus the required `anthropic-version`), not `Authorization:
//!   Bearer`.
//!
//! ## What is deliberately not supported yet
//!
//! Image inputs, streaming, thinking blocks, and tool-choice control (`tool_choice`). Each is a real
//! feature rather than a hypothetical, and each fails loudly: an image part is an error naming the
//! adapter, not a message that quietly loses its picture. Response blocks whose `type` this adapter has
//! never seen are **skipped**, not fatal — the API adds block types over time, and refusing to parse a
//! response because a future model emitted an unfamiliar block would take the whole harness down for no reason.
//! That leniency is the deliberate exception; the request side refuses unknown input rather than dropping it.

use crate::openai::classify_error;
use crate::provider::{
    ChatRequest, ChatResponse, FinishReason, Provider, StreamDelta, ToolSpec, Usage,
};
use hx_core::config::ProviderKind;
use hx_core::error::{HxError, Result};
use hx_core::ids::{ProviderId, ToolCallId};
use hx_core::message::{Message, Part, Role};
use hx_secrets::Secret;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::{json, Value};

/// The API version this adapter commits to speaking. The Messages API requires an `anthropic-version`
/// header on every request and only the `x-api-key` header authenticates.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// A `/v1/messages` endpoint. The root is the API host (`https://api.anthropic.com`), not the
/// API root — Anthropic does not shove the version into the path the way OpenAI does, so `/v1/messages`
/// is appended here.
pub struct AnthropicMessages {
    id: ProviderId,
    models: Vec<String>,
    base_url: String,
    client: reqwest::Client,
}

impl AnthropicMessages {
    /// `base_url` is the API host, e.g. `https://api.anthropic.com`.
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
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn complete_raw(&self, req: &ChatRequest, key: &Secret) -> Result<ChatResponse> {
        let url = messages_url(&self.base_url);
        let body = build_body(req)?;

        let response = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(key.expose()).map_err(|err| {
                    HxError::Provider(format!(
                        "{}: the credential is not a valid header value: {err}",
                        self.id
                    ))
                })?,
            )
            .header(
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static(ANTHROPIC_VERSION),
            )
            .json(&body)
            .send()
            .await
            .map_err(|err| {
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
            // The Anthropic error body is `{"type":"error","error":{"type":...,"message":...}}`; the
            // message field is the useful part and `classify_error` keeps the excerpt.
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
                // Reuse the openai truncate helper through classify? No — truncate lives privately;
                // construct a brief inline excerpt instead.
                text.chars().take(512).collect::<String>()
            ))
        })?;

        parse_response(&parsed, &req.model)
    }
}

#[async_trait::async_trait]
impl Provider for AnthropicMessages {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn kind(&self) -> ProviderKind {
        ProviderKind::Anthropic
    }

    fn models(&self) -> &[String] {
        &self.models
    }

    async fn complete(&self, req: ChatRequest, key: &Secret) -> Result<ChatResponse> {
        self.complete_raw(&req, key).await
    }

    /// Stream a turn, emitting deltas as they arrive.
    ///
    /// Anthropic's stream is a sequence of *named* events rather than a per-chunk delta, so the
    /// request asks for `stream: true` and the body is then read as SSE frames, each handed to
    /// [`crate::anthropic_stream::apply_event`]. Frames are assembled across TCP reads before being
    /// parsed: a half-frame parsed as JSON fails, and the failure looks like a provider fault rather
    /// than a client that did not buffer.
    async fn stream(
        &self,
        req: ChatRequest,
        key: &Secret,
        on_delta: &mut (dyn FnMut(StreamDelta) -> Result<()> + Send),
    ) -> Result<ChatResponse> {
        use futures::StreamExt;

        let url = messages_url(&self.base_url);
        let mut body = build_body(&req)?;
        body["stream"] = json!(true);

        let response = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(key.expose()).map_err(|err| {
                    HxError::Provider(format!(
                        "{}: the credential is not a valid header value: {err}",
                        self.id
                    ))
                })?,
            )
            .header(
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static(ANTHROPIC_VERSION),
            )
            .json(&body)
            .send()
            .await
            .map_err(|err| {
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

        let mut acc = crate::anthropic_stream::StreamAccumulator::default();
        // Bytes are decoded incrementally: a multi-byte character split across two reads must
        // decode whole rather than become U+FFFD scars on either side of the split.
        let mut decoder = crate::sse::Utf8StreamDecoder::new();
        let mut pending = String::new();
        let mut bytes = response.bytes_stream();

        while let Some(part) = bytes.next().await {
            let part = part.map_err(|err| {
                HxError::Provider(format!("{}: the stream was interrupted: {err}", self.id))
            })?;
            pending.push_str(&decoder.push(&part));

            // Whole frames only: a frame split across two reads must not be parsed in halves.
            while let Some(split) = crate::anthropic_stream::take_sse_frame(&mut pending) {
                let (event_name, data) = split;
                for delta in crate::anthropic_stream::apply_event(&mut acc, &event_name, &data)? {
                    on_delta(delta)?;
                }
            }
        }

        // Flush the decoder (a truncated connection may end mid-character) before reading
        // the tail: anything left without a terminating blank line is still an event if it
        // carries data — dropping it would lose the last frame of a stream that ended without
        // a trailing newline.
        pending.push_str(&decoder.finish());
        if let Some((event_name, data)) = crate::anthropic_stream::take_trailing_frame(&mut pending)
        {
            for delta in crate::anthropic_stream::apply_event(&mut acc, &event_name, &data)? {
                on_delta(delta)?;
            }
        }

        crate::anthropic_stream::finish_stream(acc, &req.model)
    }
}

/// The Messages URL for an API host.
///
/// The config names the host (`https://api.anthropic.com`), not an API root, because that is what
/// every Anthropic tool and the example config use. Messages live at `/v1/messages`. Tolerant of a
/// trailing slash and of a config that already includes `/v1`.
pub fn messages_url(base: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    if trimmed.ends_with("/v1/messages") {
        return trimmed.to_string();
    }
    if trimmed.ends_with("/v1") {
        return format!("{trimmed}/messages");
    }
    format!("{trimmed}/v1/messages")
}

/// Convert an internal request into the Anthropic wire format.
pub fn build_body(req: &ChatRequest) -> Result<Value> {
    // The system prompt is a top-level field, and the Messages API has no `system` role. Any system
    // content — the request's explicit `system` plus any stray `Role::System` transcript messages — is
    // accumulated into that one field, so nothing is dropped while keeping the wire shape Anthropic demands.
    let mut system = req.system.clone().unwrap_or_default();
    let mut messages: Vec<Value> = Vec::with_capacity(req.messages.len());

    for message in &req.messages {
        match message.role {
            Role::System => system.push_str(&message.text()),
            Role::User => messages.push(json!({
                "role": "user",
                "content": text_blocks(message)?,
            })),
            Role::Assistant => {
                let mut blocks: Vec<Value> = Vec::new();
                for part in &message.parts {
                    match part {
                        Part::Text { text } => {
                            if !text.is_empty() {
                                blocks.push(json!({ "type": "text", "text": text }));
                            }
                        }
                        Part::ToolCall {
                            id,
                            name,
                            arguments,
                        } => {
                            // `input` is the object directly; Anthropic does not stringify arguments.
                            blocks.push(json!({
                                "type": "tool_use",
                                "id": id.as_str(),
                                "name": name,
                                "input": arguments,
                            }));
                        }
                        Part::ToolResult { .. } => {
                            return Err(HxError::Provider(
                                "an assistant message cannot carry a tool result in the Anthropic \
                                 adapter"
                                    .to_string(),
                            ))
                        }
                        Part::Image { .. } => {
                            return Err(HxError::Provider(
                                "image inputs are not implemented in the Anthropic adapter yet"
                                    .to_string(),
                            ))
                        }
                    }
                }
                messages.push(json!({ "role": "assistant", "content": blocks }));
            }
            Role::Tool => {
                // One user-role message per tool-result message, with each result as a `tool_result`
                // block. Anthropic has no `tool` role; the result is spoken by a `user` turn.
                let blocks: Vec<Value> = message
                    .parts
                    .iter()
                    .filter_map(|part| match part {
                        Part::ToolResult { id, ok, content } => Some(json!({
                            "type": "tool_result",
                            "tool_use_id": id.as_str(),
                            "content": content,
                            // Failure must be signed so the model knows not to trust the content.
                            "is_error": !ok,
                        })),
                        Part::ToolCall { .. } => {
                            // A tool-result message carrying a tool *call* is malformed in our shape;
                            // it is dropped here because assistant-role calls are emitted separately and a
                            // stray one in a tool message has no place in Anthropic's wire model.
                            None
                        }
                        _ => None,
                    })
                    .collect();

                if !blocks.is_empty() {
                    messages.push(json!({ "role": "user", "content": blocks }));
                }
            }
        }
    }

    let tools: Vec<Value> = req.tools.iter().map(tool_body).collect();

    let mut body = json!({
        "model": req.model,
        "messages": messages,
        // Required. The API rejects a request without it.
        "max_tokens": req.max_tokens,
    });
    if !system.is_empty() {
        body["system"] = json!(system);
    }
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools);
    }
    if let Some(temperature) = req.temperature {
        body["temperature"] = json!(temperature);
    }

    Ok(body)
}

fn tool_body(spec: &ToolSpec) -> Value {
    json!({
        "name": spec.name,
        "description": spec.description,
        // Anthropic names the JSON-Schema field `input_schema`, not `parameters`.
        "input_schema": spec.input_schema,
    })
}

/// The text content blocks for a user or assistant message, or an error for the parts this adapter
/// cannot send. Silently dropping an image would be the worst outcome: the model answers a question about
/// a picture it never received, and nothing in the transcript says so.
fn text_blocks(message: &Message) -> Result<Vec<Value>> {
    let mut blocks: Vec<Value> = Vec::new();
    for part in &message.parts {
        match part {
            Part::Text { text } => {
                if !text.is_empty() {
                    blocks.push(json!({ "type": "text", "text": text }));
                }
            }
            Part::Image { .. } => {
                return Err(HxError::Provider(
                    "image inputs are not implemented in the Anthropic adapter yet".to_string(),
                ))
            }
            Part::ToolResult { .. } | Part::ToolCall { .. } => {
                // Not valid in a plain text conversation block; handled at the message level elsewhere.
            }
        }
    }
    Ok(blocks)
}

/// Normalise a Messages API response.
pub fn parse_response(body: &Value, requested_model: &str) -> Result<ChatResponse> {
    let content = body
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            HxError::Provider(format!(
                "the response contained no content: {}",
                truncate(&body.to_string())
            ))
        })?;

    let mut parts: Vec<Part> = Vec::new();

    for block in content {
        let kind = block.get("type").and_then(Value::as_str).unwrap_or("");
        match kind {
            "text" => {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    if !text.is_empty() {
                        parts.push(Part::text(text));
                    }
                }
            }
            "tool_use" => {
                let id = block
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        HxError::Provider("a tool_use block arrived without an id".to_string())
                    })?
                    .to_string();
                let name = block
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        HxError::Provider(format!("tool_use block {id} arrived without a name"))
                    })?
                    .to_string();
                // `input` is always an object; unlike OpenAI, it is not a JSON string.
                let arguments = block.get("input").cloned().unwrap_or(Value::Null);
                parts.push(Part::ToolCall {
                    id: ToolCallId::from_raw(id),
                    name,
                    arguments,
                });
            }
            // Block types we have never seen (thinking, document, image, …) are skipped rather than
            // fatal. The API adds new types over time; refusing the whole response would take the harness
            // down because a future model emitted something newer than this adapter.
            _ => {}
        }
    }

    if parts.is_empty() {
        return Err(HxError::Provider(
            "the model returned neither text nor a tool call".to_string(),
        ));
    }

    let finish = match body
        .get("stop_reason")
        .and_then(Value::as_str)
        .unwrap_or("end_turn")
    {
        "end_turn" => FinishReason::Stop,
        "stop_sequence" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "tool_use" => FinishReason::ToolUse,
        _ => FinishReason::Other,
    };

    let usage = body.get("usage").cloned().unwrap_or(Value::Null);
    let usage = Usage {
        input_tokens: number(&usage, "input_tokens"),
        output_tokens: number(&usage, "output_tokens"),
        // Cache reads (`cache_read_input_tokens`) are the signal that context reuse worked; cache writes
        // are billed fresh and are not counted as hits.
        cached_input_tokens: number(&usage, "cache_read_input_tokens"),
        reasoning_tokens: 0,
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

fn truncate(text: &str) -> String {
    const LIMIT: usize = 512;
    let trimmed = text.trim();
    if trimmed.chars().count() <= LIMIT {
        return trimmed.to_string();
    }
    format!(
        "{}… ({} more characters)",
        trimmed.chars().take(LIMIT).collect::<String>(),
        trimmed.chars().count() - LIMIT
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::ids::ProviderId;

    fn id() -> ProviderId {
        ProviderId::from("anthropic-main")
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
        "Run a command".to_string()
    }

    #[test]
    fn the_messages_url_is_built_from_the_host() {
        assert_eq!(
            messages_url("https://api.anthropic.com"),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            messages_url("https://api.anthropic.com/"),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            messages_url("https://api.anthropic.com/v1"),
            "https://api.anthropic.com/v1/messages",
            "already an API root: appending /v1 again would 404"
        );
        assert_eq!(
            messages_url("https://proxy.example/v1/messages"),
            "https://proxy.example/v1/messages",
            "already the full path is left alone"
        );
    }

    #[test]
    fn the_system_prompt_is_a_top_level_field_not_a_message() {
        // The Messages API has no `system` role; putting one in `messages` is a 400. The top-level
        // `system` field is the only correct home.
        let req =
            ChatRequest::new("claude-opus-4", vec![Message::user("hello")]).with_system("be terse");
        let body = build_body(&req).unwrap();

        assert_eq!(body["system"], "be terse");
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
        assert!(
            messages[0].get("role") != Some(&serde_json::Value::String("system".into())),
            "no message may carry the system role"
        );
    }

    #[test]
    fn a_transcript_system_message_is_folded_into_the_top_level_system() {
        // A stray `Role::System` transcript message has no `system`-role home in Anthropic; folding it
        // into the top-level field keeps it instead of dropping it or emitting an invalid message.
        let req = ChatRequest::new(
            "claude-opus-4",
            vec![Message::system("you are terse"), Message::user("hi")],
        );
        let body = build_body(&req).unwrap();
        assert_eq!(body["system"], "you are terse");
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn max_tokens_is_required_and_carried() {
        let req = ChatRequest::new("claude-opus-4", vec![Message::user("hi")])
            .with_max_tokens(1234)
            .with_temperature(0.25);
        let body = build_body(&req).unwrap();
        assert_eq!(body["max_tokens"], 1234);
        assert_eq!(body["temperature"], 0.25);
        assert_eq!(body["model"], "claude-opus-4");
    }

    #[test]
    fn tools_are_sent_with_input_schema_not_parameters() {
        // The field name is what a 400-vs-silently-ignored difference is made of.
        let bare = build_body(&ChatRequest::new(
            "claude-opus-4",
            vec![Message::user("hi")],
        ))
        .unwrap();
        assert!(bare.get("tools").is_none(), "{bare}");

        let req = ChatRequest::new("claude-opus-4", vec![Message::user("hi")])
            .with_tools(vec![tool("shell")]);
        let body = build_body(&req).unwrap();
        let sent = &body["tools"][0];
        assert_eq!(sent["name"], "shell");
        assert_eq!(sent["description"], describe());
        assert_eq!(sent["input_schema"]["required"][0], "cmd");
        assert!(
            sent.get("parameters").is_none(),
            "Anthropic uses input_schema, not parameters"
        );
    }

    #[test]
    fn a_tool_call_round_trips_as_a_tool_use_block_with_object_input() {
        // Anthropic's `tool_use.input` is always a JSON object, never a stringified one.
        let call = Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: ToolCallId::from_raw("toolu_abc"),
                name: "shell".into(),
                arguments: json!({ "cmd": "ls" }),
            }],
        );
        let body = build_body(&ChatRequest::new("claude-opus-4", vec![call])).unwrap();

        let blocks = body["messages"][0]["content"].as_array().unwrap();
        let tool_use = blocks
            .iter()
            .find(|b| b["type"] == "tool_use")
            .expect("a tool_use block");
        assert_eq!(tool_use["id"], "toolu_abc");
        assert_eq!(tool_use["name"], "shell");
        assert_eq!(tool_use["input"]["cmd"], "ls");
    }

    #[test]
    fn tool_results_become_user_messages_with_tool_result_blocks() {
        // Anthropic has no `tool` role; each result goes in a `user` message as a `tool_result`
        // block, paired to its `tool_use` by id.
        let message = Message::new(
            Role::Tool,
            vec![
                Part::ToolResult {
                    id: ToolCallId::from_raw("toolu_1"),
                    ok: true,
                    content: "total 0".to_string(),
                },
                Part::ToolResult {
                    id: ToolCallId::from_raw("toolu_2"),
                    ok: false,
                    content: "no such file".to_string(),
                },
            ],
        );
        let body = build_body(&ChatRequest::new("claude-opus-4", vec![message])).unwrap();

        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1, "one user message holds both results");
        assert_eq!(messages[0]["role"], "user");
        let blocks = messages[0]["content"].as_array().unwrap();
        assert_eq!(blocks[0]["type"], "tool_result");
        assert_eq!(blocks[0]["tool_use_id"], "toolu_1");
        assert_eq!(blocks[0]["content"], "total 0");
        assert_eq!(blocks[0]["is_error"], false);
        assert_eq!(blocks[1]["tool_use_id"], "toolu_2");
        assert_eq!(
            blocks[1]["is_error"], true,
            "a failed result must be signed"
        );
    }

    #[test]
    fn an_image_part_is_refused_rather_than_dropped() {
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
        let err = build_body(&ChatRequest::new("claude-opus-4", vec![message])).unwrap_err();
        assert!(err.to_string().contains("image inputs"), "{err}");
    }

    #[test]
    fn a_text_response_is_normalised() {
        let body = json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-20260514",
            "content": [ { "type": "text", "text": "hello there" } ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 12,
                "output_tokens": 3,
                "cache_read_input_tokens": 8,
                "cache_creation_input_tokens": 0
            }
        });

        let response = parse_response(&body, "claude-opus-4").unwrap();
        assert_eq!(response.message.text(), "hello there");
        assert_eq!(response.message.role, Role::Assistant);
        assert_eq!(response.finish, FinishReason::Stop);
        assert_eq!(response.model, "claude-opus-4-20260514");
        assert_eq!(response.usage.input_tokens, 12);
        assert_eq!(response.usage.output_tokens, 3);
        assert_eq!(
            response.usage.cached_input_tokens, 8,
            "cache reads are the signal context reuse worked"
        );
    }

    #[test]
    fn the_served_model_falls_back_to_the_requested_one() {
        let body = json!({
            "content": [ { "type": "text", "text": "hi" } ],
            "stop_reason": "end_turn"
        });
        assert_eq!(
            parse_response(&body, "claude-opus-4").unwrap().model,
            "claude-opus-4"
        );
    }

    #[test]
    fn tool_calls_are_parsed_from_tool_use_blocks() {
        let body = json!({
            "content": [
                { "type": "tool_use", "id": "toolu_abc", "name": "shell", "input": { "cmd": "pwd" } }
            ],
            "stop_reason": "tool_use"
        });

        let response = parse_response(&body, "claude-opus-4").unwrap();
        assert_eq!(response.finish, FinishReason::ToolUse);

        let call = response.message.tool_calls().next().unwrap();
        match call {
            Part::ToolCall {
                id,
                name,
                arguments,
            } => {
                assert_eq!(id.as_str(), "toolu_abc");
                assert_eq!(name, "shell");
                assert_eq!(arguments["cmd"], "pwd");
            }
            other => panic!("expected a tool call, got {other:?}"),
        }
    }

    #[test]
    fn stop_reason_maps_to_finish_reason() {
        for (wire, expected) in [
            ("end_turn", FinishReason::Stop),
            ("stop_sequence", FinishReason::Stop),
            ("max_tokens", FinishReason::Length),
            ("tool_use", FinishReason::ToolUse),
            ("something_new", FinishReason::Other),
        ] {
            let body = json!({
                "content": [ { "type": "text", "text": "x" } ],
                "stop_reason": wire
            });
            assert_eq!(
                parse_response(&body, "m").unwrap().finish,
                expected,
                "stop_reason={wire}"
            );
        }
    }

    #[test]
    fn unknown_content_block_types_are_skipped_not_fatal() {
        // The API adds block types over time (thinking, document, …). A future model emitting one must
        // not take the harness down; the known blocks still parse.
        let body = json!({
            "content": [
                { "type": "thinking", "thinking": "secret" },
                { "type": "text", "text": "answer" }
            ],
            "stop_reason": "end_turn"
        });
        let response = parse_response(&body, "m").unwrap();
        assert_eq!(response.message.text(), "answer");
    }

    #[test]
    fn a_response_with_no_known_blocks_is_an_error() {
        let body = json!({
            "content": [ { "type": "thinking", "thinking": "only" } ],
            "stop_reason": "end_turn"
        });
        let err = parse_response(&body, "m").unwrap_err();
        assert!(
            err.to_string().contains("neither text nor a tool call"),
            "{err}"
        );

        let err = parse_response(&json!({}), "m").unwrap_err();
        assert!(err.to_string().contains("no content"), "{err}");
    }

    #[test]
    fn a_tool_use_block_without_an_id_or_a_name_is_rejected() {
        let no_id = json!({
            "content": [ { "type": "tool_use", "name": "shell", "input": {} } ],
            "stop_reason": "tool_use"
        });
        assert!(parse_response(&no_id, "m")
            .unwrap_err()
            .to_string()
            .contains("without an id"));

        let no_name = json!({
            "content": [ { "type": "tool_use", "id": "toolu_1", "input": {} } ],
            "stop_reason": "tool_use"
        });
        assert!(parse_response(&no_name, "m")
            .unwrap_err()
            .to_string()
            .contains("without a name"));
    }

    #[test]
    fn usage_missing_entirely_is_zero_rather_than_a_panic() {
        let body = json!({
            "content": [ { "type": "text", "text": "x" } ],
            "stop_reason": "end_turn"
        });
        let usage = parse_response(&body, "m").unwrap().usage;
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
        assert_eq!(usage.cached_input_tokens, 0);
    }

    #[test]
    fn an_auth_failure_is_named_as_one() {
        // Same classification contract as the OpenAI adapter: a 401/403 is a dead credential, and the
        // pool must bench it rather than retry forever.
        let err = crate::openai::classify_error(
            &id(),
            401,
            None,
            "{\"error\":{\"type\":\"authentication_error\"}}",
        );
        assert!(err.is_auth_failure(), "{err:?}");
        assert!(!err.is_retryable(), "{err:?}");
    }
}
