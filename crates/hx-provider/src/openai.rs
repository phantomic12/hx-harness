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
//! Image parts, streaming, and tool-choice control. Each is a real feature rather than a
//! hypothetical, and each fails loudly instead of being silently dropped: an image part is an
//! error naming the adapter, not a message that quietly loses its picture.

use crate::provider::{ChatRequest, ChatResponse, FinishReason, Provider, ToolSpec, Usage};
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
/// dead, bench it", and a `500` is "the provider is having a bad day, try another".
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
        400 | 422 => HxError::Provider(format!(
            "{id}: the request was rejected (HTTP {status}): {detail}"
        )),
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
}
