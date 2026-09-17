//! The Anthropic Messages adapter, over real HTTP.
//!
//! The same stub-server approach as the OpenAI suite: the adapter is exercised through `reqwest`, so the
//! request line, the headers (including `x-api-key` and `anthropic-version`) and the serialised body
//! are the real ones, and the response is real HTTP that has to be parsed. No API key, no network, no
//! cassette — which is why this runs on every commit instead of being `#[ignore]`d.
//!
//! The differences from the OpenAI suite are the point: `POST /v1/messages` (not chat/completions),
//! auth on `x-api-key` rather than `Authorization: Bearer`, the required `anthropic-version` header,
//! and a body whose system prompt is top-level and whose tool results are `user`-role `tool_result`
//! blocks.

use hx_core::error::HxError;
use hx_core::ids::{ProviderId, ToolCallId};
use hx_core::message::{Message, Part, Role};
use hx_provider::openai::http_client;
use hx_provider::{AnthropicMessages, ChatRequest, FinishReason, Provider, ToolSpec};
use hx_secrets::Secret;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// What the stub saw, and what it was told to answer.
#[derive(Debug, Clone)]
struct Captured {
    request_line: String,
    head: String,
    body: Value,
}

/// A one-shot HTTP/1.1 server: accept one request, answer with `status` and `response_body`.
async fn stub(status: u16, extra_headers: &str, response_body: &str) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let addr = listener.local_addr().expect("a bound address");

    let status_line = format!("HTTP/1.1 {status} {}", reason(status));
    let headers = format!(
        "content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{extra_headers}",
        response_body.len()
    );
    let response = format!("{status_line}\r\n{headers}\r\n{response_body}");
    let expected_len = response_body.len();

    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("a connection");
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];

        let (head_end, content_length) = loop {
            let read = socket.read(&mut chunk).await.expect("a readable socket");
            if read == 0 {
                break (0usize, 0usize);
            }
            buffer.extend_from_slice(&chunk[..read]);

            if let Some(position) = find(&buffer, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buffer[..position]).to_string();
                let length = content_length_of(&head);
                if buffer.len() >= position + 4 + length {
                    break (position, length);
                }
            }
        };

        let head = if head_end > 0 {
            String::from_utf8_lossy(&buffer[..head_end]).to_string()
        } else {
            String::new()
        };
        let body_start = head_end + 4;
        let body_text = String::from_utf8_lossy(
            buffer
                .get(body_start..body_start + content_length)
                .unwrap_or_default(),
        )
        .to_string();

        if expected_len > 0 || status != 204 {
            socket
                .write_all(response.as_bytes())
                .await
                .expect("the stub can write");
            socket.flush().await.ok();
        }

        Captured {
            request_line: head.lines().next().unwrap_or_default().to_string(),
            head,
            body: serde_json::from_str(&body_text).unwrap_or(Value::Null),
        }
    });

    Stub {
        base_url: format!("http://{addr}"),
        handle,
    }
}

struct Stub {
    base_url: String,
    handle: tokio::task::JoinHandle<Captured>,
}

impl Stub {
    fn provider(&self) -> AnthropicMessages {
        AnthropicMessages::new(
            ProviderId::from("test-provider"),
            self.base_url.clone(),
            vec!["claude-opus-4".to_string()],
            http_client().expect("an HTTP client"),
        )
    }

    async fn captured(self) -> Captured {
        self.handle.await.expect("the stub task")
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length_of(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

fn key() -> Secret {
    Secret::new("test-key-do-not-log")
}

fn request() -> ChatRequest {
    ChatRequest::new(
        "claude-opus-4",
        vec![Message::user("what is in this repo?")],
    )
    .with_system("be terse")
}

// -------------------------------------------------------------------------------------------
// The happy path, over the wire
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_completion_round_trips_over_http() {
    let stub = stub(
        200,
        "",
        &json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4",
            "content": [ { "type": "text", "text": "a Rust agent harness" } ],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 20, "output_tokens": 5, "cache_read_input_tokens": 4 }
        })
        .to_string(),
    )
    .await;

    let response = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect("the completion succeeds");

    assert_eq!(response.message.text(), "a Rust agent harness");
    assert_eq!(response.finish, FinishReason::Stop);
    assert_eq!(response.usage.input_tokens, 20);
    assert_eq!(response.usage.cached_input_tokens, 4);

    let captured = stub.captured().await;

    // The request line proves the URL was joined correctly: `/v1/messages`, not chat/completions.
    assert_eq!(
        captured.request_line, "POST /v1/messages HTTP/1.1",
        "{}",
        captured.head
    );

    // Auth went out on `x-api-key` (not Authorization), plus the required `anthropic-version`.
    let head_lower = captured.head.to_ascii_lowercase();
    assert!(
        head_lower.contains(&format!(
            "x-api-key: {}",
            key().expose().to_ascii_lowercase()
        )),
        "the credential passed to the adapter must be the value on the wire: {}",
        captured.head
    );
    assert!(
        head_lower.contains("anthropic-version: 2023-06-01"),
        "{}",
        captured.head
    );
    assert!(
        !head_lower.contains("authorization"),
        "Anthropic does not use Bearer auth: {}",
        captured.head
    );
    assert!(
        head_lower.contains("content-type: application/json"),
        "{}",
        captured.head
    );

    // And the body is the Anthropic shape: top-level `system`, not a system-role message.
    assert_eq!(captured.body["model"], "claude-opus-4");
    assert_eq!(captured.body["system"], "be terse");
    let messages = captured.body["messages"].as_array().unwrap();
    assert_eq!(messages[0]["role"], "user");
    assert_eq!(messages[0]["content"][0]["type"], "text");
    assert_eq!(messages[0]["content"][0]["text"], "what is in this repo?");
}

#[tokio::test]
async fn a_tool_use_comes_back_over_the_wire_with_object_arguments() {
    let stub = stub(
        200,
        "",
        &json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [
                { "type": "tool_use", "id": "toolu_7", "name": "shell", "input": { "cmd": "ls" } }
            ],
            "stop_reason": "tool_use",
            "usage": { "input_tokens": 20, "output_tokens": 5 }
        })
        .to_string(),
    )
    .await;

    let tools = vec![ToolSpec {
        name: "shell".to_string(),
        description: "run a command".to_string(),
        input_schema: json!({ "type": "object", "properties": {} }),
    }];

    let response = stub
        .provider()
        .complete(request().with_tools(tools), &key())
        .await
        .expect("the completion succeeds");

    assert_eq!(response.finish, FinishReason::ToolUse);
    let calls: Vec<&Part> = response.message.tool_calls().collect();
    match calls[0] {
        Part::ToolCall {
            id,
            name,
            arguments,
        } => {
            assert_eq!(id.as_str(), "toolu_7");
            assert_eq!(name, "shell");
            assert_eq!(arguments["cmd"], "ls");
        }
        other => panic!("expected a tool call, got {other:?}"),
    }

    // The tool travelled out with `input_schema`, not `parameters`, and is not typed "function".
    let captured = stub.captured().await;
    assert_eq!(captured.body["tools"][0]["name"], "shell");
    assert_eq!(captured.body["tools"][0]["input_schema"]["type"], "object");
    assert!(
        captured.body["tools"][0].get("parameters").is_none(),
        "Anthropic names the schema field input_schema"
    );
}

#[tokio::test]
async fn a_tool_result_round_trips_as_a_user_message_with_a_tool_result_block() {
    // The second half of the tool loop: our transcript's `Role::Tool` message must become a `user`
    // message with a `tool_result` block, not a tool-role message the API would reject.
    let transcript = vec![
        Message::user("List /tmp"),
        Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: ToolCallId::from_raw("toolu_1"),
                name: "shell".into(),
                arguments: json!({"cmd": "ls /tmp"}),
            }],
        ),
        Message::tool_result(ToolCallId::from_raw("toolu_1"), true, "cargo-target"),
    ];

    let stub = stub(
        200,
        "",
        &json!({
            "id": "msg_2",
            "type": "message",
            "role": "assistant",
            "content": [ { "type": "text", "text": "Done." } ],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 30, "output_tokens": 2 }
        })
        .to_string(),
    )
    .await;

    stub.provider()
        .complete(ChatRequest::new("claude-opus-4", transcript), &key())
        .await
        .expect("the follow-up completion");

    let body = stub.captured().await.body;
    let messages = body["messages"].as_array().unwrap();

    // The assistant turn carries the tool_use block, and the result is a user-role tool_result.
    let assistant = &messages[1];
    assert_eq!(assistant["role"], "assistant");
    assert_eq!(assistant["content"][0]["type"], "tool_use");
    assert_eq!(assistant["content"][0]["id"], "toolu_1");

    let result = &messages[2];
    assert_eq!(
        result["role"], "user",
        "tool results are user-role, not tool-role"
    );
    assert_eq!(result["content"][0]["type"], "tool_result");
    assert_eq!(result["content"][0]["tool_use_id"], "toolu_1");
    assert_eq!(result["content"][0]["content"], "cargo-target");
    assert_eq!(result["content"][0]["is_error"], false);
}

// -------------------------------------------------------------------------------------------
// Failures, over the wire
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_rate_limit_becomes_a_retry_with_the_servers_own_delay() {
    let stub = stub(
        429,
        "retry-after: 2\r\n",
        "{\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\"}}",
    )
    .await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("429 is a failure");

    match err {
        HxError::RateLimited {
            scope,
            retry_after_ms,
        } => {
            assert_eq!(scope, "test-provider");
            assert_eq!(
                retry_after_ms, 2000,
                "the server's Retry-After is the truth"
            );
        }
        other => panic!("expected a rate limit, got {other:?}"),
    }
}

#[tokio::test]
async fn an_auth_failure_says_so_and_quotes_the_provider() {
    let stub = stub(
        401,
        "",
        "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"invalid x-api-key\"}}",
    )
    .await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("401 is a failure");

    // The classification a pool acts on, end to end through the adapter: this is what benches a
    // credential. A 401 here must never read like a generic provider error, or a pool retries a dead
    // key forever.
    assert!(err.is_auth_failure(), "{err:?}");
    assert!(!err.is_retryable(), "{err:?}");

    let message = err.to_string();
    assert!(message.contains("rejected the credential"), "{message}");
    assert!(
        !message.contains("test-key-do-not-log"),
        "the request must never put the key in an error: {message}"
    );
}

#[tokio::test]
async fn a_server_error_is_reported_with_its_status() {
    let stub = stub(
        500,
        "",
        "{\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"upstream is unwell\"}}",
    )
    .await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("500 is a failure");
    let message = err.to_string();
    assert!(message.contains("500"), "{message}");
    assert!(message.contains("upstream is unwell"), "{message}");
}

#[tokio::test]
async fn a_body_that_is_not_json_is_reported_rather_than_panicking() {
    let stub = stub(200, "", "<html><body>502 Bad Gateway</body></html>").await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("HTML is not a completion");
    let message = err.to_string();
    assert!(message.contains("was not JSON"), "{message}");
    assert!(message.contains("Bad Gateway"), "{message}");
}

#[tokio::test]
async fn a_json_body_with_no_content_is_an_error() {
    let stub = stub(
        200,
        "",
        "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"no content\"}}",
    )
    .await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("no content is a failure");
    assert!(err.to_string().contains("no content"), "{err}");
}

#[tokio::test]
async fn an_unreachable_endpoint_fails_with_the_url_in_the_message() {
    let provider = AnthropicMessages::new(
        ProviderId::from("test-provider"),
        "http://127.0.0.1:1",
        vec!["claude-opus-4".to_string()],
        http_client().expect("an HTTP client"),
    );

    let err = provider
        .complete(request(), &key())
        .await
        .expect_err("nothing is listening");
    let message = err.to_string();
    assert!(message.contains("could not reach"), "{message}");
    assert!(message.contains("127.0.0.1:1"), "{message}");
}

#[tokio::test]
async fn the_provider_reports_its_own_identity() {
    let stub = stub(
        200,
        "",
        "{\"id\":\"m\",\"content\":[{\"type\":\"text\",\"text\":\"x\"}],\"stop_reason\":\"end_turn\"}",
    )
    .await;
    let provider = Arc::new(stub.provider());

    assert_eq!(provider.id().as_str(), "test-provider");
    assert_eq!(provider.models(), ["claude-opus-4".to_string()]);
    assert_eq!(provider.kind(), hx_core::config::ProviderKind::Anthropic);
}

/// Every request carries the required `anthropic-version` header. Omitting it is a 400, so it must
/// be on by default with no opt-out for the sort of proxy that strips unknown headers.
#[tokio::test]
async fn every_request_sends_the_anthropic_version_header_even_without_a_key_turn() {
    // A tool-usage turn that exercises the full request path.
    let stub = stub(
        200,
        "",
        "{\"id\":\"m\",\"content\":[{\"type\":\"text\",\"text\":\"x\"}],\"stop_reason\":\"end_turn\"}",
    )
    .await;
    stub.provider()
        .complete(request(), &key())
        .await
        .expect("the completion succeeds");

    let head = stub.captured().await.head.to_ascii_lowercase();
    assert!(head.contains("anthropic-version: 2023-06-01"), "{head}");
}

/// A body of named SSE events, as the API sends for a streamed turn that calls one tool.
///
/// Taken from the shapes in the streaming docs: `input_json_delta` carries *partial JSON*, so the
/// fragments here are deliberately split mid-token — a client that parsed them per delta would fail
/// on this body, which is the point.
fn tool_call_stream_body() -> String {
    [
        r#"event: message_start"#,
        r#"data: {"type":"message_start","message":{"id":"msg_1","model":"claude-opus-4","usage":{"input_tokens":42,"output_tokens":1}}}"#,
        "",
        r#"event: content_block_start"#,
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        "",
        r#"event: ping"#,
        r#"data: {"type":"ping"}"#,
        "",
        r#"event: content_block_delta"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me look"}}"#,
        "",
        r#"event: content_block_stop"#,
        r#"data: {"type":"content_block_stop","index":0}"#,
        "",
        r#"event: content_block_start"#,
        r#"data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_9","name":"read_file","input":{}}}"#,
        "",
        r#"event: content_block_delta"#,
        r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"pa"}}"#,
        "",
        r#"event: content_block_delta"#,
        r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"th\":\"Cargo"}}"#,
        "",
        r#"event: content_block_delta"#,
        r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":".toml\"}"}}"#,
        "",
        r#"event: content_block_stop"#,
        r#"data: {"type":"content_block_stop","index":1}"#,
        "",
        r#"event: message_delta"#,
        r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":31}}"#,
        "",
        r#"event: message_stop"#,
        r#"data: {"type":"message_stop"}"#,
        "",
    ]
    .join("\n")
}

#[tokio::test]
async fn a_streamed_turn_asks_for_a_stream_and_sends_the_same_body_otherwise() {
    // Streaming must not silently become the default for the non-streaming path, and the two bodies
    // must not drift: reusing `build_body` is what keeps them the same request with one flag added.
    let stub = stub(
        200,
        "content-type: text/event-stream\r\n",
        &tool_call_stream_body(),
    )
    .await;
    let provider = stub.provider();

    let mut deltas = Vec::new();
    let reply = provider
        .stream(request(), &key(), &mut |delta| {
            deltas.push(delta);
            Ok(())
        })
        .await
        .expect("the streamed turn succeeds");

    let captured = stub.captured().await;
    assert_eq!(captured.request_line, "POST /v1/messages HTTP/1.1");
    assert_eq!(
        captured.body["stream"], true,
        "the streaming call asks for a stream: {}",
        captured.body
    );

    // The same body the non-streaming call builds, so the two cannot drift apart.
    let expected = hx_provider::anthropic::build_body(&request()).unwrap();
    let mut without_flag = captured.body.clone();
    without_flag.as_object_mut().unwrap().remove("stream");
    assert_eq!(without_flag, expected, "only the stream flag was added");

    // Text arrived as deltas rather than in one lump, which is the whole point.
    let texts: Vec<String> = deltas
        .iter()
        .filter_map(|d| match d {
            hx_provider::StreamDelta::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, vec!["Let me look".to_string()]);

    // And the assembled reply is the same shape a non-streaming call produces.
    assert_eq!(reply.message.text(), "Let me look");
    assert_eq!(reply.finish, FinishReason::ToolUse);
    assert_eq!(reply.model, "claude-opus-4");
    assert_eq!(reply.usage.input_tokens, 42);
    assert_eq!(reply.usage.output_tokens, 31);

    let call = reply
        .message
        .tool_calls()
        .next()
        .expect("the tool call is complete");
    match call {
        Part::ToolCall {
            id,
            name,
            arguments,
        } => {
            assert_eq!(id.as_str(), "toolu_9");
            assert_eq!(name, "read_file");
            // Reassembled from three partial-JSON fragments.
            assert_eq!(arguments["path"], "Cargo.toml");
        }
        other => panic!("expected a tool call, got {other:?}"),
    }
}

#[tokio::test]
async fn a_stream_that_fails_after_the_headers_is_an_error_not_a_short_answer() {
    // The API documents mid-stream errors after a 200. Returning the partial text as a finished
    // reply would look like the model deciding to stop early.
    let body = [
        r#"event: message_start"#,
        r#"data: {"type":"message_start","message":{"model":"claude-opus-4","usage":{"input_tokens":5,"output_tokens":1}}}"#,
        "",
        r#"event: error"#,
        r#"data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        "",
    ]
    .join("\n");

    let stub = stub(200, "content-type: text/event-stream\r\n", &body).await;
    let provider = stub.provider();

    let err = provider
        .stream(request(), &key(), &mut |_| Ok(()))
        .await
        .expect_err("a mid-stream error is a failure");
    let message = format!("{err}");
    assert!(message.contains("Overloaded"), "{message}");
}
