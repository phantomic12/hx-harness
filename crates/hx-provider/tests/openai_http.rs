//! The OpenAI-compatible adapter, over real HTTP.
//!
//! A stub server rather than a mock: the adapter is exercised through `reqwest`, so the request
//! line, the headers and the serialised body are all the real ones, and the response is real HTTP
//! that has to be parsed. No API key, no network, no cassette — which is why this runs on every
//! commit instead of being `#[ignore]`d.
//!
//! What a mock would not catch, and this does: a body that serialises to the wrong shape, a header
//! that is missing, a status code that maps to the wrong error, a body that never gets read.

use hx_core::error::HxError;
use hx_core::ids::ProviderId;
use hx_core::message::{Message, Part};
use hx_provider::openai::http_client;
use hx_provider::{ChatRequest, FinishReason, OpenAiCompatible, Provider, ToolSpec};
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

        // Read until the headers are complete *and* the declared body has arrived: a body read in
        // two packets is the normal case, not an edge case.
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
        base_url: format!("http://{addr}/v1"),
        handle,
    }
}

struct Stub {
    base_url: String,
    handle: tokio::task::JoinHandle<Captured>,
}

impl Stub {
    fn provider(&self) -> OpenAiCompatible {
        OpenAiCompatible::new(
            ProviderId::from("test-provider"),
            self.base_url.clone(),
            vec!["gpt-5".to_string()],
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
        502 => "Bad Gateway",
        _ => "Status",
    }
}

fn key() -> Secret {
    Secret::new("test-key-do-not-log")
}

fn request() -> ChatRequest {
    ChatRequest::new("gpt-5", vec![Message::user("what is in this repo?")]).with_system("be terse")
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
            "model": "gpt-5",
            "choices": [{
                "message": { "role": "assistant", "content": "a Rust agent harness" },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 20, "completion_tokens": 5 }
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

    let captured = stub.captured().await;

    // The request line proves the URL was joined correctly, `/v1` and all.
    assert_eq!(
        captured.request_line, "POST /v1/chat/completions HTTP/1.1",
        "{}",
        captured.head
    );

    // The credential went out as a bearer token, and it is the one we passed.
    let head_lower = captured.head.to_ascii_lowercase();
    assert!(
        head_lower.contains("authorization: bearer test-key-do-not-log"),
        "{}",
        captured.head
    );
    assert!(
        head_lower.contains("content-type: application/json"),
        "{}",
        captured.head
    );

    // And the body is the shape the API expects: system first, then the user turn.
    assert_eq!(captured.body["model"], "gpt-5");
    assert_eq!(captured.body["messages"][0]["role"], "system");
    assert_eq!(captured.body["messages"][0]["content"], "be terse");
    assert_eq!(captured.body["messages"][1]["role"], "user");
    assert_eq!(
        captured.body["messages"][1]["content"],
        "what is in this repo?"
    );
}

#[tokio::test]
async fn a_tool_call_comes_back_over_the_wire_with_parsed_arguments() {
    let stub = stub(
        200,
        "",
        &json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_7",
                        "type": "function",
                        "function": { "name": "shell", "arguments": "{\"cmd\":\"ls\"}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        })
        .to_string(),
    )
    .await;

    let tools = vec![ToolSpec {
        name: "shell".to_string(),
        description: "run a command".to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
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
            assert_eq!(id.as_str(), "call_7");
            assert_eq!(name, "shell");
            assert_eq!(arguments["cmd"], "ls");
        }
        other => panic!("expected a tool call, got {other:?}"),
    }

    // The tool travelled out as a function spec, not as some other dialect.
    let captured = stub.captured().await;
    assert_eq!(captured.body["tools"][0]["type"], "function");
    assert_eq!(captured.body["tools"][0]["function"]["name"], "shell");
}

#[tokio::test]
async fn an_endpoint_that_does_not_authenticate_sends_no_authorization_header() {
    // A local llama.cpp or a vLLM behind a reverse proxy: sending a bearer token is noise at best.
    let stub = stub(
        200,
        "",
        &json!({
            "choices": [{ "message": { "content": "local answer" }, "finish_reason": "stop" }]
        })
        .to_string(),
    )
    .await;

    let provider = stub.provider().without_auth();
    let response = provider
        .complete(request(), &key())
        .await
        .expect("the completion succeeds");
    assert_eq!(response.message.text(), "local answer");

    let captured = stub.captured().await;
    assert!(
        !captured.head.to_ascii_lowercase().contains("authorization"),
        "{}",
        captured.head
    );
}

// -------------------------------------------------------------------------------------------
// Failures, over the wire
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_rate_limit_becomes_a_retry_with_the_servers_own_delay() {
    let stub = stub(429, "retry-after: 2\r\n", "{\"error\":\"rate limited\"}").await;

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
    let stub = stub(401, "", "{\"error\":{\"message\":\"Incorrect API key\"}}").await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("401 is a failure");

    // The classification a pool acts on, end to end through the adapter: this is what benches a
    // credential, and it must not be confused with a transient provider error.
    assert!(err.is_auth_failure(), "{err:?}");
    assert!(!err.is_retryable(), "{err:?}");

    let message = err.to_string();
    assert!(message.contains("rejected the credential"), "{message}");
    assert!(message.contains("Incorrect API key"), "{message}");
    assert!(
        !message.contains("test-key-do-not-log"),
        "the request must never put the key in an error: {message}"
    );
}

#[tokio::test]
async fn a_server_error_is_reported_with_its_status() {
    let stub = stub(502, "", "upstream is unwell").await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("502 is a failure");
    let message = err.to_string();
    assert!(message.contains("502"), "{message}");
    assert!(message.contains("upstream is unwell"), "{message}");
}

#[tokio::test]
async fn a_body_that_is_not_json_is_reported_rather_than_panicking() {
    // Happens in practice: an HTML error page from a proxy in front of the provider.
    let stub = stub(200, "", "<html><body>502 Bad Gateway</body></html>").await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("HTML is not a completion");
    let message = err.to_string();
    assert!(message.contains("was not JSON"), "{message}");
    assert!(
        message.contains("Bad Gateway"),
        "the excerpt is the useful part: {message}"
    );
}

#[tokio::test]
async fn a_json_body_with_no_choices_is_an_error() {
    let stub = stub(200, "", "{\"error\":{\"message\":\"model not found\"}}").await;

    let err = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect_err("no choices is a failure");
    assert!(err.to_string().contains("no choices"), "{err}");
}

#[tokio::test]
async fn an_unreachable_endpoint_fails_with_the_url_in_the_message() {
    // Nothing is listening here. The message has to name the endpoint, because "connection refused"
    // on its own does not say which of six configured providers is misconfigured.
    let provider = OpenAiCompatible::new(
        ProviderId::from("test-provider"),
        "http://127.0.0.1:1/v1",
        vec!["gpt-5".to_string()],
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
async fn many_requests_over_one_client_do_not_share_state() {
    // The adapter holds a shared `reqwest::Client`, so this is really a check that nothing about a
    // response is cached where a caller might read it twice.
    for expected in ["first", "second"] {
        let stub = stub(
            200,
            "",
            &json!({
                "choices": [{ "message": { "content": expected }, "finish_reason": "stop" }]
            })
            .to_string(),
        )
        .await;

        let response = stub
            .provider()
            .complete(request(), &key())
            .await
            .expect("the completion succeeds");
        assert_eq!(response.message.text(), expected);
    }
}

#[tokio::test]
async fn the_provider_reports_its_own_identity() {
    let stub = stub(200, "", "{\"choices\":[{\"message\":{\"content\":\"x\"}}]}").await;
    let provider = Arc::new(stub.provider());

    assert_eq!(provider.id().as_str(), "test-provider");
    assert_eq!(provider.models(), ["gpt-5".to_string()]);
    assert_eq!(provider.kind(), hx_core::config::ProviderKind::Openai);
}

/// The body below is what litellm returned for `glm-prox/swe-2-high` over the wire, verbatim: seven
/// `tool_calls` entries, the name on the first and the arguments split across the rest, with no
/// `index` linking them. A non-streaming request, a non-streaming response, and the fragments of a
/// stream inside it — an adapter that reads it literally asks the tool layer to run six nameless
/// tools whose "arguments" are pieces of JSON.
#[tokio::test]
async fn a_proxy_that_hands_over_streaming_fragments_still_yields_one_call() {
    let stub = stub(
        200,
        "",
        &json!({
            "id": "chatcmpl-1",
            "model": "glm-prox/swe-2-high",
            "usage": { "prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18 },
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [
                        { "id": "read_file_0#00c4ad", "type": "function",
                          "function": { "arguments": "", "name": "read_file" } },
                        { "id": "", "type": "function", "function": { "arguments": "{", "name": "" } },
                        { "id": "", "type": "function",
                          "function": { "arguments": "\"path\": \"", "name": "" } },
                        { "id": "", "type": "function",
                          "function": { "arguments": "Cargo", "name": "" } },
                        { "id": "", "type": "function",
                          "function": { "arguments": ".toml", "name": "" } },
                        { "id": "", "type": "function", "function": { "arguments": "\"", "name": "" } },
                        { "id": "", "type": "function", "function": { "arguments": "}", "name": "" } }
                    ]
                },
                "finish_reason": "tool_calls"
            }]
        })
        .to_string(),
    )
    .await;

    let response = stub
        .provider()
        .complete(request(), &key())
        .await
        .expect("the completion succeeds");

    let calls: Vec<&Part> = response.message.tool_calls().collect();
    assert_eq!(calls.len(), 1, "seven fragments are one call: {calls:?}");
    match calls[0] {
        Part::ToolCall {
            id,
            name,
            arguments,
        } => {
            assert_eq!(id.as_str(), "read_file_0#00c4ad");
            assert_eq!(name, "read_file");
            assert_eq!(arguments["path"], "Cargo.toml");
        }
        other => panic!("expected a tool call, got {other:?}"),
    }
}

/// Every request says `stream: false` out loud. Omitting the key is not the same as asking for it:
/// a proxy that defaults to streaming will stream, and this adapter reads one JSON object.
#[tokio::test]
async fn the_request_asks_for_a_non_streaming_response_by_name() {
    let stub = stub(200, "", "{\"choices\":[{\"message\":{\"content\":\"x\"}}]}").await;
    stub.provider()
        .complete(request(), &key())
        .await
        .expect("the completion succeeds");

    let body = stub.captured().await.body;
    assert_eq!(body["stream"], serde_json::Value::Bool(false), "{body}");
}
