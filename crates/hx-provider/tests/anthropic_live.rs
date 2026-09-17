//! The Anthropic Messages adapter against a **real** provider.
//!
//! The hermetic suite next door proves the wire format with a stub server. This file proves the part a
//! stub cannot: that a real Claude model answers, that real usage with cache counters comes back, and that a
//! real model's `tool_use` rounds trip through our parsing, our transcript, and back out as a
//! `tool_result` the model accepts.
//!
//! ```console
//! $ HX_ANTHROPIC_TEST_KEY=… \
//!   HX_ANTHROPIC_TEST_MODEL=… \
//!   cargo test -p hx-provider --test anthropic_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The base URL defaults to the live Anthropic API; set `HX_ANTHROPIC_TEST_BASE_URL` to point at
//! a gateway instead. The key never appears in output.

use hx_core::ids::{ProviderId, ToolCallId};
use hx_core::message::{Message, Part};
use hx_provider::openai::http_client;
use hx_provider::{AnthropicMessages, ChatRequest, FinishReason, Provider, ToolSpec};
use hx_secrets::Secret;
use serde_json::json;

struct Target {
    base_url: String,
    model: String,
    key: Secret,
}

fn target() -> Option<Target> {
    let base_url = std::env::var("HX_ANTHROPIC_TEST_BASE_URL")
        .unwrap_or_else(|_| "https://api.anthropic.com".to_string());
    let model = std::env::var("HX_ANTHROPIC_TEST_MODEL").ok()?;
    let key = std::env::var("HX_ANTHROPIC_TEST_KEY").ok()?;
    Some(Target {
        base_url,
        model,
        key: Secret::new(key),
    })
}

macro_rules! skip_without_a_provider {
    () => {
        match target() {
            Some(target) => target,
            None => {
                eprintln!(
                    "skipped: set HX_ANTHROPIC_TEST_MODEL and HX_ANTHROPIC_TEST_KEY to run this \
                     against a real provider"
                );
                return;
            }
        }
    };
}

fn provider(target: &Target) -> AnthropicMessages {
    AnthropicMessages::new(
        ProviderId::from("live"),
        target.base_url.clone(),
        vec![target.model.clone()],
        http_client().expect("an HTTP client"),
    )
}

/// The `ls` tool, as Claude sees it.
fn ls_tool() -> ToolSpec {
    ToolSpec {
        name: "ls".to_string(),
        description: "List the entries of a directory".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": { "path": { "type": "string", "description": "directory to list" } },
            "required": ["path"]
        }),
    }
}

#[ignore = "requires a real Anthropic API key"]
#[tokio::test]
async fn a_real_model_answers_and_reports_usage() {
    let target = skip_without_a_provider!();
    let request = ChatRequest::new(
        target.model.clone(),
        vec![Message::user("Reply with exactly one word: ok")],
    )
    .with_system("Be terse.")
    .with_max_tokens(32);

    let response = provider(&target)
        .complete(request, &target.key)
        .await
        .expect("a real completion");

    eprintln!(
        "live text: model={} finish={:?} in={} out={} cached={} text={:?}",
        response.model,
        response.finish,
        response.usage.input_tokens,
        response.usage.output_tokens,
        response.usage.cached_input_tokens,
        response.message.text()
    );

    assert!(
        !response.message.text().trim().is_empty(),
        "a real model returned no text: {response:?}"
    );
    assert!(
        response.usage.input_tokens > 0,
        "real usage must be reported, not estimated: {:?}",
        response.usage
    );
    assert!(
        response.usage.output_tokens > 0,
        "output tokens must be counted: {:?}",
        response.usage
    );
    assert!(!response.model.is_empty());
}

#[ignore = "requires a real Anthropic API key and model"]
#[tokio::test]
async fn a_real_model_calls_a_tool_and_accepts_its_result() {
    let target = skip_without_a_provider!();
    let provider = provider(&target);

    let first = ChatRequest::new(
        target.model.clone(),
        vec![Message::user(
            "List the contents of /tmp using the ls tool.",
        )],
    )
    .with_tools(vec![ls_tool()])
    .with_max_tokens(256);

    let response = provider
        .complete(first, &target.key)
        .await
        .expect("a real completion");

    let calls: Vec<&Part> = response.message.tool_calls().collect();
    assert!(
        !calls.is_empty(),
        "the model did not call the tool; finish was {:?}, text was {:?}",
        response.finish,
        response.message.text()
    );
    assert_eq!(response.finish, FinishReason::ToolUse);

    let (call_id, name, arguments) = match calls[0] {
        Part::ToolCall {
            id,
            name,
            arguments,
        } => (id.clone(), name.clone(), arguments.clone()),
        other => panic!("expected a tool call, got {other:?}"),
    };
    eprintln!("live tool call: {name}({arguments}) id={call_id}");

    assert_eq!(name, "ls");
    assert!(
        arguments.get("path").is_some(),
        "the input object was parsed with the schema's field: {arguments}"
    );

    // Second half of the loop: the result goes back as a tool_result, and the model accepts the pairing
    // and answers in prose.
    let transcript = vec![
        Message::user("List the contents of /tmp using the ls tool."),
        response.message.clone(),
        Message::tool_result(
            ToolCallId::from_raw(call_id.as_str()),
            true,
            "cargo-target\nrustc-log.txt\nhx-workspace",
        ),
    ];

    let second = provider
        .complete(
            ChatRequest::new(target.model.clone(), transcript)
                .with_tools(vec![ls_tool()])
                .with_max_tokens(256),
            &target.key,
        )
        .await
        .expect("the follow-up completion");

    eprintln!(
        "live follow-up: finish={:?} text={:?}",
        second.finish,
        second.message.text()
    );

    assert!(
        !second.message.text().trim().is_empty(),
        "the model said nothing after receiving the tool result: {second:?}"
    );
    assert!(
        !second.message.has_tool_call(),
        "a model that has the result should answer, not call the tool again — the tool-result \
         pairing may be malformed: {second:?}"
    );
}

#[ignore = "requires a real Anthropic API key and model"]
#[tokio::test]
async fn a_real_multi_turn_transcript_keeps_its_context() {
    let target = skip_without_a_provider!();
    let provider = provider(&target);

    let messages = vec![
        Message::user("My favourite number is 41. Just acknowledge it."),
        Message::assistant("Understood."),
        Message::user("What number is it? Reply with the number only."),
    ];

    let response = provider
        .complete(
            ChatRequest::new(target.model.clone(), messages).with_max_tokens(64),
            &target.key,
        )
        .await
        .expect("a real completion");

    let text = response.message.text();
    eprintln!("live multi-turn: {text:?}");
    assert!(
        text.contains("41"),
        "the model lost the earlier turn: {text:?}"
    );
}

#[ignore = "requires a real Anthropic API key and model"]
#[tokio::test]
async fn a_bad_credential_is_reported_as_an_auth_failure_not_a_generic_error() {
    let target = skip_without_a_provider!();
    let model = target.model.clone();
    let bad_key = Secret::new("sk-ant-invalid-key-that-will-be-refused");
    let bad_provider = AnthropicMessages::new(
        ProviderId::from("live"),
        target.base_url.clone(),
        vec![model.clone()],
        http_client().expect("an HTTP client"),
    );

    let err = bad_provider
        .complete(
            ChatRequest::new(model.clone(), vec![Message::user("hi")]).with_max_tokens(8),
            &bad_key,
        )
        .await
        .expect_err("a dead key must fail");

    let message = err.to_string();
    assert!(
        message.contains("401") || message.contains("403") || message.contains("credential"),
        "the failure must be recognisable as an auth problem: {message}"
    );
    assert!(
        !message.contains("sk-ant-invalid-key-that-will-be-refused"),
        "the credential must never appear in an error: {message}"
    );
}
