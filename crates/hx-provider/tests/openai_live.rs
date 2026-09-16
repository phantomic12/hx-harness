//! The OpenAI-compatible adapter against a **real** provider.
//!
//! The hermetic suite next door proves the wire format with a stub server. This file proves the
//! part a stub cannot: that a real model answers, that real usage comes back, and that a real
//! model's tool calls round-trip through our parsing, our transcript, and back out as a tool result
//! the model accepts.
//!
//! ```console
//! $ HX_OPENAI_TEST_BASE_URL=https://…/v1 \
//!   HX_OPENAI_TEST_MODEL=… \
//!   HX_OPENAI_TEST_KEY=… \
//!   cargo test -p hx-provider --test openai_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The key never appears in output, and the endpoint is whatever the operator points it at —
//! a hosted API, a gateway with many models behind it, or a local server.

use hx_core::ids::ProviderId;
use hx_core::message::{Message, Part};
use hx_provider::openai::http_client;
use hx_provider::{ChatRequest, FinishReason, OpenAiCompatible, Provider, ToolSpec};
use hx_secrets::Secret;
use serde_json::json;

struct Target {
    base_url: String,
    model: String,
    key: Secret,
}

fn target() -> Option<Target> {
    let base_url = std::env::var("HX_OPENAI_TEST_BASE_URL").ok()?;
    let model = std::env::var("HX_OPENAI_TEST_MODEL").ok()?;
    let key = std::env::var("HX_OPENAI_TEST_KEY").ok()?;
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
                    "skipped: set HX_OPENAI_TEST_BASE_URL, HX_OPENAI_TEST_MODEL and \
                     HX_OPENAI_TEST_KEY to run this against a real provider"
                );
                return;
            }
        }
    };
}

fn provider(target: &Target) -> OpenAiCompatible {
    OpenAiCompatible::new(
        ProviderId::from("live"),
        target.base_url.clone(),
        vec![target.model.clone()],
        http_client().expect("an HTTP client"),
    )
}

/// The `ls` tool, as a model sees it.
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

#[ignore = "requires a real provider endpoint and key"]
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
    // The served model comes back from the provider; a gateway may name it differently than asked.
    assert!(!response.model.is_empty());
}

#[ignore = "requires a real provider endpoint and key"]
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
        "the arguments were parsed into an object with the schema's field: {arguments}"
    );

    // Now the second half of the loop: the tool's result goes back in the transcript, and the
    // model has to accept the pairing and answer in prose. This is the shape the agent loop will
    // run in a loop, so it is worth proving against a real model rather than a fixture.
    let transcript = vec![
        Message::user("List the contents of /tmp using the ls tool."),
        response.message.clone(),
        Message::tool_result(
            call_id.clone(),
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

#[ignore = "requires a real provider endpoint and key"]
#[tokio::test]
async fn a_real_multi_turn_transcript_keeps_its_context() {
    let target = skip_without_a_provider!();
    let provider = provider(&target);

    // Two turns, the second referring to the first. A gateway that drops history, or a transcript
    // that loses the assistant's own turn, fails here rather than in production.
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

#[ignore = "requires a real provider endpoint and key"]
#[tokio::test]
async fn a_bad_credential_is_reported_as_an_auth_failure_not_a_crash() {
    let target = skip_without_a_provider!();

    let wrong = OpenAiCompatible::new(
        ProviderId::from("live"),
        target.base_url.clone(),
        vec![target.model.clone()],
        http_client().expect("an HTTP client"),
    );

    let err = wrong
        .complete(
            ChatRequest::new(target.model.clone(), vec![Message::user("hi")]).with_max_tokens(8),
            &Secret::new("definitely-not-the-key"),
        )
        .await
        .expect_err("a wrong key must fail");

    let message = err.to_string();
    eprintln!("live auth failure: {message}");
    assert!(
        message.contains("authentication failed")
            || message.contains("401")
            || message.contains("403"),
        "the failure must be recognisable as an auth problem: {message}"
    );
    assert!(
        !message.contains("definitely-not-the-key"),
        "the credential must never appear in an error: {message}"
    );
}
