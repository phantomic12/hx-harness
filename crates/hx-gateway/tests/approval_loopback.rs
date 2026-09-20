//! The loop-back, over a real socket and through a real run.
//!
//! `telegram_http.rs` proves the connector against the Bot API; `bridge.rs`'s unit tests prove the
//! parts that touch no platform. This file is the claim the two together do not make: **a tap on a
//! phone resumes a run.** Every piece of it is the real one — a real [`AgentLoop`] gated by the real
//! [`ApprovalQueue`], the real `TelegramConnector` over a real TCP socket, the real bridge — and the
//! only thing scripted is the model, which is irrelevant to the question being asked here.
//!
//! The stub is what makes the tap honest. It does not feed the connector a callback the test made up:
//! it **reads the button the connector actually posted** and presses that, so what is exercised is the
//! round trip through Telegram's wire format — `callback_data` out, `callback_query` back — and not a
//! fixture that agrees with itself. A tap whose id did not survive that trip could not answer
//! anything, and the test would fail.
//!
//! No bot token, no network: the credential is a generated fixture that travels in the URL path the
//! way Telegram authenticates, and the assertions below include that it appears in no error and no
//! decision.

use async_trait::async_trait;
use hx_agent::approver::Approver;
use hx_agent::{AgentLoop, ApprovalQueue, ModelCall};
use hx_core::approval::{
    ActionRequest, ApprovalOption, ApprovalPolicy, ApprovalRequest, ApprovalSession, RiskClass,
    Verdict,
};
use hx_core::capability::{Action, Capability, CapabilityToken, Resource};
use hx_core::error::{HxError, Result};
use hx_core::event::AgentEvent;
use hx_core::ids::{AgentId, ConnectorId, CredentialId, ProviderId, ToolCallId};
use hx_core::message::{Message, Part};
use hx_gateway::bridge::{AnswerOutcome, AnsweringChannel, ApprovalBridge, ChannelApprover};
use hx_gateway::connector::Connector;
use hx_gateway::telegram::TelegramConnector;
use hx_gateway::{Conversation, Inbound};
use hx_provider::{ChatRequest, ChatResponse, FinishReason, Usage};
use hx_secrets::Secret;
use hx_tools::testing::FakeHost;
use hx_tools::{ShellTool, ToolContext, ToolRegistry};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// The Bot API stub
// ---------------------------------------------------------------------------------------------

/// One request the stub received, as it arrived.
#[derive(Debug, Clone)]
struct SeenRequest {
    request_line: String,
    body: Value,
}

struct Stub {
    base_url: String,
    /// Everything the stub saw, in order, once it has answered `requests` requests.
    seen: tokio::task::JoinHandle<Vec<SeenRequest>>,
}

/// A Bot API stub that answers exactly `requests` requests, in order, recording each.
///
/// `reply` sees the request number and **every request recorded so far**, so a later answer can be
/// built from an earlier one — which is how the tap below is the button the connector actually sent
/// rather than a string the test chose.
async fn bot_api<F>(requests: usize, reply: F) -> Stub
where
    F: Fn(usize, &[SeenRequest]) -> (u16, Value) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let addr = listener.local_addr().expect("a bound address");

    let seen = tokio::spawn(async move {
        let mut recorded: Vec<SeenRequest> = Vec::new();
        for index in 0..requests {
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
            let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
            let body_start = head_end + 4;
            let body_text = String::from_utf8_lossy(
                buffer
                    .get(body_start..body_start + content_length)
                    .unwrap_or_default(),
            )
            .to_string();

            recorded.push(SeenRequest {
                request_line: head.lines().next().unwrap_or_default().to_string(),
                body: serde_json::from_str(&body_text).unwrap_or(Value::Null),
            });

            let (status, body) = reply(index, &recorded);
            let body = body.to_string();
            let response = format!(
                "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                reason(status),
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("the stub can write");
            socket.flush().await.ok();
        }
        recorded
    });

    Stub {
        base_url: format!("http://{addr}"),
        seen,
    }
}

/// The `callback_query` a tap produces, built from a button the connector posted.
fn tap(callback_data: &Value, chat_id: i64, update_id: i64) -> Value {
    json!({
        "ok": true,
        "result": [{
            "update_id": update_id,
            "callback_query": {
                "data": callback_data,
                "message": { "chat": { "id": chat_id } }
            }
        }]
    })
}

/// The `callback_data` of the button whose label is `label`.
///
/// Pressing by label rather than by row: which options a request offers, and in what order, is the
/// policy layer's business, and a test that hardcoded a row would start pressing something else the
/// day that changes.
fn button_labelled(seen: &[SeenRequest], label: &str) -> Value {
    seen[0].body["reply_markup"]["inline_keyboard"]
        .as_array()
        .expect("an inline keyboard")
        .iter()
        .find(|row| row[0]["text"] == label)
        .unwrap_or_else(|| {
            panic!(
                "no button labelled {label:?} in {}",
                seen[0].body["reply_markup"]
            )
        })[0]["callback_data"]
        .clone()
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
        500 => "Internal Server Error",
        _ => "Status",
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// The token the fixtures use. Generated, never a real secret, and never logged.
fn token() -> Secret {
    Secret::new("0123456789:TESTBOT-loopback")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().build().expect("an HTTP client")
}

fn telegram(base_url: &str) -> Arc<TelegramConnector> {
    Arc::new(TelegramConnector::new(
        ConnectorId::from("main-tg"),
        base_url,
        client(),
    ))
}

/// A question built the way the loop builds one — through a session's own decision, so a test cannot
/// drift from the shape of a real prompt.
fn request_for(summary: &str) -> ApprovalRequest {
    let action = ActionRequest::shell(summary);
    let mut session = ApprovalSession::new(ApprovalPolicy::paranoid());
    match session.decide(&action, chrono::Utc::now()) {
        Verdict::Ask(request) => *request,
        other => panic!("expected a prompt for {summary:?}, got {other:?}"),
    }
}

/// A `Mutate`-risk question, which a chat bridge may answer.
///
/// The risk is asserted rather than assumed: if the classifier ever moves this command, a test that
/// means to exercise the ceiling must fail loudly instead of quietly testing something else.
fn mutate_request(summary: &str) -> ApprovalRequest {
    let request = request_for(summary);
    assert_eq!(request.risk, RiskClass::Mutate, "{summary:?}");
    request
}

/// Wait until the run has parked its question where the bridge can find it, and return it.
///
/// The scope is part of the contract under test: a question asked through a channel is waited on
/// under its conversation, which is what makes "was this asked *here*" answerable.
async fn pending(queue: &Arc<ApprovalQueue>, scope: &str) -> ApprovalRequest {
    for _ in 0..400 {
        if let Some(request) = queue.outstanding(Some(scope)).into_iter().next() {
            return request;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the question never appeared in the queue under {scope}");
}

// ---------------------------------------------------------------------------------------------
// The headline: a tap resumes the run
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_tap_on_the_posted_button_resumes_the_run_and_is_attributed_to_its_channel() {
    // The stub answers the ask, then answers `getUpdates` with **the button the connector posted**.
    let stub = bot_api(2, |index, seen| match index {
        0 => (200, json!({ "ok": true, "result": { "message_id": 1 } })),
        _ => (200, tap(&button_labelled(seen, "allow once"), 4242, 5)),
    })
    .await;

    let queue = ApprovalQueue::new(Duration::from_secs(5));
    let connector = telegram(&stub.base_url);
    let bridge = ApprovalBridge::new(
        queue.clone(),
        vec![AnsweringChannel::new(connector.clone(), RiskClass::Mutate)],
    );
    let conversation = Conversation::telegram("4242", "");
    let approver = ChannelApprover::new(
        bridge.clone(),
        ConnectorId::from("main-tg"),
        token(),
        conversation.clone(),
    );

    let request = mutate_request("echo hi > /tmp/build/out.txt");
    let action = ActionRequest::shell("echo hi > /tmp/build/out.txt");

    // The run: it asks through the phone and waits. This is a real `Approver`, the same object the
    // loop awaits — so what resumes here is the gate a run is parked on.
    let run = {
        let approver = approver.clone();
        let request = request.clone();
        let action = action.clone();
        tokio::spawn(async move { approver.decide(&request, &action).await })
    };

    let scope = conversation.canonical();
    let waiting = pending(&queue, &scope).await;
    assert_eq!(
        waiting.id, request.id,
        "the question in the queue is the one the run asked"
    );
    assert!(
        queue
            .outstanding(Some(&Conversation::telegram("999", "").canonical()))
            .is_empty(),
        "the question is scoped to the conversation it was asked in"
    );

    // The human taps. The tap is read back off the wire: the connector parses the callback_query the
    // stub answered with, which carries the button the connector itself posted.
    let inbound = connector
        .receive(&token())
        .await
        .expect("a tap")
        .expect("one inbound event");
    let (tapped_id, tapped_answer) = match &inbound {
        Inbound::ApprovalAnswer {
            approval_id,
            answer,
            ..
        } => (approval_id.clone(), answer.clone()),
        other => panic!("expected an approval answer, got {other:?}"),
    };
    assert_eq!(
        tapped_id,
        request.id.as_str(),
        "the tap names the question it answers"
    );
    assert_eq!(tapped_answer, "allow once");

    let outcome = bridge.route(&ConnectorId::from("main-tg"), inbound);
    match &outcome {
        AnswerOutcome::Answered {
            approval_id,
            option,
            by,
        } => {
            assert_eq!(approval_id, request.id.as_str());
            assert_eq!(*option, ApprovalOption::AllowOnce);
            assert_eq!(by, "telegram:4242 via main-tg");
        }
        other => panic!("expected the tap to be answered, got {other:?}"),
    }

    // The run resumed, with the decision a terminal dialog would have produced — and the answer is
    // attributed to the channel it came from, not to a faceless "user".
    let decision = run.await.expect("the run resumes");
    assert_eq!(decision.option, ApprovalOption::AllowOnce);
    assert_eq!(decision.by, "telegram:4242 via main-tg");
    assert!(
        queue.is_empty(),
        "an answered question does not linger in the queue"
    );

    // And on the wire: the question went to the chat with one button per option, each naming the
    // request.
    let seen = stub.seen.await.expect("the stub task");
    assert!(
        seen[0].request_line.contains("/sendMessage"),
        "{}",
        seen[0].request_line
    );
    assert_eq!(seen[0].body["chat_id"], "4242");
    assert!(
        seen[0].body["text"]
            .as_str()
            .expect("the rendered question")
            .contains("risk: mutate"),
        "{}",
        seen[0].body["text"]
    );
    assert!(
        seen[0].body["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
            .as_str()
            .expect("a callback payload")
            .starts_with(request.id.as_str()),
        "the button carries the id of the question it answers"
    );
    assert!(
        seen[1].request_line.contains("/getUpdates"),
        "{}",
        seen[1].request_line
    );
}

// ---------------------------------------------------------------------------------------------
// The ceiling, on the running path
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_destructive_tap_is_refused_on_the_running_path() {
    // The ceiling is judged when the *answer* arrives, not only when the question was posted: a
    // channel's ceiling can be lowered while a question is up, and the queue can hold a question
    // another surface asked. Either way, a "yes" that is above the ceiling must not reach a run.
    let queue = ApprovalQueue::new(Duration::from_millis(200));
    let bridge = ApprovalBridge::new(
        queue.clone(),
        vec![AnsweringChannel::new(
            // Never called: `route` does not talk to a platform, and if it ever started to, this
            // address is where the mistake would fail loudly.
            telegram("http://127.0.0.1:1"),
            RiskClass::Mutate,
        )],
    );
    let conversation = Conversation::telegram("4242", "");
    let scope = conversation.canonical();

    let request = request_for("rm -rf /tmp/build");
    assert_eq!(request.risk, RiskClass::Destructive, "the fixture");
    let action = ActionRequest::shell("rm -rf /tmp/build");

    // A run, waiting on the question.
    let run = {
        let queue = queue.clone();
        let request = request.clone();
        let action = action.clone();
        let scope = scope.clone();
        tokio::spawn(async move { queue.decide_in(&request, &action, Some(&scope)).await })
    };
    let waiting = pending(&queue, &scope).await;
    assert_eq!(waiting.id, request.id);

    let outcome = bridge.route(
        &ConnectorId::from("main-tg"),
        Inbound::ApprovalAnswer {
            conversation: conversation.clone(),
            approval_id: request.id.as_str().to_string(),
            answer: "allow once".to_string(),
        },
    );
    match &outcome {
        AnswerOutcome::Refused { reason, .. } => assert!(
            reason.contains("ceiling"),
            "the refusal must name the ceiling: {reason}"
        ),
        other => panic!("a Destructive tap must be refused, got {other:?}"),
    }

    // The run is still waiting, and the wait ends in a denial — not in the yes the phone offered.
    let decision = run.await.expect("the run");
    assert_eq!(decision.option, ApprovalOption::Deny);
    assert!(
        decision.by.contains("nobody answered"),
        "by: {}",
        decision.by
    );
}

#[tokio::test]
async fn a_permanent_grant_is_not_made_from_a_phone() {
    // `always allow this` writes into the deployment's allow list. A chat channel may answer for this
    // instance or for this chat; a permanent promotion is not a phone tap's to make.
    let queue = ApprovalQueue::new(Duration::from_millis(200));
    let bridge = ApprovalBridge::new(
        queue.clone(),
        vec![AnsweringChannel::new(
            telegram("http://127.0.0.1:1"),
            RiskClass::Mutate,
        )],
    );
    let conversation = Conversation::telegram("4242", "");
    let scope = conversation.canonical();

    let mut request = mutate_request("echo hi > /tmp/build/out.txt");
    request.options = vec![
        ApprovalOption::AllowOnce,
        ApprovalOption::AllowForChat,
        ApprovalOption::AllowAlways,
        ApprovalOption::Deny,
    ];
    let action = ActionRequest::shell("echo hi > /tmp/build/out.txt");

    let run = {
        let queue = queue.clone();
        let request = request.clone();
        let action = action.clone();
        let scope = scope.clone();
        tokio::spawn(async move { queue.decide_in(&request, &action, Some(&scope)).await })
    };
    pending(&queue, &scope).await;

    let tap = |answer: &str| {
        bridge.route(
            &ConnectorId::from("main-tg"),
            Inbound::ApprovalAnswer {
                conversation: conversation.clone(),
                approval_id: request.id.as_str().to_string(),
                answer: answer.to_string(),
            },
        )
    };

    match tap("always allow this") {
        AnswerOutcome::Refused { reason, .. } => assert!(
            reason.contains("permanent grant"),
            "the refusal must say what it refused: {reason}"
        ),
        other => panic!("a permanent grant from a phone must be refused, got {other:?}"),
    }

    // Chat-scoped is a different thing, and it is honoured.
    match tap("allow for this chat") {
        AnswerOutcome::Answered { option, .. } => assert_eq!(option, ApprovalOption::AllowForChat),
        other => panic!("a chat-scoped grant is honoured, got {other:?}"),
    }

    let decision = run.await.expect("the run");
    assert_eq!(decision.option, ApprovalOption::AllowForChat);
    assert_eq!(decision.by, "telegram:4242 via main-tg");
}

// ---------------------------------------------------------------------------------------------
// Untrusted input: a stale, replayed, or misplaced tap
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_stale_or_replayed_tap_does_not_answer_a_different_question() {
    // Two questions are pending in one chat. A tap must answer the one it names and nothing else: a
    // replayed tap must not be a second decision, a tap for an unknown id must answer nothing, an
    // answer the question never offered is not an instruction, and a tap in another chat is not an
    // answer to a question asked here.
    let queue = ApprovalQueue::new(Duration::from_secs(5));
    let bridge = ApprovalBridge::new(
        queue.clone(),
        vec![AnsweringChannel::new(
            telegram("http://127.0.0.1:1"),
            RiskClass::Mutate,
        )],
    );
    let here = Conversation::telegram("4242", "");
    let scope = here.canonical();

    let first = mutate_request("echo one > /tmp/build/one");
    let second = mutate_request("echo two > /tmp/build/two");
    assert_ne!(first.id, second.id, "two questions, two ids");
    let action = ActionRequest::shell("echo one > /tmp/build/one");

    let mut runs = Vec::new();
    for request in [first.clone(), second.clone()] {
        let queue = queue.clone();
        let action = action.clone();
        let scope = scope.clone();
        runs.push(tokio::spawn(async move {
            queue.decide_in(&request, &action, Some(&scope)).await
        }));
    }
    pending(&queue, &scope).await;
    assert_eq!(queue.len(), 2, "both questions are waiting");

    let tap = |conversation: &Conversation, id: &str, answer: &str| {
        bridge.route(
            &ConnectorId::from("main-tg"),
            Inbound::ApprovalAnswer {
                conversation: conversation.clone(),
                approval_id: id.to_string(),
                answer: answer.to_string(),
            },
        )
    };

    // The first question is answered by the tap that names it.
    match tap(&here, first.id.as_str(), "allow once") {
        AnswerOutcome::Answered { approval_id, .. } => assert_eq!(approval_id, first.id.as_str()),
        other => panic!("expected the first question to be answered, got {other:?}"),
    }

    // A replay of the same tap is not a second decision.
    match tap(&here, first.id.as_str(), "allow once") {
        AnswerOutcome::Refused { reason, .. } => {
            assert!(reason.contains("already answered or timed out"), "{reason}")
        }
        other => panic!("a replayed tap must be refused, got {other:?}"),
    }

    // A tap for an id nothing is waiting on answers nothing at all.
    match tap(&here, "apr_forged", "allow once") {
        AnswerOutcome::Refused { reason, .. } => {
            assert!(reason.contains("no question with that id"), "{reason}")
        }
        other => panic!("a forged id must be refused, got {other:?}"),
    }

    // The second question is still waiting, untouched by any of the above.
    assert_eq!(queue.len(), 1);
    assert_eq!(
        queue.outstanding(Some(&scope))[0].id,
        second.id,
        "the other question is still the one waiting"
    );

    // An answer the question never offered is not an instruction.
    match tap(&here, second.id.as_str(), "allow everything") {
        AnswerOutcome::Refused { reason, .. } => {
            assert!(reason.contains("among the offered options"), "{reason}")
        }
        other => panic!("an unoffered answer must be refused, got {other:?}"),
    }

    // A tap in another chat — where this question was not asked — is not an answer to it.
    match tap(
        &Conversation::telegram("999", ""),
        second.id.as_str(),
        "allow once",
    ) {
        AnswerOutcome::Refused { reason, .. } => assert!(
            reason.contains("not asked") || reason.contains("no question with that id"),
            "{reason}"
        ),
        other => panic!("a tap from another chat must be refused, got {other:?}"),
    }

    // And the question it does name, in the chat it was asked in, still works.
    match tap(&here, second.id.as_str(), "allow once") {
        AnswerOutcome::Answered { option, .. } => assert_eq!(option, ApprovalOption::AllowOnce),
        other => panic!("expected the second question to be answered, got {other:?}"),
    }

    assert_eq!(
        runs.remove(0).await.expect("the first run").option,
        ApprovalOption::AllowOnce
    );
    assert_eq!(
        runs.remove(0).await.expect("the second run").option,
        ApprovalOption::AllowOnce
    );
}

// ---------------------------------------------------------------------------------------------
// A channel that is down
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_channel_that_cannot_be_reached_denies_the_run_instead_of_leaving_it_waiting() {
    // Nothing is listening. The question was never delivered, so no human can answer it — and a run
    // left waiting for a question nobody can see is a run that will time out and blame silence. It is
    // denied now, with the reason, and the reason names the channel without naming the credential.
    let queue = ApprovalQueue::new(Duration::from_secs(30));
    let bridge = ApprovalBridge::new(
        queue.clone(),
        vec![AnsweringChannel::new(
            telegram("http://127.0.0.1:1"),
            RiskClass::Mutate,
        )],
    );
    let conversation = Conversation::telegram("4242", "");
    let approver = ChannelApprover::new(
        bridge,
        ConnectorId::from("main-tg"),
        token(),
        conversation.clone(),
    );

    let request = mutate_request("echo hi > /tmp/build/out.txt");
    let action = ActionRequest::shell("echo hi > /tmp/build/out.txt");
    let decision = approver.decide(&request, &action).await;

    assert_eq!(decision.option, ApprovalOption::Deny);
    assert!(
        decision.by.contains("telegram:4242 via main-tg"),
        "the denial says where the question would have gone: {}",
        decision.by
    );
    assert!(
        decision.by.contains("could not be asked"),
        "by: {}",
        decision.by
    );
    assert!(
        !decision.by.contains(token().expose()),
        "the token must never reach a decision that is written down: {}",
        decision.by
    );
    assert!(
        queue.is_empty(),
        "nothing was parked: the run is not waiting for a question no one was asked"
    );
    assert!(
        queue
            .outstanding(Some(&conversation.canonical()))
            .is_empty(),
        "not even under the conversation scope"
    );
}

// ---------------------------------------------------------------------------------------------
// The audit trail, through a real run
// ---------------------------------------------------------------------------------------------

/// A model that answers from a script, in order, and fails the run when the script runs out.
struct ScriptedModel {
    replies: Mutex<VecDeque<Result<ChatResponse>>>,
}

impl ScriptedModel {
    fn new(replies: Vec<Result<ChatResponse>>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(VecDeque::from(replies)),
        })
    }
}

#[async_trait]
impl ModelCall for ScriptedModel {
    async fn complete(&self, _req: ChatRequest) -> Result<ChatResponse> {
        self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
            Err(HxError::Provider(
                "the scripted model was asked for more turns than it has answers".to_string(),
            ))
        })
    }

    fn model(&self) -> String {
        "scripted".to_string()
    }

    fn provider_id(&self) -> ProviderId {
        ProviderId::from("test")
    }

    fn credential_id(&self) -> CredentialId {
        CredentialId::from("cred_test")
    }
}

fn usage() -> Usage {
    Usage {
        input_tokens: 100,
        output_tokens: 20,
        cached_input_tokens: 0,
        reasoning_tokens: 0,
    }
}

/// A turn that calls a tool.
fn reply_with(calls: Vec<(&str, &str, Value)>) -> ChatResponse {
    let mut parts = Vec::new();
    for (id, name, arguments) in calls {
        parts.push(Part::ToolCall {
            id: ToolCallId::from(id),
            name: name.to_string(),
            arguments,
        });
    }
    ChatResponse {
        message: Message::new(hx_core::message::Role::Assistant, parts),
        usage: usage(),
        finish: FinishReason::ToolUse,
        model: "scripted".to_string(),
        raw: None,
    }
}

fn reply(text: &str) -> ChatResponse {
    ChatResponse {
        message: Message::assistant(text),
        usage: usage(),
        finish: FinishReason::Stop,
        model: "scripted".to_string(),
        raw: None,
    }
}

#[tokio::test]
async fn the_running_agents_audit_trail_names_the_channel_the_answer_came_from() {
    // The whole point of attributing an answer: the loop records *who decided*, and `user` does not
    // answer the question an incident review asks when the user was on a phone. This runs a real
    // `AgentLoop` whose gate is the real queue, asks through the real connector, and presses the
    // "deny" button the connector posted — then reads the event the trail is built from.
    let stub = bot_api(2, |index, seen| match index {
        0 => (200, json!({ "ok": true, "result": { "message_id": 1 } })),
        _ => (200, tap(&button_labelled(seen, "deny"), 4242, 6)),
    })
    .await;

    let queue = ApprovalQueue::new(Duration::from_secs(5));
    let connector = telegram(&stub.base_url);
    let bridge = ApprovalBridge::new(
        queue.clone(),
        vec![AnsweringChannel::new(connector.clone(), RiskClass::Mutate)],
    );
    let conversation = Conversation::telegram("4242", "");
    let approver = ChannelApprover::new(
        bridge.clone(),
        ConnectorId::from("main-tg"),
        token(),
        conversation.clone(),
    );

    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(ShellTool::new()));
    let model = ScriptedModel::new(vec![
        Ok(reply_with(vec![(
            "tc_1",
            "shell",
            json!({ "cmd": "echo hi > /tmp/build/out.txt" }),
        )])),
        Ok(reply("understood")),
    ]);
    let agent_loop = AgentLoop::new(
        AgentId::from("agt_test"),
        model,
        Arc::new(registry),
        CapabilityToken::issue(
            AgentId::from("agt_test"),
            vec![Capability::new(Resource::Process, [Action::Execute])],
            chrono::Utc::now(),
            3600,
        ),
        ApprovalSession::new(ApprovalPolicy::paranoid()),
        approver,
    );

    let (tx, mut rx) = mpsc::channel(64);
    let agent_loop = agent_loop.with_events(tx);
    let host = Arc::new(FakeHost::unix());

    let running = tokio::spawn(async move {
        let mut transcript = vec![Message::user("write a file")];
        let ctx = ToolContext::new(host);
        let outcome = agent_loop.run(&mut transcript, &ctx).await;
        (outcome, transcript)
    });

    // The run is parked on the question; the human presses "deny" on their phone.
    pending(&queue, &conversation.canonical()).await;
    let inbound = connector
        .receive(&token())
        .await
        .expect("a tap")
        .expect("one inbound event");
    match bridge.route(&ConnectorId::from("main-tg"), inbound) {
        AnswerOutcome::Answered { option, by, .. } => {
            assert_eq!(option, ApprovalOption::Deny);
            assert_eq!(by, "telegram:4242 via main-tg");
        }
        other => panic!("expected the deny tap to be answered, got {other:?}"),
    }

    let (outcome, transcript) = running.await.expect("the run finishes");
    let outcome = outcome.expect("the run is not an error");

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }

    // The event the audit trail is written from: the decision, and who made it.
    let resolved = events
        .iter()
        .find_map(|event| match event {
            AgentEvent::ApprovalResolved { by, approved, .. } => Some((by.clone(), *approved)),
            _ => None,
        })
        .expect("the run resolved an approval");
    assert_eq!(resolved.0, "telegram:4242 via main-tg");
    assert!(!resolved.1, "the phone said no, so nothing was approved");

    // And the refusal the model is told about names the channel too, because a model that cannot see
    // who refused it will retry.
    let refused = transcript
        .iter()
        .flat_map(|message| message.parts.iter())
        .find_map(|part| match part {
            Part::ToolResult { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("a tool result");
    assert!(
        refused.contains("refused by telegram:4242 via main-tg"),
        "{refused}"
    );
    assert_eq!(outcome.refusals, 1, "the call was refused, not run");
}
