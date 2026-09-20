//! The Telegram connector over real HTTP.
//!
//! The same hermetic-stub approach as `hx-provider`'s `anthropic_http.rs`: a real TCP server
//! answers the Bot API requests, so the URL (`/bot<token>/getUpdates`, `/bot<token>/sendMessage`),
//! the auth-in-the-path, and the serialised bodies are the real ones going over a real socket. No bot
//! token, no network, no cassette — this runs on every commit.
//!
//! The token is a generated fixture, never a real secret and never logged: it travels in the *path* of
//! the URL, and the tests assert the stub saw it there (the way Telegram authenticates), but the connector
//! never puts it in a body or an error.

use hx_core::ids::ConnectorId;
use hx_gateway::answer::AnswerVerdict;
use hx_gateway::connector::Connector;
use hx_gateway::telegram::TelegramConnector;
use hx_gateway::telegram_stream::{FinalDelivery, StreamOutcome, StreamPlan};
use hx_gateway::{Conversation, Inbound, Target};
use hx_secrets::Secret;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// What the stub saw, and what it was told to answer.
#[derive(Debug, Clone)]
struct Captured {
    request_line: String,
    body: Value,
}

/// A one-shot HTTP/1.1 server: accept one request, answer with `status` and `response_body`.
async fn stub(status: u16, response_body: &str) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let addr = listener.local_addr().expect("a bound address");

    let status_line = format!("HTTP/1.1 {status} {}", reason(status));
    let headers = format!(
        "content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        response_body.len()
    );
    let response = format!("{status_line}\r\n{headers}\r\n{response_body}");

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

        socket
            .write_all(response.as_bytes())
            .await
            .expect("the stub can write");
        socket.flush().await.ok();

        Captured {
            request_line: head.lines().next().unwrap_or_default().to_string(),
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

/// A connector whose responses are captured per-request. Telegram's connector holds its polling state
/// internally, and the one-shot stub answers a single request, so each test drives one connector for one
/// request and asserts on what that request carried.
fn connector(base_url: &str) -> TelegramConnector {
    TelegramConnector::new(
        ConnectorId::from("main-tg"),
        base_url,
        hx_provider_buildless_client().expect("an HTTP client"),
    )
}

/// A minimal `reqwest` client with no provider deps pulled in. We build one locally to avoid coupling
/// this test crate to `hx-provider` just for its `http_client()` helper.
fn hx_provider_buildless_client() -> hx_core::error::Result<reqwest::Client> {
    reqwest::Client::builder()
        .build()
        .map_err(|e| hx_core::error::HxError::Provider(e.to_string()))
}

/// The token the fixtures use. Generated, never a real secret, and asserted to appear only in the path.
fn token() -> Secret {
    Secret::new("0123456789:TESTBOT-token-not-a-real-secret")
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
        400 => "Bad Request",
        401 => "Unauthorized",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

// -------------------------------------------------------------------------------------------
// The happy path, over the wire
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_message_from_the_user_is_received_over_the_wire() {
    // The stub answers a getUpdates poll with one update. The connector must parse it, advance its
    // offset, and hand out the message as an Inbound whose text is untrusted data.
    let stub = stub(
        200,
        &json!({
            "ok": true,
            "result": [
                { "update_id": 101, "message": { "message_id": 1, "chat": { "id": 777 }, "text": "list the repo" } }
            ]
        })
        .to_string(),
    )
    .await;

    let con = Arc::new(connector(&stub.base_url));
    let received = con.receive(&token()).await.expect("a message");

    let captured = stub.handle.await.expect("the stub task");
    // The token authenticates in the path: `/botTOKEN/getUpdates`.
    assert!(
        captured
            .request_line
            .contains("/bot0123456789:TESTBOT-token-not-a-real-secret/getUpdates"),
        "Token must authenticate in the path: {}",
        captured.request_line
    );
    assert!(
        captured.request_line.contains("offset=0"),
        "{}",
        captured.request_line
    );

    match received {
        Some(Inbound::Message { conversation, text }) => {
            assert_eq!(conversation.platform.as_str(), "telegram");
            assert_eq!(conversation.chat.as_str(), "777");
            // The empty thread is the single conversation of a non-threaded chat.
            assert_eq!(conversation.thread.as_str(), "");
            assert_eq!(text, "list the repo");
        }
        other => panic!("expected a message, got {other:?}"),
    }
}

#[tokio::test]
async fn an_offset_is_advancing_so_there_are_no_duplicate_deliveries() {
    // A two-shot stub: the first poll returns update id 101, the second returns nothing. The second poll
    // must carry offset=102 (101 + 1), so Telegram never re-sends the first message — this is what
    // makes a restarted daemon not re-deliver old messages.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let addr = listener.local_addr().expect("a bound address");
    let base_url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        let answers = [
            r#"{"ok":true,"result":[{"update_id":101,"message":{"message_id":1,"chat":{"id":7},"text":"first"}}]}"#,
            r#"{"ok":true,"result":[]}"#,
        ];
        let mut lines = Vec::new();
        for (i, body) in answers.iter().enumerate() {
            let (mut socket, _) = listener.accept().await.expect("a connection");
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let read = socket.read(&mut chunk).await.expect("readable");
                if read == 0 || find(&buffer, b"\r\n\r\n").is_some() {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if find(&buffer, b"\r\n\r\n").is_some() {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buffer).to_string();
            let request_line = head.lines().next().unwrap_or_default().to_string();
            lines.push(request_line);
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(resp.as_bytes()).await.expect("write");
            socket.flush().await.ok();
            let _ = i;
        }
        lines
    });

    let con = Arc::new(connector(&base_url));
    let first = con.receive(&token()).await.expect("first message");
    match first {
        Some(Inbound::Message { text, .. }) => assert_eq!(text, "first"),
        other => panic!("expected the first message, got {other:?}"),
    }
    let second = con
        .receive(&token())
        .await
        .expect("second poll returns nothing");
    assert!(second.is_none());

    let lines = handle.await.expect("the stub task");
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("offset=0"), "{}", lines[0]);
    assert!(
        lines[1].contains("offset=102"),
        "offset must advance to 102: {}",
        lines[1]
    );
}

#[tokio::test]
async fn a_delivery_sends_the_text_to_the_chat() {
    let stub = stub(
        200,
        &json!({ "ok": true, "result": { "message_id": 9 } }).to_string(),
    )
    .await;

    let con = connector(&stub.base_url);
    let to = Conversation::telegram("4242", "");
    con.deliver(&token(), &Target::Conversation(to.clone()), "hello there")
        .await
        .expect("the delivery succeeds");

    let captured = stub.handle.await.expect("the stub task");
    assert!(
        captured
            .request_line
            .contains("/bot0123456789:TESTBOT-token-not-a-real-secret/sendMessage"),
        "{}",
        captured.request_line
    );
    assert_eq!(captured.body["chat_id"], "4242");
    assert_eq!(captured.body["text"], "hello there");
}

#[tokio::test]
async fn an_approval_is_posted_with_one_button_per_option() {
    // The ask path: the request (same object a terminal renders) goes out as a message with an inline
    // keyboard. No answer is forced; whether the human's tap is *legal* is AnswerAuthority's job.
    let stub = stub(
        200,
        &json!({ "ok": true, "result": { "message_id": 10 } }).to_string(),
    )
    .await;

    let con = connector(&stub.base_url);
    let to = Conversation::telegram("4242", "");
    let request = hx_core::approval::ApprovalRequest {
        id: hx_core::ids::ApprovalId::from_raw("apr_1"),
        tool: "shell".into(),
        summary: "list /tmp".into(),
        risk: hx_core::approval::RiskClass::Read,
        reason: "t".into(),
        key: "k".into(),
        options: vec![
            hx_core::approval::ApprovalOption::AllowOnce,
            hx_core::approval::ApprovalOption::Deny,
        ],
        targets: vec![],
        reversible: false,
        undo: None,
        confined: Default::default(),
        default_on_timeout: hx_core::approval::ApprovalOption::Deny,
        timeout_secs: None,
    };
    let task = hx_gateway::types::ApprovalTask {
        request,
        ceiling: hx_core::approval::RiskClass::Mutate,
    };

    let verdict = con
        .ask(&token(), &Target::Conversation(to.clone()), &task)
        .await
        .expect("the ask is posted");

    let captured = stub.handle.await.expect("the stub task");
    assert!(
        captured
            .request_line
            .contains("/bot0123456789:TESTBOT-token-not-a-real-secret/sendMessage"),
        "{}",
        captured.request_line
    );
    let keyboard = &captured.body["reply_markup"]["inline_keyboard"];
    assert_eq!(keyboard.as_array().unwrap().len(), 2, "one row per option");
    assert_eq!(keyboard[0][0]["text"], "allow once");
    // The button carries the id of the question it answers, not just the label: a tap that arrives
    // after the run has moved on must be refusable, and only the id makes that possible.
    assert_eq!(keyboard[0][0]["callback_data"], "apr_1:allow once");
    assert_eq!(keyboard[1][0]["text"], "deny");
    assert_eq!(keyboard[1][0]["callback_data"], "apr_1:deny");

    // The prompt was posted; the connector itself never claims an answer (the tap arrives later
    // through `receive` and is joined to the waiting run by `hx_gateway::bridge`).
    assert_eq!(verdict, AnswerVerdict::NoAnswer);
}

#[tokio::test]
async fn delivering_to_the_home_channel_is_refused_until_it_is_resolved() {
    // The connector can only send to an explicit conversation; a raw `Target::Home` must be resolved
    // to a concrete conversation (by DeliveryPolicy) before delivery. Refusing here rather than guessing
    // keeps a raw home marker from going somewhere wrong.
    let con = connector("http://127.0.0.1:1");
    let err = con
        .deliver(&token(), &Target::Home, "hi")
        .await
        .expect_err("a home target must be resolved first");
    assert!(err.to_string().contains("explicit conversation"), "{err}");
}

// -------------------------------------------------------------------------------------------
// Failures, over the wire
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_receive_from_a_down_channel_fails_closed() {
    // Nothing is listening: the receive is an error, never "no messages" — otherwise a down channel
    // would look idle and a cron digest would silently vanish.
    let con = connector("http://127.0.0.1:1");
    let err = con
        .receive(&token())
        .await
        .expect_err("nothing is listening");
    assert!(err.to_string().contains("could not reach"), "{err}");
}

#[tokio::test]
async fn an_unauthed_token_is_reported_as_such_and_never_in_the_body() {
    // A 401 from the Bot API. The connector reports it; the token appears in the path (Telegram's
    // contract) but never leaks into an error that names a value.
    let stub = stub(
        401,
        r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
    )
    .await;
    let con = connector(&stub.base_url);
    let err = con
        .deliver(
            &token(),
            &Target::Conversation(Conversation::telegram("1", "")),
            "x",
        )
        .await
        .expect_err("401 is a failure");
    let message = err.to_string();
    assert!(message.contains("401"), "{message}");
    assert!(
        !message.contains(token().expose()),
        "the token must never appear in an error: {message}"
    );
}

#[tokio::test]
async fn an_unreachable_host_does_not_put_the_token_in_the_error() {
    // The token authenticates in the request *path*, and `reqwest::Error`'s Display carries the URL
    // it failed on. An error built from that error therefore carries the credential — the one place
    // this crate promised it would never be. Nothing is listening on port 1, so this is the real
    // transport-failure path, not a stub.
    let con = connector("http://127.0.0.1:1");
    let err = con
        .deliver(
            &token(),
            &Target::Conversation(Conversation::telegram("1", "")),
            "x",
        )
        .await
        .expect_err("nothing is listening");
    let message = err.to_string();
    assert!(message.contains("could not reach"), "{message}");
    assert!(
        !message.contains(token().expose()),
        "the token must never appear in an error, and this one is built from a URL: {message}"
    );
}

#[tokio::test]
async fn a_409_conflict_is_a_hard_failure() {
    // A conflicting send (e.g. out-of-order edit) is an error, not a silent drop.
    let stub = stub(
        409,
        r#"{"ok":false,"error_code":409,"description":"Conflict"}"#,
    )
    .await;
    let con = connector(&stub.base_url);
    let err = con
        .deliver(
            &token(),
            &Target::Conversation(Conversation::telegram("1", "")),
            "x",
        )
        .await
        .expect_err("409 is a failure");
    assert!(err.to_string().contains("409"), "{err}");
}

#[tokio::test]
async fn a_token_never_reaches_an_error_message_not_even_the_url() {
    // Telegram authenticates with `/bot<token>/` in the *path*, so a URL in an error message is the
    // bot token in an error message — and `reqwest::Error`'s own `Display` includes the URL it
    // failed on. A failed `ask` now denies a run with this reason attached, which means the token
    // would land in the transcript and the audit trail. The error must describe the failure without
    // the URL that names the credential.
    let con = connector("http://127.0.0.1:1");
    let request = hx_core::approval::ApprovalRequest {
        id: hx_core::ids::ApprovalId::from_raw("apr_1"),
        tool: "shell".into(),
        summary: "git push".into(),
        risk: hx_core::approval::RiskClass::External,
        reason: "t".into(),
        key: "k".into(),
        options: vec![
            hx_core::approval::ApprovalOption::AllowOnce,
            hx_core::approval::ApprovalOption::Deny,
        ],
        targets: vec![],
        reversible: false,
        undo: None,
        confined: Default::default(),
        default_on_timeout: hx_core::approval::ApprovalOption::Deny,
        timeout_secs: None,
    };
    let task = hx_gateway::types::ApprovalTask {
        request,
        ceiling: hx_core::approval::RiskClass::Mutate,
    };

    let err = con
        .ask(
            &token(),
            &Target::Conversation(Conversation::telegram("1", "")),
            &task,
        )
        .await
        .expect_err("nothing is listening");

    let message = err.to_string();
    assert!(message.contains("could not reach"), "{message}");
    assert!(
        !message.contains(token().expose()),
        "the bot token must never appear in an error: {message}"
    );
    assert!(
        !message.contains("127.0.0.1:1"),
        "not even the URL, because the URL is where the token lives: {message}"
    );
}

/// A stub that answers with a status but **promises more body than it sends**, then closes.
///
/// The send succeeds and the *body* read fails, which is the other `reqwest::Error` on this path. A
/// non-success status is what makes it observable: that is the branch which interpolates the body
/// straight into the message.
async fn truncated_stub(status: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let addr = listener.local_addr().expect("a bound address");

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("a connection");
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = socket.read(&mut chunk).await.expect("a readable socket");
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if find(&buffer, b"\r\n\r\n").is_some() {
                break;
            }
        }

        let head = format!(
            "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: 4096\r\n\
             connection: close\r\n\r\n",
            reason(status)
        );
        socket
            .write_all(head.as_bytes())
            .await
            .expect("the headers");
        // A few bytes of a body that claimed to be 4096 long, and then the socket goes away.
        socket
            .write_all(b"{\"ok\": true")
            .await
            .expect("a partial body");
        socket.flush().await.ok();
    });

    format!("http://{addr}")
}

#[tokio::test]
async fn a_body_that_cannot_be_read_is_reported_without_the_url_either() {
    // The other `reqwest::Error` on this path: the request succeeds and the *body* fails. On a failure
    // status the body is interpolated straight into the message, and for `ask` that message is the
    // reason a run denies with — so it must not carry the URL the credential lives in.
    //
    // **This test cannot fail against the pinned `reqwest`, and saying so is the point.** The error it
    // produces is `error decoding response body`, which carries no URL: reverting the `without_url()`
    // call on this path and re-running still passes. So it is kept as a guard on a *dependency*
    // contract — `reqwest` upgrades are routine here, and if a version ever attaches the request URL to
    // a body error, this is the test that says so — and not as evidence that a leak was fixed, because
    // on this path there was none.
    let base = truncated_stub(500).await;
    let con = connector(&base);

    let err = con
        .deliver(
            &token(),
            &Target::Conversation(Conversation::telegram("1", "")),
            "hello",
        )
        .await
        .expect_err("the body never arrives");

    let message = err.to_string();
    assert!(
        message.contains("<unreadable body"),
        "the failure must be reported as an unreadable body: {message}"
    );
    assert!(
        !message.contains(token().expose()),
        "the bot token must never appear in an error: {message}"
    );
    assert!(
        !message.contains(&base),
        "not the URL either, because the URL is where the token lives: {message}"
    );
}

#[tokio::test]
async fn a_receive_with_a_missing_ok_flag_fails_closed() {
    // A body that is not signed `ok: true` is not "no messages" — it is an error, so a malformed
    // or refused response cannot be mistaken for an empty inbox.
    let stub = stub(200, r#"{"ok":false,"error_code":400,"description":"bad"}"#).await;
    let con = connector(&stub.base_url);
    let err = con.receive(&token()).await.expect_err("not ok");
    assert!(err.to_string().contains("refused"), "{err}");
}

// -------------------------------------------------------------------------------------------
// The live streaming driver, over the wire
// -------------------------------------------------------------------------------------------
//
// These are the tests the one-shot `stub` above cannot express. A stream makes *several* calls, and
// the count of those calls is the property under test, so the stub here answers request after request
// and the requests are read from a shared list rather than from a task's return value.

/// One request the scripted Bot API saw, with when it arrived.
#[derive(Debug, Clone)]
struct Seen {
    /// The Bot API method, taken from the last path segment (`sendMessage`, `editMessageText`).
    method: String,
    request_line: String,
    body: Value,
    /// The status the stub answered with, so a test can assert a retry rather than a hammer.
    status: u16,
    at: Instant,
}

/// A Bot API that answers request after request.
///
/// Each route is a per-method script: answers are handed out in order and the **last one repeats**
/// once the script is exhausted, so a route with a single answer means "always this". A method with no
/// route is answered `200` with a Message object, which is what makes "the stub saw three requests"
/// assertable without scripting the boring ones.
struct Scripted {
    base_url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Scripted {
    /// Every request the stub saw, in arrival order.
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("the capture list").clone()
    }

    /// Stop the stub and hand back what it saw.
    fn stop(self) -> Vec<Seen> {
        self.handle.abort();
        self.seen()
    }
}

/// Hold one request's response open until the test releases it.
struct Gate {
    /// The 1-based request number to hold.
    at: usize,
    /// Fires once the held request has been received — so a test knows a write is *provably* in flight.
    /// `Option` because it is consumed when it fires: the gate holds exactly one request.
    ready: Option<oneshot::Sender<()>>,
    /// The held response is written when this fires.
    release: Option<oneshot::Receiver<()>>,
}

/// The Message object the Bot API answers `sendMessage` with. Not a bare integer: that mistake is
/// exactly what `sent_message_id` had, and a stub that flattens it would hide the defect it is here
/// to catch.
fn message_object(id: i64) -> String {
    json!({
        "ok": true,
        "result": { "message_id": id, "date": 1_700_000_000, "chat": { "id": 4242, "type": "private" }, "text": "" }
    })
    .to_string()
}

/// The `429` body Telegram sends, with its own `retry_after` field.
fn throttled(seconds: u64) -> String {
    json!({
        "ok": false,
        "error_code": 429,
        "description": format!("Too Many Requests: retry after {seconds}"),
        "parameters": { "retry_after": seconds }
    })
    .to_string()
}

/// The `400` Telegram answers when the new text is byte-identical to the current text.
fn not_modified() -> String {
    json!({
        "ok": false,
        "error_code": 400,
        "description": "Bad Request: message is not modified: specified new message content and reply \
                        markup are exactly the same as a current content and reply markup of the message"
    })
    .to_string()
}

fn failed_request(status: u16, description: &str) -> String {
    json!({ "ok": false, "error_code": status, "description": description }).to_string()
}

async fn scripted_bot_api(
    routes: Vec<(&'static str, Vec<(u16, String)>)>,
    gate: Option<Gate>,
) -> Scripted {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let addr = listener.local_addr().expect("a bound address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_in_task = Arc::clone(&seen);

    let mut scripts: HashMap<String, VecDeque<(u16, String)>> = routes
        .into_iter()
        .map(|(method, answers)| (method.to_string(), VecDeque::from(answers)))
        .collect();
    let mut gate = gate;

    let handle = tokio::spawn(async move {
        let mut count = 0usize;
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let (head, body) = read_request(&mut socket).await;
            let request_line = head.lines().next().unwrap_or_default().to_string();
            // The method is the last path segment of the request target: `POST /bot<token>/sendMessage
            // HTTP/1.1`. Splitting the whole line on `/` would find `1.1` in the HTTP version instead.
            let method = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .split('?')
                .next()
                .unwrap_or_default()
                .to_string();
            count += 1;

            if let Some(held) = gate.as_mut() {
                if held.at == count {
                    if let Some(ready) = held.ready.take() {
                        let _ = ready.send(());
                    }
                    if let Some(release) = held.release.take() {
                        let _ = release.await;
                    }
                }
            }

            // The script for this method: in order, then the last answer repeats.
            let (status, response_body) = scripts
                .get_mut(&method)
                .and_then(|answers| {
                    if answers.len() > 1 {
                        answers.pop_front()
                    } else {
                        answers.front().cloned()
                    }
                })
                .unwrap_or_else(|| (200, message_object(1)));

            seen_in_task.lock().expect("the capture list").push(Seen {
                method: method.clone(),
                request_line,
                body,
                status,
                at: Instant::now(),
            });

            let response = format!(
                "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
                reason(status),
                response_body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("the stub can write");
            socket.flush().await.ok();
        }
    });

    Scripted {
        base_url: format!("http://{addr}"),
        seen,
        handle,
    }
}

/// Read one whole HTTP/1.1 request off a socket: the head, and the body its `content-length` promises.
async fn read_request(socket: &mut TcpStream) -> (String, Value) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut head_end = 0usize;
    let mut content_length = 0usize;

    loop {
        let read = socket.read(&mut chunk).await.expect("a readable socket");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if head_end == 0 {
            if let Some(position) = find(&buffer, b"\r\n\r\n") {
                head_end = position;
                content_length = content_length_of(&String::from_utf8_lossy(&buffer[..position]));
            }
        }
        if head_end > 0 && buffer.len() >= head_end + 4 + content_length {
            break;
        }
    }

    let head = String::from_utf8_lossy(&buffer[..head_end.min(buffer.len())]).to_string();
    let body_start = head_end + 4;
    let body_text = String::from_utf8_lossy(
        buffer
            .get(body_start..body_start + content_length)
            .unwrap_or_default(),
    )
    .to_string();
    (
        head,
        serde_json::from_str(&body_text).unwrap_or(Value::Null),
    )
}

/// A plan with the retry backoff shrunk so a test that deliberately fails every write finishes in
/// milliseconds instead of a quarter of a second per attempt. The retry *policy* is what the unit
/// tests pin; these tests are about the stream.
fn stream_plan(unit: usize) -> StreamPlan {
    StreamPlan {
        unit,
        transient_backoff: Duration::from_millis(1),
        ..StreamPlan::default()
    }
}

/// Drive `chunks` through the driver and return what it did, with the stream closed at the end.
///
/// The sender is dropped before awaiting, which is how a model's turn ends — including when the model
/// *fails* mid-answer, which is the case where the partial text matters most.
async fn drive(
    base_url: &str,
    plan: StreamPlan,
    chunks: Vec<&str>,
) -> hx_core::error::Result<StreamOutcome> {
    let con = Arc::new(connector(base_url));
    let (tx, mut rx) = mpsc::channel::<String>(64);
    let driver = tokio::spawn(async move {
        con.stream_answer(
            &token(),
            &Target::Conversation(Conversation::telegram("4242", "")),
            plan,
            &mut rx,
        )
        .await
    });
    for chunk in chunks {
        tx.send(chunk.to_string())
            .await
            .expect("the driver keeps reading");
    }
    drop(tx);
    driver.await.expect("the driver task")
}

/// The same, but yielding between chunks so the driver sees a stream that arrives *over time* rather
/// than in one burst.
///
/// This is the shape a model actually produces, and it is the only shape in which a mid-stream write is
/// possible at all: a burst that arrives in a single poll is coalesced into one write, which is correct
/// but exercises none of the growth. Used by the tests that assert *how* the message grows, never by
/// the ones that assert a bound — a bound must hold in both shapes.
async fn drive_over_time(
    base_url: &str,
    plan: StreamPlan,
    chunks: Vec<&str>,
) -> hx_core::error::Result<StreamOutcome> {
    let con = Arc::new(connector(base_url));
    let (tx, mut rx) = mpsc::channel::<String>(1);
    let driver = tokio::spawn(async move {
        con.stream_answer(
            &token(),
            &Target::Conversation(Conversation::telegram("4242", "")),
            plan,
            &mut rx,
        )
        .await
    });
    for chunk in chunks {
        tx.send(chunk.to_string())
            .await
            .expect("the driver keeps reading");
        tokio::task::yield_now().await;
    }
    drop(tx);
    driver.await.expect("the driver task")
}

#[tokio::test]
async fn a_stream_of_small_chunks_costs_far_fewer_writes_than_it_has_chunks() {
    // The property, stated as a *number*: an edit per token is the defect, so what is asserted is the
    // count of API calls against the count of chunks. With a unit of 40 and 400 one-character chunks
    // the ceiling is 1 + 400/40 = 11 — the first chunk writes immediately and each write after that
    // needs 40 characters of new text — and a skipped flush can only lower it. A driver that awaited
    // its write inline, or coalesced nothing, cannot land under that bound.
    let api = scripted_bot_api(vec![("sendMessage", vec![(200, message_object(77))])], None).await;

    let chunks: Vec<&str> = vec!["x"; 400];
    let outcome = drive_over_time(&api.base_url, stream_plan(40), chunks)
        .await
        .expect("a stream");
    let seen = api.stop();

    assert_eq!(
        outcome.chunks, 400,
        "every chunk the model produced is taken off the stream"
    );
    assert!(
        outcome.writes <= 11,
        "one write per token is the defect: {} writes for 400 chunks",
        outcome.writes
    );
    assert!(
        outcome.writes >= 2,
        "the message has to actually grow: {} writes",
        outcome.writes
    );
    assert!(
        outcome.writes * 4 < 400,
        "the ratio is the property: {} writes for 400 chunks",
        outcome.writes
    );

    // The token still authenticates in the *path* on every streaming call — Telegram's contract — and
    // never in a body. The companion assertion (it never reaches an error) is
    // `a_streaming_error_never_carries_the_token`.
    // The needle is built from the fixture rather than copied, so it cannot drift if the fixture moves.
    let in_path = format!("/bot{}/", token().expose());
    assert!(
        seen.iter().all(|s| s.request_line.contains(&in_path)),
        "the token authenticates in the path: {:?}",
        seen.iter().map(|s| &s.request_line).collect::<Vec<_>>()
    );
    assert!(
        seen.iter()
            .all(|s| !s.body.to_string().contains(token().expose())),
        "the token must never appear in a body: {:?}",
        seen.iter().map(|s| &s.body).collect::<Vec<_>>()
    );

    // The first call creates the message; every later one edits it in place, by the id the send
    // returned. A driver that never learned that id could only ever post whole answers.
    assert_eq!(seen[0].method, "sendMessage");
    assert_eq!(seen[0].body["chat_id"], "4242");
    assert!(
        seen[1..].iter().all(|s| s.method == "editMessageText"),
        "the message is edited, never re-sent: {:?}",
        seen.iter().map(|s| &s.method).collect::<Vec<_>>()
    );
    assert!(
        seen[1..].iter().all(|s| s.body["message_id"] == 77),
        "every edit targets the message the send created"
    );

    // And the visible text only ever grows, ending at the whole answer.
    let lengths: Vec<usize> = seen
        .iter()
        .map(|s| {
            s.body["text"]
                .as_str()
                .expect("every write carries text")
                .chars()
                .count()
        })
        .collect();
    assert!(
        lengths.windows(2).all(|pair| pair[0] <= pair[1]),
        "a streamed message must never shrink: {lengths:?}"
    );
    assert_eq!(
        *lengths.last().expect("at least one write"),
        400,
        "the last write carries the whole answer"
    );
    assert_eq!(outcome.delivery, FinalDelivery::Edited);
}

#[tokio::test]
async fn the_visible_message_grows_while_the_model_is_still_generating() {
    // The point of streaming, stated as an observable event rather than a duration: while the answer is
    // still arriving, the message on the screen already holds part of it. The test waits for that edit
    // to appear (with a deadline that fails loudly) instead of sleeping and hoping, so it cannot pass by
    // accident on a fast machine.
    let (ready_tx, ready_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let api = scripted_bot_api(
        vec![("sendMessage", vec![(200, message_object(77))])],
        Some(Gate {
            at: 1,
            ready: Some(ready_tx),
            release: Some(release_rx),
        }),
    )
    .await;

    let con = Arc::new(connector(&api.base_url));
    let (tx, mut rx) = mpsc::channel::<String>(1);
    let driver = tokio::spawn(async move {
        con.stream_answer(
            &token(),
            &Target::Conversation(Conversation::telegram("4242", "")),
            stream_plan(20),
            &mut rx,
        )
        .await
    });

    // The first chunk creates the message; hold that response so nothing else can be written while the
    // buffer fills, then release it and let the stream run the way a model's does.
    tx.send("x".to_string()).await.expect("the first chunk");
    tokio::time::timeout(Duration::from_secs(10), ready_rx)
        .await
        .expect("the first write must reach the stub")
        .expect("the gate signal");
    for _ in 0..30 {
        tx.send("x".to_string())
            .await
            .expect("the driver keeps reading");
    }
    release_tx.send(()).expect("release the held write");

    // Keep the answer arriving until an edit shows up, bounded so a driver that never grows the message
    // fails loudly rather than looping.
    let mut first_edit_chars = None;
    let mut sent = 31usize;
    while sent < 400 && first_edit_chars.is_none() {
        tx.send("x".to_string())
            .await
            .expect("the driver keeps reading");
        sent += 1;
        tokio::task::yield_now().await;
        first_edit_chars = api.seen().iter().find_map(|seen| {
            (seen.method == "editMessageText").then(|| {
                seen.body["text"]
                    .as_str()
                    .unwrap_or_default()
                    .chars()
                    .count()
            })
        });
    }
    let first_edit_chars = first_edit_chars.expect(
        "the message must grow while the answer is still arriving, not only once it is complete",
    );
    assert!(
        first_edit_chars > 1,
        "the first edit carries more than the first chunk: {first_edit_chars}"
    );

    // More answer arrives, and the message must grow again.
    for _ in 0..40 {
        tx.send("x".to_string())
            .await
            .expect("the driver keeps reading");
        tokio::task::yield_now().await;
    }
    drop(tx);

    let outcome = driver.await.expect("the driver task").expect("a stream");
    let seen = api.stop();
    let first = &seen[0];
    assert_eq!(first.method, "sendMessage", "the message is created once");
    assert_eq!(
        first.body["text"], "x",
        "the first write is the first chunk — the user sees the answer begin rather than waiting for a \
         whole sentence"
    );
    assert!(
        first_edit_chars < outcome.chars,
        "the first edit was a partial answer ({first_edit_chars} of {})",
        outcome.chars
    );

    let final_chars = seen.last().expect("at least one write").body["text"]
        .as_str()
        .expect("the final write carries text")
        .chars()
        .count();
    assert_eq!(
        final_chars, outcome.chars,
        "the last write carries the whole answer"
    );
    assert!(
        final_chars > first_edit_chars,
        "the message kept growing after that first edit: {first_edit_chars} then {final_chars}"
    );
    // The bound, in the shape where writes actually land mid-stream: the first write, one per unit of
    // new text, and at most one more for the tail.
    assert!(
        outcome.writes <= 2 + (outcome.chars / 20) as u32,
        "{} writes for {} characters at a unit of 20",
        outcome.writes,
        outcome.chars
    );
    assert_eq!(outcome.delivery, FinalDelivery::Edited);
}

#[tokio::test]
async fn a_write_that_is_still_in_flight_does_not_stop_the_token_stream() {
    // The property the whole design turns on, and the one a wall-clock test cannot state honestly:
    // the stub accepts the first write and then *holds the response open*, so a write is provably in
    // flight and cannot complete. The model side must still be able to push every remaining chunk. A
    // driver that awaited its own edit would block on the second chunk, the capacity-1 channel would
    // fill, and this test fails loudly on a timeout instead of passing by accident on a fast machine.
    let (ready_tx, ready_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let api = scripted_bot_api(
        vec![("sendMessage", vec![(200, message_object(77))])],
        Some(Gate {
            at: 1,
            ready: Some(ready_tx),
            release: Some(release_rx),
        }),
    )
    .await;

    let con = Arc::new(connector(&api.base_url));
    // Capacity 1 on purpose: a driver that stops reading to wait for its own edit blocks this sender.
    let (tx, mut rx) = mpsc::channel::<String>(1);
    let driver = tokio::spawn(async move {
        con.stream_answer(
            &token(),
            &Target::Conversation(Conversation::telegram("4242", "")),
            stream_plan(10),
            &mut rx,
        )
        .await
    });

    // Chunk 1 triggers the write; wait until the stub has it and is holding the response.
    tx.send("x".to_string()).await.expect("the first chunk");
    tokio::time::timeout(Duration::from_secs(10), ready_rx)
        .await
        .expect("the first write must reach the stub")
        .expect("the gate signal");

    // The write is in flight and cannot finish. The remaining 49 chunks must all go through.
    for n in 2..=50 {
        tokio::time::timeout(Duration::from_secs(10), tx.send("x".to_string()))
            .await
            .unwrap_or_else(|_| {
                panic!("chunk {n} blocked: the driver is waiting for its own write")
            })
            .expect("the driver is still reading");
    }
    drop(tx);
    release_tx.send(()).expect("release the held write");

    let outcome = driver.await.expect("the driver task").expect("a stream");
    assert_eq!(
        outcome.chunks, 50,
        "every chunk was taken off the stream while a write was held open"
    );
    assert!(
        outcome.skipped >= 1,
        "the flushes that arrived during the write were skipped rather than queued: {}",
        outcome.skipped
    );
    assert_eq!(outcome.delivery, FinalDelivery::Edited);

    let seen = api.stop();
    assert_eq!(
        seen.len(),
        2,
        "one held write plus the final edit — not one write per skipped flush: {:?}",
        seen.iter().map(|s| &s.method).collect::<Vec<_>>()
    );
    assert_eq!(seen[1].method, "editMessageText");
    assert_eq!(
        seen[1].body["text"],
        "x".repeat(50),
        "the final edit carries all 50 chunks"
    );
}

#[tokio::test]
async fn a_throttled_write_waits_the_delay_the_api_named_before_it_is_retried() {
    // Telegram's `429` names its own delay in `parameters.retry_after`. Honouring it is the difference
    // between backing off and hammering an API that is already refusing.
    //
    // The delay is asserted as a *lower bound* on the gap between the refused call and its retry, so a
    // loaded machine makes this pass more surely, not less: the flake direction is safe, and a driver
    // that ignored the delay (retrying microseconds later) fails loudly. The call count is asserted
    // too, so "honoured" cannot be satisfied by a retry loop that hammers.
    //
    // The first write is held open so the burst of chunks is coalesced into it and the *final* write is
    // the one throttled — which is the case that matters, because a 429 on the last write is the one
    // whose loss would leave a truncated answer on the screen.
    let (ready_tx, ready_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let api = scripted_bot_api(
        vec![
            ("sendMessage", vec![(200, message_object(77))]),
            (
                "editMessageText",
                vec![
                    (429, throttled(1)),
                    (200, json!({ "ok": true, "result": true }).to_string()),
                ],
            ),
        ],
        Some(Gate {
            at: 1,
            ready: Some(ready_tx),
            release: Some(release_rx),
        }),
    )
    .await;

    let con = Arc::new(connector(&api.base_url));
    let (tx, mut rx) = mpsc::channel::<String>(8);
    let driver = tokio::spawn(async move {
        con.stream_answer(
            &token(),
            &Target::Conversation(Conversation::telegram("4242", "")),
            stream_plan(5),
            &mut rx,
        )
        .await
    });

    // Ten characters one at a time, a unit of five: the first chunk creates the message and the rest
    // accumulate as unsent text, so a final edit is required and it is that one that gets throttled.
    for chunk in "abcdefghij".chars() {
        tx.send(chunk.to_string())
            .await
            .expect("the driver keeps reading");
    }
    tokio::time::timeout(Duration::from_secs(10), ready_rx)
        .await
        .expect("the first write must reach the stub")
        .expect("the gate signal");
    drop(tx);
    release_tx.send(()).expect("release the held write");

    let outcome = driver
        .await
        .expect("the driver task")
        .expect("a stream that recovers from a throttle");
    let seen = api.stop();

    assert_eq!(
        outcome.failed_writes, 0,
        "a throttle that is retried and lands is not a failure"
    );
    assert_eq!(
        seen.iter().filter(|s| s.status == 429).count(),
        1,
        "the refused call is retried, not repeated: {:?}",
        seen.iter()
            .map(|s| (s.method.clone(), s.status))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        outcome.writes,
        3,
        "the send, the refused edit, and its retry — no hammering: {:?}",
        seen.iter()
            .map(|s| (s.method.clone(), s.status))
            .collect::<Vec<_>>()
    );

    let gap = seen[2].at.duration_since(seen[1].at);
    assert!(
        gap >= Duration::from_millis(900),
        "the 1s retry_after was ignored — retried after {gap:?}"
    );
    assert_eq!(
        seen[2].method, "editMessageText",
        "the retry is the same call"
    );
    assert_eq!(
        seen[2].body["text"], "abcdefghij",
        "and it carries the whole answer, not a truncated retry"
    );
    assert_eq!(outcome.delivery, FinalDelivery::Edited);
}

#[tokio::test]
async fn a_repeated_identical_edit_is_a_benign_no_op_over_the_wire() {
    // Telegram answers a second identical edit with a 400. It is not an error, and it must not spend
    // the retry budget either: a driver that treated it as a failure would post a duplicate message at
    // the end of every stream that happened to land on the same text twice.
    let api = scripted_bot_api(
        vec![
            ("sendMessage", vec![(200, message_object(77))]),
            ("editMessageText", vec![(400, not_modified())]),
        ],
        None,
    )
    .await;

    let chunks: Vec<String> = "abcdefghij".chars().map(|c| c.to_string()).collect();
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();

    let outcome = drive(&api.base_url, stream_plan(5), refs)
        .await
        .expect("an identical edit is not a failure");
    let seen = api.stop();

    assert_eq!(
        outcome.failed_writes, 0,
        "a benign no-op must not count as a failed write"
    );
    assert_eq!(
        seen.iter().filter(|s| s.status == 400).count(),
        1,
        "the no-op must not be retried: {:?}",
        seen.iter()
            .map(|s| (s.method.clone(), s.status))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        seen.iter().filter(|s| s.method == "sendMessage").count(),
        1,
        "no replacement message is posted for a no-op"
    );
    assert_eq!(outcome.delivery, FinalDelivery::Edited);
}

#[tokio::test]
async fn an_unrelated_bad_request_falls_back_to_a_fresh_message_so_the_answer_still_arrives() {
    // The control for the test above. The same 400 also means "message to edit not found", and calling
    // that a benign no-op would report a successful stream while the user watched a message that never
    // grew. The answer still has to reach them, so the driver posts the whole text as a new message.
    let api = scripted_bot_api(
        vec![
            (
                "sendMessage",
                vec![(200, message_object(77)), (200, message_object(88))],
            ),
            (
                "editMessageText",
                vec![(
                    400,
                    failed_request(400, "Bad Request: message to edit not found"),
                )],
            ),
        ],
        None,
    )
    .await;

    let chunks: Vec<String> = "abcdefghij".chars().map(|c| c.to_string()).collect();
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();

    let outcome = drive(&api.base_url, stream_plan(5), refs)
        .await
        .expect("the fallback delivers the text");
    let seen = api.stop();

    assert!(
        outcome.failed_writes >= 1,
        "a 400 that is not the identical-edit case is a real failure"
    );
    assert_eq!(outcome.delivery, FinalDelivery::Replaced);

    let last = seen.last().expect("at least one request");
    assert_eq!(
        last.method,
        "sendMessage",
        "the whole answer is posted fresh: {:?}",
        seen.iter().map(|s| &s.method).collect::<Vec<_>>()
    );
    assert_eq!(
        last.body["text"], "abcdefghij",
        "the fallback carries the whole answer, not the last edit's text"
    );
    assert_eq!(
        outcome.message_id,
        Some(88),
        "the replacement's own id is recorded, so a later stream could edit it"
    );
}

#[tokio::test]
async fn a_failure_mid_answer_does_not_lose_the_partial_text() {
    // The failure mode being designed out: the user is left with a message that stopped growing and no
    // answer. Every edit is refused here, so the only way the text reaches them is the fallback — and
    // the stream is still consumed in full, because a failing display must not wedge the run.
    let api = scripted_bot_api(
        vec![
            (
                "sendMessage",
                vec![(200, message_object(77)), (200, message_object(88))],
            ),
            (
                "editMessageText",
                vec![(500, failed_request(500, "Internal Server Error"))],
            ),
        ],
        None,
    )
    .await;

    let chunks: Vec<String> = "abcdefghij".chars().map(|c| c.to_string()).collect();
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();

    let outcome = drive(&api.base_url, stream_plan(5), refs)
        .await
        .expect("the fallback delivers the text");
    let seen = api.stop();

    assert_eq!(
        outcome.chunks, 10,
        "a display that keeps failing must not stop the model's stream being consumed"
    );
    assert!(
        outcome.failed_writes >= 1,
        "a 5xx after its retry budget is a failed write"
    );
    assert_eq!(outcome.delivery, FinalDelivery::Replaced);

    let last = seen.last().expect("at least one request");
    assert_eq!(last.method, "sendMessage");
    assert_eq!(
        last.body["text"], "abcdefghij",
        "the partial text is delivered in full rather than lost"
    );
    assert_eq!(outcome.chars, 10);
}

#[tokio::test]
async fn a_stream_that_ends_mid_answer_delivers_what_arrived() {
    // The model failing mid-answer, told through the channel closing. Whatever accumulated is put on
    // the screen: this is the same guarantee as the test above, reached without any write failing.
    let api = scripted_bot_api(vec![("sendMessage", vec![(200, message_object(77))])], None).await;

    let outcome = drive(&api.base_url, stream_plan(5), vec!["abcde", "f", "g"])
        .await
        .expect("a stream");
    let seen = api.stop();

    assert_eq!(outcome.delivery, FinalDelivery::Edited);
    assert_eq!(outcome.chars, 7);
    let last = seen.last().expect("at least one request");
    assert_eq!(last.method, "editMessageText");
    assert_eq!(
        last.body["text"], "abcdefg",
        "the seven characters that arrived are on the screen"
    );
}

#[tokio::test]
async fn a_stream_that_ends_before_any_text_writes_nothing_at_all() {
    // An answer that never came must not leave an empty message behind, and must not leave a stuck
    // progress signal either: the driver deliberately sends no `sendChatAction` typing indicator,
    // precisely because one that cannot be cleared is the symptom this test guards.
    let api = scripted_bot_api(vec![], None).await;

    let outcome = drive(&api.base_url, stream_plan(5), vec![])
        .await
        .expect("an empty stream is not an error");
    let seen = api.stop();

    assert_eq!(outcome.chunks, 0);
    assert_eq!(
        outcome.writes, 0,
        "no message is created for text that never arrived"
    );
    assert_eq!(outcome.delivery, FinalDelivery::NothingToSend);
    assert!(seen.is_empty(), "the API was never called: {seen:?}");
}

#[tokio::test]
async fn streaming_to_the_home_channel_is_refused_before_anything_is_sent() {
    // Same rule as `deliver`: a raw `Target::Home` must be resolved to a concrete conversation first,
    // and the refusal happens before any call so nothing goes somewhere wrong.
    let api = scripted_bot_api(vec![], None).await;
    let con = Arc::new(connector(&api.base_url));
    let (_tx, mut rx) = mpsc::channel::<String>(4);

    let err = con
        .stream_answer(&token(), &Target::Home, stream_plan(5), &mut rx)
        .await
        .expect_err("the home channel must be resolved first");
    assert!(err.to_string().contains("explicit conversation"), "{err}");
    assert!(api.stop().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn a_streaming_error_never_carries_the_token() {
    // Nothing is listening, so every write fails and the final delivery fails with it — the error that
    // names both calls is built from request URLs, which is exactly where the token lives.
    let con = Arc::new(connector("http://127.0.0.1:1"));
    let (tx, mut rx) = mpsc::channel::<String>(4);
    let driver = tokio::spawn(async move {
        con.stream_answer(
            &token(),
            &Target::Conversation(Conversation::telegram("4242", "")),
            stream_plan(5),
            &mut rx,
        )
        .await
    });

    tx.send("abcdefghij".to_string())
        .await
        .expect("the driver keeps reading");
    drop(tx);

    let err = driver
        .await
        .expect("the driver task")
        .expect_err("a channel that is down is a failure, not a silent drop");
    let message = err.to_string();
    assert!(
        message.contains("could not be put on the screen"),
        "the error says the user has no answer: {message}"
    );
    assert!(
        !message.contains(token().expose()),
        "the token must never appear in an error: {message}"
    );
}
