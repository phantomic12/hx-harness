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
use hx_gateway::{Conversation, Inbound, Target};
use hx_secrets::Secret;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
        401 => "Unauthorized",
        409 => "Conflict",
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
        !message.contains("TESTBOT-token"),
        "the token must never appear in an error: {message}"
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
