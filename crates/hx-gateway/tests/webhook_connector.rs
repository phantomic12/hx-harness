//! End-to-end tests of the generic webhook connector: [`WebhookConnector`] over the `Connector` trait
//! plus its HTTP route, all hermetic (a local stub, no external service).
//!
//! The webhook half of M5 is a **push** connector: a remote platform `POST`s an inbound event to
//! `POST /v1/connectors/{id}/webhook`, the route authenticates it against the connector's own bearer
//! token, parses the small envelope, and pushes the resulting [`Inbound`] into the channel
//! [`WebhookConnector::receive`] reads from. Outbound replies `POST` to the configured `outbound_url`,
//! or **fail closed** when none is set.

use hx_core::ids::ConnectorId;
use hx_gateway::webhook::{parse, WebhookConnector, WebhookEnvelope};
use hx_gateway::{Connector, Conversation, Inbound, Platform, Target};
use hx_secrets::Secret;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A one-shot HTTP stub that captures the request it answers. Used for both directions: the webhook route
/// under test for inbound, and the outbound endpoint for `deliver`/`ask`.
struct Stub {
    addr: SocketAddr,
    handle: tokio::task::JoinHandle<(String, String)>,
}

async fn stub(status: u16, body: &str) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body_owned = body.to_string();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 65536];
        let n = socket.read(&mut buffer).await.unwrap();
        let request = String::from_utf8_lossy(&buffer[..n]).to_string();
        let head_end = request
            .find("\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(request.len());
        let body_start = head_end;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    status,
                    match status { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 500 => "Internal Server Error", _ => "Status" },
                    body_owned.len(),
                    body_owned
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.flush().await.ok();
        (
            request[..head_end].to_string(),
            request[body_start..].to_string(),
        )
    });
    Stub { addr, handle }
}

fn webhook_connector(
    url: Option<String>,
    rx: tokio::sync::mpsc::UnboundedReceiver<Inbound>,
) -> WebhookConnector {
    WebhookConnector::new(
        ConnectorId::from("main-web"),
        url,
        reqwest::Client::new(),
        rx,
    )
}

fn conversation() -> Conversation {
    Conversation {
        platform: Platform("webhook:main-web".into()),
        chat: "777".into(),
        thread: "".into(),
    }
}

fn inbound_text() -> Inbound {
    parse(
        WebhookEnvelope {
            chat: "777".into(),
            thread: None,
            text: "list the repo".into(),
        },
        &ConnectorId::from("main-web"),
    )
}

// -------------------------------------------------------------------------------------------
// receive: what was pushed is what is handed to the harness
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn receive_yields_what_the_route_pushed() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(inbound_text()).unwrap();
    let con = webhook_connector(None, rx);
    let received = con.receive(&Secret::new("")).await.expect("a message");
    match received {
        Some(Inbound::Message { conversation, text }) => {
            assert_eq!(conversation.chat.as_str(), "777");
            assert_eq!(conversation.thread.as_str(), "");
            assert_eq!(text, "list the repo");
        }
        other => panic!("expected a message, got {other:?}"),
    }
}

#[tokio::test]
async fn receive_from_a_closed_channel_is_none_not_an_error() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Inbound>();
    let con = webhook_connector(None, rx);
    // The sender must be dropped *before* the receive: a live sender means "a push may still come",
    // so `recv` would wait forever and the test would hang rather than fail. Dropping it is what makes
    // "nothing can ever be pushed" true, which is the case under test.
    drop(tx);
    // A timeout turns a regression (sender kept alive, `recv` pending forever) into a failure
    // instead of wedging the whole suite behind this test.
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        con.receive(&Secret::new("")),
    )
    .await
    .expect("receive on a closed channel resolves instead of hanging")
    .unwrap();
    assert!(received.is_none());
}

// -------------------------------------------------------------------------------------------
// deliver / ask: POST to outbound_url, or fail closed when none is configured
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn deliver_posts_to_the_outbound_url() {
    let stub = stub(200, r#"{"ok":true}"#).await;
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let con = webhook_connector(Some(format!("http://{}/reply", stub.addr)), rx);

    con.deliver(
        &Secret::new("k"),
        &Target::Conversation(conversation()),
        "hi",
    )
    .await
    .expect("deliver succeeds when outbound_url is set");

    let (head, body) = stub.handle.await.unwrap();
    assert!(head.starts_with("POST /reply"), "{head}");
    // The connector's token authenticates the outbound POST as a bearer token. (reqwest sends the
    // header value itself, which its Debug redacts — we assert the scheme is present and the header exists.)
    assert!(head.contains("authorization: Bearer"), "{head}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["chat"], "777");
    assert_eq!(parsed["thread"], "");
    assert_eq!(parsed["text"], "hi");
}

#[tokio::test]
async fn deliver_fails_closed_when_no_outbound_url_is_configured() {
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let con = webhook_connector(None, rx);
    let err = con
        .deliver(
            &Secret::new("k"),
            &Target::Conversation(conversation()),
            "hi",
        )
        .await
        .expect_err("a webhook-only channel with no outbound URL must fail closed");
    assert!(err.to_string().contains("outbound_url"), "{err}");
}

#[tokio::test]
async fn deliver_rejects_a_home_target() {
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let con = webhook_connector(None, rx);
    let err = con
        .deliver(&Secret::new("k"), &Target::Home, "hi")
        .await
        .expect_err("a webhook can only deliver to an explicit conversation");
    assert!(err.to_string().contains("explicit conversation"), "{err}");
}

#[tokio::test]
async fn ask_posts_the_request_and_returns_no_answer() {
    let stub = stub(200, r#"{"ok":true}"#).await;
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let con = webhook_connector(Some(format!("http://{}/reply", stub.addr)), rx);

    let request = hx_core::approval::ApprovalRequest {
        id: hx_core::ids::ApprovalId::from_raw("apr_1"),
        tool: "shell".into(),
        summary: "may I run this?".into(),
        risk: hx_core::approval::RiskClass::Mutate,
        reason: "t".into(),
        key: "k".into(),
        options: vec![hx_core::approval::ApprovalOption::AllowOnce],
        targets: vec![],
        reversible: false,
        undo: None,
        unattended: None,
        confined: Default::default(),
        default_on_timeout: hx_core::approval::ApprovalOption::Deny,
        timeout_secs: None,
    };
    let task = hx_gateway::types::ApprovalTask {
        request,
        ceiling: hx_core::approval::RiskClass::Mutate,
    };

    let verdict = con
        .ask(
            &Secret::new("k"),
            &Target::Conversation(conversation()),
            &task,
        )
        .await
        .expect("ask succeeds when outbound_url is set");
    assert!(matches!(
        verdict,
        hx_gateway::answer::AnswerVerdict::NoAnswer
    ));

    let (_, body) = stub.handle.await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    // `ask` renders the whole ApprovalRequest, so the text is the full prompt — the key part is the
    // connector posted the question we asked.
    assert!(parsed["text"].as_str().unwrap().contains("may I run this?"));
}
