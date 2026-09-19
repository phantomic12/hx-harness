//! Resuming across a process boundary — the one thing unit tests with an in-memory database
//! cannot show.
//!
//! `ROADMAP.md` M1's exit criterion is "killing the TUI and reconnecting resumes the session
//! mid-flight". The clause that needs a real file is the killing: an in-memory store proves the
//! API is consistent, and proves nothing about whether the transcript is still there when the
//! process that wrote it is gone. Every test here drops the `Store` and opens a **new connection**
//! to the same path, which is the closest a test can get to a restart without forking a process.

use chrono::{DateTime, Utc};
use hx_core::event::{AgentEvent, StopReason};
use hx_core::ids::{AgentId, SessionId, ToolCallId};
use hx_core::message::{Message, Part};
use hx_store::session::UsageRecord;
use hx_store::{ExportFormat, NewSession, Store};
use serde_json::json;

fn at(offset: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + offset, 0).unwrap()
}

fn database() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hx.db");
    (dir, path)
}

fn call(id: &str, cmd: &str) -> Message {
    Message::new(
        hx_core::message::Role::Assistant,
        vec![Part::ToolCall {
            id: ToolCallId::from(id),
            name: "shell".into(),
            arguments: json!({ "cmd": cmd }),
        }],
    )
}

#[test]
fn a_session_survives_the_store_that_wrote_it() {
    let (_dir, path) = database();

    let id = {
        let store = Store::open(&path).unwrap();
        let id = store
            .create(NewSession::new().titled("build the thing"), at(0))
            .unwrap()
            .id;
        store
            .append(&id, &Message::user("build it"), at(1))
            .unwrap();
        store
            .append(&id, &Message::assistant("on it"), at(2))
            .unwrap();
        id
    }; // the store — and with it the connection — is gone

    let reopened = Store::open(&path).unwrap();
    let session = reopened.load(&id).unwrap();

    assert_eq!(session.record.title, "build the thing");
    assert_eq!(session.len(), 2);
    assert_eq!(session.messages[0].text(), "build it");
    assert_eq!(session.messages[1].role, hx_core::message::Role::Assistant);

    // Continuing the conversation picks up after what was already written, rather than starting
    // the sequence again — which is what makes a resumed transcript usable.
    let next = reopened
        .append(&id, &Message::user("carry on"), at(3))
        .unwrap();
    assert_eq!(next, 3);
    assert_eq!(reopened.message_count(&id).unwrap(), 3);

    // And the list a client shows on reconnect knows about it.
    let listed = reopened.list(10).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].record.id, id);
    assert_eq!(listed[0].messages, 3);
}

#[test]
fn a_transcript_interrupted_mid_call_is_repaired_before_it_is_sent_again() {
    let (_dir, path) = database();

    // A run that died between deciding to call a tool and hearing back about it: the assistant
    // turn is on disk, the result is not. Every provider rejects this shape, and the rejection
    // does not say why.
    let id = {
        let store = Store::open(&path).unwrap();
        let id = store.create(NewSession::new(), at(0)).unwrap().id;
        store
            .append(&id, &Message::user("run the tests"), at(1))
            .unwrap();
        store
            .append(&id, &call("tc_1", "cargo test"), at(2))
            .unwrap();
        id
    };

    let store = Store::open(&path).unwrap();
    let loaded = store.load(&id).unwrap();
    assert!(loaded.is_mid_flight(), "the transcript is not sendable yet");
    assert_eq!(loaded.interrupted_calls(), vec![ToolCallId::from("tc_1")]);

    let closed = store
        .close_interrupted(
            &id,
            "the daemon stopped before this call ran; nothing was executed",
            at(3),
        )
        .unwrap();
    assert_eq!(closed, vec![ToolCallId::from("tc_1")]);

    let repaired = store.load(&id).unwrap();
    assert!(!repaired.is_mid_flight());

    // The repair is a *result the model reads*, not a silent deletion of the call: the model has to
    // know the command did not run, or it will summarise work that never happened.
    let last = repaired.messages.last().unwrap();
    let Part::ToolResult {
        ok,
        content,
        id: call_id,
    } = &last.parts[0]
    else {
        panic!("expected a tool result, got {:?}", last.parts);
    };
    assert!(!ok);
    assert_eq!(call_id.as_str(), "tc_1");
    assert!(content.contains("nothing was executed"), "{content}");

    // Resuming is then an ordinary append: the model answers, and the session carries on.
    store
        .append(
            &id,
            &Message::assistant("I will try a different command"),
            at(4),
        )
        .unwrap();
    assert_eq!(store.message_count(&id).unwrap(), 4);

    // And the export a person would read says what happened rather than hiding it.
    let markdown = store.export(&id, ExportFormat::Markdown).unwrap();
    assert!(markdown.contains("nothing was executed"), "{markdown}");
    assert!(markdown.contains("(failed)"), "{markdown}");
}

#[test]
fn events_and_usage_outlive_the_connection() {
    let (_dir, path) = database();

    let id = {
        let store = Store::open(&path).unwrap();
        let id = store.create(NewSession::new(), at(0)).unwrap().id;
        store
            .append_event(
                &id,
                &AgentEvent::TurnStarted {
                    agent: AgentId::from("agt_1"),
                    turn: 1,
                },
                at(1),
            )
            .unwrap();
        store
            .append_event(
                &id,
                &AgentEvent::TurnFinished {
                    agent: AgentId::from("agt_1"),
                    turn: 1,
                    stop: StopReason::Completed,
                },
                at(2),
            )
            .unwrap();
        store
            .record_usage(
                &id,
                &UsageRecord::new("openrouter", "or-main", "qwen3-32b", 900, 120).costing(0.007),
                at(2),
            )
            .unwrap();
        id
    };

    let reopened = Store::open(&path).unwrap();
    let events = reopened.events(&id).unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], AgentEvent::TurnStarted { turn: 1, .. }));
    assert!(matches!(
        events[1],
        AgentEvent::TurnFinished {
            stop: StopReason::Completed,
            ..
        }
    ));
    assert_eq!(reopened.event_count(&id, "turn_started").unwrap(), 1);

    let totals = reopened.totals(&id).unwrap();
    assert_eq!(totals.input_tokens, 900);
    assert_eq!(totals.provider_calls, 1);

    // A reconnecting client reads the same numbers the daemon would report.
    let summary = &reopened.list(1).unwrap()[0];
    assert_eq!(summary.totals, totals);
}

#[test]
fn two_sessions_in_one_database_stay_separate_across_a_reopen() {
    let (_dir, path) = database();

    let (first, second) = {
        let store = Store::open(&path).unwrap();
        let first = store
            .create(NewSession::new().titled("one"), at(0))
            .unwrap()
            .id;
        let second = store
            .create(NewSession::new().titled("two"), at(1))
            .unwrap()
            .id;
        store
            .append(&first, &Message::user("first session"), at(2))
            .unwrap();
        store
            .append(&second, &Message::user("second session"), at(3))
            .unwrap();
        (first, second)
    };

    let store = Store::open(&path).unwrap();
    assert_eq!(store.count().unwrap(), 2);
    assert_eq!(store.messages(&first).unwrap()[0].text(), "first session");
    assert_eq!(store.messages(&second).unwrap()[0].text(), "second session");

    // Deleting one leaves the other intact, transcript included.
    assert!(store.delete(&first).unwrap());
    assert_eq!(store.count().unwrap(), 1);
    assert!(matches!(
        store.load(&first),
        Err(hx_core::error::HxError::NotFound(_))
    ));
    let survivor: SessionId = store.list(10).unwrap()[0].record.id.clone();
    assert_eq!(survivor, second);
    assert_eq!(store.messages(&survivor).unwrap().len(), 1);
}
