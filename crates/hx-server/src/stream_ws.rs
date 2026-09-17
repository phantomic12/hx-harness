//! The live event stream over a WebSocket: attach to one session and watch its events as they happen.
//!
//! ## Why a WebSocket on top of the SSE stream
//!
//! `POST /v1/chat/stream` pushes one *run's* events, but it is a unidirectional answer: a client
//! that connects after the run has started gets nothing until its own run begins, and it has no way to say
//! "I already saw a run, resume from it". The WebSocket room for a session is the multiplex M2 wants:
//! any number of clients attach to the same session id, each gets *that session's* stored events first and
//! then its live ones, and a reconnecting client names the last event it saw so the server replays exactly
//! the gap. Both clients of one session render the same stream, which is the honest test that the daemon
//! owns the state and every front end is a client of it.
//!
//! ## The wire contract (what a client may rely on)
//!
//! Connecting upgrades `GET /v1/sessions/{id}/ws`. Every JSON frame is a text message of the shape:
//!
//! ```json
//! { "seq": 7, "session": "ses_…", "event": { …AgentEvent… } }
//! ```
//!
//! `seq` is the event's position in the session's stored event log (1-based, per session, assigned by the
//! store). `event` is the same [`hx_core::event::AgentEvent`] the store records, so a live frame
//! and a page refreshed from `/v1/sessions/{id}/events` render identically.
//!
//! The server first replays every stored event of the session (`seq` ascending), then forwards live ones as
//! they are emitted by a run. No terminal event is sent; the stream stays open until the client closes it or
//! the daemon shuts down (the broadcast bus is the only source, so a run ending just leaves the stream
//! open to catch the next one on the same session).
//!
//! **Reconnection.** To resume without duplicates or gaps, the client sends a single JSON text message as its
//! *first* message, within one second of connecting:
//!
//! ```json
//! { "since_seq": 7 }
//! ```
//!
//! The server then replays only `seq > 7` from the store and forwards only live events with `seq > 7`
//! — events 1..7 are not repeated. A client that sends nothing, or a first message that is not a
//! `since_seq` object, is treated as `since_seq: 0` and replayed from the beginning. The client uses
//! the `seq` on each frame to know where it is, and on reconnect sends the last `seq` it saw.
//!
//! Dedup is exact because the seq is assigned by the store and travels on the bus with every event (see
//! [`crate::state::LiveEvent`]): the live half agrees with the store about where an event sits, so the
//! server can drop a live event it already replayed from the store rather than handing the client the same
//! event twice. The ordering guarantee is: subscribe to the bus *before* reading the store. A fresh bus
//! receiver sees only events sent after it was created, so any event appended in the gap is caught by the
//! store read (and never seen on the bus), and any event appended after the store read is on the bus with a
//! higher seq than the replay. No event is both sent twice and none is skipped.
//!
//! ## What is deliberately not here yet
//!
//! The PTY/terminal attach (a shell in the session's workspace) is M2's second half; this module is the
//! events half only. Messages from the client other than the opening `since_seq` are currently ignored — there
//! is no input channel a session's run could consume.
//!
//! ## Why filtering by session is non-negotiable
//!
//! Every session shares one broadcast bus ([`crate::state::AppState::event_bus`]). A subscriber that
//! relayed everything it saw would hand one client the transcripts of every other session on the daemon — a
//! leak invisible in a single-session test and obvious the moment two runs happen. The route filters by
//! session id and by `seq`; the test [`tests/ws_api.rs`](../tests/ws_api.rs) pins both filters.

use crate::state::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::{SinkExt, StreamExt};
use hx_core::ids::SessionId;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// How long the server waits for the client's opening `since_seq` before replaying from the beginning.
///
/// A client that has nothing to resume sends no message at all; waiting for it forever would stall a fresh
/// attach. One second is long enough for a legit reconnecting client to send its one message over a local
/// socket, and short enough that a silent client starts receiving its stream almost immediately.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

/// Upgrade `GET /v1/sessions/{id}/ws` to a session-scoped event stream.
///
/// The session must exist; an attach to a session that never existed is a 404, matching every other session
/// route, rather than a silently-empty stream that looks like a session with no events yet.
pub async fn session_ws(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    // A 404 route should return a 404 *status*, not upgrade to an empty stream; the client could not tell
    // "no events yet" from "no such session". `on_upgrade` can only be called once, so this check must
    // happen first and the handler takes the already-checked session.
    let session = SessionId::from_raw(id);
    if state.store.record(&session).is_err() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such session" })),
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| session_ws_stream(state, session, socket))
}

/// Drive the socket: negotiate resumption, replay history, then forward this session's live events.
async fn session_ws_stream(state: Arc<AppState>, session: SessionId, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();

    // Read the optional `{"since_seq": N}` handshake. We split the socket first so the read cannot block
    // the writer; a client that sends nothing (a fresh attach) is timed out and treated as 0 below.
    let since_seq = tokio::time::timeout(HANDSHAKE_TIMEOUT, receiver.next())
        .await
        .ok()
        .flatten()
        .and_then(|msg| msg.ok())
        .and_then(|msg| match msg {
            Message::Text(text) => parse_since_seq(&text),
            _ => None,
        })
        .unwrap_or(0);

    // Subscribe *before* reading the store: a broadcast receiver only ever sees messages sent after it was
    // created, so an event appended between now and the store read is (a) present in that read and (b)
    // never on this receiver — the store read catches it and the bus cannot duplicate it. See the module
    // doc's ordering argument.
    let mut rx = state.event_bus.subscribe();

    let mut floor = since_seq;
    match state.store.events_from(&session, since_seq) {
        Ok(batch) => {
            for (seq, event) in batch {
                if seq > floor {
                    floor = seq;
                }
                let payload = json!({
                    "seq": seq,
                    "session": session.as_str(),
                    "event": event,
                });
                if sender.send(text(payload.to_string())).await.is_err() {
                    // The client is gone; nothing left to do, and dropping the socket ends the room.
                    return;
                }
            }
        }
        Err(err) => {
            // The session vanished between the 404 check and here, or the store failed. Say so rather
            // than leaving the client on a silent, never-ending stream.
            let _ = sender
                .send(text(json!({ "error": err.to_string() }).to_string()))
                .await;
            return;
        }
    }

    // Live half. Events from other sessions are filtered out; events with `seq <= floor` are ones the
    // replay already handed over (the bus and the store share the seq, so they are provably the same).
    loop {
        match rx.recv().await {
            Ok(crate::state::LiveEvent {
                session: ev_session,
                seq,
                event,
            }) if ev_session == session && seq > floor => {
                floor = seq;
                let payload = json!({
                    "seq": seq,
                    "session": ev_session.as_str(),
                    "event": event,
                });
                if sender.send(text(payload.to_string())).await.is_err() {
                    break;
                }
            }
            // Another session's event, or one the replay already covered: nothing to forward.
            Ok(_) => {}
            // We dropped a burst. The seq floor still holds (new events keep ascending), so the next event
            // we do see is forwarded; the client reconnects for anything it missed.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            // The bus is gone (the daemon is shutting down): end the stream.
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// A [`Message::Text`] from a String.
///
/// axum's [`Message`] is backed by the zero-copy `Utf8Bytes` type (so the websocket codec never
/// re-validates or copies the string); the conversion is fallible in principle but ours is a freshly-built
/// JSON payload, so this is where the `String → Utf8Bytes` coercion is handled once.
fn text(s: String) -> Message {
    Message::Text(s.into())
}

/// `{"since_seq": N}` → `Some(N)`; anything else (a non-object, a missing or non-integer field) is
/// `None`, which the caller treats as "from the beginning".
///
/// Strictness is deliberate: greeting a mis-typed handshake with "replay everything" would blast a
/// reconnecting client with events it already rendered. But a fresh client that sends a pong or nothing must
/// not be punished, so only a *malformed since_seq-looking* message falls back — anything else simply has no
/// resumption request. The conservative reading is to treat an unparseable object as "no resumption".
fn parse_since_seq(text: &str) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let obj = value.as_object()?;
    let n = obj.get("since_seq")?.as_u64()?;
    Some(n)
}
