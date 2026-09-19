//! The terminal's WebSocket: attach a client to a server-side PTY, and let it talk back.
//!
//! ## Why this is a second socket rather than a frame on the event stream
//!
//! The session's event stream ([`crate::stream_ws`]) is a log: ordered, stored, resumable by `seq`,
//! and one-way. A terminal is none of those things. Its output is not an event, it is not stored as
//! one, it has no sequence number to resume from, and it is emphatically bidirectional — keystrokes
//! travel the other way. Folding it in would mean giving the event log a class of entries that are
//! not events, are never replayed, and cannot be ordered against the ones that are.
//!
//! So the terminal has its own socket, and the two share nothing but the session they belong to.
//!
//! ## Attaching is joining, not opening
//!
//! The PTY lives in the daemon and outlives every client ([`crate::terminal`]). Connecting does not
//! start a shell; it joins one. That is what makes M2's claim real rather than cosmetic: a browser
//! and a TUI attach to the same terminal and see the same bytes, and closing either leaves the shell
//! running for the other. A client that connects to an id with no terminal is told so instead of
//! being given a private shell, which would look identical and behave completely differently.
//!
//! ## What a client receives, in order
//!
//! 1. `{"type":"scrollback","data":"<base64>"}` — what the terminal printed before this client
//!    arrived. Sent as its own frame so a client can distinguish history from live output (a
//!    reattaching client may want to clear first; a fresh one usually does not).
//! 2. `{"type":"output","data":"<base64>"}` — live output, as it happens.
//! 3. `{"type":"exited","code":N}` — the shell ended. Sent last, so a client renders "the shell
//!    exited" rather than an output stream that simply stops, which is indistinguishable from a
//!    hung shell or a dropped connection.
//!
//! Base64 because a terminal is byte-oriented: escape sequences and partial UTF-8 sequences split
//! across reads must survive exactly, and a JSON string cannot carry arbitrary bytes.
//!
//! ## What a client sends
//!
//! `{"type":"input","data":"<base64>"}` to type, `{"type":"resize","cols":C,"rows":R}` when its
//! viewport changes. Anything else is ignored rather than fatal: an unknown frame from a newer
//! client should not kill a working terminal.
//!
//! ## The subscribe-before-read ordering
//!
//! The same argument as the event stream, and the same failure if it is reversed: subscribe first,
//! then take the scrollback snapshot. A broadcast receiver never sees messages sent before it
//! existed, so output produced in the gap is in the snapshot; output after the snapshot arrives on
//! the receiver. Subscribing second would drop whatever landed in between — bytes the shell printed
//! and no client ever saw.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::{SinkExt, StreamExt};
use serde_json::json;

use crate::state::AppState;
use crate::terminal::{decode, encode, TerminalInput, TerminalOutput};

/// `GET /v1/terminals/{id}/ws` — attach to a live terminal.
pub async fn terminal_ws(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    // A 404 *status*, before the upgrade, for the same reason as the session stream: `on_upgrade`
    // runs once and after that the response is a 101, so a check inside the stream could only be
    // reported as an error frame on a terminal that looks connected. A client attaching to a
    // terminal that does not exist must learn that, not receive a stream that never speaks.
    if state.terminals.get(&id).is_none() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({
                "error": "no such terminal",
                "hint": "terminals are created with POST /v1/terminals and live until the shell exits",
            })),
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| terminal_ws_stream(state, id, socket))
}

/// Drive one attached client: send it the scrollback, forward live output, and write its input back.
async fn terminal_ws_stream(state: Arc<AppState>, id: String, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();

    // Re-checked here rather than trusting the handler's check: the terminal can exit between the
    // 404 check and this task being scheduled, and an `expect` on a vanished terminal would take
    // the daemon down for a client that merely connected at an unlucky moment.
    let Some(terminal) = state.terminals.get(&id) else {
        let _ = sender
            .send(Message::Text(
                json!({ "type": "exited", "code": null }).to_string().into(),
            ))
            .await;
        return;
    };

    // Subscribe *before* the snapshot. See the module doc: reversed, output produced in the gap is
    // in neither the snapshot nor the receiver, and a terminal that silently drops bytes is worse
    // than one that refuses to attach.
    let mut output = terminal.subscribe();
    let scrollback = terminal.scrollback();
    if !scrollback.is_empty()
        && sender
            .send(Message::Text(
                json!({ "type": "scrollback", "data": encode(&scrollback) })
                    .to_string()
                    .into(),
            ))
            .await
            .is_err()
    {
        return;
    }

    // Resize the shell to this client's viewport only if it asks (a `resize` frame), so two clients
    // on one terminal do not fight: the last one to resize wins, which is the same thing that
    // happens when two windows show one terminal in any terminal multiplexer.
    loop {
        tokio::select! {
            // The shell's output, on its way to this client.
            msg = output.recv() => match msg {
                Ok(frame) => {
                    let payload = match &frame {
                        TerminalOutput::Output { data } => json!({ "type": "output", "data": data }),
                        TerminalOutput::Scrollback { data } => {
                            json!({ "type": "scrollback", "data": data })
                        }
                        TerminalOutput::Exited { code } => json!({ "type": "exited", "code": code }),
                    };
                    let ended = matches!(frame, TerminalOutput::Exited { .. });
                    if sender
                        .send(Message::Text(payload.to_string().into()))
                        .await
                        .is_err()
                    {
                        // The client is gone. The terminal is not: dropping this task only ends
                        // the attachment, which is the whole point of the daemon owning the PTY.
                        return;
                    }
                    if ended {
                        return;
                    }
                }
                // Lagged means this client could not keep up and output was dropped for *it*
                // alone — the terminal and any other client are unaffected. Told rather than
                // silently continuing, because a terminal with a hole in it renders wrong forever
                // after, and a client that knows can re-request the scrollback.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    let _ = sender
                        .send(Message::Text(
                            json!({ "type": "lagged", "missed": missed }).to_string().into(),
                        ))
                        .await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            },
            // The client's input, on its way to the shell.
            msg = receiver.next() => match msg {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<TerminalInput>(&text) {
                        Ok(TerminalInput::Input { data }) => match decode(&data) {
                            Ok(bytes) => {
                                // `write_async`, not `write`: this runs inside a task on the
                                // runtime, and the synchronous version has to drive the session's
                                // future to completion, which deadlocks here. See its doc.
                                if let Err(e) = terminal.write_async(&bytes).await {
                                    // The shell is gone but the reader has not reported it yet.
                                    // Say why, then end: further input cannot be delivered.
                                    let _ = sender
                                        .send(Message::Text(
                                            json!({ "type": "error", "message": e.to_string() })
                                                .to_string()
                                                .into(),
                                        ))
                                        .await;
                                    return;
                                }
                            }
                            Err(e) => {
                                // A malformed frame from one client must not close the terminal
                                // for the others, so this is reported and the loop continues.
                                let _ = sender
                                    .send(Message::Text(
                                        json!({ "type": "error", "message": e.to_string() })
                                            .to_string()
                                            .into(),
                                    ))
                                    .await;
                            }
                        },
                        Ok(TerminalInput::Resize { cols, rows }) => {
                            let _ = terminal.resize_async(cols, rows).await;
                        }
                        // An unrecognised frame is ignored, not fatal: a newer client sending
                        // something this daemon does not know should keep its terminal.
                        Err(_) => {}
                    }
                }
                // A close, a binary frame, or a transport error: detach.
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return,
            },
        }
    }
}
