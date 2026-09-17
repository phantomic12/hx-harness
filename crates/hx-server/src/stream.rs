//! The live event stream: a chat run pushed over SSE as it happens.
//!
//! ## Why SSE and not a second poll
//!
//! Events are already written to the store as a run happens, and `GET /v1/sessions/{id}/events`
//! already reads them back — but reading them back *while* the run runs is polling, which is the
//! weakest form of live. This endpoint subscribes to the daemon's [`crate::LiveEvent`] broadcast
//! bus and pushes each event the moment the loop emits it, ending with the [`crate::ChatReply`].
//! The store stays the source for a client that attaches late; the bus is the source for one that
//! was there. They carry the same [`hx_core::event::AgentEvent`], so a live surface and a
//! late reader render the same thing.
//!
//! ## What is deliberately not supported yet
//!
//! The terminal framing is a simple `data:`-line event with the reply's JSON, and the reply is
//! the last event — there is no retry/keepalive heartbeat and no event-type multiplexing beyond
//! `data`. A proxy sitting between a client and a long-lived SSE stream (the standard reason those
//! exist) is out of scope here; the per-request deadline in `run_chat` is what keeps a dead
//! run from holding the stream open forever.

use crate::state::AppState;
use crate::{chat, ChatReply, LiveEvent};
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use futures::stream::{self, Stream};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Run a chat and stream its events, ending with the run's reply.
///
/// The subscription happens *before* the run is spawned, so no event the run emits is missed: the
/// broadcast receiver is created first and the run is started second. Events are relayed tagged with
/// their session — the same [`LiveEvent`] the bus carries — so a client following more than one run
/// can tell them apart.
///
/// The HTTP status is 200 once the first event is written. A validation error from `run_chat` (an
/// empty prompt, an unknown role) therefore arrives as an `error` event rather than a 4xx — after
/// the mode switch there is no status to change. `/v1/chat` still returns the 4xx for a client
/// that wants it.
pub async fn chat_stream(
    State(state): State<Arc<AppState>>,
    Json(request): Json<chat::ChatRequest>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.event_bus.subscribe();

    let (reply_tx, reply_rx) = mpsc::channel::<Result<ChatReply, String>>(1);
    let state_clone = Arc::clone(&state);
    let now = chrono::Utc::now();
    tokio::spawn(async move {
        let result = chat::run_chat(&state_clone, request, now).await;
        reply_tx
            .send(result.map_err(|err| err.to_string()))
            .await
            .ok();
    });

    // Even if the run errors, the terminal event still arrives; the receiver closing (the run task
    // ended without a reply) is the only way the stream ends without one.
    let stream = stream::unfold((rx, reply_rx), move |(mut rx, mut reply_rx)| async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            // `biased` polls in the order written, so a *ready* bus event is always taken before
            // the reply branch. Without it `select!` picks at random among ready branches, and
            // when a run finishes its last events and the reply become ready together — so a
            // fast run would emit a bus event as the terminal one and end the stream without
            // ever sending `done`, losing the reply the client came for. Events that belong to
            // the run are delivered before the reply, which is also the order they happened in.
            tokio::select! {
                biased;
                received = rx.recv() => match received {
                    Ok(LiveEvent { session, event }) => {
                        let payload = json!({
                            "session": session.as_str(),
                            "event": event,
                        });
                        return Some((Ok(Event::default().data(payload.to_string())), (rx, reply_rx)));
                    }
                    Err(RecvError::Lagged(_)) => continue, // dropped a burst; next event resumes
                    Err(RecvError::Closed) => break,        // bus gone; end the stream
                },
                reply = reply_rx.recv() => {
                    match reply {
                        Some(Ok(reply)) => {
                            let payload = json!({ "reply": reply });
                            let event = Event::default().event("done").data(payload.to_string());
                            return Some((Ok(event), (rx, reply_rx)));
                        }
                        Some(Err(message)) => {
                            let payload = json!({ "error": message });
                            let event = Event::default().event("error").data(payload.to_string());
                            return Some((Ok(event), (rx, reply_rx)));
                        }
                        None => break,
                    }
                }
            }
        }
        None
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text(": keepalive"),
    )
}
