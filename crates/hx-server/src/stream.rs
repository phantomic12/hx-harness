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
//! ## Why the stream filters by session
//!
//! The bus is process-wide: every session's events travel on it, tagged with the session they
//! belong to. A subscriber that relayed everything it saw would hand one client the transcripts
//! of every other session on the daemon — prompts, tool arguments, output, usage, errors — a
//! leak invisible in a single-session test and obvious the moment two runs overlap. The
//! per-session WebSocket (`GET /v1/sessions/{id}/ws`) already filters; this route must too.
//!
//! ## How the filter learns the session
//!
//! A request that resumes a session names it, so the filter is known before subscribing. A
//! request that starts one does not — the id is minted inside [`chat::run_chat`] — so the run
//! reports it over a oneshot the moment the session is created, before any event is published.
//! Until the id is known, bus events are *buffered*, not forwarded: the report provably precedes
//! this run's first event, so anything buffered is another session's and is dropped once the id
//! arrives (only matching buffered events are flushed). If the run fails before owning a session
//! (an empty prompt, an unknown role) the sender is dropped instead, the buffer is discarded, and
//! the client gets the `error` event with nothing foreign preceding it.
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
use hx_core::ids::SessionId;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// What the stream knows about which session it serves.
///
/// `Pending` is the window between subscribing and learning the id of a newly created session;
/// events seen in it are held, not forwarded. `Absent` means the run failed before owning a
/// session (validation happens before creation), so no bus event can ever be ours.
enum SessionFilter {
    Pending,
    Known(SessionId),
    Absent,
}

/// How many bus events may wait for a new session's id before the oldest is shed.
///
/// A new-session request subscribes before its id exists, so every bus event until the run
/// reports it lands in the pending buffer — and a run stuck behind the `<new>` session lock
/// can wait arbitrarily long while other sessions' bursts pour in. The report precedes this
/// run's first event, so anything shed here is another session's and is dropped, not lost.
const MAX_PENDING_BUFFERED: usize = 256;

/// Run a chat and stream its events, ending with the run's reply.
///
/// The subscription happens *before* the run is spawned, so no event the run emits is missed: the
/// broadcast receiver is created first and the run is started second. Only events tagged with
/// this run's session reach the client; every other session's events are dropped, which is what
/// keeps two concurrent streams from reading each other.
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

    // A resumed session is known up front; a new one is learned from the run (see
    // `run_chat_with_session_notify`). The receiver is kept only while the filter is `Pending`.
    let filter = match request.session.clone().map(SessionId::from_raw) {
        Some(id) => SessionFilter::Known(id),
        None => SessionFilter::Pending,
    };
    let (session_tx, session_rx) = oneshot::channel::<SessionId>();
    let session_rx = matches!(filter, SessionFilter::Pending).then_some(session_rx);
    let notify = session_rx.is_some().then_some(session_tx);

    let (reply_tx, reply_rx) = mpsc::channel::<Result<ChatReply, String>>(1);
    let state_clone = Arc::clone(&state);
    let now = chrono::Utc::now();
    tokio::spawn(async move {
        let result = chat::run_chat_with_session_notify(&state_clone, request, now, notify).await;
        reply_tx
            .send(result.map_err(|err| err.to_string()))
            .await
            .ok();
    });

    // Even if the run errors, the terminal event still arrives; the receiver closing (the run task
    // ended without a reply) is the only way the stream ends without one.
    let stream = stream::unfold(
        (
            rx,
            reply_rx,
            session_rx,
            filter,
            Vec::new(),
            VecDeque::new(),
        ),
        move |(mut rx, mut reply_rx, mut session_rx, mut filter, mut buffered, mut ready)| async move {
            // A reply flush can queue several events at once (buffered own events plus the
            // terminal one); they leave in the order they happened in.
            if let Some(event) = ready.pop_front() {
                return Some((
                    Ok(event),
                    (rx, reply_rx, session_rx, filter, buffered, ready),
                ));
            }
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
                        Ok(live) => {
                            drain_session(&mut session_rx, &mut filter, &mut buffered, &mut ready);
                            if let Some(event) = ready.pop_front() {
                                return Some((Ok(event), (rx, reply_rx, session_rx, filter, buffered, ready)));
                            }
                            match &filter {
                                SessionFilter::Known(id) if live.session == *id => {
                                    let event = render_live(&live);
                                    return Some((Ok(event), (rx, reply_rx, session_rx, filter, buffered, ready)));
                                }
                                // Another session's event: dropped, not forwarded. This is the
                                // filter doing its job — the bus is shared, the stream is not.
                                SessionFilter::Known(_) => {}
                                // The run has not reported its session yet; hold the event until
                                // the id is known, then keep it only if it is ours. Bounded:
                                // a delayed run must not pile foreign bursts without limit.
                                SessionFilter::Pending => push_pending(&mut buffered, live),
                                // The run failed before owning a session, so no bus event can be
                                // ours; the `error` terminal event below is the whole answer.
                                SessionFilter::Absent => {}
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue, // dropped a burst; next event resumes
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,        // bus gone; end the stream
                    },
                    reply = reply_rx.recv() => {
                        match reply {
                            Some(Ok(reply)) => {
                                // The id outranks the channel here: a fast run's reply can be
                                // ready before the notify is polled, and the reply carries the
                                // same session id the notify would.
                                let id = known_or_reply(&mut session_rx, &mut filter, &mut buffered, &mut ready, &reply.session_id);
                                flush_matching(&mut buffered, &mut ready, &id);
                                let event = Event::default().event("done").data(
                                    json!({ "reply": reply }).to_string(),
                                );
                                ready.push_back(event);
                                let event = ready.pop_front().expect("just pushed");
                                return Some((Ok(event), (rx, reply_rx, session_rx, filter, buffered, ready)));
                            }
                            Some(Err(message)) => {
                                // A run that failed *after* creating a session may have events in
                                // the buffer that are genuinely its own; flush those before the
                                // error so the client sees what happened. A run that failed
                                // before owning one leaves only foreign events, which die here.
                                if matches!(filter, SessionFilter::Pending) {
                                    drain_session(&mut session_rx, &mut filter, &mut buffered, &mut ready);
                                }
                                if !matches!(filter, SessionFilter::Known(_)) {
                                    buffered.clear();
                                } else if let SessionFilter::Known(id) = &filter {
                                    flush_matching(&mut buffered, &mut ready, id);
                                }
                                let event = Event::default().event("error").data(
                                    json!({ "error": message }).to_string(),
                                );
                                ready.push_back(event);
                                let event = ready.pop_front().expect("just pushed");
                                return Some((Ok(event), (rx, reply_rx, session_rx, filter, buffered, ready)));
                            }
                            None => break,
                        }
                    }
                    // The run's session report, awaited on its own: without this the id is
                    // learned only when a bus event or the reply arrives to trigger a poll,
                    // so a quiet bus leaves the filter `Pending` — and the buffer growing —
                    // for no reason. Learning it eagerly shrinks the pending window to the
                    // run's creation latency, after which foreign events are dropped by the
                    // `Known` arm without ever touching the buffer.
                    notified = async {
                        match session_rx.as_mut() {
                            Some(rx) => rx.await.ok(),
                            None => std::future::pending().await,
                        }
                    }, if matches!(filter, SessionFilter::Pending) => {
                        match notified {
                            Some(id) => {
                                flush_matching(&mut buffered, &mut ready, &id);
                                filter = SessionFilter::Known(id);
                            }
                            // The sender is gone and no id ever came: the run failed before
                            // owning a session, so nothing buffered can be ours.
                            None => {
                                filter = SessionFilter::Absent;
                                buffered.clear();
                            }
                        }
                        if let Some(event) = ready.pop_front() {
                            return Some((Ok(event), (rx, reply_rx, session_rx, filter, buffered, ready)));
                        }
                    }
                }
            }
            None
        },
    );

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text(": keepalive"),
    )
}

/// Learn the session id without blocking: poll the run's oneshot report once.
///
/// Called after every bus event while the filter is `Pending`, and from the reply branches. The
/// report is sent before the run publishes its first event, so the first event that could be ours
/// always finds the filter already `Known` — the buffer provably holds only other sessions'
/// events, and flushing it keeps (nothing matches) or drops (all of it) correctly either way.
fn drain_session(
    session_rx: &mut Option<oneshot::Receiver<SessionId>>,
    filter: &mut SessionFilter,
    buffered: &mut Vec<LiveEvent>,
    ready: &mut VecDeque<Event>,
) {
    if !matches!(filter, SessionFilter::Pending) {
        return;
    }
    let Some(rx) = session_rx.as_mut() else {
        *filter = SessionFilter::Absent;
        buffered.clear();
        return;
    };
    match rx.try_recv() {
        Ok(id) => {
            flush_matching(buffered, ready, &id);
            *filter = SessionFilter::Known(id);
        }
        // The run ended before creating a session (a validation error): no bus event can be
        // ours, so the buffer — whatever strangers it holds — is discarded, not forwarded.
        Err(oneshot::error::TryRecvError::Closed) => {
            *filter = SessionFilter::Absent;
            buffered.clear();
        }
        Err(oneshot::error::TryRecvError::Empty) => {}
    }
}

/// The session id for the reply flush: the filter's, or the reply's when the notify has not been
/// polled yet (a fast run's reply and notify are sent in order but on different channels, so
/// either may be observed first).
fn known_or_reply(
    session_rx: &mut Option<oneshot::Receiver<SessionId>>,
    filter: &mut SessionFilter,
    buffered: &mut Vec<LiveEvent>,
    ready: &mut VecDeque<Event>,
    reply_session: &str,
) -> SessionId {
    drain_session(session_rx, filter, buffered, ready);
    match filter {
        SessionFilter::Known(id) => id.clone(),
        _ => SessionId::from_raw(reply_session),
    }
}

/// Move the buffered events that belong to `id` onto the ready queue, in arrival order, and drop
/// the rest. The rest are other sessions' events that arrived while the filter was `Pending` —
/// dropping them is the filter, not data loss.
fn flush_matching(buffered: &mut Vec<LiveEvent>, ready: &mut VecDeque<Event>, id: &SessionId) {
    for live in buffered.drain(..).filter(|live| live.session == *id) {
        ready.push_back(render_live(&live));
    }
}

/// Hold one bus event while the filter is `Pending`, keeping the buffer bounded.
///
/// A run delayed before it owns a session (behind the `<new>` session lock, on a slow
/// store) can watch an unbounded number of other sessions' events go by; without the cap
/// each one is retained until the id arrives only to be dropped by [`flush_matching`].
/// Shedding the oldest is safe for the same reason the flush is: the run's report precedes
/// its first event, so nothing shed here is ever this run's own.
fn push_pending(buffered: &mut Vec<LiveEvent>, live: LiveEvent) {
    if buffered.len() >= MAX_PENDING_BUFFERED {
        buffered.remove(0);
    }
    buffered.push(live);
}

/// One bus event as an SSE `data:` event, tagged with its session — the same [`LiveEvent`] the
/// bus carries — so a client following more than one run can tell them apart.
fn render_live(live: &LiveEvent) -> Event {
    Event::default().data(
        json!({
            "session": live.session.as_str(),
            "event": live.event,
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::event::AgentEvent;
    use hx_core::ids::AgentId;

    fn foreign(seq: u64) -> LiveEvent {
        LiveEvent {
            session: SessionId::from_raw("ses_pendingflood"),
            seq,
            event: AgentEvent::TurnStarted {
                agent: AgentId::from_raw("hxd:foreign"),
                turn: 1,
            },
        }
    }

    #[test]
    fn the_pending_buffer_sheds_the_oldest_first() {
        let mut buffered = Vec::new();
        for seq in 0..(MAX_PENDING_BUFFERED as u64 * 2) {
            push_pending(&mut buffered, foreign(seq));
        }
        assert_eq!(buffered.len(), MAX_PENDING_BUFFERED);
        assert_eq!(buffered.first().unwrap().seq, MAX_PENDING_BUFFERED as u64);
        assert_eq!(
            buffered.last().unwrap().seq,
            MAX_PENDING_BUFFERED as u64 * 2 - 1
        );
    }
}
