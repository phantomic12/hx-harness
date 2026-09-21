//! The consumption half of the generic webhook connectors: one driver loop per connector.
//!
//! [`AppState::build`](crate::state::AppState::build) retains each `kind: webhook` connector's
//! [`WebhookConnector`](hx_gateway::webhook::WebhookConnector) driver so the ingress channel stays
//! open — but a retained driver nobody reads is a queue that fills to capacity and then `429`s
//! forever (#73). This module is the read side: for every retained driver it spawns a task that
//! loops on [`Connector::receive`](hx_gateway::Connector::receive) and routes each [`Inbound`]
//! into the harness:
//!
//! - [`Inbound::ApprovalAnswer`] → [`ApprovalBridge::route`](hx_gateway::ApprovalBridge::route),
//!   which matches the tap to the waiting question, judges it against the channel ceiling and
//!   applies it to the shared [`ApprovalQueue`](hx_agent::ApprovalQueue). The ceiling is `Mutate`
//!   — a chat bridge is a weaker signal than a terminal, so it may never authorise a `Destructive`
//!   action — and a `NotAnAnswer` here is unreachable (that variant is for `Message`, handled
//!   below), so it is only logged.
//! - [`Inbound::Message`] → a harness session keyed by the conversation: the bridge finds or
//!   creates one session per [`Conversation::canonical`](hx_gateway::Conversation::canonical),
//!   appends the text as a user message, records it as an event and publishes it on the live bus.
//!   This is the floor, not the ceiling: the message is never dropped, and a client watching the
//!   session (SSE, WebSocket, or a late store read) sees it. Driving a full agent run off it is
//!   future work, named so the omission is a decision.
//!
//! ## Shutdown
//!
//! The task holds a [`Weak`] to the state and only strong clones of what it routes into. Each
//! iteration upgrades; a failed upgrade stops the loop. And while parked in `receive` the task
//! holds no `AppState` at all, so dropping the state drops the registry's senders, the channel
//! closes, `receive` returns `None`, and the loop exits. No join handles, no cycle: the task can
//! never keep the state alive, and the state never has to know the task exists.
//!
//! ## Errors
//!
//! `receive` on a webhook driver only errors if the connector itself fails; a failed poll is
//! logged and the loop continues. `None` means the channel closed — nobody can push any more —
//! so the loop stops rather than spinning.

use crate::state::AppState;
use hx_core::approval::RiskClass;
use hx_core::event::AgentEvent;
use hx_core::ids::{AgentId, ConnectorId};
use hx_gateway::Connector as _;
use hx_gateway::{AnswerOutcome, AnsweringChannel, ApprovalBridge, Inbound};
use std::sync::{Arc, Weak};

/// The strongest risk a webhook channel may authorise. A phone tap is a weaker signal than a
/// terminal keypress, so a chat bridge gets `Mutate` and never `Destructive` — the same ceiling
/// [`hx_gateway::answer::AnswerAuthority`] documents for a chat bridge, enforced again by the
/// queue at the moment the answer arrives.
pub const WEBHOOK_CHANNEL_CEILING: RiskClass = RiskClass::Mutate;

/// The agent id inbound webhook traffic is attributed to in the event trail. Webhook text arrives
/// from a remote platform, not from a model turn, so it must not borrow a real agent's id — a
/// reader of the trail can then tell platform input from generated output.
fn webhook_agent() -> AgentId {
    AgentId::from_raw("webhook")
}

/// Start one driver loop per retained webhook connector. Called once from
/// [`AppState::from_parts`](crate::state::AppState::from_parts), so both the daemon (`build`)
/// and any test assembling the full state get the consumption side — a configured webhook that
/// is never read is the #73 outage, and a constructor that can build one is a constructor that
/// can rebuild it.
///
/// Spawns only when a Tokio runtime is running: `from_parts` is also called from sync contexts
/// where `tokio::spawn` would panic, and in those there is no daemon to consume for anyway.
pub fn spawn_webhook_bridges(state: &Arc<AppState>) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    for id in state.webhooks.driver_ids() {
        let Some(driver) = state.webhooks.driver(&id) else {
            continue;
        };
        let connector_id = ConnectorId::from(id.clone());
        let bridge = ApprovalBridge::new(
            Arc::clone(&state.approvals),
            vec![AnsweringChannel::new(
                driver.clone() as Arc<dyn hx_gateway::Connector>,
                WEBHOOK_CHANNEL_CEILING,
            )],
        );
        // The key `receive` takes is ignored by the webhook driver (it yields what the route
        // pushed; authentication happened at `POST` time), so this is a placeholder, never a
        // credential.
        let key = hx_secrets::Secret::new("");
        let weak: Weak<AppState> = Arc::downgrade(state);
        tokio::spawn(async move {
            loop {
                // Resolve live handles without keeping the state alive across `receive`: the
                // upgraded `Arc` dies at the end of this statement, so a task parked in `recv`
                // holds the store, the queue and the bus — but never the state.
                let live = weak.upgrade().map(|state| {
                    (
                        Arc::clone(&state.store),
                        state.event_bus.clone(),
                        Arc::clone(&state),
                    )
                });
                let Some((store, event_bus, state)) = live else {
                    tracing::debug!(
                        connector = %connector_id,
                        "the webhook bridge is stopping: the daemon state is gone"
                    );
                    break;
                };
                match driver.receive(&key).await {
                    Ok(Some(inbound)) => {
                        route_inbound(&state, &store, &event_bus, &bridge, &connector_id, inbound)
                            .await;
                    }
                    Ok(None) => {
                        tracing::info!(
                            connector = %connector_id,
                            "the webhook bridge is stopping: the ingress channel closed"
                        );
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            connector = %connector_id,
                            error = %err,
                            "the webhook bridge failed to receive; continuing"
                        );
                    }
                }
            }
        });
    }
}

/// Route one consumed inbound event into the harness. Synchronous queue work (`route`) and
/// short store appends only — nothing here awaits a model, so one slow run cannot stall the
/// loop behind it.
async fn route_inbound(
    state: &Arc<AppState>,
    store: &Arc<hx_store::Store>,
    event_bus: &tokio::sync::broadcast::Sender<crate::state::LiveEvent>,
    bridge: &Arc<ApprovalBridge>,
    connector_id: &ConnectorId,
    inbound: Inbound,
) {
    match inbound {
        Inbound::ApprovalAnswer { .. } => {
            let outcome = bridge.route(connector_id, inbound);
            match outcome {
                AnswerOutcome::Answered {
                    approval_id, by, ..
                } => {
                    tracing::info!(
                        connector = %connector_id,
                        approval = %approval_id,
                        by = %by,
                        "a webhook approval answer resumed its run"
                    );
                }
                AnswerOutcome::Refused {
                    approval_id,
                    reason,
                } => {
                    tracing::warn!(
                        connector = %connector_id,
                        approval = %approval_id,
                        reason = %reason,
                        "a webhook approval answer was refused; the run keeps waiting"
                    );
                }
                AnswerOutcome::NotAnAnswer => {
                    tracing::warn!(
                        connector = %connector_id,
                        "a webhook approval event routed as not-an-answer; this is unreachable"
                    );
                }
            }
        }
        Inbound::Message { conversation, text } => {
            route_message(state, store, event_bus, connector_id, &conversation, &text).await;
        }
    }
}

/// Record an inbound chat message in the harness session for its conversation, creating that
/// session on first contact. The session, the transcript row, the event and the live broadcast
/// are the four places a message must land so no surface — store reader, SSE subscriber,
/// WebSocket room — can miss it.
async fn route_message(
    state: &Arc<AppState>,
    store: &Arc<hx_store::Store>,
    event_bus: &tokio::sync::broadcast::Sender<crate::state::LiveEvent>,
    connector_id: &ConnectorId,
    conversation: &hx_gateway::Conversation,
    text: &str,
) {
    let scope = conversation.canonical();
    let session = {
        let mut sessions = state
            .webhook_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(session) = sessions.get(&scope) {
            session.clone()
        } else {
            let now = chrono::Utc::now();
            let record = match store.create(
                hx_store::NewSession::new().titled(format!("webhook {scope}")),
                now,
            ) {
                Ok(record) => record,
                Err(err) => {
                    tracing::warn!(
                        connector = %connector_id,
                        conversation = %scope,
                        error = %err,
                        "a webhook message arrived but its session could not be created; dropping it"
                    );
                    return;
                }
            };
            // The start event goes down with the session row, so a session with no events is a
            // session that was never bridged — not one whose first message was lost.
            if let Err(err) = store.append_event(
                &record.id,
                &AgentEvent::SessionStarted {
                    session: record.id.clone(),
                    at: now,
                },
                now,
            ) {
                tracing::warn!(
                    connector = %connector_id,
                    conversation = %scope,
                    error = %err,
                    "could not record the bridged session's start event"
                );
            }
            sessions.insert(scope.clone(), record.id.clone());
            record.id
        }
    };

    let now = chrono::Utc::now();
    if let Err(err) = store.append(&session, &hx_core::message::Message::user(text), now) {
        tracing::warn!(
            connector = %connector_id,
            conversation = %scope,
            error = %err,
            "a webhook message arrived but was not recorded; dropping it"
        );
        return;
    }
    let event = AgentEvent::TextDelta {
        agent: webhook_agent(),
        text: text.to_string(),
    };
    match store.append_event(&session, &event, now) {
        Ok(seq) => {
            // No subscribers is fine — a late reader gets the same event from the store.
            let _ = event_bus.send(crate::state::LiveEvent {
                session: session.clone(),
                seq,
                event,
            });
        }
        Err(err) => {
            tracing::warn!(
                connector = %connector_id,
                conversation = %scope,
                error = %err,
                "a webhook message was stored but its event was not"
            );
        }
    }
    tracing::debug!(
        connector = %connector_id,
        conversation = %scope,
        session = %session.as_str(),
        "a webhook message reached its harness session"
    );
}
