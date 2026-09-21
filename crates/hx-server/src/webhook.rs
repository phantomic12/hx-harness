//! The generic webhook half of `hx-gateway` connectors, wired into the HTTP surface.
//!
//! A webhook connector is **push**-driven: a remote chat platform `POST`s inbound events to
//! `POST /v1/connectors/{id}/webhook`, and this module is the route that receives them. The
//! [`WebhookConnector`] in `hx-gateway` is the other half — it holds the receiver and feeds the
//! harness. This module holds the sender end, keyed by connector id, plus the connector's verification
//! token, so a `POST` can be authenticated and pushed.
//!
//! ## Fail closed
//!
//! Every failure mode is a refusal with a loud status, never a silent success:
//!
//! - **Unknown connector id** → `404`. There is no route for a connector that is not configured, and there
//!   is nowhere to push its events.
//! - **Missing or wrong bearer token** → `401`. The token is compared in constant time
//!   ([`hx_core::api_auth::ApiToken::matches`]), and the response does not say *which* of "no token"
//!   and "wrong token" it was.
//! - **Malformed body** → `400`. A body that does not name a chat and text is not an event.
//!
//! ## Untrusted input
//!
//! Everything this route parses comes from a remote platform, authenticated only by a bearer token. The
//! text is turned into an [`hx_gateway::Inbound`] and pushed to the connector as **data** — nothing
//! here interprets it as an instruction. That property is the whole reason the [`Connector`] trait treats
//! received messages as untrusted input.

use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hx_core::api_auth::ApiToken;
use hx_core::ids::ConnectorId;
use hx_gateway::webhook::WebhookEnvelope;
use hx_gateway::Inbound;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// One registered webhook connector's push endpoints.
#[derive(Clone)]
pub struct WebhookEntry {
    pub sender: UnboundedSender<Inbound>,
    /// The token a `POST` to this connector must present. **Never stored as a plain value that
    /// reaches a `Debug` render or a log line** — [`ApiToken`]'s `Debug` is redacted.
    pub token: ApiToken,
}

/// The registry of webhook connectors, held by [`AppState`].
///
/// Keyed by [`ConnectorId`]. A webhook connector is created from its config and the sender is kept here so
/// the route can push into the same channel the `hx-gateway::WebhookConnector` is reading from.
#[derive(Default)]
pub struct WebhookRegistry {
    pub connectors: HashMap<String, WebhookEntry>,
}

impl WebhookRegistry {
    /// Register a connector's push endpoint, handing back the receiver the `hx-gateway` connector is
    /// built from.
    pub fn register(&mut self, id: &ConnectorId, token: ApiToken) -> (UnboundedSender<Inbound>, UnboundedReceiver<Inbound>) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        self.connectors.insert(
            id.to_string(),
            WebhookEntry {
                sender,
                token,
            },
        );
        (self.connectors[&id.to_string()].sender.clone(), receiver)
    }

    fn lookup(&self, id: &str) -> Option<&WebhookEntry> {
        self.connectors.get(id)
    }
}

/// The bearer token a request presents, or `None`.
fn bearer_presented(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// The 401 a bad or missing token gets.
///
/// Identical for a missing token and a wrong one, and for an unknown connector — the response must not be an
/// oracle for "was my guess close". It also must not distinguish "no token" from "wrong token", so a
/// scanner cannot learn whether a token is configured.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(serde_json::json!({ "error": "authentication required" })),
    )
        .into_response()
}

/// `POST /v1/connectors/{id}/webhook` — an inbound event from a remote platform.
///
/// The route authenticates the request against the connector's own token, parses the envelope, and pushes
/// the resulting [`Inbound`] into the connector's channel. The `hx-gateway::WebhookConnector::receive`
/// is what the harness reads from that channel.
pub async fn webhook_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let Some(token) = state.webhooks.lookup(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no such connector" })),
        )
            .into_response();
    };

    let Some(presented) = bearer_presented(&headers) else {
        return unauthorized();
    };
    if !token.token.matches(presented) {
        return unauthorized();
    }

    let envelope: WebhookEnvelope = match serde_json::from_slice(&body) {
        Ok(envelope) => envelope,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("malformed webhook body: {err}") })),
            )
                .into_response()
        }
    };

    let inbound = hx_gateway::webhook::parse(envelope, &ConnectorId::from(id.clone()));
    // The sender was cloned on registration and the receiver lives on the `hx-gateway` connector, so a
    // send can only fail if the connector was dropped — which is not a condition a caller can fix by retrying,
    // so it is reported as a conflict rather than a success.
    if token.sender.send(inbound).is_err() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "the webhook connector is not listening" })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "accepted": true })),
    )
        .into_response()
}

/// Build the webhook route onto a router.
pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new().route(
        "/v1/connectors/{id}/webhook",
        axum::routing::post(webhook_handler),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_connector_id_is_not_found() {
        let mut registry = WebhookRegistry::default();
        registry.register(&ConnectorId::from("main-web"), ApiToken::new("secret"));
        assert!(registry.lookup("main-web").is_some());
        assert!(registry.lookup("other").is_none());
    }

    #[test]
    fn registration_stores_the_sender_and_token_together() {
        let mut registry = WebhookRegistry::default();
        registry.register(&ConnectorId::from("main-web"), ApiToken::new("secret"));
        let entry = registry.lookup("main-web").expect("just registered");
        assert!(entry.token.matches("secret"));
        assert!(!entry.token.matches("wrong"));
    }

    #[test]
    fn webhook_route_predicate_matches_only_the_webhook_shape() {
        assert!(crate::auth::is_webhook_route("/v1/connectors/main-web/webhook"));
        assert!(!crate::auth::is_webhook_route("/v1/connectors/main-web"));
        assert!(!crate::auth::is_webhook_route("/v1/status"));
        assert!(!crate::auth::is_webhook_route("/v1/connectors//webhook"));
    }
}
