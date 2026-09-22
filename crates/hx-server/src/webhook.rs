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
//! - **Full ingress queue** → `429` with a `Retry-After` hint. The queue is bounded (see
//!   [`DEFAULT_WEBHOOK_QUEUE_CAPACITY`]), so a burst the harness has not consumed yet is a signal to
//!   the platform to retry, not memory the daemon allocates without limit. The body says so, with
//!   `retryable: true`, because a platform that treats every non-`200` as a dead letter would drop
//!   events the daemon simply had not read yet.
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
use hx_gateway::webhook::{WebhookConnector, WebhookEnvelope};
use hx_gateway::Inbound;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};

/// WHY 256: large enough that a platform burst or a slow run does not flap into `429`s, small
/// enough that a connector nobody drains holds kilobytes rather than gigabytes. Per-connector
/// `queue_capacity` in the config overrides this when a channel's burst profile is known.
pub const DEFAULT_WEBHOOK_QUEUE_CAPACITY: usize = 256;

/// One registered webhook connector's push endpoints.
#[derive(Clone)]
pub struct WebhookEntry {
    pub sender: Sender<Inbound>,
    /// WHY stored beside the sender: the route reports how full the queue is (see
    /// [`WebhookRegistry::queue_depth`]), and a depth without its bound is a number without meaning.
    pub capacity: usize,
    /// The token a `POST` to this connector must present. **Never stored as a plain value that
    /// reaches a `Debug` render or a log line** — [`ApiToken`]'s `Debug` is redacted.
    pub token: ApiToken,
}

/// One connector's queue, as reported by [`WebhookRegistry::queue_depths`] and `/v1/status`.
///
/// WHY a struct rather than a tuple: a depth without its bound cannot tell "busy" from "stuck",
/// and the status surface renders this as JSON where named fields are the contract.
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct WebhookQueueDepth {
    pub id: String,
    pub depth: usize,
    pub capacity: usize,
}

/// The registry of webhook connectors, held by [`AppState`].
///
/// Keyed by [`ConnectorId`]. A webhook connector is created from its config and the sender is kept here so
/// the route can push into the same channel the `hx-gateway::WebhookConnector` is reading from.
///
/// WHY the drivers live here too: `AppState::build` registers each connector and must keep the receiver
/// end alive — a receiver dropped at the end of `build` closes the channel, and every `POST` after that
/// is a `409` against a connector that is configured and looks healthy. Retaining the built
/// [`WebhookConnector`] (rather than the bare receiver) keeps the channel open *and* gives the runtime a
/// ready driver to read from, with no second lookup.
#[derive(Default)]
pub struct WebhookRegistry {
    pub connectors: HashMap<String, WebhookEntry>,
    drivers: Mutex<HashMap<String, Arc<WebhookConnector>>>,
}

impl WebhookRegistry {
    /// Register a connector's push endpoint, handing back the receiver the `hx-gateway` connector is
    /// built from, with the default queue bound.
    pub fn register(
        &mut self,
        id: &ConnectorId,
        token: ApiToken,
    ) -> (Sender<Inbound>, Receiver<Inbound>) {
        self.register_with_capacity(id, token, DEFAULT_WEBHOOK_QUEUE_CAPACITY)
    }

    /// Register with an explicit queue bound. A bound below 1 clamps to 1 rather than building a
    /// channel that can never take a push — a rendezvous channel would `429` every request that does
    /// not arrive at the exact moment the harness is reading, which is a refusal shaped like a limit.
    pub fn register_with_capacity(
        &mut self,
        id: &ConnectorId,
        token: ApiToken,
        capacity: usize,
    ) -> (Sender<Inbound>, Receiver<Inbound>) {
        let capacity = capacity.max(1);
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        self.connectors.insert(
            id.to_string(),
            WebhookEntry {
                sender,
                capacity,
                token,
            },
        );
        (self.connectors[&id.to_string()].sender.clone(), receiver)
    }

    /// Retain the driver built from the receiver [`register`](Self::register) handed back, so the
    /// channel stays open for the daemon's lifetime. Called once per connector by `AppState::build`.
    pub fn retain_driver(&self, id: &str, connector: WebhookConnector) {
        match self.drivers.lock() {
            Ok(mut drivers) => {
                drivers.insert(id.to_string(), Arc::new(connector));
            }
            Err(poisoned) => {
                // A panic while holding the map must not wedge every later registration into a
                // refusal: the state behind the lock is driver handles, and losing one insert's
                // atomicity is better than losing the whole webhook surface.
                poisoned
                    .into_inner()
                    .insert(id.to_string(), Arc::new(connector));
            }
        }
    }

    /// The retained driver for `id`, if one was built. This is what proves a configured webhook is
    /// *consumed*, not just routable: the harness reads through [`hx_gateway::Connector::receive`].
    pub fn driver(&self, id: &str) -> Option<Arc<WebhookConnector>> {
        self.drivers.lock().ok()?.get(id).cloned()
    }

    /// Every retained driver id, sorted so bridge startup is deterministic.
    ///
    /// The seam [`crate::webhook_bridge::spawn_webhook_bridges`] starts one consumption loop from:
    /// one task per id here, each reading through its driver.
    pub fn driver_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = match self.drivers.lock() {
            Ok(drivers) => drivers.keys().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().keys().cloned().collect(),
        };
        ids.sort();
        ids
    }

    fn lookup(&self, id: &str) -> Option<&WebhookEntry> {
        self.connectors.get(id)
    }

    /// How many un-consumed events are waiting for `id`. `None` for an unknown id — the route
    /// answers `404` before depth is ever a question.
    pub fn queue_depth(&self, id: &str) -> Option<usize> {
        let entry = self.connectors.get(id)?;
        Some(entry.capacity.saturating_sub(entry.sender.capacity()))
    }

    /// Every connector's depth, sorted by id so `/v1/status` renders deterministically.
    pub fn queue_depths(&self) -> Vec<WebhookQueueDepth> {
        let mut depths: Vec<WebhookQueueDepth> = self
            .connectors
            .iter()
            .map(|(id, entry)| WebhookQueueDepth {
                id: id.clone(),
                depth: entry.capacity.saturating_sub(entry.sender.capacity()),
                capacity: entry.capacity,
            })
            .collect();
        depths.sort_by(|a, b| a.id.cmp(&b.id));
        depths
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
    // The push never waits: `send().await` on a bounded channel would park an HTTP worker behind a
    // harness that reads slowly, and one slow connector would then stall the whole route. `try_send`
    // turns each outcome into the status the platform should act on instead.
    if let Err(refused) = token.sender.try_send(inbound) {
        return ingress_refusal(refused);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "accepted": true })),
    )
        .into_response()
}

/// The refusal a failed ingress push becomes.
///
/// A pure function of the push outcome (rather than an inline match) so the backpressure contract
/// stays pinned by unit tests that do not depend on bridge timing: with the [`crate::webhook_bridge`]
/// loop draining the queue, a full queue at HTTP level is a race, but `Full → 429` must hold
/// whenever it happens.
fn ingress_refusal(err: TrySendError<Inbound>) -> Response {
    match err {
        // The sender was cloned on registration and a retained driver holds the receiver, so a
        // closed channel means the connector was dropped — which is not a condition a caller can
        // fix by retrying, so it is reported as a conflict rather than a success.
        TrySendError::Closed(_) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "the webhook connector is not listening" })),
        )
            .into_response(),
        // The queue is bounded, so a burst the harness has not consumed yet is backpressure, not
        // loss: `429` with `Retry-After` tells the platform to retry, and `retryable: true` tells a
        // client that treats every non-`200` as a dead letter to hold the event instead. The event
        // itself was parsed and then refused — nothing was buffered, so a full queue cannot grow
        // memory no matter how often the platform retries into it.
        TrySendError::Full(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            Json(
                serde_json::json!({ "error": "the webhook queue is full; retry this event", "retryable": true }),
            ),
        )
            .into_response(),
    }
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
        assert!(crate::auth::is_webhook_route(
            "/v1/connectors/main-web/webhook"
        ));
        assert!(!crate::auth::is_webhook_route("/v1/connectors/main-web"));
        assert!(!crate::auth::is_webhook_route("/v1/status"));
        assert!(!crate::auth::is_webhook_route("/v1/connectors//webhook"));
    }

    fn test_push(id: &ConnectorId, text: &str) -> hx_gateway::Inbound {
        hx_gateway::webhook::parse(
            WebhookEnvelope {
                chat: "777".into(),
                thread: None,
                text: text.into(),
            },
            id,
        )
    }

    #[test]
    fn a_full_ingress_queue_refuses_the_next_push_without_buffering_it() {
        // WHY this is the bound that matters: the queue caps the memory a remote platform can make
        // the daemon hold. Filling it and pushing once more must refuse — not grow — or the bound
        // is decoration and #55 is back.
        let mut registry = WebhookRegistry::default();
        let id = ConnectorId::from("main-web");
        let (sender, _rx) = registry.register_with_capacity(&id, ApiToken::new("secret"), 2);
        sender
            .try_send(test_push(&id, "one"))
            .expect("the first push fits");
        sender
            .try_send(test_push(&id, "two"))
            .expect("the second push fits");
        let refused = sender.try_send(test_push(&id, "three"));
        assert!(
            matches!(refused, Err(TrySendError::Full(_))),
            "a push past capacity refuses instead of buffering: {refused:?}"
        );
        assert_eq!(registry.queue_depth("main-web"), Some(2));
    }

    #[test]
    fn queue_depth_tracks_pushes_beside_their_bound() {
        // WHY beside the bound: a depth of 200 means "busy" against a capacity of 256 and "stuck"
        // against a capacity of 200, and the status surface cannot tell them apart from depth alone.
        let mut registry = WebhookRegistry::default();
        let id = ConnectorId::from("main-web");
        let (sender, _rx) = registry.register_with_capacity(&id, ApiToken::new("secret"), 2);
        assert_eq!(registry.queue_depth("main-web"), Some(0));
        sender
            .try_send(test_push(&id, "hi"))
            .expect("an empty queue takes the push");
        assert_eq!(
            registry.queue_depths(),
            vec![WebhookQueueDepth {
                id: "main-web".into(),
                depth: 1,
                capacity: 2,
            }]
        );
        assert_eq!(registry.queue_depth("unknown"), None);
    }

    #[test]
    fn a_zero_capacity_clamps_to_one_instead_of_a_dead_channel() {
        // WHY clamp rather than reject: a `queue_capacity: 0` typo must not build a rendezvous
        // channel that `429`s every request not arriving at the exact moment the harness reads —
        // that is a refusal shaped like a limit, and it would read as an outage.
        let mut registry = WebhookRegistry::default();
        let id = ConnectorId::from("main-web");
        let (sender, _rx) = registry.register_with_capacity(&id, ApiToken::new("secret"), 0);
        assert_eq!(registry.connectors["main-web"].capacity, 1);
        sender
            .try_send(test_push(&id, "hi"))
            .expect("the clamped slot takes a push");
    }

    #[tokio::test]
    async fn a_retained_driver_keeps_the_channel_open_and_consumes_pushes() {
        // WHY this is the #66 regression: a receiver dropped after registration closes the channel,
        // and every later `POST` is a `409` against a connector that is configured and looks
        // healthy. Retaining the driver is what keeps the channel open.
        use hx_gateway::Connector as _;
        let mut registry = WebhookRegistry::default();
        let id = ConnectorId::from("main-web");
        let (_sender, rx) = registry.register(&id, ApiToken::new("secret"));
        registry.retain_driver(
            "main-web",
            WebhookConnector::new(id.clone(), None, reqwest::Client::new(), rx),
        );
        registry.connectors["main-web"]
            .sender
            .try_send(test_push(&id, "list the repo"))
            .expect("a retained receiver keeps the channel open");
        let driver = registry.driver("main-web").expect("the driver is retained");
        let received = driver
            .receive(&hx_secrets::Secret::new(""))
            .await
            .expect("a message");
        match received {
            Some(hx_gateway::Inbound::Message { text, .. }) => assert_eq!(text, "list the repo"),
            other => panic!("expected the pushed message, got {other:?}"),
        }
    }

    /// Build the whole daemon state from config — not a hand-assembled registry — so the test
    /// proves what `build` retains, with `queue_capacity` baked into the YAML.
    async fn built_state(token_env: &str, queue_capacity: usize) -> Arc<AppState> {
        std::env::set_var(token_env, "test-supersecret");
        let yaml = format!(
            r#"
providers:
  local:
    kind: ollama
    base_url: http://127.0.0.1:9
    models: ["dead-model"]
    credentials:
      - {{ id: local-1, secret: "env:HX_TEST_KEY_NOT_SET" }}

pools:
  interactive: {{ members: ["local/dead-model"] }}

roles:
  builder: interactive

search:
  backends: []

connectors:
  main-web:
    kind: webhook
    token: "env:{token_env}"
    queue_capacity: {queue_capacity}
"#
        );
        let mut config = hx_core::config::Config::from_yaml(&yaml).expect("config parses");
        let dir = tempfile::tempdir().expect("temp dir");
        // The store must not touch the real workspace: `build` opens SQLite under `data_dir`.
        config.daemon.data_dir = dir.path().join("data").display().to_string();
        let state = crate::state::AppState::build(config, None, chrono::Utc::now())
            .await
            .expect("build keeps a configured webhook alive");
        // `dir` must outlive the state: dropping it deletes the store under a live daemon.
        std::mem::forget(dir);
        state
    }

    async fn post(
        state: &Arc<AppState>,
        id: &str,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        use http_body_util::BodyExt as _;
        let mut headers = axum::http::HeaderMap::new();
        if let Some(token) = token {
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().expect("a bearer header"),
            );
        }
        let response = webhook_handler(
            State(Arc::clone(state)),
            Path(id.to_string()),
            headers,
            Bytes::from(serde_json::to_vec(&body).expect("a body")),
        )
        .await;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("a body")
            .to_bytes();
        let json = serde_json::from_slice(&bytes).expect("a JSON refusal");
        (status, headers, json)
    }

    #[tokio::test]
    async fn a_post_reaches_the_bridge_without_a_manual_receive() {
        // WHY `build` and no `driver.receive()`: #66 was `build` registering the sender and
        // dropping the receiver, and #73 is `build` retaining the driver but never reading it —
        // so only `build` can prove the loop is running. A `200` means the push landed; the queue
        // draining to zero and the message appearing in a harness session means the *bridge*
        // consumed it, with nobody calling `receive` in this test.
        let state = built_state("HX_WEBHOOK_TEST_TOKEN_BRIDGE", 16).await;
        let (status, _, body) = post(
            &state,
            "main-web",
            Some("test-supersecret"),
            serde_json::json!({ "chat": "777", "text": "list the repo" }),
        )
        .await;
        assert_eq!(
            (status, body),
            (StatusCode::OK, serde_json::json!({ "accepted": true }))
        );

        // The bridge consumes asynchronously, so poll: the queue must drain and the session the
        // bridge opened for this conversation must hold the posted text.
        let mut bridged = None;
        for _ in 0..200 {
            let drained = state.webhooks.queue_depth("main-web") == Some(0);
            let sessions = state.store.list(100).expect("sessions list");
            let found = sessions.iter().find_map(|summary| {
                state
                    .store
                    .messages(&summary.record.id)
                    .ok()
                    .filter(|messages| messages.iter().any(|m| m.text().contains("list the repo")))
                    .map(|_| summary.record.id.clone())
            });
            if drained && found.is_some() {
                bridged = found;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let session = bridged.expect("the bridge consumed the post into a harness session");

        // The same conversation routes to the same session: a second post lands in the same
        // transcript rather than opening a session per push.
        let (status, _, _) = post(
            &state,
            "main-web",
            Some("test-supersecret"),
            serde_json::json!({ "chat": "777", "text": "and the tests" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let mut same = false;
        for _ in 0..200 {
            let messages = state.store.messages(&session).expect("bridged transcript");
            if messages.iter().any(|m| m.text().contains("and the tests")) {
                same = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(same, "the second post joined the same harness session");

        // And the bridge left an event trail, not just transcript rows: a late reader sees the
        // message as events too.
        assert!(
            !state
                .store
                .events(&session)
                .expect("bridged events")
                .is_empty(),
            "the bridged session recorded events"
        );
    }

    #[tokio::test]
    async fn a_full_ingress_queue_refuses_with_a_retry_hint_and_no_buffering() {
        // WHY through `ingress_refusal` and not HTTP: with the bridge loop draining the queue, a
        // full queue at the route is a race — but `Full → 429` must hold whenever it happens, so
        // the mapping is pinned here, deterministically, for both refusal shapes.
        use http_body_util::BodyExt as _;
        for (err, status) in [
            (
                TrySendError::Full(test_push(&ConnectorId::from("main-web"), "dropped")),
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                TrySendError::Closed(test_push(&ConnectorId::from("main-web"), "dropped")),
                StatusCode::CONFLICT,
            ),
        ] {
            let response = ingress_refusal(err);
            assert_eq!(response.status(), status);
            let retry_after = response.headers().get(header::RETRY_AFTER).cloned();
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("a body")
                .to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
            if status == StatusCode::TOO_MANY_REQUESTS {
                // WHY the three assertions together: `429` (not `200`, not `409`) tells the
                // platform the event was refused but not dead, `Retry-After`/`retryable` tells it
                // *when and how* to retry.
                assert_eq!(
                    retry_after.map(|v| v.to_str().unwrap().to_string()),
                    Some("1".into())
                );
                assert_eq!(json["retryable"], true);
            } else {
                assert!(retry_after.is_none());
            }
        }
    }
}
