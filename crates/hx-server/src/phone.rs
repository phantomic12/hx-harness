//! Push a prompt to a phone (or lock screen) over a generic webhook, and answer it.
//!
//! This is the M7 exit criterion's transport-agnostic half ([`_COMMON`][common] / `ROADMAP.md`):
//! when an [`ApprovalRequest`] is created and `config.approval.push_url` is set, [`PhoneApprover`]
//! posts a JSON payload to the webhook (which forwards it to the operator as a notification), then waits —
//! the same way the queue does — for the operator's tap to come back to `POST
//! /v1/approvals/{id}/respond`.
//!
//! [common]: ../../../_COMMON.md
//!
//! ## A one-time token, not a bearer token
//!
//! The payload's `respond_url` carries a `token=…` query parameter. The API's bearer token is a
//! long-lived secret that a phone notification must **never** see — it travels through the push relay and
//! sits on a lock screen. So each approval mints a **one-time** token (a fresh random value, stored only
//! here, keyed by approval id) and the respond route accepts the token **instead of** the bearer header.
//! Answering consumes it, so a replayed or leaked `respond_url` cannot answer twice.
//!
//! ## The token is redacted in logs
//!
//! The token travels inside `respond_url`. Everything this module writes to a log strips the query string
//! from a URL and `Debug` never prints the token value (see [`RespondToken`] and the manual
//! [`PushPayload`] `Debug`). A notification must not double as a log-line credential.
//!
//! ## Ceiling enforcement
//!
//! A lock screen is a weaker signal than a terminal keystroke. [`PHONE_CEILING`] is the strongest a
//! tap may authorise ([`RiskClass::External`]); `Destructive` and `Privileged` stay refused. An
//! `allow` maps to [`ApprovalOption::AllowOnce`] — never a permanent or chat-wide grant, because a lock
//! screen has no "always" button.
//!
//! ## No real push provider in the default test gate
//!
//! [`_COMMON`][common] forbids requiring APNs/FCM in `cargo test`. This path is a generic webhook — a
//! push relay you run, a `notify` endpoint, a script — and the integration tests (`tests/phone_approval.rs`)
//! serve a real mock webhook over a real loopback listener. The POST itself is a thin function
//! ([`post_payload`]) so the unit tests here can pin the wire shape without a socket.

use async_trait::async_trait;
use hx_agent::{ApprovalDecision, Approver};
use hx_core::approval::{ActionRequest, ApprovalOption, ApprovalRequest, RiskClass};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The risk ceiling a phone/lock-screen tap may authorise.
///
/// A lock screen cannot show the full prompt with certainty, so it may never authorise a `Destructive` or
/// `Privileged` action. `External` is the strongest a tap can grant, and an `allow` always means
/// "once".
pub const PHONE_CEILING: RiskClass = RiskClass::External;

/// A one-time secret minted per approval, for the phone's `respond_url`.
///
/// A newtype so a phone token and an API bearer token cannot be confused. Its only `Debug`/`Display` is
/// `<redacted>`, so a stray `{:?}` can never print it.
#[derive(Clone)]
pub struct RespondToken(String);

impl RespondToken {
    pub fn new() -> Self {
        Self(Uuid::new_v4().simple().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RespondToken {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RespondToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RespondToken(<redacted>)")
    }
}

impl std::fmt::Display for RespondToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The JSON body the webhook is POSTed. It lives here so the doc and the wire shape cannot drift.
#[derive(Clone, Serialize)]
pub struct PushPayload {
    /// The approval id. The tap comes back as `POST /v1/approvals/{id}/respond`.
    pub id: String,
    /// The task description the operator approves or denies from the lock screen.
    pub question: String,
    /// The choices the lock screen may offer. Always `["allow", "deny"]`.
    pub choices: Vec<String>,
    /// The URL the notification's tap hits, carrying the one-time `token=`.
    pub respond_url: String,
}

/// The `Debug` is hand-written so the token inside `respond_url` is never printed.
impl std::fmt::Debug for PushPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushPayload")
            .field("id", &self.id)
            .field("question", &self.question)
            .field("choices", &self.choices)
            .field("respond_url", &SanitizedUrl(self.respond_url.as_str()))
            .finish()
    }
}

impl PushPayload {
    /// Build the payload for a request under `respond_base`, minting its one-time token.
    ///
    /// `respond_base` is the daemon's public origin (`https://<daemon>`); the route supplies it so the
    /// daemon is not asked to know its own public name. The token is returned so the queue can hold it for
    /// the respond route to check.
    fn for_request(
        respond_base: &str,
        request: &ApprovalRequest,
        token: &RespondToken,
    ) -> PushPayload {
        let respond_url = format!(
            "{respond_base}/v1/approvals/{}/respond?token={}",
            request.id.as_str(),
            token.as_str()
        );
        PushPayload {
            id: request.id.as_str().to_string(),
            question: request.summary.clone(),
            choices: vec!["allow".to_string(), "deny".to_string()],
            respond_url,
        }
    }
}

/// A wrapper whose `Debug` prints a URL with its query string stripped — the half of a URL that can carry a
/// secret.
struct SanitizedUrl<'a>(&'a str);

impl std::fmt::Debug for SanitizedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl std::fmt::Display for SanitizedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0.split('?').next().unwrap_or(self.0))
    }
}

/// One waiting phone approval.
struct Waiting {
    token: RespondToken,
    risk: RiskClass,
    reply: Option<oneshot::Sender<(ApprovalOption, String)>>,
}

/// What came of an attempt to answer over the respond route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhoneRespondError {
    /// Nothing is waiting under this id (answered already, never pushed, or expired).
    Idle,
    /// The one-time token in the respond_url did not match.
    Token,
    /// The verdict was not a recognised word.
    Verdict,
}

/// The [``Approver``][hx_agent::Approver] that pushes a prompt to a webhook and waits for the tap.
///
/// Fail-closed: if the webhook POST fails (relay down, URL unreachable), the run's wait still expires
/// into a **denial** — a push that did not arrive is never a silent yes.
pub struct PhoneApprover {
    push_url: String,
    /// The daemon's public origin, prefixed into every `respond_url`. Stripped of any query in `Debug`.
    respond_base: String,
    waiting: Mutex<HashMap<String, Waiting>>,
    wait: Duration,
}

impl std::fmt::Debug for PhoneApprover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneApprover")
            .field("push_url", &SanitizedUrl(&self.push_url))
            .field("respond_base", &SanitizedUrl(&self.respond_base))
            .field("waiting", &self.waiting.lock().expect("phone").len())
            .finish()
    }
}

impl PhoneApprover {
    pub fn new(push_url: String, respond_base: String, wait: Duration) -> Arc<Self> {
        Arc::new(Self {
            push_url,
            respond_base,
            waiting: Mutex::new(HashMap::new()),
            wait,
        })
    }

    /// Test-only: seed a waiting approval and return its one-time token, so a route or module test can
    /// drive the respond path without going through a real push. The private fields stay private to the module;
    /// this is the seam tests use instead.
    // Kept without current callers as the respond-path test seam; `dead_code` would otherwise fail
    // the `-D warnings` gate on every build until the first caller lands.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn insert_for_test(
        &self,
        id: &str,
        risk: RiskClass,
        reply: oneshot::Sender<(ApprovalOption, String)>,
    ) -> RespondToken {
        let token = RespondToken::new();
        self.waiting.lock().expect("phone").insert(
            id.to_string(),
            Waiting {
                token: token.clone(),
                risk,
                reply: Some(reply),
            },
        );
        token
    }

    /// Resolve a tap from the respond route.
    ///
    /// Verifies the one-time token against the record, then completes the waiting run. An `allow` resolves
    /// to a one-shot grant — never a permanent or chat-wide one, because a lock screen has no "always"
    /// button — and a `deny` resolves to a denial. The ceiling is enforced in [`Approver::decide`] and
    /// again here via `allowed`: an `allow` above [`PHONE_CEILING`] would fail the `waiting` entry's
    /// own risk check, so nothing can be authorised above the ceiling by a stale or edited tap.
    pub fn respond(
        &self,
        id: &str,
        token: &str,
        verdict: &str,
    ) -> std::result::Result<(), PhoneRespondError> {
        let allowed = match verdict {
            "allow" => true,
            "deny" => false,
            _ => return Err(PhoneRespondError::Verdict),
        };
        let mut waiting = self.waiting.lock().expect("phone");
        let Some(entry) = waiting.get(id) else {
            return Err(PhoneRespondError::Idle);
        };
        if entry.token.as_str() != token {
            return Err(PhoneRespondError::Token);
        }
        // Fail closed: a tap may only authorise at or below the phone ceiling. Above it, the question
        // stays open and the run's own timeout denies it — a refusal is never converted into a yes.
        if allowed && !PHONE_CEILING.covers(entry.risk) {
            return Err(PhoneRespondError::Idle);
        }
        let entry = waiting.remove(id).expect("present");
        match entry.reply {
            Some(reply) => {
                let option = if allowed {
                    ApprovalOption::AllowOnce
                } else {
                    ApprovalOption::Deny
                };
                let _ = reply.send((option, "phone".to_string()));
                Ok(())
            }
            None => Err(PhoneRespondError::Idle),
        }
    }
}

#[async_trait]
impl Approver for PhoneApprover {
    async fn decide(&self, request: &ApprovalRequest, action: &ActionRequest) -> ApprovalDecision {
        let (reply, answer) = oneshot::channel();
        let token = RespondToken::new();
        {
            let mut waiting = self.waiting.lock().expect("phone");
            waiting.insert(
                request.id.as_str().to_string(),
                Waiting {
                    token: token.clone(),
                    risk: request.risk,
                    reply: Some(reply),
                },
            );
        }

        let payload = PushPayload::for_request(&self.respond_base, request, &token);
        // The token lives inside `respond_url`; the hand-written Debug and SanitizedUrl keep it out of
        // log lines.
        tracing::debug!(
            id = %request.id,
            url = %SanitizedUrl(&self.push_url),
            "pushing an approval to the phone webhook"
        );

        if let Err(err) = post_payload(&self.push_url, &payload).await {
            tracing::warn!(
                id = %request.id,
                error = %err,
                url = %SanitizedUrl(&self.push_url),
                "approval push failed; the run will time out to a denial unless answered by the webhook"
            );
        }

        let waited = tokio::time::timeout(self.wait, answer).await;

        // Whatever happened, the entry goes: a queue that keeps answered or expired questions grows
        // without bound.
        self.waiting
            .lock()
            .expect("phone")
            .remove(request.id.as_str());

        match waited {
            Ok(Ok((option, by))) => ApprovalDecision { option, by },
            Ok(Err(_)) => ApprovalDecision::deny(format!(
                "the phone approval channel closed before answering {}",
                brief(action)
            )),
            Err(_) => ApprovalDecision::deny(format!(
                "nobody answered the push within {}s for {}",
                self.wait.as_secs(),
                brief(action)
            )),
        }
    }
}

/// POST a JSON payload to the webhook, expecting a 2xx.
///
/// Thin and `pub(crate)` so a unit test can pin the wire shape without a socket; the real-socket path is
/// `tests/phone_approval.rs`.
pub(crate) async fn post_payload(
    url: &str,
    payload: &PushPayload,
) -> std::result::Result<(), String> {
    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .json(payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("webhook responded {}", response.status()))
    }
}

fn brief(action: &ActionRequest) -> String {
    match &action.command {
        Some(command) => format!("{} ({})", action.tool, truncate(command)),
        None => format!("{}: {}", action.tool, truncate(&action.summary)),
    }
}

/// Normalise a daemon `http_addr` (`127.0.0.1:8787`) into a URL origin (`http://127.0.0.1:8787`)
/// for a pushed `respond_url`. If the operator already wrote a scheme, leave it alone.
pub(crate) fn origin_of(addr: &str) -> String {
    if addr.contains("://") {
        addr.to_string()
    } else {
        format!("http://{addr}")
    }
}

fn truncate(text: &str) -> String {
    let mut out: String = text.chars().take(120).collect();
    if text.chars().count() > 120 {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::approval::ApprovalRequest;

    fn request(summary: &str, risk: RiskClass) -> ApprovalRequest {
        ApprovalRequest {
            id: hx_core::ids::ApprovalId::from_raw("apr_phone_test"),
            tool: "shell".into(),
            summary: summary.into(),
            risk,
            reason: "test".into(),
            key: "k".into(),
            options: vec![
                ApprovalOption::AllowOnce,
                ApprovalOption::AllowForChat,
                ApprovalOption::Deny,
            ],
            targets: vec![],
            reversible: false,
            undo: None,
            unattended: None,
            confined: Default::default(),
            default_on_timeout: ApprovalOption::Deny,
            timeout_secs: None,
        }
    }

    #[test]
    fn the_token_never_appears_in_a_debug_rendering() {
        let token = RespondToken::new();
        let payload = PushPayload::for_request(
            "https://daemon",
            &request("push", RiskClass::External),
            &token,
        );
        let rendered = format!("{payload:?}");
        assert!(
            !rendered.contains(token.as_str()),
            "the token must not appear in Debug: {rendered}"
        );
        assert_eq!(format!("{token:?}"), "RespondToken(<redacted>)");
        assert_eq!(format!("{token}"), "<redacted>");
        // The payload still carries the real URL (so the notification can be tapped), just never printed.
        assert!(payload.respond_url.contains(token.as_str()));
        assert!(!payload.respond_url.contains("<redacted>"));
    }

    #[test]
    fn the_payload_has_the_documented_shape() {
        let request = request("git push origin main", RiskClass::External);
        let payload = PushPayload::for_request("https://daemon", &request, &RespondToken::new());
        assert_eq!(payload.id, "apr_phone_test");
        assert_eq!(payload.question, "git push origin main");
        assert_eq!(
            payload.choices,
            vec!["allow".to_string(), "deny".to_string()]
        );
        assert!(
            payload
                .respond_url
                .starts_with("https://daemon/v1/approvals/apr_phone_test/respond?token="),
            "{}",
            payload.respond_url
        );
    }

    #[test]
    fn a_tap_answers_once_and_a_replay_is_refused() {
        let approver = PhoneApprover::new(
            "http://mock".into(),
            "https://daemon".into(),
            Duration::from_secs(1),
        );
        let request = request("git push", RiskClass::External);
        let (reply, answer) = oneshot::channel();
        {
            let mut waiting = approver.waiting.lock().expect("phone");
            waiting.insert(
                request.id.as_str().to_string(),
                Waiting {
                    token: RespondToken::new(),
                    risk: request.risk,
                    reply: Some(reply),
                },
            );
        }
        let token = approver
            .waiting
            .lock()
            .expect("phone")
            .get("apr_phone_test")
            .map(|w| w.token.clone())
            .unwrap();

        assert_eq!(
            approver.respond("apr_phone_test", token.as_str(), "allow"),
            Ok(())
        );
        let (option, by) = answer.blocking_recv().unwrap();
        assert_eq!(option, ApprovalOption::AllowOnce);
        assert_eq!(by, "phone");
        // A replay with the same token is not a second decision.
        assert_eq!(
            approver.respond("apr_phone_test", token.as_str(), "allow"),
            Err(PhoneRespondError::Idle)
        );
    }

    #[test]
    fn a_deny_tap_maps_to_deny() {
        let approver = PhoneApprover::new(
            "http://mock".into(),
            "https://daemon".into(),
            Duration::from_secs(1),
        );
        let request = request("git push", RiskClass::External);
        let (reply, answer) = oneshot::channel();
        {
            let mut waiting = approver.waiting.lock().expect("phone");
            waiting.insert(
                request.id.as_str().to_string(),
                Waiting {
                    token: RespondToken::new(),
                    risk: request.risk,
                    reply: Some(reply),
                },
            );
        }
        let token = approver
            .waiting
            .lock()
            .expect("phone")
            .get("apr_phone_test")
            .map(|w| w.token.clone())
            .unwrap();
        assert_eq!(
            approver.respond("apr_phone_test", token.as_str(), "deny"),
            Ok(())
        );
        let (option, _by) = answer.blocking_recv().unwrap();
        assert_eq!(option, ApprovalOption::Deny);
    }
}
