//! Answering a prompt from somewhere that is not this process.
//!
//! The loop asks an [`Approver`](crate::Approver) and waits. Until now the daemon's approver could
//! only refuse — there is no client attached to a `POST /v1/chat` — which made an unattended run
//! either trivial or `--autonomy yolo`. An [`ApprovalQueue`] is the missing middle: the request is
//! held where a client can find it, the run waits a bounded time for an answer, and **silence is a
//! denial**. Fail closed, then say so in the transcript with the reason and the wait, so the model
//! knows the difference between "the operator said no" and "nobody was there".
//!
//! This lives in `hx-agent` rather than in the HTTP layer on purpose: a Telegram button, a TUI
//! dialog and a `POST /v1/approvals/{id}` are the same decision, and the queue is the thing they
//! share. The transport only decides how the question is *rendered* and who is allowed to answer.

use crate::approver::{ApprovalDecision, Approver};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hx_core::approval::{ActionRequest, ApprovalOption, ApprovalRequest};
#[cfg(test)]
use hx_core::approval::{ApprovalPolicy, ApprovalSession, Verdict};
use hx_core::ids::ApprovalId;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

/// Where a waiting run's question goes, and where the answer comes back.
///
/// One queue per daemon, shared by every run: an approval belongs to a session and a call, and the
/// queue records both, so a client can ask "what is waiting for *this* session" rather than being
/// shown every prompt on the machine.
pub struct ApprovalQueue {
    /// How long a run waits before treating silence as a denial.
    wait: Duration,
    /// Who the answer is attributed to when a client supplies one.
    pending: Mutex<BTreeMap<String, Waiting>>,
}

struct Waiting {
    request: ApprovalRequest,
    /// The session and call this belongs to, for a client that filters by them.
    session: Option<String>,
    reply: Option<oneshot::Sender<(ApprovalOption, String)>>,
}

impl ApprovalQueue {
    pub fn new(wait: Duration) -> Arc<Self> {
        Arc::new(Self {
            wait,
            pending: Mutex::new(BTreeMap::new()),
        })
    }

    /// What is waiting, oldest first, optionally only for one session.
    ///
    /// Rendering is the client's business, but the *request* is the whole question: its reason, the
    /// action's risk and reversibility, and the options worth offering. A client that shows less than
    /// this is a client that gets a yes it did not deserve.
    pub fn outstanding(&self, session: Option<&str>) -> Vec<ApprovalRequest> {
        let pending = self.pending.lock().expect("approval queue");
        pending
            .values()
            .filter(|waiting| match session {
                Some(wanted) => waiting.session.as_deref() == Some(wanted),
                None => true,
            })
            .map(|waiting| waiting.request.clone())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.lock().expect("approval queue").is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending.lock().expect("approval queue").len()
    }

    /// Answer one waiting request. `false` means nothing was waiting under that id — a second answer
    /// to the same question, or an answer that raced the timeout.
    ///
    /// `by` is who answered, and it travels into the audit trail: "the agent did it" is not an answer
    /// anyone can act on later, and a tap on a phone is a weaker signal than a keystroke in a
    /// terminal, so the two must not look alike afterwards.
    pub fn answer(&self, id: &str, option: ApprovalOption, by: &str) -> bool {
        let mut pending = self.pending.lock().expect("approval queue");
        let Some(waiting) = pending.remove(id) else {
            return false;
        };
        match waiting.reply {
            // The run may have timed out between the removal and the send; that is not an error, it
            // is a race the timeout is allowed to win.
            Some(reply) => reply.send((option, by.to_string())).is_ok(),
            None => false,
        }
    }
}

/// Asking a queue is asking a human: the run waits, and a timeout is a denial.
#[async_trait]
impl Approver for ApprovalQueue {
    async fn decide(&self, request: &ApprovalRequest, action: &ActionRequest) -> ApprovalDecision {
        self.decide_in(request, action, None).await
    }
}

impl ApprovalQueue {
    /// The same, recording which session the question belongs to.
    ///
    /// The session is recorded at insert time rather than patched afterwards: two steps would leave a
    /// window in which a client polling the queue cannot see a question that is already being asked.
    pub async fn decide_in(
        &self,
        request: &ApprovalRequest,
        action: &ActionRequest,
        session: Option<&str>,
    ) -> ApprovalDecision {
        let (reply, answer) = oneshot::channel();

        {
            let mut pending = self.pending.lock().expect("approval queue");
            pending.insert(
                request.id.as_str().to_string(),
                Waiting {
                    request: request.clone(),
                    session: session.map(str::to_string),
                    reply: Some(reply),
                },
            );
        }

        let waited = tokio::time::timeout(self.wait, answer).await;

        // Whatever happened, the entry goes: a queue that keeps answered or expired questions grows
        // without bound and a client that polls it sees ghosts.
        self.pending
            .lock()
            .expect("approval queue")
            .remove(request.id.as_str());

        match waited {
            Ok(Ok((option, by))) => ApprovalDecision { option, by },
            Ok(Err(_)) => ApprovalDecision::deny(format!(
                "the approval channel closed before answering {}",
                brief(action)
            )),
            Err(_) => ApprovalDecision::deny(format!(
                "nobody answered within {}s for {}",
                self.wait.as_secs(),
                brief(action)
            )),
        }
    }
}

/// What the denial names: enough to know which action was dropped, short enough for a transcript.
fn brief(action: &ActionRequest) -> String {
    match &action.command {
        Some(command) => format!("{} ({})", action.tool, truncate(command)),
        None => format!("{}: {}", action.tool, truncate(&action.summary)),
    }
}

fn truncate(text: &str) -> String {
    let mut out: String = text.chars().take(120).collect();
    if text.chars().count() > 120 {
        out.push('…');
    }
    out
}

/// A queue that also records which session a question belongs to.
///
/// Separate from [`ApprovalQueue`] because a run knows its session and the approver trait does not
/// carry one: the daemon wraps the queue in this, so `outstanding(Some(session))` is exact.
pub struct SessionScopedQueue {
    queue: Arc<ApprovalQueue>,
    session: String,
}

impl SessionScopedQueue {
    pub fn new(queue: Arc<ApprovalQueue>, session: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            queue,
            session: session.into(),
        })
    }
}

#[async_trait]
impl Approver for SessionScopedQueue {
    async fn decide(&self, request: &ApprovalRequest, action: &ActionRequest) -> ApprovalDecision {
        self.queue
            .decide_in(request, action, Some(&self.session))
            .await
    }
}

/// When a run has nobody to ask and no queue to wait on: refuse, with the reason.
///
/// Kept next to the queue because the two are the same decision made under different conditions, and
/// a reader should be able to see both at once.
pub struct RefusingApprover {
    reason: String,
}

impl RefusingApprover {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl Approver for RefusingApprover {
    async fn decide(
        &self,
        _request: &ApprovalRequest,
        _action: &ActionRequest,
    ) -> ApprovalDecision {
        ApprovalDecision::deny(self.reason.clone())
    }
}

/// A timestamp for the audit line, kept here so the queue's records and the store's agree.
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// The id type a queue is keyed by, re-exported so callers do not need `hx-core` for one name.
pub type QueueId = ApprovalId;

#[cfg(test)]
mod tests {
    use super::*;

    /// An `ApprovalRequest` built the way the loop builds one: through a session's decision, so the
    /// test cannot drift from the real shape of a question.
    fn request_for(summary: &str) -> ApprovalRequest {
        let action = ActionRequest::shell(summary);
        let mut session = ApprovalSession::new(ApprovalPolicy::paranoid());
        match session.decide(&action, Utc::now()) {
            Verdict::Ask(request) => *request,
            other => panic!("expected a prompt for {summary:?}, got {other:?}"),
        }
    }

    fn queue() -> Arc<ApprovalQueue> {
        ApprovalQueue::new(Duration::from_secs(5))
    }

    #[tokio::test]
    async fn an_answer_reaches_the_run_that_asked() {
        let queue = queue();
        let request = request_for("git push");
        let action = ActionRequest::shell("git push origin main");

        // The approver waits; a client answers from "another thread".
        let asking = {
            let queue = Arc::clone(&queue);
            let request = request.clone();
            let action = action.clone();
            tokio::spawn(async move { queue.decide(&request, &action).await })
        };

        // Wait for the question to appear, then answer it.
        let mut seen = None;
        for _ in 0..50 {
            if let Some(first) = queue.outstanding(None).first() {
                seen = Some(first.id.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let id = seen.expect("the request is visible while the run waits");
        assert_eq!(queue.len(), 1);
        assert!(queue.answer(id.as_str(), ApprovalOption::AllowForChat, "phone"));

        let decision = asking.await.expect("the run resumes");
        assert_eq!(decision.option, ApprovalOption::AllowForChat);
        assert_eq!(
            decision.by, "phone",
            "the answer is attributed to its source"
        );
        assert!(queue.is_empty(), "an answered question does not linger");
    }

    #[tokio::test]
    async fn silence_is_a_denial_and_says_so() {
        let queue = ApprovalQueue::new(Duration::from_millis(30));
        let request = request_for("rm -rf ./build");
        let action = ActionRequest::shell("rm -rf ./build");

        let decision = queue.decide(&request, &action).await;
        assert_eq!(decision.option, ApprovalOption::Deny);

        // The reason distinguishes "nobody answered" from "the operator said no": a model that cannot
        // tell the difference will retry one and not the other.
        assert!(
            decision.by.contains("nobody answered"),
            "by: {}",
            decision.by
        );
        assert!(
            decision.by.contains("rm -rf ./build"),
            "by: {}",
            decision.by
        );
        assert!(queue.is_empty(), "an expired question does not linger");
    }

    #[tokio::test]
    async fn answering_twice_is_not_a_second_decision() {
        let queue = queue();
        let request = request_for("ls");
        assert!(!queue.answer("nope", ApprovalOption::AllowOnce, "someone"));
        assert!(!queue.answer(request.id.as_str(), ApprovalOption::AllowOnce, "someone"));
        assert!(!queue.answer(request.id.as_str(), ApprovalOption::AllowOnce, "someone"));
    }

    #[tokio::test]
    async fn a_scoped_queue_reports_only_its_own_session() {
        let queue = queue();
        let mine = SessionScopedQueue::new(Arc::clone(&queue), "ses_a");

        let request = request_for("git push");
        let action = ActionRequest::shell("git push");
        let asking = {
            let mine = Arc::clone(&mine);
            let request = request.clone();
            let action = action.clone();
            tokio::spawn(async move { mine.decide(&request, &action).await })
        };

        let mut id = None;
        for _ in 0..50 {
            if let Some(first) = queue.outstanding(Some("ses_a")).first() {
                id = Some(first.id.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let id = id.expect("the question is visible to its own session");
        assert!(
            queue.outstanding(Some("ses_b")).is_empty(),
            "another session must not see it"
        );

        queue.answer(id.as_str(), ApprovalOption::AllowOnce, "tui");
        assert!(asking.await.expect("resumes").option == ApprovalOption::AllowOnce);
    }
}
