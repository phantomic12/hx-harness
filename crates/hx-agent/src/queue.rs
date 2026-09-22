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
//! share. The transport only decides how the question is *rendered*.
//!
//! ## The ceiling is enforced here, not by the transport
//!
//! Because the queue is what every transport applies an answer *through*, it is also the one place a
//! **ceiling** can be enforced without a transport being able to forget. [`ApprovalQueue::answer`]
//! takes the answering surface's [`RiskClass`] ceiling as a required argument — there is no default
//! and `RiskClass` has none — and judges it against the risk of the request the queue is *holding*, at
//! the moment the answer arrives. A `Destructive` request answered from a surface whose ceiling is
//! `Mutate` is refused and the question **stays open**, so the run's own timeout still denies it: a
//! refusal is never converted into a yes. The comparison is [`RiskClass::covers`], the same one
//! `hx-gateway`'s `AnswerAuthority` uses, so the channel path and the local path cannot disagree.

use crate::approver::{ApprovalDecision, Approver};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hx_core::approval::{ActionRequest, ApprovalOption, ApprovalRequest, RiskClass};
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

/// What came of an attempt to answer a waiting question.
///
/// Three outcomes rather than a `bool` because a caller has to be able to tell "there was nothing to
/// answer" from "you are not allowed to answer that", and the two need different things said about
/// them: the first is a 404 and a client's own bug, the second is a **refusal** that must be visible
/// to whoever tried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnswerResult {
    /// The answer reached the run that was waiting on it.
    Answered,
    /// Nothing was waiting under that id — a second answer to the same question, or an answer that
    /// raced the timeout.
    Unknown,
    /// The answer was above the ceiling of the surface that gave it. The question **stays open**, so
    /// the run's own timeout still denies it: a refusal here is never converted into a yes.
    AboveCeiling { risk: RiskClass, ceiling: RiskClass },
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

    /// Answer one waiting request, judged against the answering surface's **ceiling**.
    ///
    /// `ceiling` is the strongest risk the surface that is answering may authorise, and it is a
    /// required argument with no default — the one way to make "an answer nobody was allowed to give"
    /// impossible to arrive by omission. The check is against the risk of the request the queue is
    /// *holding* (the queue's own record of what was asked, not anything the caller supplied), and it
    /// is made **now**, when the answer arrives, because a surface's ceiling can be lowered while a
    /// question is up.
    ///
    /// An answer above the ceiling is [`AnswerResult::AboveCeiling`] and the question **stays open**:
    /// the run keeps waiting and its own timeout denies it. A refusal here is never converted into a
    /// yes, and never into a silent no that looks like nobody replied.
    ///
    /// `by` is who answered, and it travels into the audit trail: "the agent did it" is not an answer
    /// anyone can act on later, and a tap on a phone is a weaker signal than a keystroke in a
    /// terminal, so the two must not look alike afterwards.
    pub fn answer(
        &self,
        id: &str,
        option: ApprovalOption,
        by: &str,
        ceiling: RiskClass,
    ) -> AnswerResult {
        let mut pending = self.pending.lock().expect("approval queue");
        let Some(risk) = pending.get(id).map(|waiting| waiting.request.risk) else {
            return AnswerResult::Unknown;
        };
        if !ceiling.covers(risk) {
            // Left in the queue on purpose: the run is still waiting, and its timeout is what ends
            // this — with a denial that says nobody answered, which is the truth.
            return AnswerResult::AboveCeiling { risk, ceiling };
        }

        let Some(waiting) = pending.remove(id) else {
            return AnswerResult::Unknown;
        };
        match waiting.reply {
            // The run may have timed out between the removal and the send; that is not an error, it
            // is a race the timeout is allowed to win.
            Some(reply) => match reply.send((option, by.to_string())) {
                Ok(()) => AnswerResult::Answered,
                Err(_) => AnswerResult::Unknown,
            },
            None => AnswerResult::Unknown,
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
        self.decide_in_with_wait(request, action, session, self.wait)
            .await
    }

    /// The same, waiting `wait` instead of the queue's own default.
    ///
    /// WHY a per-question wait rather than a per-request queue: the question has to stay visible on
    /// the one queue clients poll (`GET /v1/approvals` reads the daemon's shared queue, and answers
    /// arrive through it). A second queue per request would hold a question no client can see and no
    /// answer route can reach. The wait is therefore a property of the *ask*, not of the queue — the
    /// queue stays shared, and each run's ask carries how long that run will wait for silence to
    /// become a denial.
    pub async fn decide_in_with_wait(
        &self,
        request: &ApprovalRequest,
        action: &ActionRequest,
        session: Option<&str>,
        wait: Duration,
    ) -> ApprovalDecision {
        let (reply, answer) = oneshot::channel();

        {
            let mut pending = self.pending.lock().expect("approval queue");
            pending.insert(
                request.id.as_str().to_string(),
                Waiting {
                    // The session rides on the request too, not only in the queue's private record:
                    // `outstanding` hands clients the request, and a task list has to tell which
                    // task a question belongs to from that alone.
                    request: {
                        let mut shown = request.clone();
                        if shown.session.is_none() {
                            shown.session = session.map(hx_core::ids::SessionId::from_raw);
                        }
                        shown
                    },
                    session: session.map(str::to_string),
                    reply: Some(reply),
                },
            );
        }

        let waited = tokio::time::timeout(wait, answer).await;

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
                wait.as_secs(),
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
    /// A per-request wait, overriding the queue's own default for this run's asks. `None` means
    /// "the queue decides" — which is the daemon-wide wait, and the shape every existing caller has.
    wait: Option<Duration>,
}

impl SessionScopedQueue {
    pub fn new(queue: Arc<ApprovalQueue>, session: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            queue,
            session: session.into(),
            wait: None,
        })
    }

    /// The same, waiting `wait` for an answer instead of the queue's default.
    ///
    /// The question still lands on the shared queue (see `decide_in_with_wait` for why that
    /// matters); only the silence-becomes-denial horizon moves, to what the request asked for.
    pub fn new_with_wait(
        queue: Arc<ApprovalQueue>,
        session: impl Into<String>,
        wait: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            queue,
            session: session.into(),
            wait: Some(wait),
        })
    }
}

#[async_trait]
impl Approver for SessionScopedQueue {
    async fn decide(&self, request: &ApprovalRequest, action: &ActionRequest) -> ApprovalDecision {
        match self.wait {
            Some(wait) => {
                self.queue
                    .decide_in_with_wait(request, action, Some(&self.session), wait)
                    .await
            }
            None => {
                self.queue
                    .decide_in(request, action, Some(&self.session))
                    .await
            }
        }
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
        assert_eq!(
            queue.answer(
                id.as_str(),
                ApprovalOption::AllowForChat,
                "phone",
                // `git push` is `External`, so the ceiling has to reach that far for this test to be
                // about the answer arriving rather than about the ceiling. The ceiling itself is the
                // subject of `an_answer_above_the_ceiling_is_refused_and_the_question_stays_open`.
                RiskClass::Privileged
            ),
            AnswerResult::Answered
        );

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
        // A terminal: the full ladder, so the ceiling is not what is being tested here.
        let terminal = RiskClass::Privileged;
        assert_eq!(
            queue.answer("nope", ApprovalOption::AllowOnce, "someone", terminal),
            AnswerResult::Unknown
        );
        assert_eq!(
            queue.answer(
                request.id.as_str(),
                ApprovalOption::AllowOnce,
                "someone",
                terminal
            ),
            AnswerResult::Unknown,
            "nothing was waiting, so nothing was answered"
        );
        assert_eq!(
            queue.answer(
                request.id.as_str(),
                ApprovalOption::AllowOnce,
                "someone",
                terminal
            ),
            AnswerResult::Unknown
        );
    }

    #[tokio::test]
    async fn an_answer_above_the_ceiling_is_refused_and_the_question_stays_open() {
        // The rule the docs make ("a chat bridge can never authorise a destructive action") has to be
        // true of the path an answer is actually applied through, not only of a pure function. The
        // queue is that path: every transport — a Telegram tap, the HTTP route — answers here.
        let queue = ApprovalQueue::new(Duration::from_millis(150));
        let request = request_for("rm -rf ./build");
        assert_eq!(
            request.risk,
            RiskClass::Destructive,
            "the fixture has to be the risk the test is about"
        );
        let action = ActionRequest::shell("rm -rf ./build");

        let asking = {
            let queue = Arc::clone(&queue);
            let request = request.clone();
            let action = action.clone();
            tokio::spawn(async move { queue.decide(&request, &action).await })
        };

        let mut id = None;
        for _ in 0..50 {
            if let Some(first) = queue.outstanding(None).first() {
                id = Some(first.id.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let id = id.expect("the question is visible while the run waits");

        // A chat bridge's ceiling: `Mutate`. The tap is refused, and the refusal names both numbers so
        // a reader can see *why*.
        assert_eq!(
            queue.answer(
                id.as_str(),
                ApprovalOption::AllowOnce,
                "telegram:4242 via main-tg",
                RiskClass::Mutate
            ),
            AnswerResult::AboveCeiling {
                risk: RiskClass::Destructive,
                ceiling: RiskClass::Mutate,
            }
        );

        // Crucially, the question is still open — the refusal did not become a decision. Silence then
        // ends it the way silence always does, with a denial.
        assert_eq!(
            queue.len(),
            1,
            "the refused answer did not consume the question"
        );
        let decision = asking.await.expect("the run finishes");
        assert_eq!(decision.option, ApprovalOption::Deny);
        assert!(
            decision.by.contains("nobody answered"),
            "a refused answer must not be recorded as a decision: {}",
            decision.by
        );
        assert!(
            !decision.by.contains("telegram"),
            "the phone's refusal is not an attribution: {}",
            decision.by
        );
    }

    #[tokio::test]
    async fn an_answer_at_the_ceiling_is_accepted() {
        // The other half, so the check cannot pass by refusing everything: a `Mutate` question from a
        // `Mutate` ceiling is exactly the case the chat bridge exists for.
        let queue = queue();
        let request = request_for("git add -A");
        assert_eq!(request.risk, RiskClass::Mutate, "the fixture");
        let action = ActionRequest::shell("git add -A");

        let asking = {
            let queue = Arc::clone(&queue);
            let request = request.clone();
            let action = action.clone();
            tokio::spawn(async move { queue.decide(&request, &action).await })
        };
        let mut id = None;
        for _ in 0..50 {
            if let Some(first) = queue.outstanding(None).first() {
                id = Some(first.id.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let id = id.expect("the question is visible");

        assert_eq!(
            queue.answer(
                id.as_str(),
                ApprovalOption::AllowOnce,
                "telegram:4242 via main-tg",
                RiskClass::Mutate
            ),
            AnswerResult::Answered
        );
        assert_eq!(
            asking.await.expect("the run resumes").option,
            ApprovalOption::AllowOnce
        );
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

        // `git push` is `External`, so the terminal's ladder is what answers it.
        assert_eq!(
            queue.answer(
                id.as_str(),
                ApprovalOption::AllowOnce,
                "tui",
                RiskClass::Privileged
            ),
            AnswerResult::Answered
        );
        assert!(asking.await.expect("resumes").option == ApprovalOption::AllowOnce);
    }

    #[tokio::test]
    async fn a_custom_wait_overrides_the_queues_own_silence_horizon() {
        // The queue's default is far longer than the custom wait: if the custom wait were ignored the
        // denial would arrive late (or never, within the test's window). A short custom wait must win.
        let queue = ApprovalQueue::new(Duration::from_secs(60));
        let request = request_for("ls");
        let action = ActionRequest::shell("ls");

        let began = std::time::Instant::now();
        let decision = queue
            .decide_in_with_wait(&request, &action, None, Duration::from_millis(40))
            .await;

        assert_eq!(decision.option, ApprovalOption::Deny);
        assert!(
            began.elapsed() < Duration::from_secs(60),
            "the custom wait must win over the queue's 60s default"
        );
        assert!(queue.is_empty(), "an expired question does not linger");
    }
}
