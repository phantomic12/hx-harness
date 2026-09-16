//! Who answers an approval prompt.
//!
//! The loop asks; something answers. In the daemon that is a channel to whichever client is
//! watching — the TUI, the browser, a phone. In tests it is a script. The trait is this small on
//! purpose: everything interesting about approvals (what needs asking, what may be remembered,
//! what happens when nobody answers) is policy, and policy lives in `hx-core`.

use async_trait::async_trait;
use hx_core::approval::{ActionRequest, ApprovalOption, ApprovalRequest};
use std::collections::VecDeque;
use std::sync::Mutex;

/// One answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub option: ApprovalOption,
    /// Who decided — a user name, `"policy"`, `"timeout"`. Recorded in the audit trail, because
    /// "the agent did it" is not an answer anyone can act on later.
    pub by: String,
}

impl ApprovalDecision {
    pub fn allow_once() -> Self {
        Self {
            option: ApprovalOption::AllowOnce,
            by: "user".to_string(),
        }
    }

    pub fn allow_for_chat() -> Self {
        Self {
            option: ApprovalOption::AllowForChat,
            by: "user".to_string(),
        }
    }

    pub fn deny(by: impl Into<String>) -> Self {
        Self {
            option: ApprovalOption::Deny,
            by: by.into(),
        }
    }
}

#[async_trait]
pub trait Approver: Send + Sync {
    async fn decide(&self, request: &ApprovalRequest, action: &ActionRequest) -> ApprovalDecision;
}

/// Approves everything. For tests, and for a run an operator has explicitly handed over.
pub struct AlwaysAllow;

#[async_trait]
impl Approver for AlwaysAllow {
    async fn decide(
        &self,
        _request: &ApprovalRequest,
        _action: &ActionRequest,
    ) -> ApprovalDecision {
        ApprovalDecision::allow_for_chat()
    }
}

/// Refuses everything. The fail-closed default for an unattended run with no channel.
pub struct AlwaysDeny;

#[async_trait]
impl Approver for AlwaysDeny {
    async fn decide(
        &self,
        _request: &ApprovalRequest,
        _action: &ActionRequest,
    ) -> ApprovalDecision {
        ApprovalDecision::deny("no one is available to approve")
    }
}

/// Refuses every prompt, with a reason of the caller's choosing.
///
/// The daemon's case: a request arrives over HTTP and no client is attached to answer a prompt, so
/// the answer is "no" with an explanation a human can act on — never a silent yes. The escape hatch
/// is the request's autonomy level, which decides *whether* a prompt happens at all; this approver
/// only ever sees the ones that still need a human.
pub struct DenyWithReason {
    reason: String,
}

impl DenyWithReason {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl Approver for DenyWithReason {
    async fn decide(
        &self,
        _request: &ApprovalRequest,
        _action: &ActionRequest,
    ) -> ApprovalDecision {
        ApprovalDecision::deny(self.reason.clone())
    }
}

/// Answers from a script, in order, and refuses once it runs out.
///
/// Running out refusing rather than allowing is the point: a test whose script is exhausted is a
/// test that expected fewer prompts than it got, and it should see that rather than a silently
/// permissive run.
pub struct ScriptedApprover {
    answers: Mutex<VecDeque<ApprovalDecision>>,
    /// Every prompt this approver was shown, for assertions about *what* was asked.
    seen: Mutex<Vec<ApprovalRequest>>,
}

impl ScriptedApprover {
    pub fn new(answers: Vec<ApprovalDecision>) -> Self {
        Self {
            answers: Mutex::new(VecDeque::from(answers)),
            seen: Mutex::new(Vec::new()),
        }
    }

    pub fn seen(&self) -> Vec<ApprovalRequest> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl Approver for ScriptedApprover {
    async fn decide(&self, request: &ApprovalRequest, _action: &ActionRequest) -> ApprovalDecision {
        self.seen.lock().unwrap().push(request.clone());
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| ApprovalDecision::deny("the scripted approver had no answer left"))
    }
}
