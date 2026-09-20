//! Answer authority and delivery policy: who may answer what, and where output goes.
//!
//! ## Answer authority
//!
//! The roadmap's rule: a request can be answered from anywhere the user already is, but the *answer
//! authority* is configured per channel, "because a phone tap is a weaker signal than a terminal". The
//! concrete consequence this module holds is the per-channel **ceiling**: a chat bridge may approve a
//! `Mutate` but must **never** approve a `Destructive` action. This is enforced *here*, in pure,
//! testable logic, so no connector and no driver can accidentally let a remote human authorise `rm -rf /`.
//!
//! Enforcement is separate from rendering. A connector can *display* any question (so the human sees what was
//! asked), but an [`AnswerAuthority`] decides whether a given answer is legal for that channel. The gateway
//! consults it before ever acting on an answer, and a "yes" that is above the ceiling is refused.
//!
//! Fail closed: a channel that is down (a send that errors) is a hard failure, and a question with no
//! answer or an answer the ceiling forbids is a **no**, never a silent yes.
//!
//! ## Delivery policy
//!
//! Delivery targets / home-channel pinning: background output (a cron digest, a nightly report) must not
//! interleave with a conversation a human is actively watching. [`DeliveryPolicy::resolve`] is the rule: a
//! reply to a live conversation goes to that conversation; background output goes to the configured **home
//! channel**; and with no home channel configured, background output is refused rather than silently dropped.

use crate::types::{Conversation, Target};
use hx_core::approval::{ApprovalRequest, RiskClass};
use hx_core::error::{HxError, Result};

/// Whether a connector's `ask` produced a usable answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerVerdict {
    /// The human answered with one of the request's legal options.
    Answered { approval_id: String, answer: String },
    /// The human dismissed the prompt, or no answer arrived before the timeout / the channel died.
    NoAnswer,
}

/// Decides whether an answer from a channel is *legal* for the channel's ceiling.
///
/// The ceiling is set per channel at configuration time (a chat bridge gets `Mutate`; a terminal gets
/// the full ladder). An answer authorising a [`RiskClass`] above the ceiling is refused, return `false`,
/// and the caller must treat it as a **no**.
pub struct AnswerAuthority;

impl AnswerAuthority {
    /// May a channel whose ceiling is `ceiling` answer a request whose risk is `risk`?
    pub fn may_answer(ceiling: RiskClass, risk: RiskClass) -> bool {
        risk <= ceiling
    }

    /// Turn a raw platform answer into the option's label, *only if* that answer is within the ceiling.
    ///
    /// The request's risk is the thing being authorised, so the ceiling check is against `request.risk`,
    /// not against anything the platform said. An out-of-ceiling "yes" becomes [`AnswerVerdict::NoAnswer`]
    /// with a refusal — fail closed, never a forced yes.
    pub fn judge(
        ceiling: RiskClass,
        request: &ApprovalRequest,
        raw: &str,
    ) -> Result<AnswerVerdict> {
        if !Self::may_answer(ceiling, request.risk) {
            return Err(HxError::Denied(format!(
                "an answer of {raw:?} for a {} action cannot be accepted from a channel with \
                 ceiling {ceiling:?}; refusing rather than honouring it",
                request.risk.label()
            )));
        }

        // The answer must be one of the options the request actually offered. An arbitrary string is not
        // an instruction; only a choice the request rendered may come back as a yes.
        let label = raw.trim();
        let option = request
            .options
            .iter()
            .find(|o| o.label() == label)
            .ok_or_else(|| {
                HxError::Denied(format!(
                    "an answer not among the offered options is not accepted: {label:?}"
                ))
            })?;

        Ok(AnswerVerdict::Answered {
            approval_id: request.id.as_str().to_string(),
            answer: option.label().to_string(),
        })
    }
}

/// Where a message should be delivered.
#[derive(Clone, Debug)]
pub struct DeliveryPolicy {
    /// The pinned home channel for background output, if one is configured.
    pub home: Option<Conversation>,
}

impl DeliveryPolicy {
    pub fn new(home: Option<Conversation>) -> Self {
        Self { home }
    }

    /// Choose where a message goes.
    ///
    /// - A reply to a live conversation goes back to that conversation — the human is there and waiting.
    /// - Background output (no live conversation) goes to the pinned home channel.
    /// - Background output with no home channel is an error: **fail closed** rather than silently dropping
    ///   the output, because a cron digest that quietly vanished is indistinguishable from a cron job that never ran.
    pub fn resolve(&self, origin: Option<&Conversation>) -> Result<Target> {
        match origin {
            Some(conversation) => Ok(Target::Conversation(conversation.clone())),
            None => match &self.home {
                Some(home) => Ok(Target::Conversation(home.clone())),
                None => Err(HxError::Config(
                    "background output has no destination: no live conversation and no home channel \
                     is configured; the output was refused, not dropped"
                        .to_string(),
                )),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::approval::ApprovalRequest;

    fn request(risk: RiskClass) -> ApprovalRequest {
        hx_core::approval::ApprovalRequest {
            id: hx_core::ids::ApprovalId::from_raw("apr_test"),
            tool: "shell".into(),
            summary: "run rm -rf /tmp/x".into(),
            risk,
            reason: "testing".into(),
            key: "k".into(),
            options: vec![
                hx_core::approval::ApprovalOption::AllowOnce,
                hx_core::approval::ApprovalOption::Deny,
            ],
            targets: vec![],
            reversible: false,
            undo: None,
            confined: Default::default(),
            default_on_timeout: hx_core::approval::ApprovalOption::Deny,
            timeout_secs: None,
        }
    }

    #[test]
    fn a_chat_bridge_can_never_approve_a_destructive_action() {
        // The rule from the docs: a phone tap is a weaker signal than a terminal, so a chat bridge
        // (ceiling Mutate) must refuse to authorise anything at or above Destructive.
        assert!(AnswerAuthority::may_answer(
            RiskClass::Mutate,
            RiskClass::Read
        ));
        assert!(AnswerAuthority::may_answer(
            RiskClass::Mutate,
            RiskClass::Mutate
        ));
        assert!(!AnswerAuthority::may_answer(
            RiskClass::Mutate,
            RiskClass::External
        ));
        assert!(!AnswerAuthority::may_answer(
            RiskClass::Mutate,
            RiskClass::Destructive
        ));
        assert!(!AnswerAuthority::may_answer(
            RiskClass::Mutate,
            RiskClass::Privileged
        ));
    }

    #[test]
    fn an_answer_above_the_ceiling_is_refused_fail_closed() {
        // A destructive request answered "yes, go ahead" from a chat bridge is an error named as a
        // denial — the run must NOT proceed.
        let verdict =
            AnswerAuthority::judge(RiskClass::Mutate, &request(RiskClass::Destructive), "allow");
        let err = verdict.expect_err("a chat bridge cannot authorise destructive");
        assert!(err.to_string().contains("ceiling"), "{err}");
    }

    #[test]
    fn an_answer_within_the_ceiling_and_among_the_options_is_accepted() {
        let verdict =
            AnswerAuthority::judge(RiskClass::Mutate, &request(RiskClass::Mutate), "allow once")
                .expect("within the ceiling");
        match verdict {
            AnswerVerdict::Answered {
                approval_id,
                answer,
            } => {
                assert_eq!(approval_id, "apr_test");
                assert_eq!(answer, "allow once");
            }
            other => panic!("expected an answer, got {other:?}"),
        }
    }

    #[test]
    fn an_answer_that_is_not_an_offered_option_is_not_an_instruction() {
        // Untrusted input: a message that happens to be "allow" is data, not an approval, unless the
        // request actually offered it. Here the platform sends something the request never rendered.
        let verdict = AnswerAuthority::judge(
            RiskClass::Mutate,
            &request(RiskClass::Read),
            "allow-everything",
        );
        let err = verdict.expect_err("not an offered option");
        assert!(
            err.to_string().contains("among the offered options"),
            "{err}"
        );
    }

    #[test]
    fn background_output_with_no_home_channel_is_refused_not_dropped() {
        let policy = DeliveryPolicy::new(None);
        let err = policy.resolve(None).expect_err("no destination");
        assert!(err.to_string().contains("refused, not dropped"), "{err}");
    }

    #[test]
    fn background_output_goes_to_the_pinned_home_channel() {
        let policy = DeliveryPolicy::new(Some(Conversation::telegram("123", "")));
        match policy.resolve(None).unwrap() {
            Target::Conversation(c) => assert_eq!(c.chat.as_str(), "123"),
            _ => panic!("expected the home channel"),
        }
    }

    #[test]
    fn a_reply_goes_back_to_its_own_conversation_not_the_home_channel() {
        // Even with a home channel configured, a reply to a live conversation lands in that
        // conversation — that is the "does not interleave" property from the other side.
        let origin = Conversation::telegram("999", "42");
        let policy = DeliveryPolicy::new(Some(Conversation::telegram("123", "")));
        match policy.resolve(Some(&origin)).unwrap() {
            Target::Conversation(c) => assert_eq!(c.chat.as_str(), "999"),
            _ => panic!("a reply must go to its conversation"),
        }
    }
}
