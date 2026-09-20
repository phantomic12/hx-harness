//! The loop-back: a tap on a phone resumes the run that asked.
//!
//! The last M5 gap. The `Connector` trait, the per-channel [`AnswerAuthority`] ceiling and the
//! Telegram long-poll connector all existed, and a button tap was parsed and judged — and then the
//! answer went **nowhere**. Pressing "Approve" on a phone did nothing, because nothing joined the tap
//! to the run that was waiting for it.
//!
//! ## The three objects, and who owns what
//!
//! | | knows | does not know |
//! |---|---|---|
//! | the **connector** | how to post a question and how to hand back an inbound event | what is waiting, or who may answer |
//! | the **queue** ([`ApprovalQueue`]) | *what* is pending, keyed by [`ApprovalId`], first answer wins, a timeout is a denial | where the question was asked, or what a channel may authorise |
//! | the **bridge** | which channels may answer, how strongly, and which conversation each question went to | how to talk to a platform |
//!
//! The bridge is the join, and it is deliberately the only place that holds channel *policy*: the
//! ceiling check lives next to [`AnswerAuthority`], in the crate that owns it, rather than in a driver
//! loop where it would be re-implemented per transport.
//!
//! ## The properties, and what pins each one
//!
//! 1. **An answer is matched to the question it names, never to "the latest pending approval".**
//!    The button carries `apr_<id>:<label>` (`crate::telegram::callback_data`), so a tap names its
//!    request. A tap for an id that is not waiting in the conversation it came from is refused —
//!    a stale tap, a replayed tap, and a tap for a question asked somewhere else are all the same
//!    case. `a_stale_or_replayed_tap_does_not_answer_a_different_question`.
//! 2. **Only the channel that was asked, in the conversation it was asked in, counts.** A question
//!    asked via a channel is waited on under the *conversation* as its scope
//!    ([`ApprovalBridge::await_answer`] is the only supported way to wait for one), and [`route`]
//!    looks the question up in that scope — so an answer arriving in another chat finds nothing to
//!    answer. `an_answer_from_another_conversation_does_not_answer_this_question`.
//! 3. **The ceiling holds on the running path.** The risk is judged at the moment of the *answer*,
//!    not only when the question was posted, because a channel's ceiling can be lowered while a
//!    question is up. A `Destructive` request answered "allow once" from a `Mutate` channel is
//!    refused and the run stays waiting, which ends in the queue's timeout denial.
//!    `a_destructive_tap_is_refused_on_the_running_path`.
//! 4. **The answer is attributed to its channel.** The decision reaches the loop as
//!    `ApprovalDecision { by }` and the loop puts `by` into `AgentEvent::ApprovalResolved` — so a
//!    reader of the trail sees `telegram:4242 via main-tg` where a terminal keypress says `user`.
//!    `a_tap_resumes_the_run_and_the_trail_says_it_came_from_a_phone`.
//! 5. **A channel that is down fails closed.** Twice over: a question that could not be *posted* is
//!    denied immediately with the reason (no run waits for a question no human can see), and a
//!    question that was posted and never answered ends in the queue's timeout denial — a channel
//!    failure is never converted into a yes.
//!    `a_channel_that_cannot_be_reached_denies_the_run_instead_of_leaving_it_waiting`.
//!
//! ## What is deliberately NOT here
//!
//! - **No receive loop.** The bridge does not poll. Driving `Connector::receive` is the driver's job
//!   (one loop per channel, not one per waiting run), and the loop stays in `hxd` where the
//!   connectors are configured. This module turns *one* inbound event into an outcome.
//! - **No "allow always" from a channel.** [`AnswerAuthority`] judges what *risk* a channel may
//!   authorise; the bridge adds one restriction on what *kind* of answer it may give: `allow once`
//!   and `allow for this chat` (chat-scoped, expiring) are honoured, `always allow this` is refused,
//!   because that option writes a permanent grant into the deployment's configuration and a phone tap
//!   must not be what writes it. The rejected alternative is honouring it because the policy layer
//!   chose to offer it: the option list is the *request's* to offer, but which surfaces may exercise
//!   a permanent promotion is exactly the "a phone tap is a weaker signal" decision this layer owns.
//!   `a_permanent_grant_is_not_made_from_a_phone`.
//! - **No delivery of the outcome back to the chat** (a "denied" ack on the phone). It needs a
//!   second send on a path where a failed send would have to be handled, and the run's own answer
//!   already reaches whoever is watching it. Named here so the omission is a decision, not an
//!   oversight.
//!
//! ## Why this crate depends on `hx-agent`
//!
//! The bridge *applies* the answer, so it needs the queue — and the queue needs it: `hx-agent` never
//! imports `hx-gateway` (the crate graph's rule is that arrows only point down), and a `Connector`
//! that knew about approval queues would be a connector that is not a connector. The alternatives were
//! a newtype in `hxd` (a third indirection around a two-method call, and it would put the
//! channel-policy check in the daemon instead of beside the ceiling it enforces) and a new wiring
//! crate (a crate for one `impl`). The cost, stated plainly: building `hx-gateway` alone now builds
//! the tool and remote stack with it.
//!
//! [`ApprovalId`]: hx_core::ids::ApprovalId
//! [`route`]: ApprovalBridge::route

use crate::answer::{AnswerAuthority, AnswerVerdict};
use crate::connector::Connector;
use crate::types::{ApprovalTask, Conversation, Inbound, Target};
use hx_agent::approver::{ApprovalDecision, Approver};
use hx_agent::{AnswerResult, ApprovalQueue};
use hx_core::approval::{ActionRequest, ApprovalOption, ApprovalRequest, RiskClass};
use hx_core::error::{HxError, Result};
use hx_core::ids::ConnectorId;
use hx_secrets::Secret;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A channel allowed to answer, and how strong an answer it may give.
///
/// The ceiling is the same [`RiskClass`] ladder the deployment uses, per channel, because a phone
/// tap is a weaker signal than a terminal keypress. It is enforced by [`AnswerAuthority`] before any
/// answer is honoured — here, and at the moment the question would be posted, so a channel is never
/// shown a question it could not have answered.
pub struct AnsweringChannel {
    /// The connector that carries the question out and the answer back.
    pub connector: Arc<dyn Connector>,
    /// The strongest risk this channel may authorise (`Mutate` for a chat bridge).
    pub ceiling: RiskClass,
}

impl AnsweringChannel {
    pub fn new(connector: Arc<dyn Connector>, ceiling: RiskClass) -> Self {
        Self { connector, ceiling }
    }
}

/// Where a question was asked and an answer came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerSource {
    pub connector: ConnectorId,
    pub conversation: Conversation,
}

impl AnswerSource {
    /// The sentence the audit trail records, as `ApprovalResolved.by`.
    ///
    /// `telegram:4242 via main-tg` — the platform, the chat, and the configured connector, so a
    /// reader of the trail can tell a phone tap from a terminal keypress (`by: user`) without
    /// knowing anything about the run. This is security-relevant rather than cosmetic: "who approved
    /// this" is the question an incident review asks, and `user` does not answer it when the user was
    /// on a phone in another country.
    pub fn attribution(&self) -> String {
        let chat = match self.conversation.thread.as_str() {
            "" => self.conversation.chat.to_string(),
            thread => format!("{}/{}", self.conversation.chat, thread),
        };
        format!(
            "{}:{} via {}",
            self.conversation.platform, chat, self.connector
        )
    }
}

/// What one inbound message turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerOutcome {
    /// A tap that answered the question its run was waiting on. The run has been resumed with this.
    Answered {
        approval_id: String,
        option: ApprovalOption,
        /// The value the trail records — see [`AnswerSource::attribution`].
        by: String,
    },
    /// An inbound message that is not an answer to a question this bridge asked (a chat message).
    NotAnAnswer,
    /// An answer that was refused, and why. The run keeps waiting, and its timeout still denies:
    /// a refusal here is never a yes.
    Refused { approval_id: String, reason: String },
}

/// The join between a channel and the queue a run is waiting on.
pub struct ApprovalBridge {
    /// The channels configured to answer, by connector id.
    channels: BTreeMap<String, AnsweringChannel>,
    /// The queue every waiting run is parked in.
    queue: Arc<ApprovalQueue>,
}

impl ApprovalBridge {
    pub fn new(queue: Arc<ApprovalQueue>, channels: Vec<AnsweringChannel>) -> Arc<Self> {
        let channels = channels
            .into_iter()
            .map(|channel| (channel.connector.id().to_string(), channel))
            .collect();
        Arc::new(Self { channels, queue })
    }

    /// Post a pending question to a channel so a human can answer it.
    ///
    /// Fail closed in both directions. A question this channel could never answer is refused
    /// **before** anything is posted: showing a human a button whose answer will be thrown away
    /// teaches them that the buttons do not work. A post that fails is an error, and the caller must
    /// not leave the run waiting for a question nobody can see — [`ChannelApprover`] denies instead
    /// (see its `decide`).
    pub async fn ask_via(
        &self,
        channel: &ConnectorId,
        key: &Secret,
        conversation: &Conversation,
        request: &ApprovalRequest,
    ) -> Result<()> {
        let answering = self
            .channels
            .get(channel.as_str())
            .ok_or_else(|| HxError::Connector {
                connector: channel.to_string(),
                reason:
                    "no connector with that id is configured to answer approvals; the question \
                         was not posted"
                        .to_string(),
            })?;

        if !AnswerAuthority::may_answer(answering.ceiling, request.risk) {
            return Err(HxError::Denied(format!(
                "a {} action cannot be answered from {channel} (ceiling: {}); the question was not \
                 posted rather than posted with buttons whose answer would be refused",
                request.risk.label(),
                answering.ceiling.label()
            )));
        }

        let task = ApprovalTask {
            request: request.clone(),
            ceiling: answering.ceiling,
        };
        answering
            .connector
            .ask(key, &Target::Conversation(conversation.clone()), &task)
            .await?;
        Ok(())
    }

    /// Wait for the answer to a question that has been posted.
    ///
    /// The wait is the queue's: the run is parked where [`ApprovalBridge::route`] can find it, under
    /// **the conversation as its scope**, and silence ends in a denial naming the wait. The scope is
    /// the whole reason a tap can be matched to a conversation: it is what makes "was this question
    /// asked *here*" answerable, so a question asked through a channel must be waited on this way
    /// rather than under a session id.
    pub async fn await_answer(
        &self,
        request: &ApprovalRequest,
        action: &ActionRequest,
        conversation: &Conversation,
    ) -> ApprovalDecision {
        self.queue
            .decide_in(request, action, Some(&conversation.canonical()))
            .await
    }

    /// Turn one inbound message from a channel into an outcome, and apply it.
    ///
    /// This is the whole loop-back in one call, and it is synchronous on purpose: it touches the
    /// queue and nothing else, so a driver can call it from its receive loop without a second task,
    /// and a test can call it without a network.
    pub fn route(&self, channel: &ConnectorId, inbound: Inbound) -> AnswerOutcome {
        let Inbound::ApprovalAnswer {
            conversation,
            approval_id,
            answer,
        } = inbound
        else {
            return AnswerOutcome::NotAnAnswer;
        };

        // A channel nobody configured to answer is not a channel that may answer. This is checked
        // before the question is looked up so the refusal names the reason a reader cares about.
        let Some(answering) = self.channels.get(channel.as_str()) else {
            return AnswerOutcome::Refused {
                approval_id,
                reason: format!(
                    "{channel} is not configured to answer approvals; an answer from a channel that \
                     was not asked is not an answer"
                ),
            };
        };

        // The question, in *this* conversation, by the id the tap named. All three have to match:
        // the id makes it a particular question rather than whatever is pending, and the scope makes
        // it a question asked here rather than somewhere else. A tap that fails either check — a
        // stale one, a replayed one, one from another chat — finds nothing and is refused.
        let scope = conversation.canonical();
        let Some(request) = self
            .queue
            .outstanding(Some(&scope))
            .into_iter()
            .find(|request| request.id.as_str() == approval_id)
        else {
            return AnswerOutcome::Refused {
                approval_id,
                reason: format!(
                    "no question with that id is waiting in {scope}: a tap that names a question \
                     this channel was not asked, or one already answered or timed out, is not an \
                     answer to anything"
                ),
            };
        };

        // The authority, against the ceiling of the channel the answer *arrived on* and the options
        // this request offered. Judged now rather than only when the question was posted, because a
        // channel's ceiling can be lowered while a question is up.
        let label = match AnswerAuthority::judge(answering.ceiling, &request, &answer) {
            Ok(AnswerVerdict::Answered { answer, .. }) => answer,
            Ok(AnswerVerdict::NoAnswer) => {
                return AnswerOutcome::Refused {
                    approval_id,
                    reason: "the channel reported no answer".to_string(),
                }
            }
            Err(refused) => {
                return AnswerOutcome::Refused {
                    approval_id,
                    reason: refused.to_string(),
                }
            }
        };

        // Back through the request's own options: only a choice this question rendered can come back
        // as a yes, and the option is what the queue needs.
        let Some(option) = request
            .options
            .iter()
            .find(|option| option.label() == label)
            .copied()
        else {
            return AnswerOutcome::Refused {
                approval_id,
                reason: format!("{label:?} is not one of the options this question offered"),
            };
        };

        // A permanent grant is a write into the deployment's configuration, and a phone tap is not
        // the signal for that. `allow for this chat` is chat-scoped and expires, so it is honoured.
        if option == ApprovalOption::AllowAlways {
            return AnswerOutcome::Refused {
                approval_id,
                reason: format!(
                    "{channel} may answer this question but not make a permanent grant: \
                     \"always allow this\" writes into the deployment's allow list, and a chat \
                     channel may only answer for this instance or for this chat"
                ),
            };
        }

        let by = AnswerSource {
            connector: channel.clone(),
            conversation,
        }
        .attribution();

        // The queue is the atomic authority on whether this question is still open **and** on whether
        // this channel was allowed to give this answer: it re-judges the ceiling against the request
        // it is holding, at the moment of the answer. So the check above is not the only thing
        // standing between a phone and a run — and the two use the same comparison
        // (`RiskClass::covers`), so they cannot come to disagree.
        match self.queue.answer(&approval_id, option, &by, answering.ceiling) {
            AnswerResult::Answered => AnswerOutcome::Answered {
                approval_id,
                option,
                by,
            },
            AnswerResult::Unknown => AnswerOutcome::Refused {
                approval_id,
                reason:
                    "the question was answered or expired between the check and the answer; the \
                         first answer is the one that counts"
                        .to_string(),
            },
            AnswerResult::AboveCeiling { risk, ceiling } => AnswerOutcome::Refused {
                approval_id,
                reason: format!(
                    "a {} action cannot be answered from {channel} (ceiling: {}); the queue refused \
                     it when the answer arrived, and the run keeps waiting for one it may accept",
                    risk.label(),
                    ceiling.label()
                ),
            },
        }
    }
}

/// The approver a run uses when its question is asked through a channel.
///
/// Construct a run with this and its prompts go to the phone; a tap comes back through
/// [`ApprovalBridge::route`] and resumes the run. This is the only place the two halves are ordered,
/// and the order is the decision: **post first, then wait**. The alternative — park the run in the
/// queue and post afterwards — leaves a run waiting on a question that was never delivered if the
/// post fails, and the human is shown nothing. Here a failed post is a denial, immediately, with the
/// reason, so no run waits for a question no one can see.
pub struct ChannelApprover {
    bridge: Arc<ApprovalBridge>,
    channel: ConnectorId,
    /// The bot credential, resolved by reference (`vault:`/`env:`) before the run started and held as
    /// a [`Secret`] for the run's life. Never logged: `Debug` is redacted and the bytes are zeroed on
    /// drop. Resolving it per prompt instead would put a vault read on the approval path.
    key: Secret,
    conversation: Conversation,
}

impl ChannelApprover {
    pub fn new(
        bridge: Arc<ApprovalBridge>,
        channel: ConnectorId,
        key: Secret,
        conversation: Conversation,
    ) -> Arc<Self> {
        Arc::new(Self {
            bridge,
            channel,
            key,
            conversation,
        })
    }

    /// Where this run's questions are asked — what its answers will be attributed to.
    pub fn source(&self) -> AnswerSource {
        AnswerSource {
            connector: self.channel.clone(),
            conversation: self.conversation.clone(),
        }
    }
}

#[async_trait::async_trait]
impl Approver for ChannelApprover {
    async fn decide(&self, request: &ApprovalRequest, action: &ActionRequest) -> ApprovalDecision {
        if let Err(err) = self
            .bridge
            .ask_via(&self.channel, &self.key, &self.conversation, request)
            .await
        {
            // Nobody was asked, so the answer is no — now, with the reason, rather than after a
            // timeout that would look to the model like a human who did not reply. `by` names the
            // channel so the trail still records where the question would have gone.
            return ApprovalDecision::deny(format!(
                "{} (the question could not be asked: {err})",
                self.source().attribution()
            ));
        }

        // Posted. Now the wait, which the queue bounds and ends in a denial if nobody answers.
        self.bridge
            .await_answer(request, action, &self.conversation)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChatId, Platform, ThreadId};
    use std::time::Duration;

    /// A connector that is never called: the tests here exercise the parts that do not touch a
    /// platform, and the ones that do use the real Telegram connector over a real stub
    /// (`tests/approval_loopback.rs`).
    struct Unused;

    #[async_trait::async_trait]
    impl Connector for Unused {
        fn id(&self) -> &ConnectorId {
            static ID: std::sync::OnceLock<ConnectorId> = std::sync::OnceLock::new();
            ID.get_or_init(|| ConnectorId::from("unused"))
        }

        fn platform(&self) -> Platform {
            Platform("unused".into())
        }

        async fn receive(&self, _key: &Secret) -> Result<Option<Inbound>> {
            panic!("this connector is never polled")
        }

        async fn deliver(&self, _key: &Secret, _to: &Target, _text: &str) -> Result<()> {
            panic!("this connector is never asked to deliver")
        }

        async fn ask(
            &self,
            _key: &Secret,
            _to: &Target,
            _task: &ApprovalTask,
        ) -> Result<AnswerVerdict> {
            panic!("this connector is never asked")
        }
    }

    fn request(risk: RiskClass) -> ApprovalRequest {
        ApprovalRequest {
            id: hx_core::ids::ApprovalId::from_raw("apr_test"),
            tool: "shell".into(),
            summary: "run rm -rf /tmp/x".into(),
            risk,
            reason: "testing".into(),
            key: "k".into(),
            options: vec![ApprovalOption::AllowOnce, ApprovalOption::Deny],
            targets: vec![],
            reversible: false,
            undo: None,
            confined: Default::default(),
            default_on_timeout: ApprovalOption::Deny,
            timeout_secs: None,
        }
    }

    fn bridge() -> Arc<ApprovalBridge> {
        let queue = ApprovalQueue::new(Duration::from_secs(5));
        ApprovalBridge::new(
            queue,
            vec![AnsweringChannel::new(Arc::new(Unused), RiskClass::Mutate)],
        )
    }

    #[test]
    fn an_answer_is_attributed_to_the_channel_it_came_from() {
        // The value that lands in `ApprovalResolved.by`. A reader has to be able to tell this from
        // the terminal's `user`, and the thread has to be in it: one chat, two threads, two runs.
        let source = AnswerSource {
            connector: ConnectorId::from("main-tg"),
            conversation: Conversation::telegram("4242", ""),
        };
        assert_eq!(source.attribution(), "telegram:4242 via main-tg");

        let threaded = AnswerSource {
            connector: ConnectorId::from("main-tg"),
            conversation: Conversation {
                platform: Platform("telegram".into()),
                chat: ChatId("999".into()),
                thread: ThreadId("42".into()),
            },
        };
        assert_eq!(threaded.attribution(), "telegram:999/42 via main-tg");
    }

    #[test]
    fn a_chat_message_is_not_an_answer() {
        // The bridge sees every inbound message of a channel; only a tap is an answer. A message that
        // reads like one ("allow once", typed by hand) is data for the model, not a decision.
        let outcome = bridge().route(
            &ConnectorId::from("unused"),
            Inbound::Message {
                conversation: Conversation::telegram("4242", ""),
                text: "allow once".into(),
            },
        );
        assert_eq!(outcome, AnswerOutcome::NotAnAnswer);
    }

    #[test]
    fn an_answer_through_a_channel_that_was_not_configured_is_refused() {
        let outcome = bridge().route(
            &ConnectorId::from("someone-elses-bot"),
            Inbound::ApprovalAnswer {
                conversation: Conversation::telegram("4242", ""),
                approval_id: "apr_test".into(),
                answer: "allow once".into(),
            },
        );
        match outcome {
            AnswerOutcome::Refused { reason, .. } => {
                assert!(reason.contains("not configured to answer"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_destructive_question_is_not_posted_to_a_channel_that_could_never_answer_it() {
        // The ceiling is applied when the question is *asked*, not only when it is answered: showing
        // a human a button whose answer will be thrown away teaches them the buttons do not work. The
        // connector here panics if it is asked anything, so reaching the platform would be a failure,
        // not a silent pass.
        let err = bridge()
            .ask_via(
                &ConnectorId::from("unused"),
                &Secret::new("0123456789:TESTBOT-fixture"),
                &Conversation::telegram("4242", ""),
                &request(RiskClass::Destructive),
            )
            .await
            .expect_err("a Mutate channel cannot answer a Destructive action");
        let message = err.to_string();
        assert!(message.contains("ceiling"), "{message}");
        assert!(message.contains("not posted"), "{message}");
    }

    #[tokio::test]
    async fn a_question_cannot_be_asked_through_a_channel_that_is_not_configured() {
        let err = bridge()
            .ask_via(
                &ConnectorId::from("nobody"),
                &Secret::new("0123456789:TESTBOT-fixture"),
                &Conversation::telegram("4242", ""),
                &request(RiskClass::Mutate),
            )
            .await
            .expect_err("no such channel");
        assert!(err.to_string().contains("not posted"), "{err}");
    }
}
