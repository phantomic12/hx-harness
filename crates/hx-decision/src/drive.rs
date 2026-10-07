//! The consumer loop: **sense → decide → act**, at a fixed tick.
//!
//! M10 built the decision substrate (typed questions + [`LayaClient`]). This
//! module is the first consumer the ROADMAP names: a small loop that hands a
//! text state to Laya, gates the answer through [`DecisionGate`], and executes
//! the winning action — fast enough that a dumb loop can drive a real terminal.
//!
//! The loop is transport- and environment-agnostic: a [`Sense`] produces the
//! state text, an [`Act`] executes action ids, and a [`Predictor`] answers a
//! [`QuestionSet`] (the sidecar client is the production predictor). The `hx
//! drive` CLI wires this to a tmux pane; tests use in-memory stubs.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use hx_core::decision::{Decision, DecisionGate};
use hx_core::error::{HxError, Result};

use crate::{AnswerKind, DecisionResult, LayaClient, Question, QuestionSet};

/// Produces the text state handed to the model on each tick.
///
/// The state's job is to describe the world *in words*, not numbers — Laya is a
/// textual-entailment model; compute comparisons in the sensor and hand it
/// conclusions (see docs/laya.md).
#[async_trait]
pub trait Sense {
    /// Read the environment and return its state as text.
    async fn sense(&mut self) -> Result<String>;
}

/// Executes the action id the model picked.
#[async_trait]
pub trait Act {
    /// Perform `action_id` (one of the action question's option ids).
    async fn act(&mut self, action_id: &str) -> Result<()>;
}

/// Anything that can answer a [`QuestionSet`] in one pass.
///
/// [`LayaClient`] is the production implementation; tests substitute an
/// in-memory stub so no sidecar is needed.
#[async_trait]
pub trait Predictor {
    /// Answer every question about `questions.state` in one forward pass.
    async fn predict(&self, questions: &QuestionSet) -> Result<DecisionResult>;
}

#[async_trait]
impl Predictor for LayaClient {
    async fn predict(&self, questions: &QuestionSet) -> Result<DecisionResult> {
        LayaClient::predict(self, questions).await
    }
}

/// One loop iteration, recorded for the report.
#[derive(Debug, Clone)]
pub struct Step {
    /// Zero-based tick index.
    pub index: usize,
    /// The state text the model was asked about.
    pub state: String,
    /// The action id executed — `None` when the step escalated and nothing ran.
    pub action: Option<String>,
    /// Top probability of the action answer's winning option.
    pub top_probability: f32,
    /// Reported confidence of the action answer.
    pub confidence: f32,
    /// What the gate decided about the action answer.
    pub decision: Decision,
    /// `true` when the action came from the guard veto, not the action
    /// question's winning option.
    pub via_guard: bool,
    /// Wall time for sense + predict (excludes the tick sleep and act()).
    pub elapsed: Duration,
}

/// How a drive ended.
#[derive(Debug)]
pub enum Outcome {
    /// The `done_question` noul cleared `done_threshold` — task completed.
    Done { steps: usize },
    /// The gate escalated `max_escalations + 1` consecutive times.
    Escalated,
    /// `max_steps` ticks ran without `Done`.
    MaxSteps,
    /// Sense, predict, or act failed; `steps` holds what happened before.
    Failed(String),
}

/// The record of a finished drive: every step plus how it ended.
#[derive(Debug)]
pub struct DriveReport {
    pub steps: Vec<Step>,
    pub outcome: Outcome,
    pub total_elapsed: Duration,
}

impl DriveReport {
    /// Count of steps that escalated (acted or not).
    pub fn escalations(&self) -> usize {
        self.steps.iter().filter(|s| s.decision.escalated()).count()
    }
}

/// The loop configuration: what to ask, which answer drives, when to stop.
pub struct Drive {
    /// Every question asked per tick, in one forward pass. Must contain a
    /// `Choice` question whose id is [`Self::action_question`].
    pub questions: Vec<Question>,
    /// Id of the question whose answer drives the action. A `Choice` runs the
    /// winning option's id; a `Noul` runs `noul_actions`'s true or false side
    /// (whichever cleared the gate — an ambiguous middle escalates, which is
    /// exactly what "the screen is unclear" should do).
    pub action_question: String,
    /// For a `Noul` action question: `(on_true, on_false)` action ids.
    /// Ignored for a `Choice` action question.
    pub noul_actions: Option<(String, String)>,
    /// Optional id of a `Noul` question ("is the task finished?"); when its
    /// probability reaches `done_threshold` the loop ends [`Outcome::Done`].
    pub done_question: Option<String>,
    /// P(true) that ends the drive as done (default 0.8).
    pub done_threshold: f32,
    /// Ticks to run before the done check is trusted (default 0). A model
    /// can confabulate "finished" on the first state it sees — e.g. claiming
    /// a marker is present on a blank screen — so a queue that needs at
    /// least one action sets this to 1.
    pub warmup: usize,
    /// The cascade gate applied to the action answer each tick.
    pub gate: DecisionGate,
    /// Minimum spacing between ticks (the loop runs faster than `tick` never;
    /// slow sensing eats into the next tick).
    pub tick: Duration,
    /// Hard cap on iterations.
    pub max_steps: usize,
    /// Consecutive escalations tolerated before stopping. `0` stops on the
    /// first one; `k` skips that tick's action up to `k` times in a row —
    /// transient ambiguity usually resolves on the next state.
    pub max_escalations: usize,
    /// Optional guard: a `Noul` question evaluated *before* the action answer
    /// each tick. When P(true) reaches `guard_threshold`, `guard_action` runs
    /// instead of whatever the action question picked — a fast veto
    /// (e.g. "the step deletes data" → press `n`) that a confident-but-wrong
    /// action answer cannot override. This mirrors the upstream
    /// `LayaGuardrail` pattern: one narrow entailment question in front of
    /// the decision, because a single "choose the right key" question mixes
    /// perception and policy and misses refusals a dedicated veto catches.
    pub guard_question: Option<String>,
    /// P(true) on `guard_question` that fires the veto (default 0.8).
    pub guard_threshold: f32,
    /// The action id executed when the guard fires.
    pub guard_action: Option<String>,
}

impl Drive {
    /// Validate the configuration against the question set — the same shapes
    /// the sidecar and CLI check before starting a drive.
    pub fn validate(&self) -> Result<()> {
        let action_q = self
            .questions
            .iter()
            .find(|q| q.id() == self.action_question)
            .ok_or_else(|| {
                HxError::Config(format!(
                    "action question '{}' is not in the question set",
                    self.action_question
                ))
            })?;
        match action_q {
            Question::Choice { .. } => {}
            Question::Noul { .. } => {
                if self.noul_actions.is_none() {
                    return Err(HxError::Config(format!(
                        "action question '{}' is a noul: noul_actions (on_true, on_false) must be set",
                        self.action_question
                    )));
                }
            }
            _ => {
                return Err(HxError::Config(format!(
                    "action question '{}' must be a choice or noul question",
                    self.action_question
                )))
            }
        }
        if let Some(done) = &self.done_question {
            match self.questions.iter().find(|q| q.id() == done.as_str()) {
                Some(Question::Noul { .. }) => {}
                Some(_) => {
                    return Err(HxError::Config(format!(
                        "done question '{done}' must be a noul question"
                    )))
                }
                None => {
                    return Err(HxError::Config(format!(
                        "done question '{done}' is not in the question set"
                    )))
                }
            }
        }
        for q in &self.questions {
            q.validate()?;
        }
        match (&self.guard_question, &self.guard_action) {
            (Some(qid), Some(_)) => match self.questions.iter().find(|q| q.id() == qid.as_str()) {
                Some(Question::Noul { .. }) => {}
                Some(_) => {
                    return Err(HxError::Config(format!(
                        "guard question '{qid}' must be a noul question"
                    )))
                }
                None => {
                    return Err(HxError::Config(format!(
                        "guard question '{qid}' is not in the question set"
                    )))
                }
            },
            (None, None) => {}
            _ => {
                return Err(HxError::Config(
                    "guard_question and guard_action must be set together".into(),
                ))
            }
        }
        if self.max_steps == 0 {
            return Err(HxError::Config("max_steps must be >= 1".into()));
        }
        Ok(())
    }

    /// Run the loop until done, escalated, capped, or failed. `on_step`, when
    /// given, sees each [`Step`] as it completes — the CLI uses it for live
    /// progress; tests pass `None`.
    ///
    /// `question_hook`, when given, mutates a fresh copy of the question set
    /// between sense and predict each tick — how a GUI driver rebuilds a
    /// "which element" choice as the screen's widgets change.
    #[allow(clippy::too_many_arguments)]
    pub async fn run<S, A, P>(
        &self,
        sense: &mut S,
        act: &mut A,
        predictor: &P,
        mut on_step: Option<&mut dyn FnMut(&Step)>,
        mut question_hook: Option<&mut dyn FnMut(&mut QuestionSet)>,
    ) -> Result<DriveReport>
    where
        S: Sense,
        A: Act,
        P: Predictor,
    {
        self.validate()?;
        let started = Instant::now();
        let mut steps = Vec::new();
        let mut consecutive_escalations = 0usize;
        let outcome;

        loop {
            if steps.len() >= self.max_steps {
                outcome = Outcome::MaxSteps;
                break;
            }
            let index = steps.len();
            let tick_start = Instant::now();

            let state = match sense.sense().await {
                Ok(s) if s.is_empty() => {
                    outcome = Outcome::Failed("sensor returned an empty state".into());
                    break;
                }
                Ok(s) => s,
                Err(e) => {
                    outcome = Outcome::Failed(format!("sense failed: {e}"));
                    break;
                }
            };

            let mut set = QuestionSet::new(state.clone(), self.questions.clone());
            if let Some(hook) = &mut question_hook {
                hook(&mut set);
            }
            let result = match predictor.predict(&set).await {
                Ok(r) => r,
                Err(e) => {
                    outcome = Outcome::Failed(format!("predict failed: {e}"));
                    break;
                }
            };

            // Completion check first: a confident "done" wins over whatever the
            // action question picked this tick — the tick is recorded so the
            // report shows why the drive ended (action `None`, probability and
            // confidence from the done answer).
            if let Some(done_id) = self.done_question.as_ref().filter(|_| index >= self.warmup) {
                let done_answer = result.get(done_id);
                let (p_done, done_conf) = done_answer
                    .map(|a| {
                        (
                            match &a.kind {
                                AnswerKind::Noul { noul, .. } => *noul,
                                _ => 0.0,
                            },
                            a.confidence(),
                        )
                    })
                    .unwrap_or((0.0, 0.0));
                if p_done >= self.done_threshold {
                    steps.push(Step {
                        index,
                        state,
                        action: None,
                        top_probability: p_done,
                        confidence: done_conf,
                        decision: Decision::Act,
                        via_guard: false,
                        elapsed: tick_start.elapsed(),
                    });
                    if let Some(cb) = &mut on_step {
                        cb(steps.last().expect("step just pushed"));
                    }
                    outcome = Outcome::Done { steps: steps.len() };
                    break;
                }
            }

            // Guard veto: a narrow noul checked before the action answer.
            let mut guard_fired = false;
            if let (Some(gq), Some(ga)) = (&self.guard_question, &self.guard_action) {
                let p_guard = result
                    .get(gq)
                    .map(|a| match &a.kind {
                        AnswerKind::Noul { noul, .. } => *noul,
                        _ => 0.0,
                    })
                    .unwrap_or(0.0);
                if p_guard >= self.guard_threshold {
                    let step = Step {
                        index,
                        state: state.clone(),
                        action: Some(ga.clone()),
                        top_probability: p_guard,
                        confidence: result.get(gq).map(|a| a.confidence()).unwrap_or(0.0),
                        decision: Decision::Act,
                        via_guard: true,
                        elapsed: tick_start.elapsed(),
                    };
                    let mut act_err = None;
                    if let Err(e) = act.act(ga).await {
                        act_err = Some(format!("act failed: {e}"));
                    }
                    steps.push(step);
                    if let Some(cb) = &mut on_step {
                        cb(steps.last().expect("step just pushed"));
                    }
                    if let Some(msg) = act_err {
                        outcome = Outcome::Failed(msg);
                        break;
                    }
                    guard_fired = true;
                }
            }
            if guard_fired {
                let slack = self.tick.saturating_sub(tick_start.elapsed());
                if !slack.is_zero() {
                    tokio::time::sleep(slack).await;
                }
                continue;
            }

            let answer = match result.get(&self.action_question) {
                Some(a) => a,
                None => {
                    outcome = Outcome::Failed(format!(
                        "sidecar returned no answer for action question '{}'",
                        self.action_question
                    ));
                    break;
                }
            };
            let (picked, top) = match &answer.kind {
                AnswerKind::Choice {
                    choice,
                    probabilities,
                    ..
                } => (
                    choice.clone(),
                    probabilities.get(choice).copied().unwrap_or(0.0),
                ),
                AnswerKind::Noul { noul, .. } => {
                    // p measures the true side; top is whichever side is winning.
                    // The gate sees the winning side's probability, so a
                    // confident *no* acts just like a confident yes.
                    let (on_true, on_false) = match &self.noul_actions {
                        Some(pair) => pair.clone(),
                        None => {
                            outcome = Outcome::Failed(format!(
                                "action question '{}' is a noul but noul_actions is unset",
                                self.action_question
                            ));
                            break;
                        }
                    };
                    let top = noul.max(1.0 - *noul);
                    (if *noul >= 0.5 { on_true } else { on_false }, top)
                }
                _ => {
                    outcome = Outcome::Failed(format!(
                        "action question '{}' answered with a score answer",
                        self.action_question
                    ));
                    break;
                }
            };

            let decision = self.gate.evaluate(top, answer.confidence());
            let elapsed = tick_start.elapsed();

            let mut act_err: Option<String> = None;
            if decision.escalated() {
                consecutive_escalations += 1;
                steps.push(Step {
                    index,
                    state,
                    action: None,
                    top_probability: top,
                    confidence: answer.confidence(),
                    decision,
                    via_guard: false,
                    elapsed,
                });
            } else {
                consecutive_escalations = 0;
                if let Err(e) = act.act(&picked).await {
                    act_err = Some(format!("act failed: {e}"));
                }
                steps.push(Step {
                    index,
                    state,
                    action: Some(picked),
                    top_probability: top,
                    confidence: answer.confidence(),
                    decision,
                    via_guard: false,
                    elapsed,
                });
            }
            if let Some(cb) = &mut on_step {
                cb(steps.last().expect("step just pushed"));
            }
            if let Some(msg) = act_err {
                outcome = Outcome::Failed(msg);
                break;
            }
            if consecutive_escalations > self.max_escalations {
                outcome = Outcome::Escalated;
                break;
            }

            // Pace the loop: sleep only the slack left in the tick.
            let slack = self.tick.saturating_sub(tick_start.elapsed());
            if !slack.is_zero() {
                tokio::time::sleep(slack).await;
            }
        }

        Ok(DriveReport {
            steps,
            outcome,
            total_elapsed: started.elapsed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChoiceOption;
    use hx_core::decision::Threshold;
    use indexmap::IndexMap;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// A predictor answering with a scripted action pick (+ optional done p).
    struct StubPredictor {
        /// (choice, top_prob, confidence, done_p)
        script: Mutex<VecDeque<(String, f32, f32, f32, f32)>>,
    }

    #[async_trait]
    impl Predictor for StubPredictor {
        async fn predict(&self, _q: &QuestionSet) -> Result<DecisionResult> {
            let (choice, top, conf, done_p, guard_p) = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| ("wait".to_string(), 0.95, 0.9, 0.0, 0.0));
            let mut probabilities = IndexMap::new();
            probabilities.insert(choice.clone(), top);
            probabilities.insert("other".to_string(), 1.0 - top);
            let answers = vec![
                crate::Answer {
                    id: "act".to_string(),
                    kind: AnswerKind::Choice {
                        choice,
                        probabilities,
                        confidence: conf,
                    },
                    act_probability: top,
                },
                crate::Answer {
                    id: "done".to_string(),
                    kind: AnswerKind::Noul {
                        noul: done_p,
                        confidence: 0.9,
                    },
                    act_probability: 0.5,
                },
                crate::Answer {
                    id: "guard".to_string(),
                    kind: AnswerKind::Noul {
                        noul: guard_p,
                        confidence: 0.9,
                    },
                    act_probability: 0.5,
                },
            ];
            Ok(DecisionResult {
                answers,
                usage_input_tokens: 10,
            })
        }
    }

    struct StubSense {
        states: Mutex<VecDeque<String>>,
    }

    #[async_trait]
    impl Sense for StubSense {
        async fn sense(&mut self) -> Result<String> {
            Ok(self
                .states
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| "state".to_string()))
        }
    }

    struct StubAct {
        ran: Arc<Mutex<Vec<String>>>,
        fail: bool,
    }

    #[async_trait]
    impl Act for StubAct {
        async fn act(&mut self, action_id: &str) -> Result<()> {
            self.ran.lock().unwrap().push(action_id.to_string());
            if self.fail {
                return Err(HxError::Decision("act blew up".into()));
            }
            Ok(())
        }
    }

    fn drive(max_escalations: usize) -> Drive {
        Drive {
            questions: vec![
                Question::Choice {
                    id: "act".to_string(),
                    instructions: "what next".to_string(),
                    criteria: vec![
                        ChoiceOption::new("go", "go forward"),
                        ChoiceOption::new("wait", "do nothing"),
                        ChoiceOption::new("other", "anything else"),
                    ],
                    max_options: None,
                },
                Question::Noul {
                    id: "done".to_string(),
                    instructions: "is the task finished".to_string(),
                },
                Question::Noul {
                    id: "guard".to_string(),
                    instructions: "is the action dangerous".to_string(),
                },
            ],
            action_question: "act".to_string(),
            done_question: Some("done".to_string()),
            done_threshold: 0.8,
            warmup: 0,
            gate: DecisionGate::new(Threshold(0.8), 0.5),
            tick: Duration::ZERO,
            max_steps: 10,
            max_escalations,
            guard_question: None,
            guard_threshold: 0.8,
            guard_action: None,
            noul_actions: None,
        }
    }

    fn rig(
        script: Vec<(String, f32, f32, f32, f32)>,
        states: Vec<&str>,
    ) -> (StubPredictor, StubSense, StubAct, Arc<Mutex<Vec<String>>>) {
        let ran = Arc::new(Mutex::new(Vec::new()));
        (
            StubPredictor {
                script: Mutex::new(script.into()),
            },
            StubSense {
                states: Mutex::new(states.iter().map(|s| s.to_string()).collect()),
            },
            StubAct {
                ran: ran.clone(),
                fail: false,
            },
            ran,
        )
    }

    #[tokio::test]
    async fn confident_actions_execute_each_tick() {
        let (p, mut s, mut a, ran) = rig(
            vec![
                ("go".to_string(), 0.9, 0.9, 0.1, 0.0),
                ("wait".to_string(), 0.85, 0.9, 0.1, 0.0),
                ("go".to_string(), 0.9, 0.9, 0.9, 0.0), // then done
            ],
            vec!["s1", "s2", "s3"],
        );
        let report = drive(0)
            .run(&mut s, &mut a, &p, None, None)
            .await
            .expect("drive runs");
        assert!(matches!(report.outcome, Outcome::Done { steps: 3 }));
        assert_eq!(ran.lock().unwrap().as_slice(), &["go", "wait"]);
    }

    #[tokio::test]
    async fn escalation_skips_the_action_then_stops() {
        let (p, mut s, mut a, ran) = rig(
            vec![
                ("go".to_string(), 0.5, 0.9, 0.0, 0.0), // below 0.8 -> escalate
                ("go".to_string(), 0.4, 0.9, 0.0, 0.0), // second consecutive -> stop
            ],
            vec!["s1", "s2"],
        );
        let report = drive(1)
            .run(&mut s, &mut a, &p, None, None)
            .await
            .expect("drive runs");
        assert!(matches!(report.outcome, Outcome::Escalated));
        assert_eq!(report.escalations(), 2);
        assert!(ran.lock().unwrap().is_empty());
        assert!(report.steps.iter().all(|st| st.action.is_none()));
    }

    #[tokio::test]
    async fn a_single_escalation_recovers_on_the_next_confident_tick() {
        let (p, mut s, mut a, ran) = rig(
            vec![
                ("go".to_string(), 0.5, 0.9, 0.0, 0.0),
                ("go".to_string(), 0.95, 0.9, 0.0, 0.0), // acts, not done yet
                ("go".to_string(), 0.95, 0.9, 0.9, 0.0), // then done
            ],
            vec!["s1", "s2", "s3"],
        );
        let report = drive(1)
            .run(&mut s, &mut a, &p, None, None)
            .await
            .expect("drive runs");
        assert!(matches!(report.outcome, Outcome::Done { steps: 3 }));
        assert_eq!(ran.lock().unwrap().as_slice(), &["go"]);
    }

    #[tokio::test]
    async fn max_steps_caps_a_never_done_task() {
        let (p, mut s, mut a, _) = rig(vec![], vec!["s1", "s2", "s3", "s4", "s5"]);
        let mut d = drive(0);
        d.max_steps = 3;
        let report = d
            .run(&mut s, &mut a, &p, None, None)
            .await
            .expect("drive runs");
        assert!(matches!(report.outcome, Outcome::MaxSteps));
        assert_eq!(report.steps.len(), 3);
    }

    #[tokio::test]
    async fn act_failure_is_reported_not_panicked() {
        let (p, mut s, mut a, _) = rig(vec![], vec!["s1"]);
        a.fail = true;
        let report = drive(0)
            .run(&mut s, &mut a, &p, None, None)
            .await
            .expect("drive runs");
        match report.outcome {
            Outcome::Failed(msg) => assert!(msg.contains("act blew up"), "{msg}"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_noul_action_question_needs_its_two_actions() {
        let mut d = drive(0);
        d.action_question = "done".to_string(); // a noul
        let e = d.validate().unwrap_err();
        assert!(e.to_string().contains("noul_actions"), "{e}");
        d.noul_actions = Some(("go".to_string(), "wait".to_string()));
        d.validate()
            .expect("noul action question with both actions validates");
    }

    #[tokio::test]
    async fn a_noul_action_question_drives_either_side() {
        // P(true) high -> on_true; P(true) low -> on_false; the middle escalates.
        let (p, mut s, mut a, ran) = rig(
            vec![
                ("x".to_string(), 0.0, 0.9, 0.9, 0.0), // done_p unused here; noul answer comes next
            ],
            vec!["s1", "s2", "s3"],
        );
        // Reuse the 'done' noul as the action question for simplicity: script
        // the done_p slot — the answer id matches because the predictor always
        // emits both questions.
        let mut d = drive(0);
        d.action_question = "done".to_string();
        d.done_question = None;
        d.noul_actions = Some(("go".to_string(), "wait".to_string()));
        // script: done_p is the noul value for 'done' — 0.9 -> 'go', 0.1 -> 'wait', 0.5 -> escalate
        let report = d
            .run(&mut s, &mut a, &p, None, None)
            .await
            .expect("drive runs");
        // First scripted answer: noul 0.9 -> 'go'. The default entries emit
        // done_p = 0.0 -> 'wait' for the remaining ticks until max_steps.
        let actions = ran.lock().unwrap().clone();
        assert_eq!(actions[0], "go");
        assert!(actions.iter().skip(1).all(|a| a == "wait"));
        assert!(matches!(report.outcome, Outcome::MaxSteps));
    }

    #[tokio::test]
    async fn flat_confidence_escalates_through_the_gate() {
        // top prob clears the threshold but confidence is below the floor.
        let (p, mut s, mut a, ran) = rig(vec![("go".to_string(), 0.95, 0.2, 0.0, 0.0)], vec!["s1"]);
        let report = drive(0)
            .run(&mut s, &mut a, &p, None, None)
            .await
            .expect("drive runs");
        assert!(matches!(report.outcome, Outcome::Escalated));
        assert!(ran.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_firing_guard_overrides_the_action_pick() {
        let (p, mut s, mut a, ran) = rig(
            vec![
                ("go".to_string(), 0.95, 0.9, 0.0, 0.9), // guard fires
                ("go".to_string(), 0.95, 0.9, 0.0, 0.1), // guard quiet -> 'go' runs
                ("go".to_string(), 0.95, 0.9, 0.9, 0.0), // done
            ],
            vec!["s1", "s2", "s3"],
        );
        let mut d = drive(0);
        d.guard_question = Some("guard".to_string());
        d.guard_action = Some("deny".to_string());
        let report = d
            .run(&mut s, &mut a, &p, None, None)
            .await
            .expect("drive runs");
        assert!(matches!(report.outcome, Outcome::Done { steps: 3 }));
        // tick 0 ran the veto, not the model's confident 'go'.
        assert_eq!(ran.lock().unwrap().as_slice(), &["deny", "go"]);
        assert!(report.steps[0].via_guard);
        assert!(!report.steps[1].via_guard);
    }

    #[tokio::test]
    async fn guard_and_action_must_pair_up() {
        let mut d = drive(0);
        d.guard_question = Some("guard".to_string());
        let e = d.validate().unwrap_err();
        assert!(e.to_string().contains("must be set together"), "{e}");
    }
}
