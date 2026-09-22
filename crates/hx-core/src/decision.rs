//! Laya decision helper: cascade gate over typed model answers.
//!
//! The Laya sidecar (see `PLAN-LAYA.md`) answers **typed questions** about a text
//! state and returns **probabilities**, never generated text. This module is the
//! `hx-core` decision helper that consumes those answers: given a top probability
//! (and a confidence), decide whether to **act** on the fast System-1 answer or
//! **escalate** to a slower rung (LLM / person).
//!
//! # Cascade pattern
//!
//! ```rust
//! use hx_core::decision::{decides, Threshold};
//!
//! let t = Threshold(0.8);
//! assert!(!decides(0.9, t).escalated());
//! assert!(decides(0.5, t).escalated());
//! ```
//!
//! When the sibling `hx-decision` crate exists (S1/S2 chunks), its `LayaClient`
//! can implement [`DecisionClient`]; until then the [`Question`]/[`Answer`]
//! types here are the minimal compatible schema so the helper compiles standalone.
//! This crate stays IO-free: the trait is transport-agnostic and the gate is a
//! pure function.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Confidence threshold for the cascade gate.
///
/// Answers whose top probability is at or above the inner value may act;
/// anything below escalates.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Threshold(pub f32);

impl Threshold {
    /// Build a threshold, clamping into `[0.0, 1.0]`.
    pub fn new(v: f32) -> Self {
        Self(v.clamp(0.0, 1.0))
    }
}

/// Cascade outcome for one answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Decision {
    /// Top probability cleared the threshold (and the confidence floor): act.
    Act,
    /// Below threshold, or confidence below the floor: escalate to LLM/person.
    Escalate,
}

impl Decision {
    /// `true` when this decision escalates instead of acting.
    pub fn escalated(&self) -> bool {
        matches!(self, Decision::Escalate)
    }
}

/// Decide from a single top probability against a threshold.
///
/// Acts at or above the threshold, escalates below it. NaN never acts
/// (fail-closed: an uncomparable probability escalates).
pub fn decides(prob: f32, threshold: Threshold) -> Decision {
    if prob.is_nan() || prob < threshold.0 {
        Decision::Escalate
    } else {
        Decision::Act
    }
}

/// Decide from a top probability plus a confidence value.
///
/// Escalates when `prob < threshold` **or** the answer's `confidence` is below
/// `floor` (probabilities too flat to trust even a threshold-clearing top
/// pick). This is the "confidence floor" half of the cascade.
pub fn decides_with_confidence(
    prob: f32,
    confidence: f32,
    threshold: Threshold,
    floor: f32,
) -> Decision {
    if confidence.is_nan() || confidence < floor {
        return Decision::Escalate;
    }
    decides(prob, threshold)
}

/// Cascade gate bundling a threshold with a confidence floor.
///
/// Evaluate one answer (or one raw probability pair) per question; a batch of
/// answers maps to a batch of [`Decision`]s so callers can act on the confident
/// subset and escalate the rest.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisionGate {
    /// Act when the top probability is at or above this.
    pub threshold: Threshold,
    /// Escalate when `confidence` is below this, however high the top pick.
    pub min_confidence: f32,
}

impl DecisionGate {
    /// Build a gate; the floor is clamped into `[0.0, 1.0]`.
    pub fn new(threshold: Threshold, min_confidence: f32) -> Self {
        Self {
            threshold,
            min_confidence: min_confidence.clamp(0.0, 1.0),
        }
    }

    /// Evaluate a raw `(top probability, confidence)` pair.
    pub fn evaluate(&self, prob: f32, confidence: f32) -> Decision {
        decides_with_confidence(prob, confidence, self.threshold, self.min_confidence)
    }

    /// Evaluate one typed [`Answer`].
    pub fn decide_answer(&self, answer: &Answer) -> Decision {
        self.evaluate(answer.top_probability(), answer.confidence())
    }

    /// Evaluate a batch of answers, preserving order.
    pub fn decide_all(&self, answers: &[Answer]) -> Vec<(String, Decision)> {
        answers
            .iter()
            .map(|a| (a.id.clone(), self.decide_answer(a)))
            .collect()
    }
}

impl Default for DecisionGate {
    /// Threshold 0.8, confidence floor 0.5.
    fn default() -> Self {
        Self::new(Threshold(0.8), 0.5)
    }
}

// ---------------------------------------------------------------------------
// Minimal Laya-compatible schema
// ---------------------------------------------------------------------------
//
// Mirrors the three Laya question types from PLAN-LAYA.md (`choice`, `score`,
// `noul`). If/when the `hx-decision` crate lands with the canonical schema,
// these convert 1:1 (same variant names, same fields) and `DecisionClient`
// below is the trait its `LayaClient` implements.

/// One typed question posed to the decision model in a single forward pass.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Question {
    /// Question id; answers echo it back.
    pub id: String,
    /// What kind of answer is expected.
    #[serde(flatten)]
    pub kind: QuestionKind,
}

/// The three Laya question types.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QuestionKind {
    /// Pick one of `options`; criteria is the option list.
    Choice {
        /// Candidate labels to choose between.
        options: Vec<String>,
    },
    /// Pick an ordered level (e.g. `["low", "medium", "high"]`).
    Score {
        /// Ordered levels, low to high.
        levels: Vec<String>,
    },
    /// Optional true/false question.
    Noul,
}

/// One typed answer: the winning pick plus its full distribution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Answer {
    /// Echoes the [`Question::id`].
    pub id: String,
    /// Reported confidence (flat distributions score low here).
    #[serde(default)]
    pub confidence: f32,
    /// Laya's `action.act_probability` for this answer.
    #[serde(default)]
    pub act_probability: f32,
    /// The winning pick and its distribution.
    #[serde(flatten)]
    pub kind: AnswerKind,
}

/// The winning pick per question type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnswerKind {
    /// Winning choice + P(option) per option.
    Choice {
        /// Winning option label.
        choice: String,
        /// Probability per option label.
        probabilities: HashMap<String, f32>,
    },
    /// Winning level + P(level) per level.
    Score {
        /// Winning level.
        score: String,
        /// Probability per level.
        probabilities: HashMap<String, f32>,
        /// Ordered level legend, low to high.
        #[serde(default)]
        legend: Vec<String>,
    },
    /// P(true) for a true/false question.
    Noul {
        /// Probability the statement is true.
        noul: f32,
    },
}

impl Answer {
    /// Highest probability in the answer's distribution.
    ///
    /// For `noul` this is `max(noul, 1 - noul)`: the model's confidence in
    /// whichever side it leans toward.
    pub fn top_probability(&self) -> f32 {
        match &self.kind {
            AnswerKind::Choice { probabilities, .. } | AnswerKind::Score { probabilities, .. } => {
                probabilities.values().copied().fold(0.0_f32, f32::max)
            }
            AnswerKind::Noul { noul } => noul.max(1.0 - noul),
        }
    }

    /// Reported confidence (flat distributions score low).
    pub fn confidence(&self) -> f32 {
        self.confidence
    }
}

/// Transport-agnostic decision client: given a text state plus a question set,
/// return one typed [`Answer`] per question (single forward pass, no looping).
///
/// The HTTP sidecar client (`LayaClient` in the sibling `hx-decision` crate,
/// when it lands) implements this trait; tests use an in-memory stub.
pub trait DecisionClient {
    /// Error type for transport / schema failures.
    type Error;

    /// Answer every question about `state` in one pass.
    async fn predict(
        &self,
        state: &str,
        questions: &[Question],
    ) -> Result<Vec<Answer>, Self::Error>;
}

/// Run one cascade step: ask `client` for answers, then gate each one.
///
/// Returns `(question_id, answer, decision)` triples in question order so the
/// caller can act on the confident subset and escalate the rest.
pub async fn cascade<C: DecisionClient>(
    client: &C,
    gate: &DecisionGate,
    state: &str,
    questions: &[Question],
) -> Result<Vec<(String, Answer, Decision)>, C::Error> {
    let answers = client.predict(state, questions).await?;
    Ok(answers
        .into_iter()
        .map(|a| {
            let d = gate.decide_answer(&a);
            (a.id.clone(), a, d)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choice_answer(id: &str, top: f32, confidence: f32) -> Answer {
        let rest = ((1.0 - top) / 2.0).max(0.0);
        Answer {
            id: id.to_string(),
            confidence,
            act_probability: top,
            kind: AnswerKind::Choice {
                choice: "a".to_string(),
                probabilities: HashMap::from([
                    ("a".to_string(), top),
                    ("b".to_string(), rest),
                    ("c".to_string(), rest),
                ]),
            },
        }
    }

    #[test]
    fn acts_at_threshold() {
        assert_eq!(decides(0.8, Threshold(0.8)), Decision::Act);
        assert!(!decides(0.8, Threshold(0.8)).escalated());
    }

    #[test]
    fn acts_above_threshold() {
        assert_eq!(decides(0.95, Threshold(0.8)), Decision::Act);
    }

    #[test]
    fn escalates_below_threshold() {
        let d = decides(0.79, Threshold(0.8));
        assert_eq!(d, Decision::Escalate);
        assert!(d.escalated());
    }

    #[test]
    fn nan_probability_escalates() {
        assert!(decides(f32::NAN, Threshold(0.0)).escalated());
    }

    #[test]
    fn confidence_floor_escalates_despite_high_top_prob() {
        // Top pick clears the threshold, but the distribution is flat
        // (confidence below the floor): must escalate.
        let d = decides_with_confidence(0.95, 0.2, Threshold(0.8), 0.5);
        assert_eq!(d, Decision::Escalate);
        assert!(d.escalated());
    }

    #[test]
    fn confidence_at_floor_acts_when_prob_clears() {
        let d = decides_with_confidence(0.9, 0.5, Threshold(0.8), 0.5);
        assert_eq!(d, Decision::Act);
    }

    #[test]
    fn gate_evaluate_matches_floor_semantics() {
        let gate = DecisionGate::new(Threshold(0.8), 0.5);
        assert_eq!(gate.evaluate(0.9, 0.9), Decision::Act);
        assert_eq!(gate.evaluate(0.5, 0.9), Decision::Escalate);
        assert_eq!(gate.evaluate(0.95, 0.1), Decision::Escalate);
    }

    #[test]
    fn gate_decide_answer_uses_top_probability() {
        let gate = DecisionGate::new(Threshold(0.8), 0.5);
        assert_eq!(
            gate.decide_answer(&choice_answer("q1", 0.9, 0.9)),
            Decision::Act
        );
        assert_eq!(
            gate.decide_answer(&choice_answer("q2", 0.4, 0.9)),
            Decision::Escalate
        );
        // Flat distribution: high-ish top pick, low confidence -> escalate.
        assert_eq!(
            gate.decide_answer(&choice_answer("q3", 0.9, 0.1)),
            Decision::Escalate
        );
    }

    #[test]
    fn gate_decide_all_preserves_order() {
        let gate = DecisionGate::default();
        let answers = vec![choice_answer("q1", 0.9, 0.9), choice_answer("q2", 0.4, 0.9)];
        let out = gate.decide_all(&answers);
        assert_eq!(
            out,
            vec![
                ("q1".to_string(), Decision::Act),
                ("q2".to_string(), Decision::Escalate),
            ]
        );
    }

    #[test]
    fn noul_top_probability_takes_winning_side() {
        let t = Answer {
            id: "n".to_string(),
            confidence: 0.9,
            act_probability: 0.8,
            kind: AnswerKind::Noul { noul: 0.8 },
        };
        assert!((t.top_probability() - 0.8).abs() < 1e-6);
        let f = Answer {
            id: "n".to_string(),
            confidence: 0.9,
            act_probability: 0.2,
            kind: AnswerKind::Noul { noul: 0.2 },
        };
        assert!((f.top_probability() - 0.8).abs() < 1e-6);
    }
}
