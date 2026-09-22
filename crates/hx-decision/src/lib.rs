//! Typed question/answer schema for Laya, the System-1 decision model.
//!
//! Laya answers **typed questions** about a piece of text and returns
//! **probabilities**, never generated text. The three question types mirror the
//! sidecar API (`POST /predict` with `{"state", "questions"}`):
//!
//! - `choice` — criteria = option list → `{choice, probabilities, confidence}`
//! - `score` — criteria = ordered level list → `{score, probabilities, legend, confidence}`
//! - `noul` — no criteria → `{noul: P(true), confidence}`
//!
//! Every answer also carries `action.act_probability`, and the result carries
//! `usage.input_tokens`. All questions for one decision go in a single forward
//! pass ([`QuestionSet`]); do not loop one question at a time.
//!
//! This crate holds only the schema + validation. The HTTP transport lives in a
//! follow-up chunk (`LayaClient`).

use hx_core::error::{HxError, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// One selectable option in a [`Question::Choice`].
///
/// The `id` is the key used in the answer's `probabilities` map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChoiceOption {
    pub id: String,
    pub description: String,
}

impl ChoiceOption {
    pub fn new(id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
        }
    }
}

/// A typed question posed to the decision model in a single forward pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Question {
    /// Pick (up to `max_options`) from a fixed option list.
    Choice {
        id: String,
        instructions: String,
        criteria: Vec<ChoiceOption>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_options: Option<u32>,
    },
    /// Rate along an ordered level list (index 0 = `levels[0]`).
    Score {
        id: String,
        instructions: String,
        levels: Vec<String>,
    },
    /// Probability that the statement holds, P(true). No criteria.
    Noul { id: String, instructions: String },
}

impl Question {
    /// The question id: key of this question in the request map and of its
    /// answer in the response map.
    pub fn id(&self) -> &str {
        match self {
            Question::Choice { id, .. }
            | Question::Score { id, .. }
            | Question::Noul { id, .. } => id,
        }
    }

    pub fn instructions(&self) -> &str {
        match self {
            Question::Choice { instructions, .. }
            | Question::Score { instructions, .. }
            | Question::Noul { instructions, .. } => instructions,
        }
    }

    /// Structural validation: shapes the sidecar would reject.
    pub fn validate(&self) -> Result<()> {
        if self.id().is_empty() {
            return Err(HxError::Config("question id must not be empty".into()));
        }
        if self.instructions().is_empty() {
            return Err(HxError::Config(format!(
                "question '{}' instructions must not be empty",
                self.id()
            )));
        }
        match self {
            Question::Choice {
                id,
                criteria,
                max_options,
                ..
            } => {
                if criteria.is_empty() {
                    return Err(HxError::Config(format!(
                        "choice question '{id}' needs at least one option"
                    )));
                }
                let mut seen = std::collections::HashSet::new();
                for opt in criteria {
                    if opt.id.is_empty() {
                        return Err(HxError::Config(format!(
                            "choice question '{id}' has an option with an empty id"
                        )));
                    }
                    if !seen.insert(opt.id.as_str()) {
                        return Err(HxError::Config(format!(
                            "choice question '{id}' has a duplicate option id '{}'",
                            opt.id
                        )));
                    }
                }
                if let Some(n) = max_options {
                    if *n == 0 {
                        return Err(HxError::Config(format!(
                            "choice question '{id}' max_options must be >= 1"
                        )));
                    }
                    if (*n as usize) > criteria.len() {
                        return Err(HxError::Config(format!(
                            "choice question '{id}' max_options ({n}) exceeds option count ({})",
                            criteria.len()
                        )));
                    }
                }
            }
            Question::Score { id, levels, .. } => {
                if levels.len() < 2 {
                    return Err(HxError::Config(format!(
                        "score question '{id}' needs at least two levels"
                    )));
                }
            }
            Question::Noul { .. } => {}
        }
        Ok(())
    }
}

/// The full input for one decision: the text state plus every question asked
/// about it in a single forward pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuestionSet {
    pub state: String,
    pub questions: Vec<Question>,
}

impl QuestionSet {
    pub fn new(state: impl Into<String>, questions: Vec<Question>) -> Self {
        Self {
            state: state.into(),
            questions,
        }
    }

    pub fn get(&self, id: &str) -> Option<&Question> {
        self.questions.iter().find(|q| q.id() == id)
    }

    /// Validate the whole set: non-empty state, unique non-empty question ids,
    /// and each question valid.
    pub fn validate(&self) -> Result<()> {
        if self.state.is_empty() {
            return Err(HxError::Config("decision state must not be empty".into()));
        }
        if self.questions.is_empty() {
            return Err(HxError::Config(
                "question set must contain at least one question".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for q in &self.questions {
            if !seen.insert(q.id()) {
                return Err(HxError::Config(format!(
                    "duplicate question id '{}'",
                    q.id()
                )));
            }
            q.validate()?;
        }
        Ok(())
    }

    /// Request body for `POST /predict`: questions as a map keyed by id, which
    /// is the shape the sidecar answers with (`answers[id]`).
    pub fn predict_body(&self) -> Result<serde_json::Value> {
        self.validate()?;
        let mut questions = serde_json::Map::with_capacity(self.questions.len());
        for q in &self.questions {
            let v = serde_json::to_value(q).map_err(|e| {
                HxError::Config(format!("question '{}' is not JSON-clean: {e}", q.id()))
            })?;
            questions.insert(q.id().to_owned(), v);
        }
        Ok(serde_json::json!({
            "state": self.state,
            "questions": questions,
        }))
    }
}

/// The typed answer payload for one question, mirroring the sidecar's
/// `answers[id]` value (minus the `action` wrapper, which lives on [`Answer`]).
///
/// Untagged so the JSON shape matches the sidecar exactly: the presence of
/// `choice`, `score`, or `noul` selects the variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnswerKind {
    Choice {
        choice: String,
        probabilities: IndexMap<String, f32>,
        confidence: f32,
    },
    Score {
        score: f32,
        probabilities: Vec<f32>,
        legend: Vec<String>,
        confidence: f32,
    },
    Noul {
        noul: f32,
        confidence: f32,
    },
}

impl AnswerKind {
    pub fn confidence(&self) -> f32 {
        match self {
            AnswerKind::Choice { confidence, .. }
            | AnswerKind::Score { confidence, .. }
            | AnswerKind::Noul { confidence, .. } => *confidence,
        }
    }

    fn validate(&self, id: &str) -> Result<()> {
        let confidence = self.confidence();
        if !(0.0..=1.0).contains(&confidence) {
            return Err(HxError::Config(format!(
                "answer '{id}' confidence {confidence} is outside [0, 1]"
            )));
        }
        match self {
            AnswerKind::Choice {
                choice,
                probabilities,
                ..
            } => {
                if !probabilities.contains_key(choice) {
                    return Err(HxError::Config(format!(
                        "answer '{id}' choice '{choice}' is missing from probabilities"
                    )));
                }
                for (opt, p) in probabilities {
                    if !(0.0..=1.0).contains(p) {
                        return Err(HxError::Config(format!(
                            "answer '{id}' probability for '{opt}' ({p}) is outside [0, 1]"
                        )));
                    }
                }
            }
            AnswerKind::Score {
                score,
                probabilities,
                legend,
                ..
            } => {
                if probabilities.len() != legend.len() {
                    return Err(HxError::Config(format!(
                        "answer '{id}' probabilities len ({}) != legend len ({})",
                        probabilities.len(),
                        legend.len()
                    )));
                }
                if !(0.0..=(legend.len() as f32 - 1.0)).contains(score) {
                    return Err(HxError::Config(format!(
                        "answer '{id}' score {score} is outside [0, {}]",
                        legend.len() - 1
                    )));
                }
            }
            AnswerKind::Noul { noul, .. } => {
                if !(0.0..=1.0).contains(noul) {
                    return Err(HxError::Config(format!(
                        "answer '{id}' noul {noul} is outside [0, 1]"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// One typed answer: the payload plus the sidecar's `action.act_probability`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Answer {
    pub id: String,
    pub kind: AnswerKind,
    pub act_probability: f32,
}

impl Answer {
    pub fn confidence(&self) -> f32 {
        self.kind.confidence()
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(HxError::Config("answer id must not be empty".into()));
        }
        if !(0.0..=1.0).contains(&self.act_probability) {
            return Err(HxError::Config(format!(
                "answer '{}' act_probability {} is outside [0, 1]",
                self.id, self.act_probability
            )));
        }
        self.kind.validate(&self.id)
    }
}

/// The typed result of one decision: every answer plus billed input tokens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionResult {
    pub answers: Vec<Answer>,
    #[serde(default)]
    pub usage_input_tokens: u64,
}

impl DecisionResult {
    pub fn get(&self, id: &str) -> Option<&Answer> {
        self.answers.iter().find(|a| a.id == id)
    }

    pub fn validate(&self) -> Result<()> {
        if self.answers.is_empty() {
            return Err(HxError::Config("decision result has no answers".into()));
        }
        for a in &self.answers {
            a.validate()?;
        }
        Ok(())
    }

    /// Parse the sidecar's `POST /predict` response shape:
    /// `{"answers": {id: {..., "action": {"act_probability": p}}}, "usage": {"input_tokens": n}}`.
    pub fn from_sidecar_value(v: &serde_json::Value) -> Result<Self> {
        let answers_obj = v
            .get("answers")
            .and_then(|a| a.as_object())
            .ok_or_else(|| HxError::Config("sidecar response has no 'answers' object".into()))?;
        let mut answers = Vec::with_capacity(answers_obj.len());
        for (id, raw) in answers_obj {
            let kind: AnswerKind = serde_json::from_value(raw.clone()).map_err(|e| {
                HxError::Config(format!("answer '{id}' does not match any answer kind: {e}"))
            })?;
            let act_probability = raw
                .get("action")
                .and_then(|a| a.get("act_probability"))
                .and_then(serde_json::Value::as_f64)
                .ok_or_else(|| {
                    HxError::Config(format!("answer '{id}' has no action.act_probability"))
                })? as f32;
            let answer = Answer {
                id: id.clone(),
                kind,
                act_probability,
            };
            answer.validate()?;
            answers.push(answer);
        }
        let usage_input_tokens = v
            .get("usage")
            .and_then(|u| u.get("input_tokens"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let result = Self {
            answers,
            usage_input_tokens,
        };
        result.validate()?;
        Ok(result)
    }
}
