//! Schema round-trip + validation tests for `hx-decision`.
//!
//! The JSON fixtures mirror the sidecar shapes from PLAN-LAYA.md:
//! `POST /predict {"state", "questions"}` → `{"answers": {id: {...}}, "usage": {"input_tokens": n}}`.

use hx_decision::{Answer, AnswerKind, ChoiceOption, DecisionResult, Question, QuestionSet};
use indexmap::IndexMap;

fn choice_question() -> Question {
    Question::Choice {
        id: "route".into(),
        instructions: "Where should this request go?".into(),
        criteria: vec![
            ChoiceOption::new("retry", "retry the same member"),
            ChoiceOption::new("failover", "draw another member"),
        ],
        max_options: Some(1),
    }
}

fn score_question() -> Question {
    Question::Score {
        id: "urgency".into(),
        instructions: "How urgent is this?".into(),
        levels: vec!["low".into(), "medium".into(), "high".into()],
    }
}

fn noul_question() -> Question {
    Question::Noul {
        id: "should_act".into(),
        instructions: "Should the agent act now?".into(),
    }
}

#[test]
fn choice_question_json_round_trip() {
    let q = choice_question();
    let v = serde_json::to_value(&q).unwrap();
    assert_eq!(v["type"], "choice");
    assert_eq!(v["id"], "route");
    assert_eq!(v["criteria"].as_array().unwrap().len(), 2);
    assert_eq!(v["max_options"], 1);
    let back: Question = serde_json::from_value(v).unwrap();
    assert_eq!(back, q);
    back.validate().unwrap();
}

#[test]
fn choice_question_omits_max_options_when_none() {
    let q = Question::Choice {
        id: "c".into(),
        instructions: "Pick.".into(),
        criteria: vec![ChoiceOption::new("a", "A")],
        max_options: None,
    };
    let v = serde_json::to_value(&q).unwrap();
    assert!(v.get("max_options").is_none());
    let back: Question = serde_json::from_value(v).unwrap();
    assert_eq!(back, q);
}

#[test]
fn score_question_json_round_trip() {
    let q = score_question();
    let v = serde_json::to_value(&q).unwrap();
    assert_eq!(v["type"], "score");
    assert_eq!(v["levels"], serde_json::json!(["low", "medium", "high"]));
    let back: Question = serde_json::from_value(v).unwrap();
    assert_eq!(back, q);
    back.validate().unwrap();
}

#[test]
fn noul_question_json_round_trip() {
    let q = noul_question();
    let v = serde_json::to_value(&q).unwrap();
    assert_eq!(v["type"], "noul");
    assert!(v.get("criteria").is_none());
    let back: Question = serde_json::from_value(v).unwrap();
    assert_eq!(back, q);
    back.validate().unwrap();
}

#[test]
fn question_type_tag_selects_variant() {
    let raw = serde_json::json!({
        "type": "score",
        "id": "s",
        "instructions": "Rate it.",
        "levels": ["bad", "good"],
    });
    let q: Question = serde_json::from_value(raw).unwrap();
    assert!(matches!(q, Question::Score { .. }));
    assert_eq!(q.id(), "s");
    assert_eq!(q.instructions(), "Rate it.");
}

#[test]
fn question_set_predict_body_keys_questions_by_id() {
    let set = QuestionSet::new(
        "provider 500 on /v1/chat",
        vec![choice_question(), score_question(), noul_question()],
    );
    let body = set.predict_body().unwrap();
    assert_eq!(body["state"], "provider 500 on /v1/chat");
    let questions = body["questions"].as_object().unwrap();
    assert_eq!(questions.len(), 3);
    assert_eq!(questions["route"]["type"], "choice");
    assert_eq!(questions["urgency"]["type"], "score");
    assert_eq!(questions["should_act"]["type"], "noul");
}

#[test]
fn question_set_get_finds_by_id() {
    let set = QuestionSet::new("s", vec![choice_question(), noul_question()]);
    assert!(set.get("route").is_some());
    assert!(set.get("missing").is_none());
}

#[test]
fn question_set_rejects_empty_state_and_empty_questions() {
    assert!(QuestionSet::new("", vec![noul_question()])
        .validate()
        .is_err());
    assert!(QuestionSet::new("s", vec![]).validate().is_err());
}

#[test]
fn question_set_rejects_duplicate_ids() {
    let set = QuestionSet::new("s", vec![noul_question(), noul_question()]);
    let err = set.validate().unwrap_err();
    assert!(err.to_string().contains("duplicate question id"));
}

#[test]
fn choice_validation_catches_bad_criteria() {
    // Empty criteria.
    let q = Question::Choice {
        id: "c".into(),
        instructions: "Pick.".into(),
        criteria: vec![],
        max_options: None,
    };
    assert!(q.validate().is_err());

    // Duplicate option ids.
    let q = Question::Choice {
        id: "c".into(),
        instructions: "Pick.".into(),
        criteria: vec![ChoiceOption::new("a", "A"), ChoiceOption::new("a", "A2")],
        max_options: None,
    };
    assert!(q.validate().is_err());

    // max_options of zero, and max_options beyond the option count.
    let mk = |n| Question::Choice {
        id: "c".into(),
        instructions: "Pick.".into(),
        criteria: vec![ChoiceOption::new("a", "A")],
        max_options: Some(n),
    };
    assert!(mk(0).validate().is_err());
    assert!(mk(2).validate().is_err());
    assert!(mk(1).validate().is_ok());
}

#[test]
fn score_validation_needs_two_levels() {
    let q = Question::Score {
        id: "s".into(),
        instructions: "Rate.".into(),
        levels: vec!["only".into()],
    };
    assert!(q.validate().is_err());
}

#[test]
fn answer_kind_untagged_disambiguation() {
    // Choice: presence of `choice` selects the variant.
    let raw = serde_json::json!({
        "choice": "failover",
        "probabilities": {"retry": 0.25, "failover": 0.75},
        "confidence": 0.8,
    });
    let kind: AnswerKind = serde_json::from_value(raw).unwrap();
    assert!(matches!(kind, AnswerKind::Choice { .. }));
    assert!((kind.confidence() - 0.8).abs() < 1e-6);

    // Score.
    let raw = serde_json::json!({
        "score": 1.7,
        "probabilities": [0.1, 0.3, 0.6],
        "legend": ["low", "medium", "high"],
        "confidence": 0.6,
    });
    let kind: AnswerKind = serde_json::from_value(raw).unwrap();
    assert!(matches!(kind, AnswerKind::Score { .. }));

    // Noul.
    let raw = serde_json::json!({"noul": 0.92, "confidence": 0.9});
    let kind: AnswerKind = serde_json::from_value(raw).unwrap();
    assert!(matches!(kind, AnswerKind::Noul { .. }));
}

#[test]
fn decision_result_json_round_trip() {
    let mut probs = IndexMap::new();
    probs.insert("retry".to_string(), 0.25);
    probs.insert("failover".to_string(), 0.75);
    let result = DecisionResult {
        answers: vec![
            Answer {
                id: "route".into(),
                kind: AnswerKind::Choice {
                    choice: "failover".into(),
                    probabilities: probs,
                    confidence: 0.8,
                },
                act_probability: 0.9,
            },
            Answer {
                id: "should_act".into(),
                kind: AnswerKind::Noul {
                    noul: 0.92,
                    confidence: 0.9,
                },
                act_probability: 0.95,
            },
        ],
        usage_input_tokens: 128,
    };
    let v = serde_json::to_value(&result).unwrap();
    let back: DecisionResult = serde_json::from_value(v).unwrap();
    assert_eq!(back, result);
    back.validate().unwrap();
    assert_eq!(result.get("route").unwrap().confidence(), 0.8_f32);
    assert!(result.get("missing").is_none());
}

#[test]
fn from_sidecar_value_parses_all_three_kinds() {
    let raw = serde_json::json!({
        "answers": {
            "route": {
                "choice": "failover",
                "probabilities": {"retry": 0.25, "failover": 0.75},
                "confidence": 0.8,
                "action": {"act_probability": 0.9},
            },
            "urgency": {
                "score": 1.7,
                "probabilities": [0.1, 0.3, 0.6],
                "legend": ["low", "medium", "high"],
                "confidence": 0.6,
                "action": {"act_probability": 0.5},
            },
            "should_act": {
                "noul": 0.92,
                "confidence": 0.9,
                "action": {"act_probability": 0.95},
            },
        },
        "usage": {"input_tokens": 128},
    });
    let result = DecisionResult::from_sidecar_value(&raw).unwrap();
    assert_eq!(result.answers.len(), 3);
    assert_eq!(result.usage_input_tokens, 128);

    let route = result.get("route").unwrap();
    assert!((route.act_probability - 0.9).abs() < 1e-6);
    match &route.kind {
        AnswerKind::Choice {
            choice,
            probabilities,
            confidence,
        } => {
            assert_eq!(choice, "failover");
            assert_eq!(probabilities.len(), 2);
            assert!((*confidence - 0.8).abs() < 1e-6);
        }
        other => panic!("expected choice, got {other:?}"),
    }
    assert!(matches!(
        result.get("urgency").unwrap().kind,
        AnswerKind::Score { .. }
    ));
    assert!(matches!(
        result.get("should_act").unwrap().kind,
        AnswerKind::Noul { .. }
    ));
}

#[test]
fn from_sidecar_value_tolerates_missing_usage() {
    let raw = serde_json::json!({
        "answers": {
            "should_act": {
                "noul": 0.5,
                "confidence": 0.5,
                "action": {"act_probability": 0.5},
            },
        },
    });
    let result = DecisionResult::from_sidecar_value(&raw).unwrap();
    assert_eq!(result.usage_input_tokens, 0);
}

#[test]
fn from_sidecar_value_rejects_missing_answers_and_action() {
    let no_answers = serde_json::json!({"usage": {"input_tokens": 1}});
    assert!(DecisionResult::from_sidecar_value(&no_answers).is_err());

    let no_action = serde_json::json!({
        "answers": {"q": {"noul": 0.5, "confidence": 0.5}},
        "usage": {"input_tokens": 1},
    });
    let err = DecisionResult::from_sidecar_value(&no_action).unwrap_err();
    assert!(err.to_string().contains("act_probability"));

    let unknown_kind = serde_json::json!({
        "answers": {"q": {"bogus": 1, "action": {"act_probability": 0.5}}},
        "usage": {"input_tokens": 1},
    });
    assert!(DecisionResult::from_sidecar_value(&unknown_kind).is_err());
}

#[test]
fn answer_validation_catches_out_of_range_fields() {
    let bad_confidence = Answer {
        id: "q".into(),
        kind: AnswerKind::Noul {
            noul: 0.5,
            confidence: 1.5,
        },
        act_probability: 0.5,
    };
    assert!(bad_confidence.validate().is_err());

    let bad_act = Answer {
        id: "q".into(),
        kind: AnswerKind::Noul {
            noul: 0.5,
            confidence: 0.5,
        },
        act_probability: 2.0,
    };
    assert!(bad_act.validate().is_err());

    // Choice naming an option absent from probabilities.
    let mut probs = IndexMap::new();
    probs.insert("a".to_string(), 1.0);
    let bad_choice = Answer {
        id: "q".into(),
        kind: AnswerKind::Choice {
            choice: "b".into(),
            probabilities: probs,
            confidence: 0.5,
        },
        act_probability: 0.5,
    };
    assert!(bad_choice.validate().is_err());

    // Score with legend/probabilities length mismatch.
    let bad_score = Answer {
        id: "q".into(),
        kind: AnswerKind::Score {
            score: 0.0,
            probabilities: vec![1.0],
            legend: vec!["low".into(), "high".into()],
            confidence: 0.5,
        },
        act_probability: 0.5,
    };
    assert!(bad_score.validate().is_err());
}
