//! The [`LayaClient`] HTTP transport to the Laya decision sidecar.
//!
//! Talks to the loopback sidecar (`examples/laya-sidecar.py`) over `reqwest`. All failures map
//! onto [`hx_core::error::HxError::Decision`] so a sidecar that is down, refuses the
//! connection, or returns a non-success status is surfaced with the sidecar URL named.

use std::time::Duration;

use hx_core::error::{HxError, Result};
use serde_json::Value;

use crate::{DecisionResult, QuestionSet};

/// A loopback client for the Laya decision sidecar.
#[derive(Clone, Debug)]
pub struct LayaClient {
    base_url: String,
    http: reqwest::Client,
}

impl LayaClient {
    /// Build a client for the sidecar at `base_url` (e.g. `http://127.0.0.1:8770`).
    pub fn new(base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client builds");
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    /// `GET /health`; `Ok(())` when the sidecar answers and its status is 2xx.
    pub async fn health(&self) -> Result<()> {
        let url = format!("{}/health", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| HxError::Decision(format!("sidecar unreachable at {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(HxError::Decision(format!(
                "sidecar /health at {url} returned {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// `POST /predict` a whole [`QuestionSet`] in one forward pass, returning the typed decisions.
    pub async fn predict(&self, questions: &QuestionSet) -> Result<DecisionResult> {
        let url = format!("{}/predict", self.base_url);
        let body = questions
            .predict_body()
            .map_err(|e| HxError::Decision(format!("building /predict body: {e}")))?;
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| HxError::Decision(format!("sidecar predict at {url} failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(HxError::Decision(format!(
                "sidecar predict at {url} returned {}",
                resp.status()
            )));
        }
        let value: Value = resp.json().await.map_err(|e| {
            HxError::Decision(format!("sidecar predict JSON at {url} invalid: {e}"))
        })?;
        DecisionResult::from_sidecar_value(&value).map_err(|e| {
            HxError::Decision(format!("sidecar predict response at {url} unusable: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChoiceOption, Question};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A mock sidecar: an axum-free raw tokio listener that answers /health and /predict.
    /// No Python needed.
    struct MockSidecar {
        addr: String,
    }

    impl MockSidecar {
        async fn spawn() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                loop {
                    let (mut sock, _) = listener.accept().await.unwrap();
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    // read until blank line ends the headers
                    let _ = sock.read(&mut tmp).await;
                    buf.extend_from_slice(&tmp[..]);
                    let request = String::from_utf8_lossy(&buf).to_string();
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = if path == "/health" {
                        "{\"ok\":true,\"model\":\"laya\"}".to_string()
                    } else {
                        // /predict: one choice answer with a clear winner
                        "{\"answers\":{\"q1\":{\"choice\":\"a\",\"probabilities\":{\"a\":0.9,\"b\":0.1},\"confidence\":0.8,\"action\":{\"act_probability\":0.9}}},\"usage\":{\"input_tokens\":10}}"
                            .to_string()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.flush().await;
                }
            });
            MockSidecar { addr }
        }
    }

    #[tokio::test]
    async fn health_reports_ok_when_sidecar_up() {
        let mock = MockSidecar::spawn().await;
        let client = LayaClient::new(&mock.addr);
        client.health().await.expect("health should pass");
    }

    #[tokio::test]
    async fn predict_returns_typed_answers_in_one_pass() {
        let mock = MockSidecar::spawn().await;
        let client = LayaClient::new(&mock.addr);
        let q = Question::Choice {
            id: "q1".to_string(),
            instructions: "pick a".to_string(),
            criteria: vec![
                ChoiceOption::new("a", "option a"),
                ChoiceOption::new("b", "option b"),
            ],
            max_options: None,
        };
        let qs = QuestionSet::new("the state", vec![q]);
        let res = client.predict(&qs).await.expect("predict should pass");
        assert_eq!(res.usage_input_tokens, 10);
        let ans = res.get("q1").expect("answer q1 present");
        assert_eq!(ans.act_probability, 0.9);
    }

    #[tokio::test]
    async fn predict_fails_when_sidecar_down() {
        // A port that is not listening.
        let client = LayaClient::new("http://127.0.0.1:1");
        let qs = QuestionSet::new("x", vec![]);
        assert!(client.predict(&qs).await.is_err());
    }
}
