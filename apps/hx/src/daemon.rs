//! The daemon client.
//!
//! `hx` prints configuration from files, but a *run* belongs to `hxd`: the process that owns the
//! routing table, the session store and the limits. So the chat-shaped commands are clients, exactly
//! like the TUI and the browser will be, and this module is that client — the HTTP surface is the
//! only way in.
//!
//! Every failure here says which of two things went wrong: the daemon is not there (an actionable
//! "start it with …"), or the daemon answered with an error of its own (which is quoted, not
//! paraphrased — the daemon's message is usually better than one this layer could invent).

use anyhow::{bail, Context};
use hx_core::config::Config;
use serde_json::Value;

/// Where to reach the daemon: `--daemon`, else the config, else the documented default.
///
/// `daemon.http_addr` is a bare `host:port` — there is no scheme in the config because the daemon
/// serves one protocol — so the scheme is added here rather than demanded from every deployment.
pub fn base_url(config: &Config, explicit: Option<&str>) -> String {
    let raw = match explicit {
        Some(url) => url.to_string(),
        None => config.daemon.http_addr.clone(),
    };

    if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.trim_end_matches('/').to_string()
    } else {
        format!("http://{}", raw.trim_end_matches('/'))
    }
}

async fn send(
    request: reqwest::RequestBuilder,
    base: &str,
    what: &str,
) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let response = request.send().await.map_err(|err| {
        anyhow::anyhow!(
            "could not reach the daemon at {base} ({err}). Start it with `hxd --config <config>`, \
             or point this command elsewhere with --daemon"
        )
    })?;

    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| format!("{what}: the daemon's reply could not be read"))?;

    let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text.clone()));

    if !status.is_success() {
        // The daemon's own words: it knows why, this layer does not.
        let message = body
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or(text);
        bail!("{what} failed: {} — {message}", status.as_u16());
    }

    Ok((status, body))
}

/// Run one prompt against one session.
pub async fn chat(client: &reqwest::Client, base: &str, body: &Value) -> anyhow::Result<Value> {
    let (_, reply) = send(
        client.post(format!("{base}/v1/chat")).json(body),
        base,
        "the run",
    )
    .await?;

    if reply.get("session_id").is_none() {
        bail!("the daemon answered a run with something that is not a run: {reply}");
    }
    Ok(reply)
}

/// Run a chat and hand each event to `on_event` as it arrives, returning the reply.
///
/// Unlike [`chat`], this does not buffer the whole response: it asks the daemon for the SSE form and
/// parses frames off the socket, so a caller can render a turn while it is still running.
pub async fn chat_stream(
    client: &reqwest::Client,
    base: &str,
    body: &Value,
    mut on_event: impl FnMut(&crate::stream::Streamed),
) -> anyhow::Result<Value> {
    use futures::StreamExt;

    let response = client
        .post(format!("{base}/v1/chat/stream"))
        .json(body)
        .send()
        .await
        .map_err(|err| anyhow::anyhow!("connecting to {base}: {err}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        bail!("the daemon refused the run ({status}): {text}");
    }

    let mut parser = crate::stream::SseParser::new();
    let mut pending = String::new();
    let mut bytes = response.bytes_stream();
    let mut outcome: Option<Value> = None;

    while let Some(chunk) = bytes.next().await {
        let chunk = chunk.map_err(|err| anyhow::anyhow!("reading the run's stream: {err}"))?;
        pending.push_str(&String::from_utf8_lossy(&chunk));

        // Only whole lines are parsed: a frame split across two TCP chunks must not be parsed as
        // half a frame, which is the same rule the provider's stream reader follows.
        while let Some(newline) = pending.find('\n') {
            let line: String = pending.drain(..=newline).collect();
            let line = line.strip_suffix('\n').unwrap_or(&line);
            if let Some(frame) = parser.apply_line(line) {
                match &frame {
                    crate::stream::Streamed::Done(payload) => {
                        // The `done` event wraps the reply (`{"reply": {...}}`) so that the terminal
                        // frame is distinguishable from a run event on the wire; `/v1/chat` returns
                        // the reply flat. Unwrapping here keeps both paths handing the same shape to
                        // `render_chat`, which is what stops this command from printing `session ?`.
                        outcome = Some(match payload.get("reply") {
                            Some(inner) => inner.clone(),
                            None => payload.clone(),
                        });
                    }
                    crate::stream::Streamed::Failed(message) => {
                        bail!("the run failed: {message}")
                    }
                    crate::stream::Streamed::Event { .. } => {}
                }
                on_event(&frame);
            }
        }
    }

    // A stream that ends without a reply is a dropped connection, not a completed run: saying so is
    // the difference between a failed run and a silent empty success.
    outcome.ok_or_else(|| {
        anyhow::anyhow!("the daemon's stream ended without a reply (connection dropped mid-run)")
    })
}

/// The sessions the daemon knows about.
pub async fn sessions(client: &reqwest::Client, base: &str, limit: usize) -> anyhow::Result<Value> {
    let (_, list) = send(
        client.get(format!("{base}/v1/sessions?limit={limit}")),
        base,
        "listing sessions",
    )
    .await?;
    Ok(list)
}

/// One session's record, totals and dangling calls.
pub async fn session(
    client: &reqwest::Client,
    base: &str,
    id: &str,
    transcript: bool,
) -> anyhow::Result<Value> {
    let (_, session) = send(
        client.get(format!("{base}/v1/sessions/{id}?transcript={transcript}")),
        base,
        "reading the session",
    )
    .await?;
    Ok(session)
}

/// The questions a client could answer, from the daemon's own queue.
///
/// Whole requests, not a summary of them: the daemon's `/v1/approvals` hands over the same
/// `ApprovalRequest` the loop asked about, targets and reversibility included, and a client that
/// re-summarised it would be a client inventing a second opinion about what is being asked.
pub async fn approvals(
    client: &reqwest::Client,
    base: &str,
    session: Option<&str>,
) -> anyhow::Result<Value> {
    let url = match session {
        Some(id) => format!("{base}/v1/approvals?session={id}"),
        None => format!("{base}/v1/approvals"),
    };
    let (_, list) = send(client.get(url), base, "listing approvals").await?;
    Ok(list)
}

/// Answer one waiting question.
///
/// `by` travels into the audit trail, which is why it is a parameter rather than a constant here: an
/// answer typed in a terminal and a tap on a phone must not look alike afterwards.
pub async fn approve(
    client: &reqwest::Client,
    base: &str,
    id: &str,
    option: &str,
    by: &str,
) -> anyhow::Result<Value> {
    let (_, reply) = send(
        client
            .post(format!("{base}/v1/approvals/{id}"))
            .json(&serde_json::json!({ "option": option, "by": by })),
        base,
        "answering an approval",
    )
    .await?;
    Ok(reply)
}

/// A session's transcript as a document.
pub async fn export(
    client: &reqwest::Client,
    base: &str,
    id: &str,
    format: &str,
) -> anyhow::Result<String> {
    let url = format!("{base}/v1/sessions/{id}/export?format={format}");
    let response = client.get(url).send().await.map_err(|err| {
        anyhow::anyhow!(
            "could not reach the daemon at {base} ({err}). Start it with `hxd --config <config>`, \
             or point this command elsewhere with --daemon"
        )
    })?;

    let status = response.status();
    let text = response.text().await.context("reading the export")?;

    if !status.is_success() {
        let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let message = parsed
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or(&text)
            .to_string();
        bail!("the export failed: {} — {message}", status.as_u16());
    }

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(http_addr: &str) -> Config {
        let mut config = Config::default();
        config.daemon.http_addr = http_addr.to_string();
        config
    }

    #[test]
    fn an_explicit_daemon_wins_and_gets_a_scheme() {
        let config = config_with("127.0.0.1:9999");
        assert_eq!(
            base_url(&config, Some("192.168.1.5:8799")),
            "http://192.168.1.5:8799"
        );
        // A URL that already carries one is left alone, including a trailing slash.
        assert_eq!(
            base_url(&config, Some("http://box:8799/")),
            "http://box:8799"
        );
        assert_eq!(
            base_url(&config, Some("https://hx.example.com")),
            "https://hx.example.com"
        );
    }

    #[test]
    fn the_config_supplies_the_default_address() {
        assert_eq!(
            base_url(&config_with("127.0.0.1:8799"), None),
            "http://127.0.0.1:8799"
        );
    }
}
