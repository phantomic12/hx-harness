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
//!
//! ## Authentication
//!
//! A daemon that requires a bearer token answers `401` to everything else, so every command here
//! goes through [`connect`], which resolves the token exactly the way the daemon does
//! ([`hx_secrets::resolve_api_token`]: `api.token`, else `HX_API_TOKEN`) and puts it on the client's
//! default headers. Resolving it once per process rather than per request keeps one answer to "what
//! token is this client using", and `HeaderValue::set_sensitive` keeps it out of a `Debug` rendering
//! of the request.
//!
//! One honest limit: this client has no vault, so a config whose `api.token` is a `vault:`
//! reference cannot be resolved here. That is reported rather than silently ignored — the operator
//! is told to put the token in the environment for the CLI, which is the form a script or a
//! container would use anyway.

use anyhow::{bail, Context};
use hx_core::api_auth::API_TOKEN_ENV;
use hx_core::config::Config;
use serde_json::Value;
use std::sync::Arc;

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

/// Everything a daemon-facing command needs: where the daemon is, and a client that can
/// authenticate to it.
///
/// The token is resolved with the same rule the daemon uses, so a deployment cannot end up with a
/// daemon checking one token and its own CLI sending another.
pub fn connect(
    config: &Config,
    explicit: Option<&str>,
) -> anyhow::Result<(reqwest::Client, String)> {
    let base = base_url(config, explicit);

    // The same store set `AppState::build` has: the environment. A vault-backed reference cannot be
    // resolved from here and is reported rather than ignored.
    let secrets = hx_secrets::SecretStores::new().with(Arc::new(hx_secrets::EnvSecrets));
    let token = hx_secrets::resolve_api_token(config, &secrets).context(
        "could not work out the daemon's API token from this config (put it in the environment as \
         HX_API_TOKEN if it lives in the vault, which this command cannot open)",
    )?;

    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = token {
        let mut value =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.expose()))
                .context("the API token is not a valid header value")?;
        // Marked sensitive so a `Debug` of the header map renders `Sensitive` rather than the
        // token: the same reason `Secret`'s own `Debug` is redacted.
        value.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .context("could not build the HTTP client")?;

    Ok((client, base))
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
        // A 401 is the one status whose fix is not in the message the daemon sends — deliberately,
        // because the body must not distinguish "no token" from "wrong token". So the *client* says
        // which two settings to look at, and says nothing about the token itself.
        if status == reqwest::StatusCode::UNAUTHORIZED {
            bail!(
                "{what} failed: 401 — {message}. This daemon requires a bearer token: set \
                 `api.token` in the config, or {API_TOKEN_ENV} in the environment, to the token the \
                 daemon was started with."
            );
        }
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

/// Whether a session's stored trail still matches its recorded digests.
pub async fn audit(client: &reqwest::Client, base: &str, id: &str) -> anyhow::Result<Value> {
    let (_, report) = send(
        client.get(format!("{base}/v1/sessions/{id}/audit")),
        base,
        "the audit check",
    )
    .await?;
    Ok(report)
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
///
/// The **ceiling** is sent explicitly because the route requires it and has no default. This command
/// *is* the terminal, so its ceiling is the full ladder ([`RiskClass::Privileged`]) — the same
/// authority a keypress at a prompt has always had, which is why the value is here and not a flag: a
/// surface that is not the terminal declares its own, and a client that declares nothing is refused
/// rather than quietly granted everything.
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
            .json(&serde_json::json!({
                "option": option,
                "ceiling": hx_core::approval::RiskClass::Privileged.label(),
                "by": by,
            })),
        base,
        "answering an approval",
    )
    .await?;
    Ok(reply)
}

/// Run a fan-out: N child calls across N **distinct** members of one pool.
///
/// `children` is the list of child calls, each an object with `session` (a session id that
/// exists on the daemon, under which the child's usage is recorded) and `prompt`. One reply
/// object comes back with one result per child, in request order; see the route's
/// [`FanOutOutcome`](hx_server::fanout::FanOutOutcome) for the shape.
pub async fn fanout(
    client: &reqwest::Client,
    base: &str,
    children: &[serde_json::Value],
) -> anyhow::Result<Value> {
    let (_, reply) = send(
        client
            .post(format!("{base}/v1/fanout"))
            .json(&serde_json::json!({ "children": children })),
        base,
        "the fan-out",
    )
    .await?;
    Ok(reply)
}

/// Research a question: fan out over the configured backends, fetch and extract the pages they
/// point at, and cite them.
///
/// `body` is built by [`crate::commands::research_body`], so the argument-to-request mapping is
/// tested with the renderings rather than here. The reply is returned as it came: this layer does
/// not re-shape a report whose fields are the pipeline's own.
pub async fn research(client: &reqwest::Client, base: &str, body: &Value) -> anyhow::Result<Value> {
    let (_, reply) = send(
        client.post(format!("{base}/v1/research")).json(body),
        base,
        "the research request",
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
    /// A one-shot HTTP stub that records the request head it received and answers with `status`.
    ///
    /// Hand-rolled over a real socket rather than mocked: the property under test is "this request
    /// carried this header on the wire", and `reqwest::Client`'s default headers have no getter to
    /// assert on — a test that inspected the builder would be agreeing with itself.
    async fn recording_stub(status: &'static str) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let recorded: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let sink = Arc::clone(&recorded);

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                sink.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..read]).to_string());

                let body = r#"{"error":"authentication required"}"#;
                let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        (addr.to_string(), recorded)
    }

    #[tokio::test]
    async fn a_configured_token_is_sent_as_a_bearer_credential_on_the_wire() {
        let (addr, recorded) = recording_stub("200 OK").await;
        let config = hx_core::config::Config::from_yaml("api:\n  token: \"cli-sentinel-2a9f\"\n")
            .expect("config parses");

        let (client, base) = connect(&config, Some(&addr)).expect("client builds");
        client
            .get(format!("{base}/v1/status"))
            .send()
            .await
            .expect("a response");

        let heads = recorded.lock().unwrap().clone();
        assert_eq!(heads.len(), 1, "one request was made");
        assert!(
            heads[0].contains("authorization: Bearer cli-sentinel-2a9f")
                || heads[0].contains("Authorization: Bearer cli-sentinel-2a9f"),
            "the request carried no bearer token:\n{}",
            heads[0]
        );
    }

    #[tokio::test]
    async fn no_configured_token_means_no_authorization_header_at_all() {
        // The loopback-optional rule from the client's side: a daemon that requires nothing must not
        // receive a header, or "no token" would be indistinguishable from "a token" on the wire.
        //
        // The variable is cleared rather than left to the ambient environment: a machine with
        // `HX_API_TOKEN` exported would otherwise make this test pass or fail depending on where it ran.
        std::env::remove_var(hx_core::api_auth::API_TOKEN_ENV);

        let (addr, recorded) = recording_stub("200 OK").await;
        let config = hx_core::config::Config::from_yaml("roles: {}\n").expect("config parses");

        let (client, base) = connect(&config, Some(&addr)).expect("client builds");
        client
            .get(format!("{base}/v1/status"))
            .send()
            .await
            .expect("a response");

        let heads = recorded.lock().unwrap().clone();
        assert_eq!(heads.len(), 1);
        assert!(
            !heads[0].to_lowercase().contains("authorization"),
            "an unconfigured client sent a credential:\n{}",
            heads[0]
        );
    }

    #[tokio::test]
    async fn fanout_posts_the_children_and_returns_the_outcome() {
        // A real loopback listener records the request body so the client cannot agree with itself
        // about what it sent: the wire is the truth.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let recorded: Arc<std::sync::Mutex<String>> = Arc::default();
        let sink = Arc::clone(&recorded);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let read = stream.read(&mut buf).await.unwrap_or(0);
            *sink.lock().unwrap() = String::from_utf8_lossy(&buf[..read]).to_string();
            let body = r#"{"members":["cheap"],"children":[{"Ran":{"model":"cheap"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });

        let config = hx_core::config::Config::from_yaml("roles: {}\n").expect("config parses");
        let (client, base) = connect(&config, Some(&addr.to_string())).expect("client builds");
        let children = vec![
            serde_json::json!({ "session": "ses_1", "prompt": "do a" }),
            serde_json::json!({ "session": "ses_1", "prompt": "do b" }),
        ];
        let outcome = fanout(&client, &base, &children).await.expect("a reply");

        let sent = recorded.lock().unwrap().clone();
        let (_, body) = sent.split_once("\r\n\r\n").expect("a body");
        let parsed: serde_json::Value = serde_json::from_str(body).expect("the body is JSON");
        assert_eq!(parsed["children"][0]["session"], "ses_1");
        assert_eq!(parsed["children"][1]["prompt"], "do b");
        // And the outcome comes back whole, in request order.
        assert_eq!(outcome["members"][0], "cheap");
    }

    #[tokio::test]
    async fn a_401_tells_the_operator_which_setting_to_look_at_without_quoting_the_token() {
        // The daemon's own 401 body deliberately does not distinguish "no token" from "wrong token", so
        // the *client* is where the actionable sentence lives. It must name the settings and never the
        // value.
        let (addr, _) = recording_stub("401 Unauthorized").await;
        let config = hx_core::config::Config::from_yaml("api:\n  token: \"cli-sentinel-2a9f\"\n")
            .expect("config parses");

        let (client, base) = connect(&config, Some(&addr)).expect("client builds");
        let err = audit(&client, &base, "ses_1")
            .await
            .expect_err("a 401 is an error")
            .to_string();

        assert!(err.contains("401"), "{err}");
        assert!(err.contains("api.token"), "{err}");
        assert!(err.contains(hx_core::api_auth::API_TOKEN_ENV), "{err}");
        assert!(!err.contains("cli-sentinel-2a9f"), "{err}");
    }
}
