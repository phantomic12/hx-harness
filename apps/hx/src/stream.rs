//! Reading the daemon's SSE stream as it arrives, so a run is watchable while it happens.
//!
//! ## Why this is a separate module from the request
//!
//! `daemon::chat` awaits the whole reply and hands back one JSON object. This module instead hands
//! back the *events* as they are produced, which is what makes a long turn bearable to watch: a
//! model that has been reading files for forty seconds should say so, not sit silent and then print
//! everything at once.
//!
//! The parsing is deliberately separated from the transport. `apply_line` is a pure function over
//! one line of an SSE body, so the framing rules can be tested without a server, a socket, or a
//! timeout — and framing is exactly where a hand-rolled SSE client goes wrong, because a body that
//! is *almost* right (one newline instead of two) is accepted by no spec-compliant parser and would
//! look like a server bug in the field, not a client bug here.
//!
//! ## What a caller gets
//!
//! Events in the order the run produced them, then exactly one terminal outcome: the reply, or the
//! error the daemon sent. Never both, and never nothing — a stream that ends without either means
//! the connection dropped, and the caller is told so rather than shown a blank success.

use serde_json::Value;

/// One thing that came off the wire.
#[derive(Clone, Debug, PartialEq)]
pub enum Streamed {
    /// A run event, already parsed. The `session` field says which run it belongs to.
    Event { session: String, event: Value },
    /// The run finished and this is its reply.
    Done(Value),
    /// The daemon refused the run, and this is why.
    Failed(String),
}

/// Accumulates SSE fields until a blank line completes the event.
///
/// A frame may carry `event:` and `data:` lines in any order, and a `data:` payload may span several
/// lines (each one joined with a newline, per the spec). The body here is single-line JSON produced
/// by the daemon, but a client that only works against its own server is one proxy away from
/// breaking — so the general shape is implemented rather than the convenient one.
#[derive(Default)]
pub struct SseParser {
    event: Option<String>,
    data: Vec<String>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one line (without its terminator) and get back a frame if this line completed one.
    ///
    /// A blank line is the frame delimiter. Note `line` is compared against `""` *after* a trailing
    /// `\r` is stripped: a stream served over a connection that uses CRLF would otherwise never
    /// terminate a frame, and every event would silently buffer forever.
    pub fn apply_line(&mut self, line: &str) -> Option<Streamed> {
        let line = line.strip_suffix('\r').unwrap_or(line);

        if line.is_empty() {
            return self.take_frame();
        }
        // A comment (`: keepalive`) keeps the connection warm and carries no payload.
        if line.starts_with(':') {
            return None;
        }

        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };

        match field {
            "event" => self.event = Some(value.to_string()),
            "data" => self.data.push(value.to_string()),
            // `id` and `retry` are part of the spec and meaningless here; ignoring them is correct
            // rather than incomplete, and reading them would invent behaviour nothing depends on.
            _ => {}
        }
        None
    }

    /// Complete a frame from whatever has accumulated.
    fn take_frame(&mut self) -> Option<Streamed> {
        let event = self.event.take();
        let data = std::mem::take(&mut self.data);
        if data.is_empty() {
            return None;
        }
        let payload = data.join("\n");

        match event.as_deref() {
            Some("done") => Some(Streamed::Done(
                serde_json::from_str(&payload).unwrap_or(Value::Null),
            )),
            Some("error") => {
                let message = serde_json::from_str::<Value>(&payload)
                    .ok()
                    .and_then(|value| value["error"].as_str().map(str::to_string))
                    .unwrap_or(payload);
                Some(Streamed::Failed(message))
            }
            // An unnamed frame is a run event. A *named* frame we do not know is skipped rather than
            // guessed at: a future daemon adding a name must not make this client print nonsense.
            None => match serde_json::from_str::<Value>(&payload) {
                Ok(value) => Some(Streamed::Event {
                    session: value["session"].as_str().unwrap_or("?").to_string(),
                    event: value["event"].clone(),
                }),
                Err(_) => None,
            },
            Some(_) => None,
        }
    }
}

/// One line of progress for a run event, or `None` for events with nothing to say.
///
/// The point of streaming is that these are *not* the finished reply: they are what is happening.
/// Showing every event verbatim would bury the run in JSON, so the ones a person cares about while
/// waiting get a line and the rest are silent.
pub fn progress_line(event: &Value) -> Option<String> {
    let kind = event["event"].as_str()?;
    match kind {
        "turn_started" => {
            let turn = event["turn"].as_u64().unwrap_or(0);
            Some(format!("turn {turn}"))
        }
        "tool_started" => {
            let name = event["call"]["name"].as_str().unwrap_or("?");
            let args = summarise_args(&event["call"]["arguments"]);
            Some(format!("  → {name}{args}"))
        }
        "tool_finished" => {
            let name = event["call"]["name"].as_str().unwrap_or("?");
            let ok = event["result"]["is_error"] != Value::Bool(true);
            Some(format!("  {} {name}", if ok { "ok" } else { "failed" }))
        }
        "text_delta" => None, // already printed live, as it arrived
        // Inbound platform input: shown as input, never as model output (#77).
        "message_received" => {
            let text = event["text"].as_str().unwrap_or("?");
            Some(format!("< {text}"))
        }
        "turn_finished" => None, // the reply itself carries the outcome
        _ => None,
    }
}

/// A one-line gist of a call's arguments, short enough to sit on one line.
fn summarise_args(args: &Value) -> String {
    let Some(obj) = args.as_object() else {
        return String::new();
    };
    // The first string argument is what a person reads: a path, a command, a pattern.
    let first = obj
        .iter()
        .find(|(_, value)| value.is_string())
        .map(|(key, value)| {
            let raw = value.as_str().unwrap_or("");
            let short: String = raw.chars().take(72).collect();
            format!("{key}={short}")
        });
    match first {
        Some(s) => format!("  {s}"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a whole body, returning the frames it completed.
    ///
    /// Every line is fed, blank ones included: a helper that skipped them would swallow the frame
    /// delimiter, so a two-`data:`-line payload would appear to lose its second line — which looks
    /// exactly like a parser bug and is not one.
    fn feed(parser: &mut SseParser, body: &str) -> Vec<Streamed> {
        body.split('\n')
            .filter_map(|line| parser.apply_line(line))
            .collect::<Vec<_>>()
    }

    #[test]
    fn a_frame_needs_a_blank_line_to_complete() {
        // The framing rule the whole module exists to get right: without the delimiter, the first
        // event is never delivered, no matter how much data arrives.
        let mut parser = SseParser::new();
        assert!(parser.apply_line("data: {\"a\":1}").is_none());
        let frame = parser.apply_line("").expect("the blank line completes it");
        assert_eq!(
            frame,
            Streamed::Event {
                session: "?".to_string(),
                event: Value::Null
            }
        );
    }

    #[test]
    fn a_crlf_stream_still_terminates_frames() {
        // A proxy that terminates lines with CRLF would otherwise buffer every event forever, and
        // the symptom is a stream that hangs with no error — worth a test rather than a comment.
        let mut parser = SseParser::new();
        let frames = feed(
            &mut parser,
            "data: {\"session\":\"ses_1\",\"event\":{\"event\":\"turn_started\",\"turn\":1}}\r\n\r\n",
        );
        assert_eq!(frames.len(), 1, "{frames:?}");
    }

    #[test]
    fn a_run_event_carries_its_session_and_event() {
        let mut parser = SseParser::new();
        let frames = feed(
            &mut parser,
            "data: {\"session\":\"ses_1\",\"event\":{\"event\":\"turn_started\",\"turn\":2}}\n\n",
        );
        match &frames[0] {
            Streamed::Event { session, event } => {
                assert_eq!(session, "ses_1");
                assert_eq!(event["turn"], 2);
            }
            other => panic!("expected a run event, got {other:?}"),
        }
    }

    #[test]
    fn the_done_frame_is_the_reply_and_the_error_frame_is_the_reason() {
        let mut parser = SseParser::new();
        let frames = feed(
            &mut parser,
            "event: done\ndata: {\"reply\":{\"stop\":\"completed\"}}\n\n\
             event: error\ndata: {\"error\":\"prompt is empty\"}\n\n",
        );
        assert_eq!(
            frames[0],
            Streamed::Done(serde_json::json!({"reply":{"stop":"completed"}}))
        );
        assert_eq!(frames[1], Streamed::Failed("prompt is empty".to_string()));
    }

    #[test]
    fn a_keepalive_comment_is_not_a_frame() {
        // Emitting an event per keepalive would make an idle run look busy, and a keepalive that
        // terminated a frame would end a healthy stream early.
        let mut parser = SseParser::new();
        assert!(feed(&mut parser, ": keepalive\n").is_empty());
        assert!(
            parser.apply_line("").is_none(),
            "a comment leaves nothing behind"
        );
    }

    #[test]
    fn an_unknown_named_frame_is_skipped_rather_than_guessed_at() {
        let mut parser = SseParser::new();
        assert!(feed(&mut parser, "event: telemetry\ndata: {\"x\":1}\n\n").is_empty());
    }

    #[test]
    fn a_multi_line_data_payload_joins_with_newlines() {
        // Multi-line means several `data:` fields, per the spec — a bare continuation line is a
        // field of its own and carries no payload. Getting this wrong is a real way to lose half a
        // message from a server that writes its payloads that way.
        let mut parser = SseParser::new();
        let frames = feed(
            &mut parser,
            "event: error\ndata: could not\ndata: start\n\n",
        );
        // Joined with a newline, which is what the spec says each `data:` line contributes — not
        // with a space, which would be this client inventing a convention the server never agreed to.
        assert_eq!(frames[0], Streamed::Failed("could not\nstart".to_string()));
    }

    #[test]
    fn the_done_frame_carries_the_reply_in_the_same_shape_as_the_json_route() {
        // `/v1/chat` returns `ChatReply` flat; the stream wraps it so `done` is distinguishable from
        // a run event. A client that forgot to unwrap printed `session ?` and `0 turn(s)` for a run
        // that had done real work — the fields were all there, one level too deep.
        let mut parser = SseParser::new();
        let frames = feed(
            &mut parser,
            "event: done\ndata: {\"reply\":{\"session_id\":\"ses_1\",\"turns\":2,\"tool_calls\":3,\"stop\":\"completed\"}}\n\n",
        );
        let Streamed::Done(payload) = &frames[0] else {
            panic!("expected done, got {:?}", frames[0]);
        };
        // The envelope is the server's contract; a client unwraps it, and this asserts the shape it
        // unwraps *to* — the same one `render_chat` already expects.
        let reply = payload
            .get("reply")
            .expect("the reply is wrapped on the wire");
        assert_eq!(reply["session_id"], "ses_1");
        assert_eq!(reply["turns"], 2);
        assert_eq!(reply["tool_calls"], 3);
        assert!(reply["stop"].as_str().is_some(), "{reply}");
    }

    #[test]
    fn progress_lines_name_the_thing_that_is_happening() {
        let started = progress_line(&serde_json::json!({
            "event": "tool_started",
            "call": {"name": "read_file", "arguments": {"path": "Cargo.toml"}},
        }))
        .unwrap();
        assert!(started.contains("read_file"), "{started}");
        assert!(started.contains("Cargo.toml"), "{started}");

        // A finished call says whether it worked, because "ok" and "failed" are the two things a
        // person watching needs to distinguish.
        let failed = progress_line(&serde_json::json!({
            "event": "tool_finished",
            "call": {"name": "shell"},
            "result": {"is_error": true},
        }))
        .unwrap();
        assert!(failed.contains("failed"), "{failed}");

        // Text deltas and turn boundaries are rendered elsewhere, so they are not duplicated here.
        assert!(progress_line(&serde_json::json!({"event": "text_delta", "text": "hi"})).is_none());
        assert!(progress_line(&serde_json::json!({"event": "turn_finished"})).is_none());
    }

    #[test]
    fn inbound_input_is_shown_as_input_not_model_output() {
        // #77: a bridged platform message renders as inbound text, visibly distinct from the
        // model's own deltas (which `progress_line` stays silent on).
        let line = progress_line(&serde_json::json!({
            "event": "message_received",
            "conversation": "webhook:main-web/777/",
            "text": "list the repo",
        }))
        .expect("inbound input gets a line");
        assert!(line.contains("list the repo"), "{line}");
        assert_ne!(
            progress_line(&serde_json::json!({"event": "text_delta", "text": "list the repo"})),
            Some(line.clone()),
            "input and output never render the same way"
        );
    }

    #[test]
    fn a_long_argument_is_truncated_to_stay_on_one_line() {
        let long = "x".repeat(500);
        let line = progress_line(&serde_json::json!({
            "event": "tool_started",
            "call": {"name": "shell", "arguments": {"command": long}},
        }))
        .unwrap();
        assert!(line.len() < 120, "kept to one line: {}", line.len());
    }
}
