//! The server half, driven by a hand-rolled MCP client over a real pipe.
//!
//! ## What is real here
//!
//! `tests/support/fake_mcp_server.rs` is a hand-rolled MCP *server* this crate's client half is
//! tested against. This file is the same idea in reverse: a hand-rolled MCP **client** — newline-
//! delimited JSON-RPC 2.0, written here, on the pipes of a real child process — driving the **real
//! server binary** (`src/bin/mcp_server.rs`, found through `CARGO_BIN_EXE_hx-mcp-server`). Nothing in
//! this file is a mock: the framing, the handshake, the process spawn and the shutdown all run for
//! real, and the tool the client calls is `hx`'s own `read_file`/`delete` acting on a real temporary
//! directory through the real `LocalHost`.
//!
//! The client is deliberately strict rather than forgiving: a line it cannot parse, a response to a
//! request it did not make, or a reply to a call it did not send fails the test with the offending
//! line in the message. A client that shrugged those off would let the server send anything and still
//! pass.
//!
//! ## The property under test
//!
//! **A call that needs approval is refused, and nothing is left that a person could answer.** The
//! first half is on the wire: the result is an error whose text names the approval, the tool, the
//! risk and the two ways to allow it. The second half is read from the server's *own* approval
//! session, through the `--report` file the binary writes when the connection ends — because
//! "no approval request was raised" is a fact about an object inside the server process, and the
//! report is how a client-side test can observe it rather than infer it from a message.
//!
//! Every test also has a control, because a refusal proves nothing on its own: the same tool under a
//! policy that allows it runs, and a `delete` that is refused leaves the file it named exactly where
//! it was.
//!
//! ## Bounded waits, and no sleeps
//!
//! The client reads each reply with `recv_timeout` and fails with the server's stderr attached, so a
//! server that wedges produces a readable failure rather than a hung test. Nothing here sleeps to
//! "give the server a moment": a wait is always a wait *for something*, bounded, with a message.

use hx_mcp::default_registry;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The binary under test. `[[bin]] hx-mcp-server` in `Cargo.toml` is what makes cargo build it and
/// export this variable to the test process.
const SERVER: &str = env!("CARGO_BIN_EXE_hx-mcp-server");

/// How long any single wait may take before the test fails with the server's own stderr attached.
const WAIT: Duration = Duration::from_secs(60);

/// A distinctive string that travels *through* a tool call. If it ever appeared on the server's
/// stderr, this file's last test would say so.
const SENTINEL: &str = "hx-mcp-server-sentinel-value-that-must-not-reach-stderr";

/// A scratch directory, and the report file inside it.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("a temp dir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn report(&self) -> PathBuf {
        self.path("report.json")
    }

    /// A file inside the workspace, with contents the test chose.
    fn file(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, contents).expect("the fixture writes a file");
        path
    }
}

/// What the server wrote to its report file when the connection ended.
#[derive(Debug)]
struct Report {
    raw: Value,
}

impl Report {
    fn read(path: &Path) -> Self {
        let text = std::fs::read_to_string(path).unwrap_or_else(|err| {
            panic!("the server wrote no report at {}: {err}", path.display())
        });
        Self {
            raw: serde_json::from_str(&text)
                .unwrap_or_else(|err| panic!("the report is not JSON ({err}): {text}")),
        }
    }

    fn outstanding_approval(&self) -> bool {
        self.raw["outstanding_approval"]
            .as_bool()
            .expect("the report says whether a request was outstanding")
    }

    fn counter(&self, name: &str) -> u64 {
        self.raw[name]
            .as_u64()
            .unwrap_or_else(|| panic!("the report has no {name}: {}", self.raw))
    }
}

/// A hand-rolled MCP client over the pipes of a real server process.
struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    /// One line of the server's stdout per message, read on its own thread so a reply that never
    /// comes is a timeout rather than a hang.
    replies: Receiver<String>,
    /// Everything the server has written to stderr so far.
    stderr: Arc<Mutex<String>>,
    next_id: i64,
    fixture_report: PathBuf,
}

impl Client {
    /// Spawn the server with the given extra arguments, over a real pipe.
    fn spawn(fixture: &Fixture, args: &[&str]) -> Self {
        let report = fixture.report();
        let mut command = Command::new(SERVER);
        command
            .arg("--workspace")
            .arg(fixture.dir.path())
            .arg("--report")
            .arg(&report)
            .args(args)
            // stdout is the wire and stderr is drained separately; neither is inherited.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().expect("the server binary starts");
        let stdin = child.stdin.take().expect("a stdin pipe");
        let stdout = child.stdout.take().expect("a stdout pipe");
        let stderr_pipe = child.stderr.take().expect("a stderr pipe");

        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Dropping the sender is what tells the test the server's stdout closed.
        });

        let stderr = Arc::new(Mutex::new(String::new()));
        {
            let sink = Arc::clone(&stderr);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr_pipe).lines().map_while(Result::ok) {
                    let mut sink = sink.lock().expect("the stderr sink");
                    sink.push_str(&line);
                    sink.push('\n');
                }
            });
        }

        Self {
            child,
            stdin: Some(stdin),
            replies,
            stderr,
            next_id: 1,
            fixture_report: report,
        }
    }

    fn stderr(&self) -> String {
        self.stderr.lock().expect("the stderr sink").clone()
    }

    /// The next line the server wrote, whatever it is. Used by the malformed-frame tests, which are
    /// about the *absence* of a reply as much as its shape.
    fn next_line(&mut self) -> Option<String> {
        match self.replies.recv_timeout(WAIT) {
            Ok(line) => Some(line),
            // A closed channel is the server having closed its stdout, which is how the EOF test
            // observes a shutdown. Not an error.
            Err(RecvTimeoutError::Disconnected) => None,
            Err(RecvTimeoutError::Timeout) => panic!(
                "the server wrote nothing for {}s. Its stderr:\n{}",
                WAIT.as_secs(),
                self.stderr()
            ),
        }
    }

    /// Send a request and return its response, failing on anything that is not a reply to *this*
    /// request.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.write_line(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));

        loop {
            let line = self
                .next_line()
                .unwrap_or_else(|| panic!("the server closed stdout before answering {method}"));
            let message: Value = serde_json::from_str(&line).unwrap_or_else(|err| {
                panic!("the server wrote a line that is not JSON ({err}): {line}")
            });
            match message.get("id").and_then(Value::as_i64) {
                Some(got) if got == id => return message,
                // A notification: the server may send them, and they carry no id.
                None if message.get("method").is_some() => continue,
                other => panic!(
                    "the server answered something this client never asked ({other:?} for id {id}): \
                     {line}"
                ),
            }
        }
    }

    /// Send a request and return its `result`, failing if the protocol answered with an error.
    fn result(&mut self, method: &str, params: Value) -> Value {
        let message = self.request(method, params);
        match message.get("error") {
            Some(error) => panic!("{method} was answered with a protocol error: {error}"),
            None => message.get("result").cloned().unwrap_or_else(|| {
                panic!("{method} was answered with neither a result nor an error: {message}")
            }),
        }
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.write_line(&json!({ "jsonrpc": "2.0", "method": method, "params": params }));
    }

    fn write_line(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("the server is still connected");
        writeln!(stdin, "{message}").expect("the server's stdin accepts a line");
        stdin.flush().expect("the line reaches the server");
    }

    /// The MCP handshake, as a client performs it.
    fn handshake(&mut self) -> Value {
        let result = self.result(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "hx-mcp-test-client", "version": "0" },
            }),
        );
        self.notify("notifications/initialized", json!({}));
        result
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        self.result(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }

    /// End the connection the way a client does — close the pipe — and wait for the server to exit.
    fn finish(mut self) -> Finished {
        drop(self.stdin.take());

        // The server's stdout closing is the signal that it is done. Bounded, and the failure says
        // what the server last wrote rather than hanging.
        let mut closed = false;
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if matches!(
                self.replies.recv_timeout(Duration::from_millis(0)),
                Err(RecvTimeoutError::Disconnected)
            ) {
                closed = true;
                break;
            }
            std::thread::yield_now();
        }
        assert!(
            closed,
            "the server kept its stdout open for {}s after the pipe closed. Its stderr:\n{}",
            WAIT.as_secs(),
            self.stderr()
        );

        let status = self.child.wait().expect("the server process is reaped");
        let stderr = self.stderr();
        Finished {
            status,
            stderr,
            report: Report::read(&self.fixture_report),
        }
    }
}

/// A finished server: how it exited, what it wrote to stderr, and what its report says.
struct Finished {
    status: std::process::ExitStatus,
    stderr: String,
    report: Report,
}

impl Finished {
    /// The exit and the silence every test expects: a server that answered every request, wrote no
    /// tool output to stderr, and left nothing parked.
    fn assert_clean(&self) {
        assert!(
            self.status.success(),
            "the server exited with {}; stderr:\n{}",
            self.status,
            self.stderr
        );
    }
}

/// A workspace with a readable file and a file a `delete` could take.
fn fixture_with_notes() -> (Fixture, PathBuf, PathBuf) {
    let fixture = Fixture::new();
    let notes = fixture.file("notes.txt", SENTINEL);
    let doomed = fixture.file("doomed.txt", "still here");
    (fixture, notes, doomed)
}

#[test]
fn the_tool_list_is_the_registrys_own_tools_and_schemas() {
    let fixture = Fixture::new();
    let mut client = Client::spawn(&fixture, &[]);
    client.handshake();

    let listed = client.result("tools/list", json!({}));
    let tools = listed["tools"].as_array().expect("tools is an array");

    // The expectation is the registry's own description, built here from the same function the
    // binary calls — not a second hand-written list that would agree with itself forever.
    let expected = default_registry().describe();
    assert_eq!(
        tools.len(),
        expected.len(),
        "the server advertises the registry's tools: {listed}"
    );

    for info in &expected {
        let advertised = tools
            .iter()
            .find(|tool| tool["name"] == info.name)
            .unwrap_or_else(|| panic!("`{}` is missing from the wire: {listed}", info.name));
        assert_eq!(
            advertised["inputSchema"], info.schema,
            "the schema for `{}` is the one the tool declared",
            info.name
        );
        assert_eq!(advertised["description"], info.description, "{}", info.name);
    }

    // And the tool the tests below call really does take the argument they send it.
    let read_file = tools
        .iter()
        .find(|tool| tool["name"] == "read_file")
        .expect("read_file is advertised");
    assert_eq!(
        read_file["inputSchema"]["properties"]["path"]["type"],
        "string"
    );

    let finished = client.finish();
    finished.assert_clean();
}

#[test]
fn a_read_only_call_runs_and_its_result_reaches_the_client() {
    let (fixture, notes, _) = fixture_with_notes();
    let mut client = Client::spawn(&fixture, &[]);
    client.handshake();

    let result = client.call_tool("read_file", json!({ "path": notes.to_string_lossy() }));

    assert_eq!(result["isError"], false, "{result}");
    let text = result["content"][0]["text"]
        .as_str()
        .expect("a text content block");
    assert!(
        text.contains(SENTINEL),
        "the file's contents are what came back: {text}"
    );

    let finished = client.finish();
    finished.assert_clean();
    assert_eq!(
        finished.report.counter("ran"),
        1,
        "the call reached the tool: {:?}",
        finished.report
    );
}

#[test]
fn a_call_that_needs_approval_is_refused_with_a_reason_that_names_the_approval() {
    // `--ask read_file`: the policy wants to see every read, and a stdio connection has nobody to
    // show it to.
    let (fixture, notes, _) = fixture_with_notes();
    let mut client = Client::spawn(&fixture, &["--ask", "read_file"]);
    client.handshake();

    let result = client.call_tool("read_file", json!({ "path": notes.to_string_lossy() }));

    assert_eq!(
        result["isError"], true,
        "a refusal is an error result, not a success: {result}"
    );
    let text = result["content"][0]["text"]
        .as_str()
        .expect("a text content block");
    for expected in ["needs approval", "stdio", "read_file", "allow"] {
        assert!(
            text.contains(expected),
            "{expected:?} missing from the refusal: {text}"
        );
    }
    assert!(
        text.contains("no approval request"),
        "the refusal says the request was never raised: {text}"
    );

    let finished = client.finish();
    finished.assert_clean();
}

#[test]
fn the_same_call_under_a_policy_that_allows_it_runs() {
    // The control for the test above. Same tool, same arguments, same binary — one `--ask` flag
    // apart. Without this, the refusal could be a capability denial or an argument error wearing an
    // approval-shaped message.
    let (fixture, notes, _) = fixture_with_notes();

    let mut refused = Client::spawn(&fixture, &["--ask", "read_file"]);
    refused.handshake();
    let refusal = refused.call_tool("read_file", json!({ "path": notes.to_string_lossy() }));
    assert_eq!(refusal["isError"], true, "{refusal}");
    refused.finish().assert_clean();

    let mut allowed = Client::spawn(&fixture, &[]);
    allowed.handshake();
    let ran = allowed.call_tool("read_file", json!({ "path": notes.to_string_lossy() }));
    assert_eq!(ran["isError"], false, "{ran}");
    assert!(
        ran["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains(SENTINEL),
        "{ran}"
    );
    allowed.finish().assert_clean();
}

#[test]
fn a_destructive_call_is_refused_and_the_file_it_named_is_still_there() {
    // `delete` is `FsPath` + `Delete` → `Destructive`, above `balanced`'s threshold, so the policy
    // asks and the server refuses. The file is the evidence: a refusal that still deleted would pass
    // a test that only read the message.
    let (fixture, _, doomed) = fixture_with_notes();
    let mut client = Client::spawn(&fixture, &[]);
    client.handshake();

    let result = client.call_tool("delete", json!({ "path": doomed.to_string_lossy() }));

    assert_eq!(result["isError"], true, "{result}");
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(text.contains("destructive"), "{text}");
    assert!(
        doomed.exists(),
        "the refused call must not have deleted anything"
    );

    let finished = client.finish();
    finished.assert_clean();
    assert_eq!(
        finished.report.counter("refused_needing_approval"),
        1,
        "refused at the approval step, not by a capability or an argument: {:?}",
        finished.report
    );
    assert_eq!(finished.report.counter("ran"), 0);
}

#[test]
fn a_refused_call_leaves_no_approval_request_in_the_servers_own_session() {
    // The property the brief is about, observed rather than inferred: the report is written by the
    // server at the end of the connection and carries `ApprovalSession::outstanding()`. If a refusal
    // had parked a question, this is the field that would say so — and the counter next to it proves
    // the refusal came from the approval step, so a server that never reached that step at all could
    // not pass this test by refusing for some other reason.
    let (fixture, notes, _) = fixture_with_notes();
    let mut client = Client::spawn(&fixture, &["--ask", "read_file"]);
    client.handshake();

    let result = client.call_tool("read_file", json!({ "path": notes.to_string_lossy() }));
    assert_eq!(result["isError"], true, "{result}");

    let finished = client.finish();
    finished.assert_clean();

    assert_eq!(
        finished.report.counter("calls"),
        1,
        "the server served exactly the one call: {:?}",
        finished.report
    );
    assert_eq!(finished.report.counter("refused_needing_approval"), 1);
    assert_eq!(finished.report.counter("ran"), 0);
    assert!(
        !finished.report.outstanding_approval(),
        "a refusal left an approval request outstanding, so there was something a person could \
         have answered: {:?}",
        finished.report
    );
}

#[test]
fn a_malformed_frame_is_answered_with_a_json_rpc_error_and_the_connection_survives() {
    // Well-formed JSON that is not a JSON-RPC message: the transport answers with an Invalid Request
    // error (id `null`, because there is no id to correlate to) and the session carries on. The
    // second half is the important one — a server that dies on bad input is a server a client can
    // kill with one malformed line.
    let fixture = Fixture::new();
    let mut client = Client::spawn(&fixture, &[]);
    client.handshake();

    client.write_line(&json!({ "jsonrpc": "2.0", "id": 99 }));

    let line = client
        .next_line()
        .expect("the transport answers a well-formed-but-invalid message");
    let message: Value = serde_json::from_str(&line).expect("a JSON-RPC message");
    let error = message
        .get("error")
        .unwrap_or_else(|| panic!("expected a JSON-RPC error, got: {line}"));
    assert_eq!(error["code"], -32600, "Invalid Request: {line}");
    assert_eq!(
        message["id"],
        Value::Null,
        "there was no id to correlate: {line}"
    );

    // And the connection is still good.
    let listed = client.result("tools/list", json!({}));
    assert!(
        listed["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "the server answered a request after the malformed frame: {listed}"
    );

    let finished = client.finish();
    finished.assert_clean();
}

#[test]
fn a_line_that_is_not_json_does_not_kill_the_connection() {
    // The transport ignores input it cannot parse — there is no id to answer to, and echoing an error
    // for unparsable bytes is how an error storm starts — so the honest assertion is the one that
    // matters to a client: the *session* survives, and the next real request is answered.
    let fixture = Fixture::new();
    let mut client = Client::spawn(&fixture, &[]);
    client.handshake();

    let stdin = client.stdin.as_mut().expect("connected");
    writeln!(stdin, "this is not json").expect("the pipe accepts bytes");
    stdin.flush().expect("flushed");

    let listed = client.result("tools/list", json!({}));
    assert!(
        listed["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "the server answered a request after a line it could not parse: {listed}"
    );

    let finished = client.finish();
    finished.assert_clean();
}

#[test]
fn stderr_carries_no_tool_output_and_no_credential() {
    // The sentinel is written to a file, read back through `read_file`, and *also* written through
    // `write_file` — so it genuinely travels through the server, in both directions, before the
    // assertion that stderr never saw it. A leak test against a value that never reached the process
    // would be a no-op that passes forever.
    let fixture = Fixture::new();
    let target = fixture.path("written-by-the-client.txt");
    let source = fixture.file("secret.txt", SENTINEL);

    let mut client = Client::spawn(&fixture, &[]);
    client.handshake();

    let written = client.call_tool(
        "write_file",
        json!({ "path": target.to_string_lossy(), "content": SENTINEL }),
    );
    assert_eq!(written["isError"], false, "{written}");

    let read = client.call_tool("read_file", json!({ "path": source.to_string_lossy() }));
    assert_eq!(read["isError"], false, "{read}");
    assert!(
        read["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains(SENTINEL),
        "the sentinel reached the client through the tool result: {read}"
    );

    let finished = client.finish();
    finished.assert_clean();
    assert!(
        !finished.stderr.contains(SENTINEL),
        "a tool's content reached stderr, which is not a log sink here:\n{}",
        finished.stderr
    );
    // The startup line is the only thing this binary writes to stderr, and it must not contain a
    // path the client chose either.
    assert!(
        !finished.stderr.contains("written-by-the-client"),
        "an argument reached stderr:\n{}",
        finished.stderr
    );
}
