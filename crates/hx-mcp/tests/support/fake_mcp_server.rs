//! A hand-rolled MCP server over stdio: the *other end of the wire* `tests/stdio.rs` drives.
//!
//! ## Why this is hand-rolled and not `rmcp`'s server
//!
//! Everywhere else in this crate the argument is the opposite — `rmcp` implements the protocol and
//! a second copy would be a worse copy. The test double is the exception, and the reason is the one
//! property a double has to have: **it must fail loudly when it is fed something unscripted.**
//!
//! A real MCP server answers whatever it is asked, so a client bug that sends the wrong method, a
//! malformed frame, or a request twice is answered politely and the test passes while proving
//! nothing. This server instead knows the *exact* sequence a correct `hx-mcp` connection produces —
//! `initialize`, `notifications/initialized`, `tools/list`, `tools/call` — and records anything else
//! in the pid file as an `UNEXPECTED` line and exits non-zero. `tests/stdio.rs` asserts that file is
//! clean, so an unscripted request fails the test rather than passing silently.
//!
//! The protocol it does speak is real JSON-RPC 2.0 over newline-delimited stdout, on a real pipe, in
//! a real child process. Nothing here is a mock: the client's own framing, handshake, timeout and
//! process-reaping code all run against it for real.
//!
//! ## The pid file is the observability channel
//!
//! A child's stderr is captured and counted by design (see `src/stdio.rs`) and its stdout is the
//! wire, so the tests have no channel to ask it questions. They do not need one: the pid file is
//! appended to on every start, which is how a test can prove *how many times a server was spawned*
//! (the bounded-restart property) and *which process to look for* after the host shuts down (the
//! reaping property).
//!
//! ## Modes
//!
//! `--mode <name>`, default `ok`:
//!
//! | mode | behaviour |
//! |---|---|
//! | `ok` | the full handshake, then serve `echo` / `fail` / `structured` |
//! | `silent` | accept stdin, never write a byte, never exit |
//! | `garbage` | write non-JSON to stdout, then hang with the pipe open |
//! | `exit-on-start` | exit(1) before answering anything |
//! | `exit-after-init` | answer `initialize`, then exit(0) |
//! | `die-on-tool` | full handshake, then exit(1) on the first `tools/call` |
//! | `hang-on-tool` | full handshake, then never answer a `tools/call` |
//! | `noisy-stderr` | write the sentinel to stderr many times, then behave as `ok` |

use std::io::{BufRead, Write};

/// The stderr sentinel `tests/stdio.rs` greps for. It is deliberately shaped like something a person
/// would not want in a model's context.
const STDERR_SENTINEL: &str = "hx-mcp-stderr-sentinel-token-please-do-not-echo";

/// The words the fake server uses to describe `echo`. A test asserts this text reaches the model
/// labelled as the server's own, so it must be distinctive.
const ECHO_DESCRIPTION: &str = "the fake server's own description of echo, which is data";

/// How many lines `noisy-stderr` writes. Past the bounded tail (`STDERR_TAIL_LINES = 8`), so a test
/// can tell "kept everything" from "kept a bounded tail".
const NOISY_STDERR_LINES: usize = 40;

struct Args {
    mode: String,
    pid_file: Option<String>,
}

fn main() {
    let args = match parse_args(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("hx-mcp-fake-server: {message}");
            std::process::exit(64);
        }
    };

    // Recorded before anything else, so a mode that dies immediately still leaves evidence that it
    // was started. One line per process: the line count is the spawn count.
    if let Some(path) = &args.pid_file {
        record(path, &format!("{}\n", std::process::id()));
    }

    match args.mode.as_str() {
        "silent" => {
            // Hold stdin open and never write. This is the "accepts the connection and says nothing"
            // case, which is the one a naive client waits on forever.
            std::thread::sleep(std::time::Duration::from_secs(3_600));
        }
        "garbage" => {
            let mut out = std::io::stdout();
            let _ = out.write_all(b"this is not json\n");
            let _ = out.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\n");
            let _ = out.flush();
            std::thread::sleep(std::time::Duration::from_secs(3_600));
        }
        "exit-on-start" => {
            eprintln!("{STDERR_SENTINEL}: refusing to start");
            std::process::exit(1);
        }
        _ => {}
    }

    if args.mode == "noisy-stderr" {
        for line in 0..NOISY_STDERR_LINES {
            eprintln!("{STDERR_SENTINEL} line {line}");
        }
    }

    serve(&args);
}

fn parse_args(argv: Vec<String>) -> Result<Args, String> {
    let mut mode = "ok".to_string();
    let mut pid_file = None;
    let mut iter = argv.into_iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--mode" => mode = iter.next().ok_or("--mode needs a value")?,
            "--pid-file" => pid_file = Some(iter.next().ok_or("--pid-file needs a value")?),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Args { mode, pid_file })
}

/// Append to the pid file. Not atomic, and it does not need to be: the tests that count lines are
/// the only writers and they run one server at a time.
fn record(path: &str, line: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

/// The one loud failure: input this server was not scripted for.
fn unexpected(args: &Args, what: &str) -> ! {
    if let Some(path) = &args.pid_file {
        record(path, &format!("UNEXPECTED {what}\n"));
    }
    eprintln!("hx-mcp-fake-server: UNEXPECTED input: {what}");
    std::process::exit(3);
}

fn serve(args: &Args) {
    let stdin = std::io::stdin();
    let lines = stdin.lock().lines();

    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(err) => unexpected(args, &format!("could not read stdin: {err}")),
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            // A blank line is not valid framing for this transport, and accepting it would let a
            // client that writes two newlines per message pass.
            unexpected(args, "a blank line, which is not valid stdio framing");
        }

        let message: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(message) => message,
            Err(err) => unexpected(args, &format!("a line that is not JSON ({err}): {trimmed}")),
        };

        let method = match message.get("method").and_then(|m| m.as_str()) {
            Some(method) => method.to_string(),
            None => unexpected(
                args,
                &format!("a JSON-RPC message with no method: {trimmed}"),
            ),
        };
        let id = message.get("id").cloned();

        // A notification has no `id`. The client is entitled to fire-and-forget these, so they are
        // not answered and not treated as unscripted; `notifications/*` is the whole set MCP uses.
        if id.is_none() {
            if method.starts_with("notifications/") {
                continue;
            }
            unexpected(
                args,
                &format!("a notification with an unscripted method: {method}"),
            );
        }

        match method.as_str() {
            "initialize" => {
                let protocol = message
                    .get("params")
                    .and_then(|params| params.get("protocolVersion"))
                    .and_then(|version| version.as_str())
                    .unwrap_or("2025-06-18")
                    .to_string();
                // Echo the client's own version back. A conformant server picks one both support;
                // echoing is the pick that cannot fail, and a client that cannot parse this
                // response is the thing under test.
                reply(
                    id,
                    serde_json::json!({
                        "protocolVersion": protocol,
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "hx-mcp-fake-server", "version": env!("CARGO_PKG_VERSION") }
                    }),
                );

                if args.mode == "exit-after-init" {
                    // The handshake is half done: the child is gone before the client can list its
                    // tools. This is the "started and immediately died" case.
                    std::process::exit(0);
                }
            }
            "ping" => reply(id, serde_json::json!({})),
            "tools/list" => reply(id, serde_json::json!({ "tools": tool_definitions() })),
            "tools/call" => {
                let name = message
                    .get("params")
                    .and_then(|params| params.get("name"))
                    .and_then(|name| name.as_str())
                    .unwrap_or_default()
                    .to_string();
                let arguments = message
                    .get("params")
                    .and_then(|params| params.get("arguments"))
                    .cloned()
                    .unwrap_or(serde_json::json!({}));

                match args.mode.as_str() {
                    "die-on-tool" => std::process::exit(1),
                    "hang-on-tool" => {
                        // Alive, connected, and never answering. The client has to cut this off on
                        // its own clock; there is nothing here to time out for it.
                        std::thread::sleep(std::time::Duration::from_secs(3_600));
                    }
                    _ => {}
                }

                reply(id, call_result(&name, &arguments));
            }
            other => {
                // A real request for a method this server does not implement. Answering with
                // JSON-RPC's `MethodNotFound` is what a conformant server does; recording it is what
                // makes an unscripted request a *test failure* rather than a silent success.
                reply_error(id, -32601, &format!("Method not found: {other}"));
                unexpected(
                    args,
                    &format!("a request for an unscripted method: {other}"),
                );
            }
        }
    }
}

fn tool_definitions() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "echo",
            "description": ECHO_DESCRIPTION,
            "inputSchema": {
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }
        },
        {
            "name": "fail",
            "description": "always reports an error, which is a result and not a death",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "structured",
            "description": "answers with structured content and no prose",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            // A tool name the provider charset cannot carry verbatim: `hx` folds it to
            // `ns__a_b` for the model, and a call has to be sent back as `a b` — the server's own
            // spelling. Nothing else in the suite would catch a client that sent the folded name.
            "name": "a b",
            "description": "a name with a space in it",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ])
}

fn call_result(name: &str, arguments: &serde_json::Value) -> serde_json::Value {
    match name {
        "echo" => {
            let text = arguments
                .get("text")
                .and_then(|text| text.as_str())
                .unwrap_or_default();
            serde_json::json!({
                "content": [{ "type": "text", "text": text }],
                "isError": false
            })
        }
        "fail" => serde_json::json!({
            "content": [{ "type": "text", "text": "the fake server refused, on purpose" }],
            "isError": true
        }),
        "structured" => serde_json::json!({
            "content": [],
            "structuredContent": { "answer": 42 },
            "isError": false
        }),
        "a b" => serde_json::json!({
            "content": [{ "type": "text", "text": "called with the server's own spelling" }],
            "isError": false
        }),
        other => serde_json::json!({
            "content": [{ "type": "text", "text": format!("no such tool: {other}") }],
            "isError": true
        }),
    }
}

fn reply(id: Option<serde_json::Value>, result: serde_json::Value) {
    write_line(&serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }));
}

fn reply_error(id: Option<serde_json::Value>, code: i64, message: &str) {
    write_line(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    }));
}

/// One JSON object per line, flushed immediately: an unflushed reply is indistinguishable from a
/// server that never answered, which is the failure this whole file exists to be able to produce.
fn write_line(value: &serde_json::Value) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}
