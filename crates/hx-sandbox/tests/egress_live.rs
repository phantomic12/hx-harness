//! Live proof over real sockets that the **real** `hx-egress-proxy` binary enforces an IP/CIDR
//! allowlist.
//!
//! The matching of a raw-IP or CIDR entry is already pinned hermetically (`egress/policy.rs`,
//! `tests/egress_policy.rs`), and so is the proxy's own decision function when it is called
//! in-process (`src/bin/egress_proxy.rs`'s own tests, `handle` behind a loopback listener). Neither
//! of those runs the *binary*. What is proven here is the thing an operator's sandbox actually
//! depends on: this compiled executable, started as a child process, listening on a socket, letting
//! a `CONNECT` to an address inside the allowed block through and refusing one outside it.
//!
//! Nothing here needs a container engine, a privileged port or the internet: the child is the real
//! binary, but every other socket is a loopback listener this test owns, and the addresses in the
//! policy are documentation ranges. So these tests run in the ordinary gate rather than behind
//! `#[ignore]`.
//!
//! The proof is deliberately a **pair** in each test. A refusal alone could come from a proxy that
//! refuses everything, or from a listener that never worked; the same target dialed `200` under a
//! policy that contains it is what makes the `403` an allowlist decision rather than a blanket
//! block. The `egress ALLOWED` / `egress DENIED` lines the child writes to stderr are read back too,
//! so a refusal has a stated reason and not just a status code.
//!
//! The child is given `HX_EGRESS_LISTEN=127.0.0.1:0` — a free kernel-chosen loopback port — because
//! the binary's production address (`0.0.0.0:3128`) is fixed and assuming a fixed port is free is
//! how a test fails for a reason that has nothing to do with the code. The port the kernel actually
//! handed out is read from the child's startup line, so nothing is guessed.
//!
//! Every wait is bounded: startup, the response head, the tunneled bytes and the log lines all have
//! a deadline, and a failure says which one expired and what the child had logged.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// What the client pushes through the tunnel.
const CLIENT_BYTES: &[u8] = b"hx-through-the-proxy\n";
/// What the in-range target answers, pushed back through the same tunnel.
const TARGET_BYTES: &[u8] = b"hx-back-through!!\r\n";

/// How long the child may take to print its startup line. Generous, because a cold CI runner has to
/// fault the binary in — and a failure names what was waited for rather than hanging.
const STARTUP: Duration = Duration::from_secs(30);
/// The bound on every socket read and every log line. Without it, a proxy that neither answers nor
/// closes would hang the gate instead of failing it.
const WAIT: Duration = Duration::from_secs(15);

/// The real proxy binary, started as a child process, on a loopback port only this test knows.
struct ProxyUnderTest {
    child: Child,
    addr: SocketAddr,
    /// stderr, line by line, as the child writes it.
    lines: mpsc::Receiver<String>,
    /// Everything read so far, so a failure can print what the child said.
    logged: Arc<Mutex<Vec<String>>>,
}

impl ProxyUnderTest {
    /// Start the compiled binary with `allow` as its allowlist, and wait for it to report a bound
    /// address.
    fn start(allow: &str) -> ProxyUnderTest {
        let mut child = Command::new(env!("CARGO_BIN_EXE_hx-egress-proxy"))
            .env("HX_EGRESS_ALLOW", allow)
            // Port 0: the kernel picks a free one and the child reports it, so no fixed port is
            // assumed free and no port is guessed (and possibly taken by the time it is used).
            .env("HX_EGRESS_LISTEN", "127.0.0.1:0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the compiled hx-egress-proxy binary must start");

        let stderr = child.stderr.take().expect("stderr was piped");
        let (tx, lines) = mpsc::channel();
        let logged = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&logged);
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                sink.lock().expect("the log lock").push(line.clone());
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let addr = wait_for_bound_address(&lines, &logged);
        ProxyUnderTest {
            child,
            addr,
            lines,
            logged,
        }
    }

    /// A real TCP connection to the proxy's listening socket, with every read and write bounded.
    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(self.addr)
            .unwrap_or_else(|e| panic!("connecting to the proxy at {} failed: {e}", self.addr));
        stream
            .set_read_timeout(Some(WAIT))
            .expect("a read timeout on the proxy connection");
        stream
            .set_write_timeout(Some(WAIT))
            .expect("a write timeout on the proxy connection");
        stream
    }

    /// The next stderr line containing `needle`, waiting at most [`WAIT`].
    fn expect_log(&self, needle: &str) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "the proxy logged no line containing {needle:?} within {WAIT:?}; it logged {:?}",
                self.logged.lock().expect("the log lock")
            );
            match self.lines.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return line,
                // A line this test is not waiting for (the startup line was consumed already, so
                // this is a second connection's line) — keep looking.
                Ok(_) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
                    "the proxy's stderr closed before it logged {needle:?}; it logged {:?}",
                    self.logged.lock().expect("the log lock")
                ),
            }
        }
    }

    fn logged(&self) -> Vec<String> {
        self.logged.lock().expect("the log lock").clone()
    }
}

impl Drop for ProxyUnderTest {
    /// The child is a process of this test's making; nothing outlives the test.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Wait for the child's `egress proxy listening on <addr>` line and read the address out of it.
fn wait_for_bound_address(
    lines: &mpsc::Receiver<String>,
    logged: &Arc<Mutex<Vec<String>>>,
) -> SocketAddr {
    let deadline = Instant::now() + STARTUP;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "the proxy printed no bound address within {STARTUP:?}; it logged {:?}",
            logged.lock().expect("the log lock")
        );
        match lines.recv_timeout(left) {
            Ok(line) => {
                if let Some(addr) = line.split("listening on ").nth(1) {
                    return addr.trim().parse().unwrap_or_else(|e| {
                        panic!("the proxy reported an address that does not parse ({line:?}): {e}")
                    });
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
                "the proxy exited before it reported a bound address; it logged {:?}",
                logged.lock().expect("the log lock")
            ),
        }
    }
}

/// A loopback listener standing in for the `CONNECT` target, plus the number of connections that
/// reached it.
///
/// This is the tripwire that makes "never reaches the target" an observation rather than a
/// deduction: a refused `CONNECT` that was in fact dialed would be accepted here and counted. The
/// first connection accepted is handed to `on_connect`; later ones are just counted and dropped, so
/// a test can use its own direct connection as the control that proves the listener and the counter
/// work at all.
fn target_on(
    bind: &str,
    on_connect: impl FnOnce(TcpStream) + Send + 'static,
) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((bind, 0))
        .unwrap_or_else(|e| panic!("binding the target's listener on {bind}:0 failed: {e}"));
    let port = listener
        .local_addr()
        .expect("a bound listener has a local address")
        .port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    thread::spawn(move || {
        let mut on_connect = Some(on_connect);
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            if let Some(handler) = on_connect.take() {
                handler(stream);
            }
        }
    });
    (port, accepted)
}

/// Write a `CONNECT` request for `target` the way a client behind `HTTP_PROXY` does.
fn send_connect(stream: &mut TcpStream, target: &str) {
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .unwrap_or_else(|e| panic!("writing the CONNECT {target} request: {e}"));
}

/// Read the response head (status line and headers) and return it with any bytes that followed it.
///
/// For a relayed `CONNECT` the bytes after the head are the beginning of the tunnel; for a refusal
/// there are none, because the proxy sends `Content-Length: 0` and closes.
fn read_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return (String::from_utf8_lossy(&buf).to_string(), rest);
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                // Closed before a complete head: return what arrived, so the assertion on it names
                // the trivially different thing the proxy actually said.
                return (String::from_utf8_lossy(&buf).to_string(), Vec::new());
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("reading the proxy's response head failed: {e}"),
        }
    }
}

/// Read exactly `len` bytes, panicking with `what` if the deadline passes first.
fn read_exactly(stream: &mut TcpStream, len: usize, what: &str) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .unwrap_or_else(|e| panic!("{what} (waited {WAIT:?}): {e}"));
    buf
}

/// Assert the response head is a refusal, and that the proxy closes rather than leaving the client
/// hanging — a sandbox must observe a denial, not a black hole.
fn assert_refused(head: &str, mut client: TcpStream, target: &str) {
    assert!(
        head.contains("403 Forbidden"),
        "a CONNECT to {target} outside the allowlist must be refused with 403: {head:?}"
    );
    assert!(
        !head.contains("200"),
        "a refused target must never be answered as established: {head:?}"
    );
    let mut tail = [0u8; 1];
    match client.read(&mut tail) {
        Ok(0) => {}
        Ok(n) => panic!("a refusal must carry no tunnel bytes, read {n}: {tail:?}"),
        Err(e) => panic!("a refusal must close the connection, not hang: {e}"),
    }
}

/// A `CONNECT` to an address inside a CIDR entry is tunneled: a byte written by the client arrives
/// at the target, and a byte written by the target arrives back at the client.
#[test]
fn a_cidr_entry_tunnels_an_in_range_target_over_a_real_socket() {
    let seen_by_target: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen_by_target);
    let (port, accepted) = target_on("127.0.0.1", move |mut stream| {
        stream
            .set_read_timeout(Some(WAIT))
            .expect("a read timeout on the target");
        let mut got = vec![0u8; CLIENT_BYTES.len()];
        if stream.read_exact(&mut got).is_ok() {
            *sink.lock().expect("the target's buffer") = got;
        }
        let _ = stream.write_all(TARGET_BYTES);
    });

    let proxy = ProxyUnderTest::start("127.0.0.0/8,example.com");
    let target = format!("127.0.0.1:{port}");
    let mut client = proxy.connect();
    send_connect(&mut client, &target);

    let (head, early) = read_head(&mut client);
    assert!(
        head.contains("200 Connection established"),
        "an address inside 127.0.0.0/8 must be dialed and relayed: {head:?}"
    );

    // The client's bytes reach the target...
    client
        .write_all(CLIENT_BYTES)
        .expect("writing through the established tunnel");
    let mut back = early;
    back.extend_from_slice(&read_exactly(
        &mut client,
        TARGET_BYTES.len(),
        "the target's answer must come back through the tunnel",
    ));
    assert_eq!(
        back, TARGET_BYTES,
        "what the target wrote must arrive at the client unchanged"
    );
    // ...and the target saw exactly what was sent.
    assert_eq!(
        *seen_by_target.lock().expect("the target's buffer"),
        CLIENT_BYTES,
        "the target must have received exactly the client's bytes"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "a relayed CONNECT opens exactly one connection to the target"
    );
    assert!(
        proxy
            .expect_log(&format!("egress ALLOWED {target}"))
            .contains(&target),
        "the allowed target must be logged by name; the child logged {:?}",
        proxy.logged()
    );
}

/// A name that resolves into an allowed CIDR is tunneled too: the entry is an address rule, and the
/// proxy tests the address it resolved the `CONNECT` target to.
#[test]
fn a_name_that_resolves_into_the_cidr_is_tunnelled_over_a_real_socket() {
    let (port, accepted) = target_on("127.0.0.1", |mut stream| {
        let _ = stream.write_all(TARGET_BYTES);
    });

    // `localhost` is not an entry; `127.0.0.0/8` is, and `localhost` resolves into it.
    let proxy = ProxyUnderTest::start("127.0.0.0/8,example.com");
    let target = format!("localhost:{port}");
    let mut client = proxy.connect();
    send_connect(&mut client, &target);

    let (head, _) = read_head(&mut client);
    assert!(
        head.contains("200 Connection established"),
        "a name resolving into 127.0.0.0/8 must be dialed and relayed: {head:?}"
    );
    assert_eq!(
        read_exactly(&mut client, TARGET_BYTES.len(), "the target's answer"),
        TARGET_BYTES,
        "the tunnel must carry the target's bytes for a name as well"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "exactly one connection must reach the target"
    );
}

/// A `CONNECT` to an address outside every entry is refused with `403`, the refusal is logged, and
/// no connection is ever opened to the target.
#[test]
fn an_out_of_cidr_target_is_refused_with_403_and_never_reaches_the_target() {
    // The listener a dial would have reached, so "never dialed" is observed rather than assumed.
    let (port, accepted) = target_on("127.0.0.1", |mut stream| {
        let _ = stream.write_all(TARGET_BYTES);
    });

    // The allowlist contains everything except loopback's family, so a refusal here cannot be the
    // proxy refusing by default.
    let proxy = ProxyUnderTest::start("203.0.113.0/24,example.com");
    let target = format!("127.0.0.1:{port}");
    let mut client = proxy.connect();
    send_connect(&mut client, &target);

    let (head, _) = read_head(&mut client);
    assert_refused(&head, client, &target);

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "a refused CONNECT must not open a connection to the target"
    );
    let denial = proxy.expect_log(&format!("egress DENIED {target}"));
    assert!(
        denial.contains(&target),
        "the refusal must be logged with the target it refused: {denial:?}"
    );

    // The control that makes the zero above mean something: the same listener does accept and count
    // a connection, so "no connection reached it" is about the proxy's behaviour and not about a
    // listener that never worked.
    let mut direct = TcpStream::connect(("127.0.0.1", port)).expect("the target's own port");
    direct
        .set_read_timeout(Some(WAIT))
        .expect("a read timeout on the direct control");
    assert_eq!(
        read_exactly(
            &mut direct,
            TARGET_BYTES.len(),
            "the target's direct answer"
        ),
        TARGET_BYTES,
        "the control connection must be answered by the same target"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the target counts the control connection, so its zero above was a real absence"
    );
}

/// A raw-IP entry admits exactly that address and no neighbour: `127.0.0.1` is tunneled while
/// `127.0.0.2`, which a `/8` or a name rule would have swept in, is refused and never dialed.
#[test]
fn a_raw_ip_entry_admits_exactly_that_address_and_no_neighbour() {
    let (allowed_port, allowed_accepted) = target_on("127.0.0.1", |mut stream| {
        let _ = stream.write_all(TARGET_BYTES);
    });
    // Bound to 0.0.0.0 on purpose: the refused address (127.0.0.2) then *has* a live port behind
    // it, so a dial that should never happen would be accepted and counted rather than failing to
    // connect for a reason of its own.
    let (neighbour_port, neighbour_accepted) = target_on("0.0.0.0", |mut stream| {
        let _ = stream.write_all(TARGET_BYTES);
    });

    let proxy = ProxyUnderTest::start("127.0.0.1,example.com");

    let allowed = format!("127.0.0.1:{allowed_port}");
    let mut client = proxy.connect();
    send_connect(&mut client, &allowed);
    let (head, _) = read_head(&mut client);
    assert!(
        head.contains("200 Connection established"),
        "the address the entry names must be dialed and relayed: {head:?}"
    );
    assert_eq!(
        read_exactly(
            &mut client,
            TARGET_BYTES.len(),
            "the allowed target's answer"
        ),
        TARGET_BYTES,
        "the tunnel must carry the allowed target's bytes"
    );
    assert_eq!(allowed_accepted.load(Ordering::SeqCst), 1);

    let neighbour = format!("127.0.0.2:{neighbour_port}");
    let mut refused = proxy.connect();
    send_connect(&mut refused, &neighbour);
    let (head, _) = read_head(&mut refused);
    assert_refused(&head, refused, &neighbour);
    assert_eq!(
        neighbour_accepted.load(Ordering::SeqCst),
        0,
        "an address the entry does not name must never be dialed"
    );
    assert!(
        proxy
            .expect_log(&format!("egress DENIED {neighbour}"))
            .contains(&neighbour),
        "the refusal must be logged with the neighbour it refused; the child logged {:?}",
        proxy.logged()
    );
}
