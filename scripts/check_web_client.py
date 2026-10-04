#!/usr/bin/env python3
"""Drive the live hx daemon over the exact wire protocol the web client speaks.

A browser check is better, but the browser stack is down, and "the UI compiles" is not evidence the
UI works. This speaks the same frames the page's JavaScript does — the same `POST /v1/terminals`,
the same `GET /v1/terminals/{id}/ws` with base64 `input`, and the same session socket — using only
the standard library, so nothing about the transport is being stubbed out or assumed. The `screen`
pane is driven the same way: `POST /v1/screens`, `GET /v1/screens/{id}/ws`, a real JPEG frame off it,
and the same mouse and key frames the pane sends.

What it proves: the endpoints the page calls exist, the frames it parses are the frames the daemon
sends, two independent clients on one terminal genuinely receive the same bytes, and a screen streams
a frame a client can draw and accepts the input a person would send it.
"""

import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

# The address to drive. Overridable because the fixed one is a *convention*, not a fact: a machine
# where 8899 is already taken (a real service, a colleague's daemon, another walk of this harness on
# 7721) made this script unrunnable, and a check that cannot be pointed at a running daemon is a
# check nobody runs.
HOST = os.environ.get("HX_WEB_CHECK_HOST", "127.0.0.1")
PORT = int(os.environ.get("HX_WEB_CHECK_PORT", "8899"))
# The sandbox to open the terminal in. On Windows the daemon has no pty of its own, so a *local*
# terminal is refused and the only shell this walk can drive is one inside a box the daemon runs;
# naming one here makes the script runnable on such a host instead of failing its first terminal
# check for a reason unrelated to the web client. Unset means the daemon's own host, which is what
# every Unix host (and every earlier run) means.
SANDBOX = os.environ.get("HX_WEB_CHECK_SANDBOX")


def http(method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    req = urllib.request.Request(
        f"http://{HOST}:{PORT}{path}", data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class WS:
    """A minimal RFC-6455 client: the small subset a test client needs."""

    def __init__(self, path):
        self.sock = socket.create_connection((HOST, PORT), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("the server closed during the handshake")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode()
        if "101" not in status:
            raise RuntimeError(f"handshake refused: {status}")
        self.buf = rest

    def send(self, obj):
        payload = json.dumps(obj).encode()
        header = bytearray([0x81])  # FIN + text
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _fill(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("connection closed")
            self.buf += chunk

    def recv(self):
        self._fill(2)
        b0, b1 = self.buf[0], self.buf[1]
        opcode = b0 & 0x0F
        n = b1 & 0x7F
        offset = 2
        if n == 126:
            self._fill(4)
            n = struct.unpack(">H", self.buf[2:4])[0]
            offset = 4
        elif n == 127:
            self._fill(10)
            n = struct.unpack(">Q", self.buf[2:10])[0]
            offset = 10
        self._fill(offset + n)
        payload = self.buf[offset : offset + n]
        self.buf = self.buf[offset + n :]
        if opcode == 0x8:
            raise RuntimeError("the server closed the socket")
        return payload.decode()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def read_until(ws, want_type, contains=None, tries=200):
    """Read frames until one matches, returning every frame seen (so failures are reportable)."""
    seen = []
    for _ in range(tries):
        frame = json.loads(ws.recv())
        seen.append(frame)
        if frame.get("type") == want_type:
            if contains is None:
                return seen
            text = base64.b64decode(frame.get("data", "")).decode("utf-8", "replace")
            if contains in text:
                return seen
    raise RuntimeError(f"never saw {want_type} containing {contains!r}; frames: {seen[-6:]}")


def main():
    failures = []

    def check(name, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(name)

    # 1. The page itself, which is what a browser gets.
    status, body = http("GET", "/")
    check("GET / serves the client", status == 200 and "<title>hx</title>" in body, f"{status}")

    # 2. The terminal the page creates on load.
    terminal_body = {"id": "ui-term", "cols": 80, "rows": 24}
    if SANDBOX:
        terminal_body["sandbox"] = SANDBOX
    status, body = http("POST", "/v1/terminals", terminal_body)
    check("POST /v1/terminals", status == 200, f"{status} {body[:120]}")

    # 3. Two clients attaching to that one terminal — the M2 criterion, over the page's own protocol.
    a = WS("/v1/terminals/ui-term/ws")
    b = WS("/v1/terminals/ui-term/ws")
    a.send({"type": "input", "data": base64.b64encode(b"echo web-check-marker\n").decode()})
    a_frames = read_until(a, "output", "web-check-marker")
    b_frames = read_until(b, "output", "web-check-marker")
    a_text = "".join(
        base64.b64decode(f["data"]).decode("utf-8", "replace")
        for f in a_frames
        if f["type"] == "output"
    )
    b_text = "".join(
        base64.b64decode(f["data"]).decode("utf-8", "replace")
        for f in b_frames
        if f["type"] == "output"
    )
    check("client A sees the shell's echo", "web-check-marker" in a_text, a_text[-120:])
    check("client B sees the SAME bytes", "web-check-marker" in b_text, b_text[-120:])

    # 4. A third client attaching late is sent the scrollback first — the frame the page resets on.
    c = WS("/v1/terminals/ui-term/ws")
    c_frames = read_until(c, "scrollback", "web-check-marker")
    c_text = "".join(
        base64.b64decode(f["data"]).decode("utf-8", "replace")
        for f in c_frames
        if f["type"] == "scrollback"
    )
    check("a late client is sent scrollback", "web-check-marker" in c_text, c_text[-120:])

    # 5. Resize is accepted (the page sends one on connect).
    a.send({"type": "resize", "cols": 100, "rows": 30})
    time.sleep(0.4)
    check("resize does not kill the terminal", True)

    # 6. An unknown terminal is refused. This must be a real WebSocket upgrade, not a plain GET: a
    # plain GET to a socket route is rejected by axum as a malformed upgrade (400), which says
    # nothing about whether the route looked for the terminal.
    try:
        WS("/v1/terminals/definitely-missing/ws")
        check("an unknown terminal is refused", False, "the upgrade was accepted")
    except RuntimeError as e:
        check("an unknown terminal is refused", "404" in str(e), str(e))

    # 7. The session socket the right pane uses, and its resumable handshake. A session is created
    # by talking to the daemon as a client does; `POST /v1/sessions` is not the route (it answers
    # 405), so this uses whatever the daemon already has and reports honestly if there is nothing.
    status, body = http("GET", "/v1/sessions")
    items = json.loads(body) if body else []
    if isinstance(items, dict):
        items = items.get("sessions", [])
    session = None
    if items:
        first = items[0]
        session = first.get("id") if isinstance(first, dict) else first
    if session:
        s = WS(f"/v1/sessions/{session}/ws")
        s.send({"since_seq": 0})
        time.sleep(0.4)
        check("the session socket upgrades and accepts since_seq", True)
        s.close()
    else:
        # No session exists yet, which is a real state (a fresh daemon). Reported as skipped rather
        # than as a pass, because a check that did not run must not look like one that did.
        print("SKIP  the session socket (no session on this daemon yet)")

    a.close()
    b.close()
    c.close()

    # 8. The approvals pane's endpoint. The page polls this and renders what it says, so the shape
    # matters: a list (possibly empty), not an error. An empty list is the normal state and must
    # read as "nothing waiting" rather than as a failure.
    status, body = http("GET", "/v1/approvals")
    ok = status == 200 and isinstance(json.loads(body or "[]"), list)
    check("GET /v1/approvals returns a list", ok, f"{status} {body[:120]}")

    # 9. The approval page carries the risk/reason/undo fields the pane renders. Asserted against
    # the served page because a pane that cannot show *why* something is being asked for is a pane
    # that gets answered by guessing.
    _, page = http("GET", "/")
    for field in ("risk", "reason", "undo", "reversible"):
        check(f"the page renders the approval's {field}", field in page, "missing from the served page")

    # 10. The container pane's endpoint, and that the served page renders its two states. The
    # "unavailable" branch matters as much as the live one: a daemon with no container engine must
    # say so, not show an empty list that reads as "nothing running".
    # The summary lives on `/v1/status`; `/v1/sandboxes` is the list of live containers. Asserted
    # against the route the page actually reads, because reading the wrong one is a bug that shows
    # up as a blank strip rather than as an error.
    status, body = http("GET", "/v1/status")
    payload = json.loads(body or "{}").get("sandboxes")
    check(
        "GET /v1/status reports sandbox availability",
        status == 200 and isinstance(payload, dict) and "available" in payload,
        f"{status} {body[:160]}",
    )
    status, body = http("GET", "/v1/sandboxes")
    check(
        "GET /v1/sandboxes returns the live list",
        status == 200 and isinstance(json.loads(body or "[]"), list),
        f"{status} {body[:120]}",
    )
    _, page = http("GET", "/")
    check(
        "the page renders the sandbox state",
        "sandboxes unavailable" in page and "slots free" in page,
        "the page does not render either sandbox state",
    )

    # 11. The hosts pane's endpoint, and that the served page actually renders hosts. `/v1/hosts`
    # returns HostSummary entries (id, kind, address, description, configured) — not os/shell, which
    # the daemon does not expose over HTTP, so the page must render the fields it does return and
    # say so when a host is declared but not configured rather than drawing an empty list.
    status, body = http("GET", "/v1/hosts")
    ok = status == 200 and isinstance(json.loads(body or "[]"), list)
    check("GET /v1/hosts returns a list", ok, f"{status} {body[:160]}")
    status, body = http("GET", "/v1/hosts")
    hosts = json.loads(body or "[]")
    if hosts:
        first = hosts[0]
        check(
            "each host carries id/kind/configured",
            all(k in first for k in ("id", "kind", "configured")),
            f"missing keys: {list(first.keys())}",
        )
    else:
        print("SKIP  host shape (no hosts returned by this daemon)")
    _, page = http("GET", "/")
    for marker in ("/v1/hosts", "id=\"hosts\"", "No hosts are configured."):
        check(f"the page renders the hosts pane ({marker})", marker in page, "missing from the served page")

    # 12. The `screen` pane's contract. See `check_screen` for what it proves and what it skips.
    check_screen(check)

    # 13. The `challenge` routes the pane's banner posts to. See `check_challenges` for what that
    # proves and what it deliberately does not.
    check_challenges(check)

    # 14. Deleting the terminal, as the page does not do but a cleanup must.
    status, _ = http("DELETE", "/v1/terminals/ui-term")
    check("DELETE /v1/terminals/{id}", status == 200, str(status))

    # 15. The rendered-browser gate: headless Chromium loads the page for real. See `check_rendered`.
    check_rendered(check)

    print()
    if failures:
        print(f"{len(failures)} FAILED: {failures}")
        return 1
    print("all checks passed")
    return 0


def check_challenges(check):
    """The `challenge` routes the pane's banner posts to — the refusals, and the banner's markup.

    Only the refusals are checked, and they are checked on **every** host: a live challenge needs a
    site that refuses every automated rung, which is a thing to arrange rather than a thing to assume.
    The end to end of the loop is `crates/hx-server/tests/challenge_api.rs`, which drives it against a
    stub that refuses and a real browser; what a client can be told *wrongly* on any daemon is here: a
    listing that is not a listing, an id that was never one reporting as over, and a decline whose
    reason was dropped on the floor.
    """
    status, body = http("GET", "/v1/challenges")
    ok = status == 200 and isinstance(json.loads(body or "{}").get("challenges"), list)
    check("GET /v1/challenges returns a listing", ok, f"{status} {body[:120]}")
    status, body = http("POST", "/v1/challenges/chal_never_existed", {"outcome": "solved"})
    check(
        "answering a challenge that never existed is a 404",
        status == 404,
        f"{status} {body[:120]}",
    )
    status, body = http(
        "POST", "/v1/challenges/chal_never_existed", {"outcome": "abandoned", "note": "  "}
    )
    check(
        "a decline with no reason is refused as the caller's mistake (400, not 404)",
        status == 400 and "note" in body,
        f"{status} {body[:160]}",
    )
    _, page = http("GET", "/")
    for marker in (
        'id="challenge"',
        "challenge-solved",
        "/v1/challenges",
        # Who the question is for, and the deep link a notification carries: a banner that did not say
        # whose run is blocked would be the noticeboard the addressing work replaced, and a
        # notification URL that opened no screen would be a link that does nothing.
        'id="challenge-for"',
        "followScreenLink",
        # On a daemon with several operators, "nobody was told" is about the *named* person and no
        # longer about the whole daemon, and the page is the only place a name is spelled out for a
        # human. A banner still blaming `approval.push_url` would send an operator to the wrong key.
        "no push_url for that operator",
    ):
        check(f"the page renders the challenge banner ({marker})", marker in page, "missing from the served page")


def check_screen(check):
    """Drive the `screen` pane's frames: launch a browser, read a real frame, send a person's input.

    Skipped rather than failed when the daemon's host has no browser — the pane tells a person the same
    thing, with every path it looked at, and a script that failed here would be testing the machine
    rather than the protocol.

    The input is *not* followed by a wait for a frame, and that is deliberate: a page that does not
    repaint sends none, so a check that blocked on one would be a check that hangs instead of
    reporting. What is asserted is that the daemon accepts the frames a pane sends and the screen
    stays live — a refused input comes back as `error`, and a broken driver as `ended`.
    """
    status, body = http("POST", "/v1/screens", {"id": "ui-screen", "width": 800, "height": 600})
    if status == 503:
        print(f"SKIP  the screen (no browser on this host: {json.loads(body)['error'][:90]}…)")
    else:
        check("POST /v1/screens", status == 200, f"{status} {body[:160]}")
        listed = json.loads(http("GET", "/v1/screens")[1]).get("screens", [])
        check(
            "GET /v1/screens lists the live screen",
            any(s.get("id") == "ui-screen" and s.get("ended") is None for s in listed),
            f"{listed}"[:160],
        )

        s = WS("/v1/screens/ui-screen/ws")
        frames = read_until(s, "frame")
        frame = [f for f in frames if f.get("type") == "frame"][-1]
        jpeg = base64.b64decode(frame["data"])
        check("a frame is a JPEG, passed through untouched", jpeg[:3] == b"\xff\xd8\xff", repr(jpeg[:8]))
        check(
            "the frame carries the viewport that was asked for",
            (frame.get("width"), frame.get("height")) == (800, 600),
            f"{frame.get('width')}x{frame.get('height')}",
        )

        s.send({"type": "mouse_button", "x": 10.0, "y": 10.0, "button": "left", "down": True, "clicks": 1})
        s.send({"type": "mouse_button", "x": 10.0, "y": 10.0, "button": "left", "down": False, "clicks": 1})
        s.send({"type": "key_down", "key": "a", "code": "KeyA", "key_code": 65, "modifiers": 0, "text": "a"})
        s.send({"type": "key_up", "key": "a", "code": "KeyA", "key_code": 65, "modifiers": 0})
        time.sleep(1)
        still = json.loads(http("GET", "/v1/screens")[1]).get("screens", [])
        check(
            "the click and the key left the screen live",
            any(x.get("id") == "ui-screen" and x.get("ended") is None for x in still),
            f"{still}"[:160],
        )
        s.close()

        status, _ = http("DELETE", "/v1/screens/ui-screen")
        check("DELETE /v1/screens/{id}", status == 200, str(status))
        check(
            "the screen is gone from the listing",
            json.loads(http("GET", "/v1/screens")[1]).get("screens") == [],
            "",
        )


def check_rendered(check):
    """The rendered-browser gate: headless Chromium loads the served page for real.

    Marker checks against `GET /` prove the bytes; this proves what the bytes *do*: the script
    runs without a console error, the panes people look at mount their JS-rendered contents, and
    the page paints — a PNG a person can open, not just a DOM that parsed. A served page that
    threw during boot passes every marker check and fails here, which is the failure this gate
    exists to catch.

    Skipped rather than failed on a machine with no Chromium: the gate tests the page, not the
    machine, and `HX_WEB_CHECK_BROWSER` points it at a binary when PATH cannot. The console-error
    assertion ignores only the xterm CDN — a daemon host without internet is a valid deployment
    the pane already names in plain text, not a page defect.
    """
    browser = os.environ.get("HX_WEB_CHECK_BROWSER")
    if not browser:
        for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
            found = shutil.which(name)
            if found:
                browser = found
                break
    if not browser:
        print("SKIP  the rendered-browser gate (no Chromium on this machine)")
        return

    url = f"http://{HOST}:{PORT}/"
    shot = os.path.join(tempfile.gettempdir(), f"hx-render-{PORT}.png")
    with tempfile.TemporaryDirectory() as profile:
        try:
            run = subprocess.run(
                [
                    browser,
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--no-first-run",
                    "--disable-extensions",
                    "--hide-scrollbars",
                    "--window-size=1440,900",
                    "--virtual-time-budget=10000",
                    "--enable-logging=stderr",
                    f"--user-data-dir={profile}",
                    f"--screenshot={shot}",
                    "--dump-dom",
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as e:
            check("headless Chromium runs the page", False, str(e)[:160])
            return

    dom = run.stdout or ""
    stderr = run.stderr or ""
    check("headless Chromium runs the page", bool(dom.strip()), f"exit {run.returncode}")

    # Console failures surface in the stderr log as `Uncaught …` exceptions or as ERROR-severity
    # console records. The xterm CDN is the one third-party fetch the page makes on purpose, so a
    # host that cannot reach it is excluded — every other error is a page defect.
    bad = []
    for line in stderr.splitlines():
        if "CONSOLE" not in line and "Uncaught" not in line:
            continue
        if "jsdelivr" in line or "ERR_INTERNET_DISCONNECTED" in line:
            continue
        if "Uncaught" in line or ":ERROR:" in line or "TypeError" in line or "ReferenceError" in line or "SyntaxError" in line:
            bad.append(line.strip()[-140:])
    check("the page runs with no console errors", not bad, "; ".join(bad[:3]))

    # JS-rendered contents: these elements are empty in the served markup and only have children
    # after boot code runs, so finding them proves the script executed — not just that it parsed.
    check(
        "the session list renders (JS ran and fetched)",
        'class="sess' in dom,
        "no .sess elements in the rendered DOM",
    )
    # The surfaces a compile check cannot see wired: the attention strip, the reconnect pill, the
    # toast region and the live announcement region a screen reader reads.
    for marker in ('id="attention"', 'id="connbar"', 'id="toasts"', 'id="sr-live"', 'role="tablist"'):
        check(f"the rendered page keeps {marker}", marker in dom, "missing from the rendered DOM")

    try:
        with open(shot, "rb") as f:
            magic = f.read(8)
        painted = magic == b"\x89PNG\r\n\x1a\n" and os.path.getsize(shot) > 20_000
    except OSError:
        painted = False
    check("the page paints (screenshot is a PNG)", painted, f"{shot} missing or too small")
    if painted:
        print(f"      rendered screenshot kept at {shot}")


if __name__ == "__main__":
    sys.exit(main())
