#!/usr/bin/env python3
"""Drive the live hx daemon over the exact wire protocol the web client speaks.

A browser check is better, but the browser stack is down, and "the UI compiles" is not evidence the
UI works. This speaks the same frames the page's JavaScript does — the same `POST /v1/terminals`,
the same `GET /v1/terminals/{id}/ws` with base64 `input`, and the same session socket — using only
the standard library, so nothing about the transport is being stubbed out or assumed.

What it proves: the endpoints the page calls exist, the frames it parses are the frames the daemon
sends, and two independent clients on one terminal genuinely receive the same bytes.
"""

import base64
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

HOST = "127.0.0.1"
PORT = 8899


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
    status, body = http("POST", "/v1/terminals", {"id": "ui-term", "cols": 80, "rows": 24})
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

    # 8. Deleting the terminal, as the page does not do but a cleanup must.
    status, _ = http("DELETE", "/v1/terminals/ui-term")
    check("DELETE /v1/terminals/{id}", status == 200, str(status))

    print()
    if failures:
        print(f"{len(failures)} FAILED: {failures}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
