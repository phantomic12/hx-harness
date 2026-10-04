// ---------------------------------------------------------------------------------------------
// Terminal

let term = null, fit = null, termSocket = null, terminalId = null;
let termReconnectDelay = 250;

function initTerm() {
  if (typeof Terminal === "undefined") {
    // The CDN is the one external dependency. Say so instead of leaving a blank pane that looks
    // like a broken shell.
    $("terminal").innerHTML =
      '<p style="color:var(--bad-ink);font-size:12px;padding:8px">' +
      "xterm.js could not be loaded from the CDN — check network access.</p>";
    return false;
  }
  term = new Terminal({
    cursorBlink: true,
    fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace',
    fontSize: 13,
    theme: {
      background: cssVar("--bg-inset"),
      foreground: cssVar("--tx-0"),
      cursor: cssVar("--accent"),
    },
    scrollback: 5000,
  });
  fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($("terminal"));
  fit.fit();

  // Typing goes to the daemon, not to a local shell: the PTY is server-side, which is what lets a
  // second client share this terminal.
  term.onData((data) => {
    if (termSocket && termSocket.readyState === WebSocket.OPEN) {
      termSocket.send(JSON.stringify({ type: "input", data: b64encode(data) }));
    }
  });
  // Resizing the window resizes the *shell*, so full-screen programs redraw correctly.
  term.onResize(({ cols, rows }) => sendResize(cols, rows));
  new ResizeObserver(() => { try { fit.fit(); } catch (_) {} }).observe($("terminal"));
  window.addEventListener("resize", () => { try { fit.fit(); } catch (_) {} });
  return true;
}

function sendResize(cols, rows) {
  if (termSocket && termSocket.readyState === WebSocket.OPEN && cols > 0 && rows > 0) {
    termSocket.send(JSON.stringify({ type: "resize", cols, rows }));
  }
}

// Terminal bytes are not text: escape sequences and partial UTF-8 sequences split across reads
// must survive exactly, so input is base64 and output is decoded back to bytes before xterm sees it.
function b64encode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64decodeToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/// Which machine the pane is showing, printed above it. See `#term-where`'s style for why.
let termWhere = "";

function paintTermWhere() {
  const el = $("term-where");
  if (!el) return;
  el.textContent = termWhere;
  el.classList.toggle("inbox", termWhere.startsWith("in "));
}

/// Create (or reattach to) a terminal under `id`, optionally inside a sandbox, and show it.
///
/// One function for all three ways in — the boot terminal, the `new` button, and clicking a box's
/// `shell` button — because they differ only in the id and the extra field, and three copies of
/// "POST, tolerate already-exists, attach" is three places for the tolerance to rot.
async function ensureTerminalFor(id, extra, where) {
  const res = await apiFetch(`${API}/v1/terminals`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(Object.assign(
      { id, cols: term ? term.cols : 80, rows: term ? term.rows : 24 },
      extra || {}
    )),
  });
  // 200 = created; anything else may mean it already exists, which is fine — attach and find out.
  // A real refusal (no engine, a box that is gone, a backend that cannot attach a session) is a
  // failure here, and its body is the daemon's sentence about why: shown verbatim.
  if (res.status !== 200) {
    const list = await apiFetch(`${API}/v1/terminals`).then((r) => r.json()).catch(() => ({}));
    if (!(list.terminals || []).includes(id)) {
      const body = await res.text();
      throw new Error(`could not create a terminal: ${body}`);
    }
  }
  terminalId = id;
  termWhere = where || "";
  paintTermWhere();
  // Cleared on purpose: the previous terminal's output belongs to a different shell, and appending
  // one machine's scrollback above another's prompt is how a person runs a command in the wrong
  // place.
  if (term) term.reset();
  attachTerminal();
}

/// The terminal this page starts with, or reattaches to after a reload.
///
/// Reuse across reloads is deliberate: `hx-term` is a fixed id, so a page refresh reattaches to the
/// shell that is already running instead of starting a second one.
async function ensureTerminal() {
  terminalId = terminalId || "hx-term";
  await ensureTerminalFor(terminalId, null, "on this machine");
}

/// Open a shell **inside** a sandbox, replacing whatever the pane was showing.
///
/// The id is derived from the box, so pressing `shell` twice reattaches to the same session rather
/// than starting a second shell in the same container — the box has one of these per page, and a
/// reload should not leave a shell running that nobody can reach again.
async function openSandboxTerminal(sandboxId) {
  // The drawer may be showing another pane; the tab's own click handler is what keeps panes,
  // buttons and the xterm fit in step, so it is clicked rather than bypassed.
  document.querySelector('.tabs button[data-tab="terminal"]')?.click();
  await ensureTerminalFor(
    `hx-sbx-${sandboxId}`,
    { sandbox: sandboxId },
    `in ${sandboxId}`
  );
}

async function attachTerminal() {
  if (termSocket) { try { termSocket.close(); } catch (_) {} }
  termSocket = new WebSocket(await wsURL(`/v1/terminals/${terminalId}/ws`));

  termSocket.onopen = () => {
    termReconnectDelay = 250;
    if (typeof netUp === "function") netUp();
    sendResize(term.cols, term.rows);
    term.focus();
  };
  termSocket.onmessage = (ev) => {
    let frame;
    try { frame = JSON.parse(ev.data); } catch (_) { return; }
    switch (frame.type) {
      case "scrollback":
        // History, sent before any live output. Cleared first so a reattaching client does not
        // append to what it already rendered.
        term.reset();
        term.write(b64decodeToBytes(frame.data));
        break;
      case "output":
        term.write(b64decodeToBytes(frame.data));
        break;
      case "lagged":
        // This client fell behind and frames were dropped *for it*. Said out loud, because a
        // terminal with a hole in it renders wrong from here on and looks like the shell's doing.
        term.write(`\r\n\x1b[33m[${frame.missed} frames dropped — the terminal is still running]\x1b[0m\r\n`);
        attachTerminal();
        break;
      case "exited":
        term.write(`\r\n\x1b[90m[shell exited${frame.code === null ? "" : ` with code ${frame.code}`}]\x1b[0m\r\n`);
        break;
      case "error":
        term.write(`\r\n\x1b[31m[${frame.message}]\x1b[0m\r\n`);
        break;
    }
  };
  termSocket.onclose = (e) => {
    // Same guard as the session socket: closing the previous attachment on purpose is not the
    // connection dying.
    if (e && e.target !== termSocket) return;
    // Reconnect with a backoff. The shell is still running server-side, so this is a failed
    // *attachment*, not a lost terminal — reattaching is the whole recovery.
    if (typeof netDown === "function") netDown("terminal disconnected — retrying");
    setTimeout(() => { if (terminalId) attachTerminal(); }, termReconnectDelay);
    termReconnectDelay = Math.min(termReconnectDelay * 2, 8000);
  };
  termSocket.onerror = () => { /* onclose handles it */ };
}

