// ---------------------------------------------------------------------------------------------
// Screen — a browser the daemon runs, streamed as frames with the input going back
//
// A separate pane from the terminal rather than a mode of it: a screen is not bytes on a pty. Its
// frames are JPEGs, its input is mouse and keyboard events *in the frame's own coordinates*, and the
// two have nothing in common but the ownership model — the browser lives in the daemon, so closing
// this tab does not close the screen and reattaching shows the picture as it is now.
//
// What it deliberately does not do is claim the browser is *in* a sandbox. It is on the daemon's
// machine; the pane says so. A box's own pixels need a browser inside the box, which needs an image
// that carries one and a way for the daemon to reach its port — neither of which exists here yet.

let screenId = null, screenSocket = null, screenReconnectDelay = 250, screenEnded = false;
// The page the browser is showing, for the address bar and for `reload`.
let screenURL = "";
// Frame coalescing: a draw is asynchronous (`createImageBitmap`), and frames can arrive faster than
// one paints. The newest one wins — an older frame drawn after a newer one would show the past.
let screenDrawing = false, screenPending = null;

/// Where a pointer event lands, in the *frame's* coordinates.
///
/// The canvas is displayed scaled to fit the pane, so the raw `clientX`/`clientY` are not frame
/// pixels. Mapping through the element's rect is what makes a click land where the person clicked
/// rather than where the browser would have drawn it at full size.
function screenPoint(ev) {
  const canvas = $("screen-canvas");
  const rect = canvas.getBoundingClientRect();
  const scaleX = rect.width ? canvas.width / rect.width : 1;
  const scaleY = rect.height ? canvas.height / rect.height : 1;
  return { x: (ev.clientX - rect.left) * scaleX, y: (ev.clientY - rect.top) * scaleY };
}

function screenButton(ev) {
  return ev.button === 1 ? "middle" : ev.button === 2 ? "right" : "left";
}

/// Which of Alt(1)/Ctrl(2)/Meta(4)/Shift(8) are held, as CDP's own mask.
///
/// Sent with every key because a shortcut *is* the mask: the same "a" with Ctrl held has to arrive
/// as one, or the page types a letter where the person asked it to select.
function screenModifiers(ev) {
  return (ev.altKey ? 1 : 0) | (ev.ctrlKey ? 2 : 0) | (ev.metaKey ? 4 : 0) | (ev.shiftKey ? 8 : 0);
}

function screenSend(frame) {
  if (screenSocket && screenSocket.readyState === WebSocket.OPEN) {
    screenSocket.send(JSON.stringify(frame));
    return true;
  }
  return false;
}

function initScreen() {
  const canvas = $("screen-canvas");
  if (!canvas) return false;
  canvas.width = 1280;
  canvas.height = 800;

  // A canvas takes no focus on its own, so a click focuses it *and* is sent: the first click into a
  // pane that was not focused must still reach the page, or every first click is swallowed.
  canvas.addEventListener("mousedown", (ev) => {
    ev.preventDefault();
    canvas.focus();
    const p = screenPoint(ev);
    screenSend({ type: "mouse_move", x: p.x, y: p.y });
    screenSend({
      type: "mouse_button",
      x: p.x,
      y: p.y,
      button: screenButton(ev),
      down: true,
      clicks: Math.max(1, ev.detail | 0),
    });
  });
  canvas.addEventListener("mouseup", (ev) => {
    const p = screenPoint(ev);
    screenSend({
      type: "mouse_button",
      x: p.x,
      y: p.y,
      button: screenButton(ev),
      down: false,
      clicks: Math.max(1, ev.detail | 0),
    });
  });
  canvas.addEventListener("mousemove", (ev) => {
    const p = screenPoint(ev);
    screenSend({ type: "mouse_move", x: p.x, y: p.y });
  });
  // Right-click reaches the page rather than this page's menu: the context menu belongs to whatever
  // the screen is showing, and a pane that opened its own would make a web app's menu unreachable.
  canvas.addEventListener("contextmenu", (ev) => ev.preventDefault());
  canvas.addEventListener(
    "wheel",
    (ev) => {
      ev.preventDefault();
      const p = screenPoint(ev);
      // `deltaMode` is the unit the browser chose: 0 pixels, 1 lines, 2 pages. A line is not a pixel
      // and a screen that scrolled a whole line's worth for one notch would feel broken.
      const unit = ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? canvas.height : 1;
      screenSend({
        type: "wheel",
        x: p.x,
        y: p.y,
        delta_x: ev.deltaX * unit,
        delta_y: ev.deltaY * unit,
      });
    },
    { passive: false }
  );

  const onKey = (ev) => {
    const mods = screenModifiers(ev);
    if (ev.type === "keydown") {
      // A character key inserts only with *no* Ctrl/Meta/Alt: with them it is a shortcut, and sending
      // text as well would have the page do both — select-all *and* type an "a".
      const inserts = ev.key.length === 1 && !ev.ctrlKey && !ev.metaKey && !ev.altKey;
      screenSend({
        type: "key_down",
        key: ev.key,
        code: ev.code,
        key_code: ev.keyCode || 0,
        modifiers: mods,
        text: inserts ? ev.key : null,
      });
    } else {
      screenSend({ type: "key_up", key: ev.key, code: ev.code, key_code: ev.keyCode || 0, modifiers: mods });
    }
    // The pane keeps the keys the *page* should have: Tab to move focus, Space and the arrows to
    // scroll, Backspace to go back. Without this they act on this page instead, and the screen looks
    // like it is ignoring input. The browser's own keys (F5, F12, Ctrl+W) are left alone.
    if (ev.key !== "F5" && ev.key !== "F12") ev.preventDefault();
  };
  canvas.addEventListener("keydown", onKey);
  canvas.addEventListener("keyup", onKey);

  $("screen-open").addEventListener("click", () => openScreenFromBar());
  $("screen-url").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") { ev.preventDefault(); openScreenFromBar(); }
  });
  $("screen-close").addEventListener("click", async () => {
    if (!screenId) return;
    const id = screenId;
    // Cleared first: the socket's close handler would otherwise reconnect to a screen this request
    // is about to delete, and the reconnect would win the race often enough to matter.
    screenEnded = true;
    try { if (screenSocket) screenSocket.close(); } catch (_) {}
    screenSocket = null;
    screenId = null;
    try {
      const res = await apiFetch(`${API}/v1/screens/${encodeURIComponent(id)}`, { method: "DELETE" });
      if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
      paintScreenWhere(`closed ${id}`);
    } catch (e) {
      $("screen-error").textContent = `could not close ${id}: ${e.message || e}`;
    }
    // Closing a screen that was presenting a challenge ends the challenge — the person walked away
    // from the question — so the banner is re-read rather than left showing a fetch nobody is
    // waiting for any more.
    pollChallenges();
  });

  $("challenge-watch").addEventListener("click", watchChallenge);
  $("challenge-solved").addEventListener("click", () => answerChallenge("solved"));
  $("challenge-give-up").addEventListener("click", () =>
    answerChallenge("abandoned", $("challenge-note").value.trim())
  );
  $("challenge-note").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") answerChallenge("abandoned", $("challenge-note").value.trim());
  });
  // Title repainting on tab visibility is owned by the shared painter in 05-attention.js.
  return true;
}

function paintScreenWhere(text) {
  const el = $("screen-where");
  if (el) el.textContent = text || "";
}

/// Open the address bar's URL: navigate the live screen if there is one, else launch it at that page.
async function openScreenFromBar() {
  const typed = $("screen-url").value.trim();
  $("screen-error").textContent = "";
  if (screenId && screenSocket && screenSocket.readyState === WebSocket.OPEN) {
    // An empty bar means *the page it is already on*, not `about:blank`: the bar is filled from the
    // `navigated` frames, so a person who clears it and presses open means "show me this again".
    const url = typed || screenURL;
    if (!url) return;
    screenURL = url;
    screenSend({ type: "navigate", url });
    return;
  }
  try {
    // A reload after the screen is gone reattaches to the same id, so the browser is reused rather
    // than a second one launched under a new name every time the pane is opened. An empty bar on a
    // *first* open means the daemon's configured `screen.url`, which is why nothing is invented here.
    await ensureScreen(screenId || "hx-screen", typed);
  } catch (e) {
    $("screen-error").textContent = String(e.message || e);
  }
}

/// Launch a screen under `id` and attach to it.
async function ensureScreen(id, url) {
  const res = await apiFetch(`${API}/v1/screens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ id, url: url || undefined }),
  });
  if (!res.ok) {
    // The daemon's own sentence, verbatim: a missing browser names every path it searched, and a
    // rewritten version of that would be a paraphrase of the one useful fact.
    throw new Error(await res.text());
  }
  const body = await res.json();
  screenId = id;
  screenURL = (body.screen && body.screen.url) || url || "";
  if (body.screen && body.screen.width && body.screen.height) {
    const canvas = $("screen-canvas");
    canvas.width = body.screen.width;
    canvas.height = body.screen.height;
  }
  attachScreen();
}

async function attachScreen() {
  screenEnded = false;
  if (screenSocket) { try { screenSocket.close(); } catch (_) {} }
  screenSocket = new WebSocket(await wsURL(`/v1/screens/${screenId}/ws`));

  screenSocket.onopen = () => {
    screenReconnectDelay = 250;
    if (typeof netUp === "function") netUp();
    paintScreenWhere(screenURL || screenId);
  };
  screenSocket.onmessage = (ev) => {
    let frame;
    try { frame = JSON.parse(ev.data); } catch (_) { return; }
    switch (frame.type) {
      case "frame":
        drawScreenFrame(frame);
        break;
      case "navigated":
        screenURL = frame.url;
        $("screen-url").value = frame.url;
        paintScreenWhere(frame.url);
        break;
      case "lagged":
        // Frames were dropped *for this client*. Said out loud, because a screen missing frames shows
        // a state that never existed, and "my picture is stale" is otherwise indistinguishable from
        // "the page is not changing".
        paintScreenWhere(`${screenURL} — ${frame.missed} frames dropped`);
        break;
      case "ended":
        screenEnded = true;
        paintScreenWhere(`screen ended: ${frame.reason}`);
        break;
      case "error":
        $("screen-error").textContent = frame.message;
        break;
    }
  };
  screenSocket.onclose = async (e) => {
    // Reconnect with a backoff, unless the daemon said the screen is over: the browser lives in the
    // daemon, so a dropped socket is a failed *attachment* and reattaching is the whole recovery.
    if (screenEnded || !screenId) return;
    // Same deliberate-close guard as the other sockets.
    if (e && e.target !== screenSocket) return;
    if (typeof netDown === "function") netDown("screen disconnected — retrying");
    // A screen the daemon no longer has is not a failed attachment. It was closed — by another tab,
    // by the challenge it was presenting ending, by the daemon — and a socket to a name nothing
    // answers to is a 404 the browser's WebSocket API does not expose apart from any other failure,
    // so the retry would be forever. Asked about rather than guessed: a *failed* listing is a daemon
    // that is down, which is exactly the case reconnecting is for.
    const gone = await screenGone(screenId);
    if (gone) {
      screenEnded = true;
      screenId = null;
      paintScreenWhere(`screen closed: ${gone}`);
      return;
    }
    // Said out loud, because the caption would otherwise keep the last thing that happened — a
    // screen closed a moment ago, or a page that never loaded — while the pane is quietly doing
    // something else.
    paintScreenWhere(`reconnecting to ${screenId}…`);
    setTimeout(() => { if (screenId && !screenEnded) attachScreen(); }, screenReconnectDelay);
    screenReconnectDelay = Math.min(screenReconnectDelay * 2, 8000);
  };
}

/// Why the screen `id` is not there any more, or `null` when it is (or when the daemon could not be
/// asked, which is a different situation and not this function's to report).
async function screenGone(id) {
  try {
    const res = await apiFetch(`${API}/v1/screens`);
    if (!res.ok) return null;
    const body = await res.json();
    const screens = body.screens || [];
    const found = screens.find((s) => s.id === id);
    if (!found) return "the daemon no longer has it";
    // A screen that is over is still listed, with its reason: attaching to it would succeed and then
    // end immediately, so the honest thing is to show why instead of bouncing.
    return found.ended ? `it ended: ${found.ended}` : null;
  } catch (_) {
    return null;
  }
  screenSocket.onerror = () => { /* onclose handles it */ };
}

