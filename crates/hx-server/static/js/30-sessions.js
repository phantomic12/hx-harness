// ---------------------------------------------------------------------------------------------
// Tasks (sessions)
//
// The left rail is a task list, the way Codex and Devin put one conversation per row. The daemon
// already has the primitives — GET/POST /v1/sessions, POST /v1/sessions/{id}/rename, DELETE — so
// this is a client of those, not a second store. localStorage remembers which task was open so a
// reload resumes it instead of minting a new empty one on every visit (the old behaviour).

const SESSION_KEY = "hx.session";
let sessions = [];
// Per-task liveness, derived from the event stream rather than polled. `running` holds the tool
// names a task currently has in flight (a start with no matching finish); `waiting` is the set of
// tasks with an approval nobody has answered. Both feed the row marker and the composer chip.
const runningTools = new Map();
let waitingSessions = new Set();
// Tasks with a run in flight (turn started, no turn finished yet) — what the stop button is for.
const activeRuns = new Set();
// Unsent composer text per task — the Codex draft marker. Switching tasks must not eat a
// half-written prompt, and the rail marks which tasks hold one (the grey dot, quiet on purpose).
const drafts = new Map();
// The session record does not carry the model — the usage frames that land while a task runs do.
// Remember the latest per task so the header can name what's answering without waiting for the
// next frame.
const sessionModels = new Map();
// Frames that arrive while a (re)attach replays history must not count as "unseen" — the
// browser restores scroll position mid-transcript on reload, which would otherwise flag the
// whole backlog as new. The flag clears once the socket has been quiet for a beat.
let snapToBottom = true;
let snapTimer = 0;

const sidOf = (s) => (typeof s === "string" ? s : (s && (s.id || s.session))) || "";
const titleOf = (s) => {
  if (!s || typeof s === "string") return "untitled";
  const t = (s.title || "").trim();
  return t && t !== "untitled" ? t : "untitled";
};
const whenOf = (s) => {
  const raw = s && (s.updated_at || s.created_at);
  if (!raw) return "";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return "";
  const diff = Date.now() - d.getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h`;
  return `${Math.floor(diff / 86_400_000)}d`;
};

function paintTaskHeader() {
  const s = sessions.find((x) => sidOf(x) === sessionId);
  const label = $("session-label");
  if (label && document.activeElement !== label) label.value = s ? titleOf(s) : "";
  const meta = $("session-meta");
  if (meta) {
    const bits = [];
    const model = (s && s.model) || sessionModels.get(sessionId);
    if (model) bits.push(model);
    if (s && s.turns) bits.push(`${s.turns} turns`);
    meta.textContent = bits.join(" · ");
  }
}

function renderSessions() {
  const host = $("sessions");
  if (!host) return;
  const count = $("session-count");
  if (count) count.textContent = sessions.length ? ` ${sessions.length}` : "";
  host.innerHTML = "";
  if (!sessions.length) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "No tasks yet. + new starts one.";
    host.appendChild(p);
    paintTaskHeader();
    return;
  }
  for (const s of sessions) {
    const id = sidOf(s);
    const btn = document.createElement("button");
    btn.className = "sess" + (id === sessionId ? " active" : "");
    btn.type = "button";
    const title = document.createElement("span");
    title.className = "stitle";
    title.textContent = titleOf(s);
    const row = document.createElement("span");
    row.className = "srow";
    // The mark answers "which task needs me" without opening it. Waiting outranks running: a
    // question nobody has answered is the thing a person can act on, a running tool is not.
    const state = taskState(id);
    if (state) {
      const mark = document.createElement("span");
      mark.className = "mark " + state;
      mark.title =
        state === "wait" ? "waiting on you" :
        state === "draft" ? "unsent text in the composer" : "working";
      row.appendChild(mark);
    }
    row.appendChild(title);
    const meta = document.createElement("span");
    meta.className = "smeta";
    const bits = [];
    const when = whenOf(s);
    if (when) bits.push(when);
    if (s && s.workspace) bits.push(String(s.workspace).split("/").filter(Boolean).pop() || "");
    meta.textContent = bits.filter(Boolean).join(" · ");
    btn.appendChild(row);
    btn.appendChild(meta);
    btn.addEventListener("click", () => openSession(id));
    host.appendChild(btn);
  }
  paintTaskHeader();
}

async function refreshSessions() {
  try {
    const res = await apiFetch(`${API}/v1/sessions?limit=100`);
    if (!res.ok) return;
    const body = await res.json();
    const items = body.sessions || body || [];
    sessions = Array.isArray(items) ? items : [];
  } catch (_) {}
  renderSessions();
}

// Open an existing task: clear the transcript, reset the resume floor, reattach the socket.
// A no-op when it is already the open one, so a poll cannot wipe a live transcript.
async function openSession(id) {
  if (!id || id === sessionId) { renderSessions(); return; }
  noteDraft(); // bank whatever the composer holds against the task it was typed on
  sessionId = id;
  lastSeq = 0;
  streaming = null;
  snapToBottom = true;
  try { localStorage.setItem(SESSION_KEY, id); } catch (_) {}
  const events = $("events");
  if (events) events.innerHTML = "";
  setUnseen(0);
  $("prompt").value = drafts.get(id) || "";
  showError("");
  renderSessions();
  paintActivity();
  paintMode();
  attachSession();
}

// The composer's unsent text is per task: an input event banks it, a send spends it, and the
// rail re-marks only when the has-a-draft state flips — repainting the list on every keystroke
// would be work nobody can see.
function noteDraft() {
  const input = $("prompt");
  if (!sessionId || !input) return;
  const had = drafts.has(sessionId);
  if (input.value.trim()) drafts.set(sessionId, input.value);
  else drafts.delete(sessionId);
  if (drafts.has(sessionId) !== had) renderSessions();
}
$("prompt").addEventListener("input", noteDraft);

async function createSession() {
  const btn = $("new-session");
  if (btn) btn.disabled = true;
  try {
    const res = await apiFetch(`${API}/v1/sessions`, { method: "POST" });
    if (res.status !== 200 && res.status !== 201) {
      throw new Error(`could not open a task: ${res.status} ${await res.text()}`);
    }
    const body = await res.json();
    const id = body.id || body.session;
    if (!id) throw new Error("create response had no id");
    // The created record rides on the response; show it immediately, then reconcile with the list.
    if (body.record) sessions.unshift(Object.assign({ messages: 0, turns: 0 }, body.record));
    await openSession(id);
    await refreshSessions();
    $("prompt").focus();
  } catch (e) {
    showError(String(e.message || e));
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function renameSession(title) {
  const next = (title || "").trim();
  const current = sessions.find((x) => sidOf(x) === sessionId);
  // Unchanged (including a blur that follows Enter) must not write. An empty field is "never
  // mind", not a request to store a blank title the daemon would reject anyway.
  if (!sessionId || !next || (current && titleOf(current) === next)) { paintTaskHeader(); return; }
  try {
    const res = await apiFetch(`${API}/v1/sessions/${sessionId}/rename`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: next }),
    });
    if (!res.ok) throw new Error(`rename failed: ${res.status} ${await res.text()}`);
    const rec = await res.json();
    const i = sessions.findIndex((s) => sidOf(s) === sessionId);
    if (i >= 0) sessions[i] = Object.assign({}, sessions[i], rec);
    renderSessions();
    if (typeof toast === "function") toast(`renamed to “${next}”`, "ok");
  } catch (e) {
    showError(String(e.message || e));
    if (typeof toast === "function") toast(`rename failed: ${e.message || e}`, "bad");
    paintTaskHeader();
  }
}

async function deleteSession() {
  if (!sessionId) return;
  const s = sessions.find((x) => sidOf(x) === sessionId);
  const name = s ? titleOf(s) : sessionId;
  if (!confirm(`Delete task “${name}”? The transcript goes with it.`)) return;
  try {
    const res = await apiFetch(`${API}/v1/sessions/${sessionId}`, { method: "DELETE" });
    if (!res.ok && res.status !== 404) throw new Error(`delete failed: ${res.status} ${await res.text()}`);
    const gone = sessionId;
    sessions = sessions.filter((x) => sidOf(x) !== gone);
    sessionId = null;
    lastSeq = 0;
    streaming = null;
    runningTools.delete(gone);
    activeRuns.delete(gone);
    drafts.delete(gone);
    try { localStorage.removeItem(SESSION_KEY); } catch (_) {}
    $("events").innerHTML = "";
    if (eventSocket) { try { eventSocket.close(); } catch (_) {} eventSocket = null; }
    const next = sessions[0] && sidOf(sessions[0]);
    if (next) await openSession(next);
    else renderSessions();
    if (typeof toast === "function") toast(`deleted “${name}”`, "info");
  } catch (e) {
    showError(String(e.message || e));
    if (typeof toast === "function") toast(`delete failed: ${e.message || e}`, "bad");
  }
}

// Boot: resume the last open task if it still exists, else the most recent, else make one.
// Creating on every load was the bug — a reload minted an empty session and abandoned the last one.
async function ensureSession() {
  await refreshSessions();
  let wanted = "";
  try { wanted = localStorage.getItem(SESSION_KEY) || ""; } catch (_) {}
  const known = new Set(sessions.map(sidOf));
  if (wanted && known.has(wanted)) { await openSession(wanted); return; }
  const first = sessions[0] && sidOf(sessions[0]);
  if (first) { await openSession(first); return; }
  await createSession();
}

async function attachSession() {
  if (eventSocket) { try { eventSocket.close(); } catch (_) {} }
  eventSocket = new WebSocket(await wsURL(`/v1/sessions/${sessionId}/ws`));

  eventSocket.onopen = () => {
    eventReconnectDelay = 250;
    if (typeof netUp === "function") netUp();
    // Resume from the last event actually rendered. Without this a reconnect re-renders the entire
    // history, which looks like the session repeating itself.
    if (lastSeq > 0) eventSocket.send(JSON.stringify({ since_seq: lastSeq }));
  };
  eventSocket.onmessage = (ev) => {
    let frame;
    try { frame = JSON.parse(ev.data); } catch (_) { return; }
    if (typeof frame.seq === "number") {
      // The floor is what makes the resume exact: events at or below it were already rendered.
      if (frame.seq <= lastSeq) return;
      lastSeq = frame.seq;
    }
    const arrived = frame.event || {};
    const arrivedKind = kindOf(arrived);
    if (arrivedKind === "usage" && arrived.model) {
      if (sessionModels.get(sessionId) !== arrived.model) {
        sessionModels.set(sessionId, arrived.model);
        paintTaskHeader();
      }
    }
    if (arrivedKind === "turn_started") showError(""); // a turn starting proves the last send landed
    if (kindOf(arrived) === "text_delta" && typeof arrived.text === "string") {
      // Deltas append. A card per token would be one bordered box per word, which is how a
      // transcript becomes unreadable exactly when the model is busiest.
      appendDelta(frame.seq, arrived.text);
    } else {
      streaming = null;
      const el = renderEvent(frame);
      $("events").appendChild(el);
      clampBody(el);
    }
    noteActivity(sessionId, arrived);
    noteAttention(arrived);
    if (snapToBottom) {
      jumpToLatest();
      clearTimeout(snapTimer);
      snapTimer = setTimeout(() => { snapToBottom = false; }, 400);
    } else {
      followEvents();
    }
  };
  eventSocket.onclose = (e) => {
    // A deliberate close (switching tasks reattaches under a fresh socket) is not a lost
    // connection — only the live socket's death counts.
    if (e && e.target !== eventSocket) return;
    if (typeof netDown === "function") netDown("transcript disconnected — retrying");
    setTimeout(() => { if (sessionId) attachSession(); }, eventReconnectDelay);
    eventReconnectDelay = Math.min(eventReconnectDelay * 2, 8000);
  };
}

