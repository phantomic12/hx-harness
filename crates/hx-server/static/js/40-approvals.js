// ---------------------------------------------------------------------------------------------
// Approvals

// Pushed for the open task: an approval is an ordinary event on the session socket, so
// `noteAttention` re-reads the queue the moment a question is asked or answered. The timer is now
// only the cross-task fallback (a question on a task this page is not open on) — and the thing
// that keeps the sandbox/host panes fresh, which is why it stays quick.
const APPROVAL_POLL_MS = 2000;
let approvalTimer = null;

/// The sandbox state, shown above the approval list.
///
/// It sits here because the two are read together: an approval is often *about* running something,
/// and whether the daemon can run it at all — no container engine, or every slot taken — is the
/// context that decides how to answer. Hidden when unavailable is the wrong call: "sandboxes are
/// off" is exactly what a person needs to know before wondering why their build never starts.
async function pollSandboxes() {
  const host = $("sandbox-status");
  try {
    // `/v1/status`, not `/v1/sandboxes`: the latter returns the list of *live containers*, while
    // the summary this strip renders — availability, slots, the reason — is part of the status
    // snapshot. Reading the list route would leave the strip permanently blank, which looks the
    // same as a daemon with no container engine.
    const res = await apiFetch(`${API}/v1/status`);
    if (!res.ok) throw new Error(`${res.status}`);
    const s = (await res.json()).sandboxes || {};
    host.innerHTML = "";
    const span = document.createElement("span");
    if (s.available) {
      span.className = "live";
      const slots = s.free_slots === undefined || s.free_slots === null ? "?" : s.free_slots;
      const max = s.max_concurrent === undefined || s.max_concurrent === null ? "?" : s.max_concurrent;
      span.textContent = `sandboxes: ${s.live} live, ${slots}/${max} slots free`;
    } else {
      span.className = "off";
      // The reason is shown verbatim. "unavailable" alone sends someone to read logs; the daemon
      // already knows why — a missing socket, no engine — and that sentence is the whole value here.
      span.textContent = `sandboxes unavailable${s.reason ? `: ${s.reason}` : ""}`;
    }
    host.appendChild(span);
  } catch (e) {
    host.textContent = `sandbox state unknown: ${e.message || e}`;
    return;
  }
  // The boxes themselves, each with the way in. `/v1/status` gives the summary and not the ids, so
  // this second read is the one that knows what there is to enter — a daemon with a working engine
  // and no live boxes renders nothing here, which is the honest picture.
  try {
    const res = await apiFetch(`${API}/v1/sandboxes`);
    if (!res.ok) return;
    const boxes = await res.json();
    for (const box of boxes) {
      const row = document.createElement("div");
      row.className = "box";
      const line = document.createElement("div");
      line.className = "line";
      const id = document.createElement("span");
      id.className = "id";
      // The profile and remaining life, not just the id: which box is which is unreadable from an
      // opaque id alone, and "expires in 40m" is what decides whether to bother.
      const left = Math.max(0, Math.round((new Date(box.expires_at) - Date.now()) / 60000));
      id.textContent = `${box.profile} · ${box.id} · ${left}m left`;
      id.title = `${box.id} (${box.isolation})`;
      // What it runs, when it runs anything: an idle box has no command and adds nothing here.
      let runs = null;
      if (Array.isArray(box.command) && box.command.length) {
        runs = document.createElement("span");
        runs.className = "runs";
        runs.textContent = `runs ${box.command.join(" ")}`;
        runs.title = box.command.join(" ");
      }
      const shell = document.createElement("button");
      shell.type = "button";
      shell.textContent = "shell";
      shell.title = `open a terminal inside ${box.id}`;
      shell.addEventListener("click", async () => {
        try {
          await openSandboxTerminal(box.id);
        } catch (e) {
          // The daemon's own sentence, verbatim: for a refused session it already says what is
          // wrong (a backend with no way to open one, a box that just stopped) and inventing a
          // friendlier message would replace the answer with a paraphrase.
          showError(String(e.message || e));
        }
      });
      line.appendChild(id);
      line.appendChild(shell);
      row.appendChild(line);
      // Below the identity, not beside it: what a box runs is worth a line of its own and would
      // otherwise take the width the id needs to be readable at all.
      if (runs) row.appendChild(runs);
      host.appendChild(row);
    }
  } catch (e) {
    // The summary above is already rendered and useful; a failed list read is not worth replacing
    // it with an error line, so this stays quiet.
  }
}

// A question arriving on the open task's socket is the push half of the approval surface: it
// only re-reads the queue (one request, every session) — the notification itself is driven from
// what that read returns, so a question can never alarm twice or alarm on replayed history.
function noteAttention(event) {
  const kind = kindOf(event);
  if (kind === "approval_requested" || kind === "approval_resolved") pollApprovals();
  // A priced call just happened: money moved, so the spend panel re-reads. Cheap and idempotent.
  if (kind === "usage") refreshSpend();
  // A turn finished: if this page is in the background, tell the person their answer is ready —
  // the run-completion half of "answer from anywhere". A foreground page says nothing (the
  // stream is the answer); a page that cannot notify just keeps its title.
  if (kind === "turn_finished" && document.hidden) notifyRunDone(event);
}

// One notification per finished run: `tag` collapses repeats, and a notification that fires while
// the page regains focus is worse than none. Degrades silently like the approval notification.
function notifyRunDone(event) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  try {
    new Notification("hx: run finished", {
      body: `${titleBase} — the run ended, the answer is on the transcript`,
      tag: `hx-done-${sessionId || "global"}`,
    });
  } catch (_) {}
}

// Money made visible. The store always carried every usage row; this is the panel that finally
// asks it where the money went — by day, by model, by session — so a budget stops being
// decorative. A row priced at zero with tokens stands as `unpriced`, never as free.
function spendCost(row) {
  const cost = typeof row.cost_usd === "number" ? row.cost_usd : 0;
  const tokens = (row.input_tokens || 0) + (row.output_tokens || 0);
  if (cost > 0) return `$${cost.toFixed(4)}`;
  return tokens > 0 ? "unpriced" : "—";
}

function spendRow(key, row) {
  // Two lines, never one wrapping mess: the name and the money on top (the two things a person
  // scans for), the token counts beneath in a smaller voice.
  const div = document.createElement("div");
  div.className = "spend-row";
  const top = document.createElement("div");
  top.className = "line";
  const label = document.createElement("span");
  label.textContent = key;
  const money = document.createElement("span");
  const cost = typeof row.cost_usd === "number" ? row.cost_usd : 0;
  const tokens = (row.input_tokens || 0) + (row.output_tokens || 0);
  if (cost > 0 || tokens === 0) {
    const b = document.createElement("b");
    b.textContent = spendCost(row);
    money.append(b);
  } else {
    money.className = "unpriced";
    money.textContent = "unpriced";
  }
  top.append(label, money);
  const counts = document.createElement("div");
  counts.className = "counts";
  counts.textContent = `${row.calls || 0} call(s) · ${row.input_tokens || 0} in / ${row.output_tokens || 0} out`;
  div.append(top, counts);
  return div;
}

async function refreshSpend() {
  const host = $("spend-body");
  if (!host) return;
  try {
    const res = await apiFetch(`${API}/v1/usage`);
    if (!res.ok) return;
    const report = await res.json();
    const total = report.total || {};
    const ticker = $("spend-ticker");
    if (ticker) ticker.textContent = `spend ${spendCost(total)} / 30d`;
    const head = $("spend-total");
    if (head) {
      head.textContent = `${spendCost(total)} · ${total.calls || 0} call(s)`;
    }
    host.replaceChildren();
    const section = (title, rows, keyOf) => {
      if (!Array.isArray(rows) || rows.length === 0) return;
      const h = document.createElement("div");
      h.className = "spend-head";
      h.textContent = title;
      host.append(h);
      for (const row of rows) host.append(spendRow(keyOf(row), row));
    };
    section("by model", report.by_model, (r) => r.key || "?");
    section("by day", report.by_day, (r) => r.key || "?");
    section("by session", report.by_session, (r) => r.title || r.key || "?");
    if (!host.childElementCount) {
      const empty = document.createElement("div");
      empty.className = "spend-row";
      empty.textContent = "no provider calls in the last 30 days";
      host.append(empty);
    }
  } catch (_) { /* a panel that cannot read is not worth an error banner */ }
}

// The title bar joins the alarm: a tab left open in the background is where a run's question
// actually waits. `paintTitle` (the shared painter in the attention strip) owns it — one mark for
// every waiting state instead of a prefix per pane.
const titleBase = document.title;
window.addEventListener("focus", () => { document.title = titleBase; });

// Desktop notification for a question that needs a person. Degrades silently: a browser that has
// not granted (or does not support) notifications still has the pane, the chip and the title.
function notifyApprovals(reqs) {
  if (!("Notification" in window)) return;
  const fire = () => {
    for (const req of reqs.slice(0, 3)) {
      try {
        new Notification("hx: approval needed", {
          body: `${req.tool || "tool"} — ${req.summary || req.reason || ""}`,
          tag: `hx-approval-${req.id}`,
        });
      } catch (_) {}
    }
  };
  if (Notification.permission === "granted") fire();
  else if (Notification.permission === "default") {
    const asked = Notification.requestPermission();
    if (asked && asked.then) asked.then((p) => { if (p === "granted") fire(); }, () => {});
  }
}

async function pollApprovals() {
  try {
    const res = await apiFetch(`${API}/v1/approvals`);
    if (!res.ok) throw new Error(`${res.status}`);
    const items = await res.json();
    renderApprovals(Array.isArray(items) ? items : []);
    $("approval-error").textContent = "";
  } catch (e) {
    $("approval-error").textContent = `approvals unavailable: ${e.message || e}`;
  }
}

// Ids already seen. `null` means "not primed yet": the first read only records, so opening the
// page beside an old question does not raise an alarm for it.
let knownApprovals = null;
function renderApprovals(items) {
  const ids = new Set(items.map((r) => r && r.id).filter(Boolean));
  const fresh = knownApprovals ? new Set([...ids].filter((id) => !knownApprovals.has(id))) : new Set();
  knownApprovals = ids;
  const host = $("approvals");
  $("approval-count").textContent = items.length ? `${items.length}` : "";
  // Which tasks are blocked on a person. The session rides on the request itself (the queue stamps
  // it when the question is asked), so one unfiltered poll marks every row — a request per row
  // would be one round trip per task for a fact the list already carries.
  const waiting = new Set();
  for (const req of items) {
    const sid = req && (typeof req.session === "string" ? req.session : (req.session && req.session.id));
    if (sid) waiting.add(sid);
  }
  const changed = waiting.size !== waitingSessions.size || [...waiting].some((s) => !waitingSessions.has(s));
  waitingSessions = waiting;
  // The strip is a window onto this same queue — every render tells it what is still waiting.
  attnApprovals = items;
  // Rebuilt wholesale: the list is small and every field can change, so a diff would be more
  // machinery than the thing it optimises.
  host.innerHTML = "";
  if (items.length === 0) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "Nothing waiting.";
    host.appendChild(p);
  } else {
    for (const req of items) host.appendChild(renderApproval(req));
  }
  if (changed) { renderSessions(); paintActivity(); }
  paintAttention();
  if (fresh.size) {
    paintTitle();
    notifyApprovals(items.filter((r) => fresh.has(r.id)));
    announce(`${items.length} approval${items.length > 1 ? "s" : ""} waiting — ${firstTitle(items)}`);
  }
}

// One-line digest of the first pending approval, for the screen-reader announcement.
function firstTitle(items) {
  const r = items[0] || {};
  return `${r.tool || "tool"}: ${r.summary || r.reason || "approval requested"}`;
}

function renderApproval(req) {
  const el = document.createElement("div");
  el.className = "approval";

  const risk = document.createElement("span");
  const riskClass = (req.risk || "medium").toString().toLowerCase();
  risk.className = `risk ${riskClass}`;
  // The risk class is a *string* here because the serialised enum may be a name or a tagged object;
  // rendering it plainly beats rendering `undefined` for a shape this does not recognise.
  risk.textContent = riskClass;
  el.appendChild(risk);

  const tool = document.createElement("div");
  tool.className = "tool";
  tool.textContent = req.tool || "tool";
  el.appendChild(tool);

  const summary = document.createElement("div");
  summary.className = "summary";
  summary.textContent = req.summary || "";
  el.appendChild(summary);

  const reason = document.createElement("div");
  reason.className = "reason";
  // The reason is the point of the pane: a prompt with no reason is one a person cannot answer
  // without guessing, and guessing is how a "yes" gets given to something nobody understood.
  reason.textContent = req.reason || "no reason given";
  el.appendChild(reason);

  if (req.undo) {
    const undo = document.createElement("div");
    undo.className = "undo";
    undo.textContent = `undo: ${req.undo}`;
    el.appendChild(undo);
  } else if (req.reversible === false) {
    const undo = document.createElement("div");
    undo.className = "undo";
    // Said explicitly, because "no undo line" must not read as "there is nothing more to know".
    undo.textContent = "this cannot be undone";
    el.appendChild(undo);
  }

  // The remaining unattended budget, when the run that asked has one.
  //
  // Shown only when the daemon sent it. A policy with no check-in cadence sends nothing, and a `0`
  // or an `∞` invented here would be a number nobody is bound by — worse than saying nothing. When
  // it *is* sent, `0` is the interesting case: it means this question is the check-in the budget
  // forced, which is what a person deciding whether to let the run keep going needs to know.
  if (req.unattended && typeof req.unattended.budget === "number") {
    const rope = document.createElement("div");
    rope.className = "unattended";
    const left =
      typeof req.unattended.remaining === "number" ? req.unattended.remaining : req.unattended.budget;
    rope.textContent =
      left === 0
        ? `unattended: this is the check-in (0 of ${req.unattended.budget} left)`
        : `unattended: ${left} of ${req.unattended.budget} left before a check-in`;
    el.appendChild(rope);
  }

  const opts = document.createElement("div");
  opts.className = "opts";
  // The wire values the daemon's route accepts, with the label a person reads. Kept as an explicit
  // table rather than passing through whatever the request carried: the route rejects anything
  // outside `once|chat|always|deny`, so sending the serialised option back would turn a working
  // button into a 400 depending on which enum shape the daemon happened to serialise.
  const OPTIONS = [
    { value: "once", label: "Allow once" },
    { value: "chat", label: "Allow for this chat" },
    { value: "always", label: "Always allow" },
    { value: "deny", label: "Deny" },
  ];
  // Only the options the daemon actually offered, so the pane cannot present a choice the policy
  // engine does not intend to honour.
  const offered = new Set(
    (req.options || []).map((o) =>
      (typeof o === "string" ? o : o.option || o.value || o.label || "").toString().toLowerCase()
    )
  );
  const known = (v) => offered.size === 0 || [...offered].some((o) => o.includes(v));
  for (const option of OPTIONS) {
    if (!known(option.value)) continue;
    const btn = document.createElement("button");
    btn.textContent = option.label;
    if (option.value === "deny") btn.className = "deny";
    btn.addEventListener("click", () => answerApproval(req.id, option.value));
    opts.appendChild(btn);
  }
  el.appendChild(opts);
  return el;
}

// The ceiling this page answers with.
//
// The route requires one and has no default, so the client has to say what it is. This page is served
// by the daemon itself and is the owner's own surface on the owner's own machine — the same authority
// as a keystroke at the prompt — so it declares the full ladder. A surface that is not the terminal
// (a chat bridge, say) must declare its own, and the queue refuses an answer above it.
const CEILING = "privileged";

async function answerApproval(id, option) {
  try {
    const res = await apiFetch(`${API}/v1/approvals/${encodeURIComponent(id)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ option, ceiling: CEILING, by: "web" }),
    });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    if (typeof toast === "function") {
      toast(option === "deny" ? "denied" : `allowed (${option})`, option === "deny" ? "warn" : "ok");
    }
    // Answered immediately rather than waiting for the next poll, so the card does not sit there
    // looking unanswered after it has been decided.
    await pollApprovals();
  } catch (e) {
    $("approval-error").textContent = `could not answer: ${e.message || e}`;
    if (typeof toast === "function") toast(`could not answer: ${e.message || e}`, "bad");
  }
}

