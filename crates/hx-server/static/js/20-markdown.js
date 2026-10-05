// ---------------------------------------------------------------------------------------------
// ---- markdown ---------------------------------------------------------------------------------

// Escape before any markup is interpreted. Every renderer here runs on the escaped text, so
// model output can never become page markup — the one security property a chat pane must hold.
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Inline rules: `code`, **bold**, *italic*, [text](https://…). Inline code is lifted out first so
// the other rules cannot touch its contents. Links only match http(s) — a `javascript:` URL can
// only ever be text here.
function mdInline(s) {
  const slots = [];
  let out = s.replace(/`([^`]+)`/g, (_, code) => {
    slots.push(`<code>${code}</code>`);
    return `\u0000${slots.length - 1}\u0000`;
  });
  out = out
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>")
    .replace(
      /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
      (_, t, u) => `<a href="${u}" target="_blank" rel="noreferrer">${t}</a>`
    );
  return out.replace(/\u0000(\d+)\u0000/g, (_, i) => slots[+i]);
}

// Block rules over **already-escaped** text: fenced code (with a copy button), headings, quotes,
// lists, rules, paragraphs. Whatever this does not recognise is a paragraph line — a markdown
// dialect that drops text would be worse than plain text.
function mdToHtml(text) {
  const lines = String(text).split("\n");
  const out = [];
  let para = [];
  let list = null;
  let quote = [];
  const flushPara = () => {
    if (para.length) { out.push(`<p>${para.map(mdInline).join("<br>")}</p>`); para = []; }
  };
  const flushList = () => {
    if (list) { out.push(`</${list}>`); list = null; }
  };
  const flushQuote = () => {
    if (quote.length) {
      out.push(`<blockquote>${quote.map(mdInline).join("<br>")}</blockquote>`);
      quote = [];
    }
  };
  const flushAll = () => { flushPara(); flushList(); flushQuote(); };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*```/.test(line)) {
      flushAll();
      const body = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) { body.push(lines[i]); i++; }
      const code = body.join("\n");
      out.push(
        `<div class="md-pre"><button class="md-copy" type="button">copy</button>` +
          `<pre><code>${code}</code></pre></div>`
      );
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      flushAll();
      out.push(`<h${heading[1].length}>${mdInline(heading[2])}</h${heading[1].length}>`);
      continue;
    }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { flushAll(); out.push("<hr>"); continue; }
    const bullet = line.match(/^\s*[-*+]\s+(.*)$/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (bullet || numbered) {
      flushPara(); flushQuote();
      const want = bullet ? "ul" : "ol";
      if (list && list !== want) flushList();
      if (!list) { out.push(`<${want}>`); list = want; }
      out.push(`<li>${mdInline((bullet || numbered)[1])}</li>`);
      continue;
    }
    const quoted = line.match(/^\s*&gt;\s?(.*)$/);
    if (quoted) { flushPara(); flushList(); quote.push(quoted[1]); continue; }
    if (/^\s*$/.test(line)) { flushAll(); continue; }
    flushList(); flushQuote();
    para.push(line);
  }
  flushAll();
  return out.join("\n");
}

// Session events

let sessionId = null, eventSocket = null, lastSeq = 0, eventReconnectDelay = 250;
// The text card currently being appended to. Reset whenever a non-delta arrives, so two replies
// never merge into one bubble.
let streaming = null;
// The raw text behind the streaming card, kept apart from its rendered form.
let streamingText = "";

function kindOf(event) {
  // The daemon tags events with `event` (`#[serde(tag = "event", rename_all = "snake_case")]`).
  // `type` is read first only so an older frame still renders rather than becoming a blank card.
  return String((event && (event.event || event.type)) || "event");
}

// "wait" outranks "run" outranks "draft": an unanswered question is the one state a person can
// act on, a running tool is the daemon's business, and unsent composer text is only a reminder.
function taskState(id) {
  if (waitingSessions.has(id)) return "wait";
  const tools = runningTools.get(id);
  if (tools && tools.size) return "run";
  if (typeof drafts !== "undefined" && drafts.has(id)) return "draft";
  return "";
}

// ---- scroll pinning --------------------------------------------------------------------------------
// The transcript follows new events only while the reader is already at the bottom — a person
// scrolled up to read must never be yanked to the live edge mid-sentence. What arrives while
// scrolled up counts on the pill, so "3 new" is one click back to live.
let unseen = 0;
const NEAR_BOTTOM_PX = 90;

function nearBottom() {
  const ev = $("events");
  return !ev || ev.scrollTop + ev.clientHeight >= ev.scrollHeight - NEAR_BOTTOM_PX;
}

function setUnseen(n) {
  unseen = n;
  const pill = $("new-events");
  if (!pill) return;
  pill.hidden = n <= 0;
  pill.textContent = n > 0 ? `↓ ${n} new` : "";
}

function jumpToLatest() {
  const ev = $("events");
  if (ev) ev.scrollTop = ev.scrollHeight;
  setUnseen(0);
}

// Called for every event that lands in the transcript: autoscroll when pinned, count when not.
function followEvents() {
  if (nearBottom()) { jumpToLatest(); return; }
  setUnseen(unseen + 1);
}

// Reaching the bottom by hand reads the backlog — the pill's count is spent.
$("events").addEventListener("scroll", () => { if (nearBottom()) setUnseen(0); });
$("new-events").addEventListener("click", jumpToLatest);

// ---- long bodies -------------------------------------------------------------------------------------
// A card taller than a screenful of transcript folds to a preview with a fade — the pattern
// Hermes uses for tool rows. The choice lives on the card (.clamped/.open), so a streaming body
// that re-renders on every delta keeps whatever the reader picked.
const CLAMP_PX = 300;

function clampBody(el) {
  const body = el.querySelector(":scope > .body");
  if (!body) return;
  const tall = body.scrollHeight > CLAMP_PX;
  let tog = el.querySelector(":scope > .body-toggle");
  if (!tall) {
    if (tog) { tog.remove(); }
    el.classList.remove("clamped", "open");
    return;
  }
  el.classList.add("clamped");
  if (!tog) {
    tog = document.createElement("button");
    tog.type = "button";
    tog.className = "body-toggle";
    tog.addEventListener("click", () => {
      el.classList.toggle("open");
      tog.textContent = el.classList.contains("open") ? "show less ↑" : "show all ↓";
    });
    tog.textContent = "show all ↓";
    el.appendChild(tog);
  }
}

// Collapse a burst of tool events into one line. A start names the tool; the matching finish
// removes it; the chip shows whatever is still open, which is what the agent is doing *now*.
function noteActivity(id, event) {
  const kind = kindOf(event);
  if (kind === "tool_call_started") {
    let tools = runningTools.get(id);
    if (!tools) { tools = new Set(); runningTools.set(id, tools); }
    tools.add(event.name || "tool");
    activeRuns.add(id);
  } else if (kind === "tool_call_finished") {
    const tools = runningTools.get(id);
    if (tools) { tools.delete(event.name || "tool"); if (!tools.size) runningTools.delete(id); }
    activeRuns.add(id);
  } else if (kind === "turn_started") {
    activeRuns.add(id);
  } else if (kind === "turn_finished" || kind === "error") {
    runningTools.delete(id);
    activeRuns.delete(id);
  } else {
    return;
  }
  renderSessions();
  paintActivity();
}

function paintActivity() {
  paintStop();
  const host = $("activity");
  if (!host) return;
  const tools = sessionId ? runningTools.get(sessionId) : null;
  const waiting = sessionId && waitingSessions.has(sessionId);
  host.classList.toggle("wait", !!waiting);
  if (waiting) {
    host.innerHTML = "";
    const dot = document.createElement("span");
    dot.className = "pulse";
    host.appendChild(dot);
    host.appendChild(document.createTextNode("waiting on your approval"));
    return;
  }
  if (tools && tools.size) {
    host.innerHTML = "";
    const dot = document.createElement("span");
    dot.className = "pulse";
    host.appendChild(dot);
    const names = Array.from(tools);
    const shown = names.slice(0, 3).join(", ");
    const more = names.length > 3 ? ` +${names.length - 3}` : "";
    host.appendChild(document.createTextNode("working · " + shown + more));
    return;
  }
  host.textContent = "";
}

// The stop button rides the same liveness as the chip: it exists while a run does, so a person
// always has a brake within reach — and never sees a brake for a run that already ended.
function paintStop() {
  const stop = $("stop");
  if (stop) stop.hidden = !sessionId || !activeRuns.has(sessionId);
}

function appendDelta(seq, text) {
  const host = $("events");
  if (!streaming || !streaming.isConnected) {
    const el = document.createElement("div");
    el.className = "event role-agent";
    const meta = document.createElement("div");
    meta.className = "meta";
    const s = document.createElement("span");
    s.className = "seq";
    s.textContent = seq === undefined ? "" : `#${seq}`;
    const k = document.createElement("span");
    k.className = "kind";
    k.textContent = "text";
    meta.appendChild(s);
    meta.appendChild(k);
    const body = document.createElement("div");
    body.className = "body md";
    el.appendChild(meta);
    el.appendChild(body);
    host.appendChild(el);
    streaming = body;
    streamingText = "";
  }
  // Re-rendered whole on every delta, from the raw text: a delta can split a code fence or a
  // word, so the accumulated source has to survive each render.
  streamingText += text;
  streaming.innerHTML = mdToHtml(esc(streamingText));
  // The streaming card is the one that grows past the fold — re-check the clamp on every delta.
  if (streaming.parentElement) clampBody(streaming.parentElement);
}

function renderEvent(frame) {
  const el = document.createElement("div");
  const event = frame.event || {};
  const kind = kindOf(event);
  const k = kind.toLowerCase();
  let role = "agent";
  if (k === "message_received" || /(user|prompt|human|input)/.test(k)) role = "user";
  else if (/(tool|exec|command|call|result|output)/.test(k)) role = "tool";
  else if (/(system|status|notice|error|approval)/.test(k)) role = "system";
  el.className = `event role-${role}`;
  const meta = document.createElement("div");
  meta.className = "meta";
  const seq = document.createElement("span");
  seq.className = "seq";
  seq.textContent = frame.seq === undefined ? "" : `#${frame.seq}`;
  const kk = document.createElement("span");
  kk.className = "kind";
  kk.textContent = kind;
  // The kind label is the raw event's door: one click shows the whole JSON, one hides it. The
  // transcript reads as prose first, and nothing is hidden behind a re-renderer.
  kk.title = "click for the raw event";
  kk.addEventListener("click", () => {
    const open = el.querySelector("pre.raw");
    if (open) { open.remove(); return; }
    const raw = document.createElement("pre");
    raw.className = "raw";
    raw.textContent = JSON.stringify(event, null, 2);
    el.appendChild(raw);
  });
  meta.appendChild(seq);
  meta.appendChild(kk);
  const note = oneLine(event);
  if (note) {
    const n = document.createElement("span");
    n.className = "note";
    n.textContent = note;
    meta.appendChild(n);
  }
  el.appendChild(meta);
  const text =
    event.text || event.content || event.message || event.output ||
    event.summary || event.reason || event.value || "";
  if (typeof text === "string" && text) {
    const b = document.createElement("div");
    // The agent's own words are markdown — its answers are full of code and lists — while a user
    // prompt or a tool summary is shown exactly as typed: rendering somebody's pasted text as
    // markup is how a transcript starts lying about what was said.
    if (role === "agent") {
      b.className = "body md";
      b.innerHTML = mdToHtml(esc(text));
    } else {
      b.className = "body";
      b.textContent = text;
    }
    el.appendChild(b);
    // A prompt can be steered: loaded back into the composer to change, or sent again as it was.
    // Both append to the trail rather than rewriting it — the store is the audit, and an edited
    // prompt leaves the original standing beside the new one.
    if (role === "user") {
      const actions = document.createElement("div");
      actions.className = "actions";
      const edit = document.createElement("button");
      edit.textContent = "edit";
      edit.title = "load this prompt back into the composer, to change and resend";
      edit.addEventListener("click", () => {
        const input = $("prompt");
        input.value = text;
        input.focus();
      });
      const again = document.createElement("button");
      again.textContent = "ask again";
      again.title = "send this prompt again — the trail keeps both";
      again.addEventListener("click", () => submitPrompt(text));
      actions.appendChild(edit);
      actions.appendChild(again);
      el.appendChild(actions);
    }
  }
  return el;
}

// One compact human line per structural event — what the raw JSON used to dump under every
// card. ""` means the card's body already says it. The full event is one click on the kind label
// away, so nothing is hidden by being tidy.
function oneLine(event) {
  switch (kindOf(event)) {
    case "turn_started":
      return `turn ${event.turn ?? "?"}`;
    case "turn_finished":
      return `stop ${event.stop || "?"}`;
    case "usage":
      return `${event.input_tokens ?? 0} in / ${event.output_tokens ?? 0} out · ${event.model || event.provider || "?"}`;
    case "tool_call_started":
      return `${event.name || "tool"} ${shortJson(event.arguments)}`;
    case "approval_resolved":
      return `${event.approved ? "allowed" : "denied"} by ${event.by || "?"}`;
    case "message_received":
    case "tool_call_finished":
    case "approval_requested":
    case "error":
    case "text_delta":
      return "";
    default:
      return shortJson(event);
  }
}

function shortJson(value) {
  const s = JSON.stringify(value ?? {});
  return s.length > 120 ? s.slice(0, 117) + "…" : s;
}

