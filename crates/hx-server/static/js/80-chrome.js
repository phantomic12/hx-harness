// ---- Codex chrome: drawer tabs, panel toggles, version, onboarding (no API contract changes) ----
// File-scope: both the IIFE below and the global key handler at the bottom ask this whether the
// flanking panels are overlay sheets (narrow) or grid columns (wide).
const narrowMQ = window.matchMedia("(max-width: 980px)");
(function codexChrome() {
  const tabBtns = Array.from(document.querySelectorAll(".tabs button[data-tab]"));
  const panes = {
    terminal: $("dp-terminal"), screen: $("dp-screen"), diff: $("dp-diff"),
    review: $("dp-review"), fanout: $("dp-fanout"), providers: $("dp-providers"),
  };
  let currentTab = "terminal";
  function showTab(name) {
    if (!panes[name]) return;
    currentTab = name;
    for (const [key, pane] of Object.entries(panes)) {
      if (pane) pane.hidden = key !== name;
    }
    for (const b of tabBtns) {
      const on = b.dataset.tab === name;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    }
    const drawer = $("drawer");
    if (drawer) drawer.hidden = false;
    for (const b of viewBtns) {
      if (b.dataset.view === "side") continue;
      const on = b.dataset.view === name;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    }
    if (name === "terminal" && typeof fit !== "undefined" && fit) {
      try { fit.fit(); } catch (_) {}
    }
  }
  for (const b of tabBtns) b.addEventListener("click", () => showTab(b.dataset.tab));

  const viewBtns = Array.from(document.querySelectorAll('.top-views button[data-view]'));
  for (const b of viewBtns) {
    b.addEventListener("click", () => {
      const v = b.dataset.view;
      if (v === "side") {
        const side = $("side");
        side.hidden = !side.hidden;
        b.classList.toggle("active", !side.hidden);
        b.setAttribute("aria-pressed", !side.hidden ? "true" : "false");
        return;
      }
      const drawer = $("drawer");
      const willOpen = drawer.hidden || currentTab !== v;
      if (!willOpen) {
        drawer.hidden = true;
        b.classList.remove("active");
        b.setAttribute("aria-pressed", "false");
        return;
      }
      showTab(v);
    });
  }
  // The drawer's edge handle and the tab bar agree: both are ways to close/reopen the panel.
  $("drawer-edge").addEventListener("click", () => {
    $("drawer").hidden = true;
    for (const b of viewBtns) {
      if (b.dataset.view !== "side") {
        b.classList.remove("active");
        b.setAttribute("aria-pressed", "false");
      }
    }
  });
  window.__showTab = showTab;
  window.__tabFor = () => currentTab;

  // Narrow layout: both panels are overlay sheets, so they start closed — opening them would
  // cover the transcript the page is for. The rail opens from the "tasks" nav button, the drawer
  // from its tabs; on desktop nothing changes. `narrowMQ` is file-scope so the Escape handler
  // can ask it whether panels are sheets or columns.
  const applyNarrow = () => {
    if (narrowMQ.matches) {
      $("side").hidden = true;
      $("drawer").hidden = true;
      for (const b of viewBtns) { b.classList.remove("active"); b.setAttribute("aria-pressed", "false"); }
      const sideBtn = document.querySelector('.top-views button[data-view="side"]');
      if (sideBtn) sideBtn.setAttribute("aria-pressed", "false");
    } else {
      $("side").hidden = false;
      $("drawer").hidden = false;
      const sideBtn = document.querySelector('.top-views button[data-view="side"]');
      if (sideBtn) { sideBtn.classList.add("active"); sideBtn.setAttribute("aria-pressed", "true"); }
      showTab(currentTab);
    }
  };
  applyNarrow();
  if (narrowMQ.addEventListener) narrowMQ.addEventListener("change", applyNarrow);
  else if (narrowMQ.addListener) narrowMQ.addListener(applyNarrow);

  // The tap-away door for narrow sheets — a touchscreen has no Esc. The scrim exists whenever
  // either sheet covers the transcript; tapping it closes the rail first, then the drawer,
  // the same order the Escape key unwinds them.
  const scrim = $("sheet-scrim");
  const paintScrim = () => {
    if (!scrim) return;
    scrim.hidden = !(narrowMQ.matches && (!$("side").hidden || !$("drawer").hidden));
  };
  if (scrim) {
    new MutationObserver(paintScrim).observe($("side"), { attributes: true, attributeFilter: ["hidden"] });
    new MutationObserver(paintScrim).observe($("drawer"), { attributes: true, attributeFilter: ["hidden"] });
    scrim.addEventListener("click", () => {
      if (!$("side").hidden) {
        const b = document.querySelector('.top-views button[data-view="side"]');
        if (b) { b.click(); return; }
      }
      if (!$("drawer").hidden) $("drawer-edge").click();
    });
    paintScrim();
  }

  // Token button reflects stored state without ever showing the secret.
  try { refreshAuthUI(); } catch (_) {}

  // ---- onboarding ---------------------------------------------------------
  // First-run setup is a stream of beats inside the transcript surface (the Hermes
  // setup-chat pattern): one card at a time, options are labeled rows, finished
  // beats stay as history with a quiet acknowledgment between them. The last beat
  // is a real first prompt — sending it IS finishing setup, not a "done" screen.
  const OB_KEY = "hx.onboard.dismissed";
  const obEl = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const obScroll = () => { const s = $("ob-stream"); s.scrollTop = s.scrollHeight; };
  const obSay = (text, cls) => {
    const d = obEl("div", "ob-line" + (cls ? " " + cls : ""), text);
    $("ob-stream").appendChild(d); obScroll();
    return d;
  };
  const obAck = (text) => obSay("· " + text, "ob-ack");
  const obCard = (question, note) => {
    const c = obEl("div", "ob-beat");
    c.appendChild(obEl("div", "ob-q", question));
    if (note) c.appendChild(obEl("div", "ob-note", note));
    $("ob-stream").appendChild(c); obScroll();
    return c;
  };
  const obErr = (card, text) => {
    let e = card.querySelector(".ob-err");
    if (!e) { e = obEl("div", "ob-err"); card.appendChild(e); }
    e.textContent = text || ""; obScroll();
  };
  const obInput = (card, attrs) => {
    const i = obEl("input");
    for (const k in attrs) i.setAttribute(k, attrs[k]);
    card.appendChild(i);
    return i;
  };
  // Option rows — each pick disables the card, leaves the choice lit, and appends
  // its acknowledgment. Rows keep working only until the first answer, like a sent
  // message in the transcript.
  function obOptions(card, options, onPick) {
    for (const opt of options) {
      const b = obEl("button", "ob-opt");
      b.type = "button";
      b.appendChild(obEl("span", "ob-opt-label", opt.label));
      if (opt.detail) b.appendChild(obEl("span", "ob-opt-detail", opt.detail));
      b.addEventListener("click", () => {
        card.querySelectorAll(".ob-opt").forEach((o) => { o.disabled = true; });
        b.classList.add("picked");
        onPick(opt);
      });
      card.appendChild(b);
    }
    obScroll();
  }
  function obGo(card, label, onClick) {
    const b = obEl("button", "ob-go", label);
    b.type = "button";
    b.addEventListener("click", onClick);
    card.appendChild(b);
    obScroll();
    return b;
  }

  const OB_PRESETS = [
    { label: "zen · keyless", detail: "opencode shim on this machine — 127.0.0.1:8399, no key",
      name: "zen", kind: "openai", base: "http://127.0.0.1:8399/v1", models: "nemotron-3.5-lightning-free" },
    { label: "openai-compatible", detail: "any /v1 chat endpoint — openai, together, groq, fireworks",
      name: "default", kind: "openai", base: "", models: "" },
    { label: "ollama · local", detail: "models running on this machine at :11434",
      name: "ollama", kind: "ollama", base: "http://127.0.0.1:11434", models: "" },
    { label: "custom", detail: "name, kind, routing, models — the full form",
      name: "default", kind: "custom", base: "", models: "", custom: true },
  ];

  function obFinish(openTour) {
    try { localStorage.setItem(OB_KEY, "1"); } catch (_) {}
    $("ob-wrap").hidden = true;
    $("events").hidden = false;
    if (openTour) { openHelp(); return; }
    setTimeout(() => $("prompt").focus(), 50);
  }

  // Beat: welcome — always first, it is the stream's opening line.
  function obBeatWelcome() {
    obSay("hx · first run", "ob-kicker");
    obSay("Ship work from one prompt.", "ob-head");
    obSay("A few cards and you're talking to the agent. Nothing stored leaves this daemon.", "ob-sub2");
  }

  // Beat: login — only when the probe proved the daemon asks for credentials
  // (a non-loopback deployment; loopback never sees this card).
  function obBeatLogin() {
    const c = obCard("Log in — this daemon asks for credentials",
      "every /v1/* call needs auth; the token stays in this browser's localStorage");
    const user = obInput(c, { id: "ob-username", placeholder: "username", autocomplete: "username", spellcheck: "false" });
    const pass = obInput(c, { id: "ob-password", type: "password", placeholder: "password", autocomplete: "current-password", spellcheck: "false" });
    const adv = obEl("details", "ob-adv");
    adv.appendChild(obEl("summary", "", "advanced: paste token instead"));
    const tok = obEl("input");
    tok.id = "ob-token"; tok.type = "password";
    tok.setAttribute("placeholder", "bearer token"); tok.setAttribute("autocomplete", "off"); tok.setAttribute("spellcheck", "false");
    adv.appendChild(tok);
    c.appendChild(adv);
    const proceed = async () => {
      const pasted = tok.value.trim();
      if (!user.value.trim() && !pass.value && pasted) {
        setToken(pasted); tok.value = "";
      } else {
        if (!user.value.trim() || !pass.value) { obErr(c, "enter your username and password — or skip below"); return; }
        try { setToken(await doLogin(user.value.trim(), pass.value)); pass.value = ""; }
        catch (e) { obErr(c, String((e && e.message) || e)); return; }
      }
      obAck("logged in");
      // Re-probe with the credential: providers may already exist — setup could be done.
      try {
        const res = await apiFetch(`${API}/v1/providers`);
        const items = res.ok ? provListItems(await res.json()) : [];
        if (res.ok && items.length) { await pollProviders(); obBeatTour(); return; }
      } catch (_) {}
      obBeatPreset();
    };
    user.addEventListener("keydown", (e) => { if (e.key === "Enter") pass.focus(); });
    for (const i of [pass, tok]) i.addEventListener("keydown", (e) => { if (e.key === "Enter") proceed(); });
    obGo(c, "log in · continue", proceed);
    setTimeout(() => user.focus(), 50);
  }

  // Beat: provider preset — the "where do your models come from" card. A pick
  // pre-fills everything the endpoint beat needs; custom opens the full form there.
  function obBeatPreset() {
    const c = obCard("Where do your models come from?");
    obOptions(c, OB_PRESETS, (p) => { obAck(p.label + ", noted."); obBeatEndpoint(p); });
  }

  // Beat: endpoint + key — the quick path is two fields; "customize" unfolds the
  // full provider form (name / kind / routing / models) underneath the same save.
  function obBeatEndpoint(p) {
    const c = obCard(p.custom ? "Provider — the full form" : "Endpoint + key",
      "the key is write-only: sent once, never displayed");
    const nameI = obInput(c, { placeholder: "name (e.g. default)", value: p.name || "default", autocomplete: "off", spellcheck: "false" });
    const urlI = obInput(c, { placeholder: "base_url — https://…/v1 (ollama can stay blank)", value: p.base || "", autocomplete: "off", spellcheck: "false" });
    const keyI = obInput(c, { type: "password", placeholder: "api key (write-only — may stay empty for keyless)", autocomplete: "off", spellcheck: "false" });
    const adv = obEl("details", "ob-adv");
    if (p.custom) adv.open = true;
    adv.appendChild(obEl("summary", "", "customize: kind · routing · models"));
    const grid = obEl("div", "ob-grid");
    const kind = obEl("select");
    for (const k of ["openai", "anthropic", "google", "ollama", "custom"]) {
      const o = obEl("option", "", k); o.value = k; if (k === p.kind) o.selected = true;
      kind.appendChild(o);
    }
    const routing = obEl("select");
    for (const r of ["least_loaded", "priority", "round_robin", "weighted", "cheapest_capable"]) {
      const o = obEl("option", "", r); o.value = r;
      routing.appendChild(o);
    }
    grid.appendChild(kind); grid.appendChild(routing);
    adv.appendChild(grid);
    const modelsI = obEl("input");
    modelsI.setAttribute("placeholder", "models, comma-separated"); modelsI.setAttribute("autocomplete", "off"); modelsI.setAttribute("spellcheck", "false");
    modelsI.value = p.models || "";
    adv.appendChild(modelsI);
    c.appendChild(adv);
    const save = async () => {
      const name = nameI.value.trim();
      if (!name) { obErr(c, "give the provider a name"); return; }
      $("prov-name").value = name;
      $("prov-kind").value = kind.value;
      $("prov-routing").value = routing.value;
      $("prov-base-url").value = urlI.value;
      $("prov-models").value = modelsI.value;
      $("prov-api-key").value = keyI.value;
      await saveProvider();
      const ok = ($("prov-msg").className || "").includes("ok");
      if (!ok) { obErr(c, $("prov-msg").textContent || "could not save — check the providers pane after setup"); return; }
      keyI.value = "";
      obAck("provider saved");
      obBeatTour();
    };
    for (const i of [nameI, urlI, keyI, modelsI]) i.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); });
    obGo(c, "save provider · continue", save);
    setTimeout(() => (p.base ? keyI : urlI).focus(), 50);
  }

  // Beat: the tour offer — one opt-in card, never a forced walkthrough.
  function obBeatTour() {
    const c = obCard("Want a look around first?");
    obOptions(c, [
      { label: "open the keymap", detail: "the ? sheet — every chord on one page", tour: true },
      { label: "straight to it", detail: "no tour — send the first prompt", tour: false },
    ], (o) => { if (o.tour) obAck("keymap after the first prompt."); obBeatPrompt(o.tour); });
  }

  // Beat: first prompt — the handoff. Sending here writes into the real composer
  // and fires the real send path: finishing setup is the first message, not a
  // "you're done" screen.
  function obBeatPrompt(tour) {
    const c = obCard("First prompt — what should hx do?");
    const row = obEl("div", "ob-prompt-row");
    const input = obEl("input");
    input.setAttribute("placeholder", "ask something small — e.g. list the hosts");
    input.setAttribute("autocomplete", "off"); input.setAttribute("spellcheck", "false");
    const send = obEl("button", "ob-go", "send →");
    send.type = "button";
    const chip = obEl("button", "ob-chip", "try “list the hosts” →");
    chip.type = "button";
    const fire = (text) => {
      if (!text) return;
      $("prompt").value = text;
      obFinish(tour);
      $("send").click();
    };
    send.addEventListener("click", () => fire(input.value.trim()));
    chip.addEventListener("click", () => fire("list the hosts"));
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") fire(input.value.trim()); });
    row.appendChild(input); row.appendChild(send);
    c.appendChild(row); c.appendChild(chip);
    obScroll();
    setTimeout(() => input.focus(), 50);
  }

  // Start the stream — hides the transcript, clears prior beats, plays welcome,
  // then login only when the daemon asks for it.
  function obStart(authNeeded) {
    $("events").hidden = true;
    const w = $("ob-wrap");
    w.hidden = false;
    $("ob-stream").innerHTML = "";
    obBeatWelcome();
    if (authNeeded) obBeatLogin(); else obBeatPreset();
  }
  $("ob-skip").addEventListener("click", () => obFinish(false));

  // First-run detection: no token saved AND daemon reports no providers (or we
  // cannot prove otherwise). Runs after boot's first poll so providers are known.
  // Probe shared with palette re-entry: a 200 on /v1/providers with no credential
  // attached proves this daemon does not ask for one (the loopback deployment).
  // The login card can only fail there — POST /v1/login 404s without an admin
  // password — so on auth-free daemons the stream skips straight to providers.
  async function obProbe() {
    try {
      const res = await apiFetch(`${API}/v1/providers`);
      if (res.ok) return { none: provListItems(await res.json()).length === 0, authNeeded: false };
      if (res.status === 401) return { none: true, authNeeded: true };
    } catch (_) {}
    return { none: true, authNeeded: true };
  }
  async function maybeOnboard() {
    try {
      if (localStorage.getItem(OB_KEY) === "1") return;
      if (localStorage.getItem(TOKEN_KEY)) return;
      const probe = await obProbe();
      if (probe.none) obStart(probe.authNeeded);
    } catch (_) {}
  }
  // Expose for boot ordering; called after the first pollProviders(). Also the palette's
  // way back in: "setup wizard" replays the stream even after it was dismissed — at
  // provider setup on auth-free daemons, so re-entry can't land on the dead-end login.
  window.__maybeOnboard = maybeOnboard;
  window.__openOnboard = async () => {
    try { obStart((await obProbe()).authNeeded); } catch (_) { obStart(false); }
  };
})();


// ---- account panel wiring -----------------------------------------------------------------------

// The palette's "log in / out" action and the removed account button share this path.
function toggleAccountPanel() {
  $("token-panel").hidden = !$("token-panel").hidden;
  if (!$("token-panel").hidden) ($("login-user").value ? $("login-pass") : $("login-user")).focus();
}
// The hamburger is the palette's mouse door — every command a top-bar button used to own lives
// behind it, so there is exactly one place "everything else" can come from.
$("menu-open").addEventListener("click", () => openPalette());
async function panelLogin() {
  // Advanced fallback: a pasted bearer token is stored directly, no login round-trip.
  const pasted = $("token-input").value.trim();
  const user = $("login-user").value.trim();
  const pass = $("login-pass").value;
  const st = $("token-status");
  st.classList.toggle("err", false);
  if (!user && !pass && pasted) {
    setToken(pasted);
    $("token-input").value = "";
    $("token-panel").hidden = true;
    // A reload rather than a patch-up: the sockets already opened (or already refused) carry the
    // previous credential, and every pane's first render depends on a request that has already
    // happened. Reloading re-runs all of it against the new token, which is one code path instead of
    // two that could disagree.
    location.reload();
    return;
  }
  if (!user || !pass) {
    st.textContent = "enter username + password";
    st.classList.toggle("err", true);
    (user ? $("login-pass") : $("login-user")).focus();
    return;
  }
  st.textContent = "logging in…";
  try {
    const token = await doLogin(user, pass);
    setToken(token);
    $("login-pass").value = "";
    $("token-input").value = "";
    $("token-panel").hidden = true;
    // Same reload rationale as above: sockets + first renders already ran under the old credential.
    location.reload();
  } catch (e) {
    st.textContent = String((e && e.message) || e);
    st.classList.toggle("err", true);
  }
}
$("token-save").addEventListener("click", panelLogin);
$("login-pass").addEventListener("keydown", (e) => { if (e.key === "Enter") panelLogin(); });
$("login-user").addEventListener("keydown", (e) => { if (e.key === "Enter") $("login-pass").focus(); });
$("token-clear").addEventListener("click", () => {
  setToken("");
  location.reload();
});
refreshAuthUI();

// ---------------------------------------------------------------------------------------------
// Boot

(async function main() {
  try {
    const health = await apiFetch(`${API}/healthz`).then((r) => r.text()).catch(() => null);
    setStatus(health ? "connected" : "daemon unreachable", !!health);
  } catch (_) {
    setStatus("daemon unreachable", false);
  }
  if (initTerm()) {
    try { await ensureTerminal(); } catch (e) { showError(String(e.message || e)); }
  }
  // Wired, not started: no browser is launched until someone opens the pane and asks for a page.
  // A page load that started a browser would spend the daemon's memory on every refresh of every
  // window, which is not what opening a UI means.
  initScreen();
  // A notification's deep link, before the first poll: the person who followed it is owed the screen
  // it names, whether or not they arrived in time to see the banner.
  try { await followScreenLink(); } catch (_) {}
  // Polled like the approval queue, and for its reason: a challenge can arrive with no other activity
  // on this page — it belongs to a fetch the daemon is running, not to anything this tab did — and the
  // daemon is holding that fetch until somebody answers.
  try { await pollChallenges(); } catch (_) {}
  try { await ensureSession(); } catch (e) { showError(String(e.message || e)); }
  // Polled for the page's lifetime: an approval can arrive with no other activity, so there is no
  // event to hang the refresh off.
  await Promise.all([pollApprovals(), pollSandboxes(), pollHosts(), pollProviders(), refreshSpend()]);
  try { if (window.__maybeOnboard) await window.__maybeOnboard(); } catch (_) {}
  approvalTimer = setInterval(() => {
    pollApprovals();
    pollChallenges();
    pollSandboxes();
    pollHosts();
    refreshSessions();
  }, APPROVAL_POLL_MS);
  // Spend moves only when a run spends: re-read on the `usage` push (noteAttention) and here on a
  // slow tick as the cross-task fallback — the 2s cadence would be noise for a number this stable.
  setInterval(refreshSpend, 60_000);
  window.addEventListener("beforeunload", () => clearInterval(approvalTimer));
})();

$("prompt").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) sendPrompt(); });
$("send").addEventListener("click", sendPrompt);
$("stop").addEventListener("click", stopRun);
// Copy buttons are delegated: the markdown renderer builds HTML strings, so no handler can ride
// along on the elements it makes.
document.addEventListener("click", (e) => {
  const btn = e.target.closest && e.target.closest(".md-copy");
  if (!btn) return;
  const code = btn.parentNode && btn.parentNode.querySelector("code");
  if (!code) return;
  const done = () => {
    btn.textContent = "copied";
    setTimeout(() => { btn.textContent = "copy"; }, 1200);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(code.innerText).then(done, () => {});
  } else {
    done();
  }
});
$("new-session").addEventListener("click", createSession);
$("session-label").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); renameSession(e.target.value); e.target.blur(); }
  if (e.key === "Escape") { paintTaskHeader(); e.target.blur(); }
});
$("session-label").addEventListener("blur", (e) => renameSession(e.target.value));
$("new-term").addEventListener("click", async () => {
  // A *new* terminal, deliberately under a fresh id: the point of the `new` button is a second
  // shell, and reusing the id would just reattach to the first.
  const id = `hx-term-${Date.now().toString(36)}`;
  try {
    await ensureTerminalFor(id, null, "on this machine");
  } catch (e) {
    showError(String(e.message || e));
  }
});

// ---- host browser wiring ---------------------------------------------------------------------

$("host-modal-close").addEventListener("click", () => {
  $("host-modal").hidden = true;
  // Clearing the host is what stops a stray Enter in the dialog from firing at the last machine
  // opened, which is the one way this could touch a box nobody is looking at.
  browseHost = null;
});
// Click the backdrop to dismiss, but not the box itself — a stray click while editing a file must
// not close the dialog.
$("host-modal").addEventListener("click", (e) => {
  if (e.target === $("host-modal")) $("host-modal-close").click();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("host-modal").hidden) $("host-modal-close").click();
});

$("host-go").addEventListener("click", () => listDir($("host-path").value));
$("host-path").addEventListener("keydown", (e) => {
  if (e.key === "Enter") listDir($("host-path").value);
});
$("host-up").addEventListener("click", () => {
  if (!browsePath) return;
  // Trim a trailing slash first, or the parent of `/a/b/` computes as `/a/b`.
  const trimmed = browsePath.replace(/\/+$/, "");
  const cut = trimmed.lastIndexOf("/");
  listDir(cut <= 0 ? "/" : trimmed.slice(0, cut));
});
$("host-save").addEventListener("click", saveFile);
$("host-run").addEventListener("click", runOnHost);
$("host-cmd").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runOnHost();
});

// ---- fan-out wiring -------------------------------------------------------------------------

$("fanout-add").addEventListener("click", () => { addFanoutRow(); });
$("fanout-run").addEventListener("click", runFanout);
// One row to start with, so the pane reads as a form rather than an empty box.
addFanoutRow();

// ---- providers wiring -----------------------------------------------------------------------

$("prov-save").addEventListener("click", saveProvider);
$("prov-clear").addEventListener("click", clearProviderForm);

// ---- diff/review wiring ---------------------------------------------------------------------

$("diff-run").addEventListener("click", runDiff);
$("review-run").addEventListener("click", runReview);
// The mode is per task and remembered, so switching tasks (openSession) repaints it. Clicking here
// only records the choice; the next send is what acts on it.
for (const btn of document.querySelectorAll(".mode button[data-mode]")) {
  btn.addEventListener("click", () => { if (sessionId) setMode(sessionId, btn.dataset.mode); });
}
$("diff-path").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runDiff();
});

// ---------------------------------------------------------------------------------------------
// Input polish: keyboard map, density, card folds, the help overlay, and the connection bar's
// retry path. Everything here is chrome — the daemon's protocol is untouched.

// ---- connection bar + status pill ---------------------------------------------------------------

$("connbar-retry").addEventListener("click", async () => {
  $("connbar-text").textContent = "checking…";
  try {
    const r = await apiFetch(`${API}/healthz`);
    if (r.ok) { netUp(); setStatus("connected", true); }
    else $("connbar-text").textContent = "still unreachable — will keep retrying";
  } catch (_) {
    $("connbar-text").textContent = "still unreachable — will keep retrying";
  }
});
$("conn-status").addEventListener("click", () => {
  const bar = $("connbar");
  if (netDownCount) { bar.hidden = false; }
  else toast($("status-text").textContent || "connected", "info");
});

// ---- density -------------------------------------------------------------------------------------
// One dial, persisted: the panes keep their own geometry and only the scale moves.
const DENSITY_KEY = "hx.density";
function setDensity(mode) {
  document.body.dataset.density = mode;
  try { localStorage.setItem(DENSITY_KEY, mode); } catch (_) {}
  if (typeof fit !== "undefined" && fit) setTimeout(() => { try { fit.fit(); } catch (_) {} }, 30);
}
try {
  const saved = localStorage.getItem(DENSITY_KEY);
  if (saved === "compact") setDensity("compact");
} catch (_) {}

// ---- rail card folds ------------------------------------------------------------------------------
// Each section header's chevron folds its card; the choice is remembered per card.
const FOLD_KEY = "hx.folds";
let folds = {};
try { folds = JSON.parse(localStorage.getItem(FOLD_KEY) || "{}"); } catch (_) {}
// Reference cards the rail carries but nobody opens first — hosts and spend start folded; a
// first visit should read as "tasks, and only tasks". Approvals stays open: it's the queue that
// can wait on a person, so it earns the space it takes.
const FOLDED_BY_DEFAULT = new Set(["hosts", "spend"]);
for (const card of document.querySelectorAll(".card[data-card]")) {
  const name = card.dataset.card;
  const btn = card.querySelector("h2 button.fold");
  if (!(name in folds)) folds[name] = FOLDED_BY_DEFAULT.has(name);
  const apply = () => {
    const folded = !!folds[name];
    card.dataset.folded = folded ? "1" : "0";
    btn.setAttribute("aria-expanded", folded ? "false" : "true");
    btn.textContent = folded ? "▸" : "▾";
    btn.title = folded ? "expand" : "collapse";
  };
  apply();
  btn.addEventListener("click", () => {
    folds[name] = !folds[name];
    try { localStorage.setItem(FOLD_KEY, JSON.stringify(folds)); } catch (_) {}
    apply();
  });
}

// ---- help overlay ---------------------------------------------------------------------------------

function openHelp() {
  $("help").hidden = false;
  $("help-close").focus();
}
function closeHelp() { $("help").hidden = true; }
$("help-close").addEventListener("click", closeHelp);
$("help").addEventListener("click", (e) => { if (e.target === $("help")) closeHelp(); });

// ---- keyboard map -----------------------------------------------------------------------------------
// From anywhere a text field is not focused. Every chord is a pane answer or an attention answer —
// nothing here mutates a task without the banner that asks for it being the same thing on screen.
const inField = () => {
  const el = document.activeElement;
  return el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
};
const anyOverlayOpen = () =>
  !$("host-modal").hidden || !$("help").hidden || !$("ob-wrap").hidden || !$("palette").hidden;

function switchTask(step) {
  const rows = Array.from(document.querySelectorAll("#sessions .sess"));
  if (rows.length < 2) return;
  const i = rows.findIndex((r) => r.classList.contains("active"));
  const next = rows[(i + step + rows.length) % rows.length];
  if (next) next.click();
}

document.addEventListener("keydown", (e) => {
  // Escape unwinds the topmost open thing: help → host modal → token panel → drawer.
  if (e.key === "Escape") {
    if (!$("palette").hidden) { closePalette(); return; }
    if (!$("help").hidden) { closeHelp(); return; }
    if (!$("host-modal").hidden) { $("host-modal-close").click(); return; }
    if (!$("token-panel").hidden) { $("token-panel").hidden = true; return; }
    // On narrow layouts the flanking panels are overlay sheets: Esc puts them away, the rail
    // first if both are somehow open, then the drawer.
    if (narrowMQ.matches) {
      if (!$("side").hidden) { $(".top-views button[data-view='side']").click(); return; }
      if (!$("drawer").hidden) { $("drawer-edge").click(); return; }
    }
    return;
  }
  // Pane chords work even inside fields — that is the point of a chord rather than a bare key.
  // The drawer owns pane switching: ctrl+1 toggles the rail, ctrl+2..7 land on drawer tabs.
  if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key >= "1" && e.key <= "7") {
    const order = ["side", "terminal", "screen", "diff", "review", "fanout", "providers"];
    const v = order[Number(e.key) - 1];
    if (v === "side") {
      const btn = document.querySelector('.top-views button[data-view="side"]');
      if (btn) { btn.click(); e.preventDefault(); }
    } else if (window.__showTab) {
      window.__showTab(v);
      e.preventDefault();
    }
    return;
  }
  if (e.ctrlKey && !e.shiftKey && e.key === "\\") {
    const drawer = $("drawer");
    if (drawer.hidden) {
      if (window.__showTab) window.__showTab(window.__tabFor ? window.__tabFor() : "terminal");
    } else {
      $("drawer-edge").click();
    }
    e.preventDefault();
    return;
  }
  if (e.ctrlKey && !e.shiftKey && e.key === "/") {
    $("prompt").focus();
    e.preventDefault();
    return;
  }
  // ctrl+k works inside fields like the other chords — it is the jump box, not a bare key.
  if (e.ctrlKey && !e.shiftKey && (e.key === "k" || e.key === "K")) {
    if (!$("palette").hidden) closePalette(); else openPalette();
    e.preventDefault();
    return;
  }
  if (e.altKey && (e.key === "ArrowUp" || e.key === "ArrowDown") && !inField()) {
    switchTask(e.key === "ArrowUp" ? -1 : 1);
    e.preventDefault();
    return;
  }
  if (inField() || e.metaKey || e.ctrlKey || e.altKey || anyOverlayOpen()) return;
  if (e.key === "?") { openHelp(); return; }
  if (e.key === "/") { $("prompt").focus(); e.preventDefault(); return; }
  // Approvals answer from the keyboard — but only the banner's own buttons, and only while it is
  // showing, so a keypress can never answer a question the person cannot see.
  if ((e.key === "y" || e.key === "n") && attnApprovals.length) {
    answerApproval(attnApprovals[0].id, e.key === "y" ? "once" : "deny");
    return;
  }
  if (e.key === "r" && (attnApprovals.length || attnChallenge)) {
    const side = $("side");
    const btn = document.querySelector('.top-views button[data-view="side"]');
    if (side.hidden && btn) btn.click();
    if (attnChallenge && window.__showTab) window.__showTab("screen");
  }
});
