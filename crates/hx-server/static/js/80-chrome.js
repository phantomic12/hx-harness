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
  const OB_KEY = "hx.onboard.dismissed";
  let obStep = 1;
  const obMsg = (t, ok) => {
    const el = $("ob-msg");
    el.textContent = t || "";
    el.className = t ? (ok ? "ok" : "err") : "";
  };
  function obShow(step) {
    obStep = step;
    for (let i = 1; i <= 3; i++) {
      $("ob-step-" + i).hidden = i !== step;
      const dot = $("ob-s" + i);
      dot.className = i < step ? "done" : (i === step ? "now" : "");
    }
    $("ob-back").hidden = step === 1;
    $("ob-next").textContent =
      step === 1 ? "Log in · continue" :
      step === 2 ? "Save provider · continue" : "Open the transcript →";
    obMsg("");
    if (step === 1) setTimeout(() => $("ob-username").focus(), 50);
    if (step === 2) setTimeout(() => $("ob-prov-name").focus(), 50);
  }
  function obDismiss() {
    try { localStorage.setItem(OB_KEY, "1"); } catch (_) {}
    $("onboard").hidden = true;
    setTimeout(() => $("prompt").focus(), 50);
  }
  async function obNext() {
    if (obStep === 1) {
      // Advanced fallback: a pasted bearer token skips the login round-trip (also covers
      // daemons without POST /v1/login).
      const pasted = $("ob-token").value.trim();
      const user = $("ob-username").value.trim();
      const pass = $("ob-password").value;
      if (!user && !pass && pasted) {
        // Reuse the exact token save path: localStorage + reload-free re-entry.
        setToken(pasted);
        $("ob-token").value = "";
        obMsg("token saved ✓", true);
      } else {
        if (!user || !pass) { obMsg("enter your username and password — or skip", false); return; }
        const btn = $("ob-next");
        btn.disabled = true;
        try {
          const token = await doLogin(user, pass);
          // Reuse the exact token save path: localStorage + reload-free re-entry.
          setToken(token);
          $("ob-password").value = "";
          obMsg("logged in ✓", true);
        } catch (e) {
          obMsg(String((e && e.message) || e), false);
          return;
        } finally {
          btn.disabled = false;
        }
      }
      // Re-probe providers with the new credential before deciding step 2 vs 3.
      try {
        const res = await apiFetch(`${API}/v1/providers`);
        const items = res.ok ? provListItems(await res.json()) : [];
        if (res.ok && items.length) { await pollProviders(); obShow(3); return; }
      } catch (_) {}
      obShow(2);
      return;
    }
    if (obStep === 2) {
      // Reuse the provider PUT flow through the main form fields + saveProvider().
      const name = $("ob-prov-name").value.trim();
      if (!name) { obMsg("give the provider a name", false); return; }
      $("prov-name").value = name;
      $("prov-kind").value = $("ob-prov-kind").value;
      $("prov-base-url").value = $("ob-prov-base-url").value;
      $("prov-models").value = $("ob-prov-models").value;
      $("prov-api-key").value = $("ob-prov-key").value;
      await saveProvider();
      const ok = ($("prov-msg").className || "").includes("ok");
      if (!ok) { obMsg($("prov-msg").textContent || "could not save — see providers pane", false); showTab("providers"); return; }
      $("ob-prov-key").value = "";
      obMsg("");
      obShow(3);
      return;
    }
    obDismiss();
  }
  $("ob-next").addEventListener("click", obNext);
  $("ob-back").addEventListener("click", () => obShow(Math.max(1, obStep - 1)));
  $("ob-skip").addEventListener("click", obDismiss);
  $("ob-username").addEventListener("keydown", (e) => { if (e.key === "Enter") $("ob-password").focus(); });
  $("ob-password").addEventListener("keydown", (e) => { if (e.key === "Enter") obNext(); });
  $("ob-token").addEventListener("keydown", (e) => { if (e.key === "Enter") obNext(); });
  $("ob-prov-name").addEventListener("keydown", (e) => { if (e.key === "Enter") obNext(); });

  // First-run detection: no token saved AND daemon reports no providers (or we
  // cannot prove otherwise). Runs after boot's first poll so providers are known.
  async function maybeOnboard() {
    try {
      if (localStorage.getItem(OB_KEY) === "1") return;
      if (localStorage.getItem(TOKEN_KEY)) return;
      let none = true;
      try {
        const res = await apiFetch(`${API}/v1/providers`);
        if (res.ok) none = provListItems(await res.json()).length === 0;
        else if (res.status === 401) none = true;
        else none = true;
      } catch (_) { none = true; }
      if (none) { $("onboard").hidden = false; obShow(1); }
    } catch (_) {}
  }
  // Expose for boot ordering; called after the first pollProviders().
  window.__maybeOnboard = maybeOnboard;
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
  !$("host-modal").hidden || !$("help").hidden || !$("onboard").hidden || !$("palette").hidden;

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
