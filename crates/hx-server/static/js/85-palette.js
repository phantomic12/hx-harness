// ---------------------------------------------------------------------------------------------
// Command palette (ctrl+k)
//
// The Codex command menu and Synara's recent-view switcher, in the shape this page already has:
// one box that answers "jump to …" for tasks, panes, and the handful of actions that otherwise
// need a remembered chord. Every command closes over the same handler its button uses — the
// palette has no way of doing anything the UI could not already do.

const PAL = { items: [], sel: 0 };

// The catalogue, rebuilt on every open and every keystroke so it always reflects live state —
// a task that appeared, a run that started, a draft that landed all show up without a refresh.
function palCommands() {
  const cmds = [];
  const pane = (label, hint, view) => cmds.push({
    section: "panes", label, hint,
    run: () => {
      if (view === "side") {
        const b = document.querySelector('.top-views button[data-view="side"]');
        if (b) b.click();
      } else if (window.__showTab) window.__showTab(view);
    },
  });
  const act = (label, hint, fn) => cmds.push({ section: "actions", label, hint, run: fn });

  for (const s of sessions.slice(0, 60)) {
    const id = sidOf(s);
    if (!id || id === sessionId) continue;
    const st = taskState(id);
    cmds.push({
      section: "tasks",
      label: `switch to “${titleOf(s)}”`,
      hint: st === "wait" ? "waiting" : st === "run" ? "working" : st === "draft" ? "draft" : whenOf(s),
      run: () => openSession(id),
    });
  }
  pane("task list", "ctrl+1", "side");
  pane("terminal", "ctrl+2", "terminal");
  pane("screen", "ctrl+3", "screen");
  pane("diff", "ctrl+4", "diff");
  pane("review", "ctrl+5", "review");
  pane("fan-out", "ctrl+6", "fanout");
  pane("providers", "ctrl+7", "providers");
  act("new task", "", createSession);
  act("rename task", "", () => { const el = $("session-label"); el.focus(); el.select(); });
  act("delete task", "", deleteSession);
  act("focus the prompt", "ctrl+/", () => $("prompt").focus());
  if (sessionId && activeRuns.has(sessionId)) act("stop the run", "", stopRun);
  act("toggle density", "", () => setDensity(document.body.dataset.density === "compact" ? "" : "compact"));
  act("keyboard shortcuts", "?", openHelp);
  act("log in / out", "", toggleAccountPanel);
  if (window.__openOnboard) act("setup wizard", "", () => window.__openOnboard());
  return cmds;
}

function openPalette() {
  $("palette").hidden = false;
  const input = $("pal-input");
  input.value = "";
  PAL.sel = 0;
  paintPalette();
  input.focus();
}

function closePalette() {
  $("palette").hidden = true;
}

function paintSel() {
  const rows = Array.from($("pal-list").querySelectorAll(".pal-row"));
  rows.forEach((r, i) => r.classList.toggle("sel", i === PAL.sel));
  const cur = rows[PAL.sel];
  if (cur) {
    cur.scrollIntoView({ block: "nearest" });
    $("pal-input").setAttribute("aria-activedescendant", cur.id);
  }
}

function paintPalette() {
  const q = $("pal-input").value.trim().toLowerCase();
  PAL.items = palCommands().filter((c) => !q || c.label.toLowerCase().includes(q));
  if (PAL.sel >= PAL.items.length) PAL.sel = 0;
  const host = $("pal-list");
  host.innerHTML = "";
  let lastSection = "";
  PAL.items.slice(0, 40).forEach((c, i) => {
    if (c.section !== lastSection) {
      lastSection = c.section;
      const h = document.createElement("div");
      h.className = "pal-sec";
      h.textContent = c.section;
      host.appendChild(h);
    }
    const row = document.createElement("button");
    row.type = "button";
    row.className = "pal-row" + (i === PAL.sel ? " sel" : "");
    row.id = `pal-opt-${i}`;
    row.setAttribute("role", "option");
    const label = document.createElement("span");
    label.textContent = c.label;
    row.appendChild(label);
    if (c.hint) {
      const k = document.createElement("kbd");
      k.textContent = c.hint;
      row.appendChild(k);
    }
    row.addEventListener("click", () => { closePalette(); c.run(); });
    row.addEventListener("mousemove", () => { if (PAL.sel !== i) { PAL.sel = i; paintSel(); } });
    host.appendChild(row);
  });
  if (!PAL.items.length) {
    const empty = document.createElement("div");
    empty.className = "pal-empty";
    empty.textContent = "nothing matches — the palette knows tasks, panes, and page actions";
    host.appendChild(empty);
  }
}

$("pal-input").addEventListener("input", () => { PAL.sel = 0; paintPalette(); });
$("pal-input").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { PAL.sel = Math.min(PAL.sel + 1, PAL.items.length - 1); paintSel(); e.preventDefault(); }
  else if (e.key === "ArrowUp") { PAL.sel = Math.max(PAL.sel - 1, 0); paintSel(); e.preventDefault(); }
  else if (e.key === "Enter") {
    const c = PAL.items[PAL.sel];
    if (c) { closePalette(); c.run(); }
    e.preventDefault();
  }
});
// The backdrop dismisses, the box does not — same contract as the host modal.
$("palette").addEventListener("click", (e) => { if (e.target === $("palette")) closePalette(); });
