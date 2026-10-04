// ---------------------------------------------------------------------------------------------
// Plan / act
//
// Two ways to send a prompt. "act" is what the daemon does by default: the agent may edit. "plan"
// asks for `read_only`, which the approval policy answers by refusing every write — so the agent
// can look and report, and nothing on disk moves. The choice is remembered per task, because a
// plan that silently becomes an edit on the next send is worse than no toggle at all.

const MODE_KEY = "hx.mode";
const modeOf = (id) => {
  try {
    const all = JSON.parse(localStorage.getItem(MODE_KEY) || "{}");
    return all[id] === "plan" ? "plan" : "act";
  } catch (_) { return "act"; }
};
const setMode = (id, mode) => {
  let all = {};
  try { all = JSON.parse(localStorage.getItem(MODE_KEY) || "{}"); } catch (_) {}
  if (mode === "plan") all[id] = "plan";
  else delete all[id];
  try { localStorage.setItem(MODE_KEY, JSON.stringify(all)); } catch (_) {}
  paintMode();
};
function paintMode() {
  const mode = sessionId ? modeOf(sessionId) : "act";
  for (const btn of document.querySelectorAll(".mode button[data-mode]")) {
    btn.classList.toggle("active", btn.dataset.mode === mode);
  }
}

