// ---------------------------------------------------------------------------------------------
// Session review
//
// What *this task* changed, as opposed to the diff pane, which diffs whatever text a person pastes
// against whatever path they type. The list comes from the session's own transcript — the daemon
// replays the write and patch calls and diffs each against the file as it is now — so a shell
// command's effect, which the transcript does not record, is named rather than silently missing.

function reviewError(msg) {
  const host = $("review-error");
  if (host) host.textContent = msg || "";
}

function renderReview(body) {
  const out = $("review-out");
  out.innerHTML = "";
  // The route answers with one object per file, not a wrapper: `{path, edits, unapplied, diff}`.
  // `unapplied` is the list of patch anchors that could not be replayed, carried on the file they
  // belong to — a patch that failed to land is the edit most worth seeing, so it stays with the file.
  const files = Array.isArray(body) ? body : [];
  const count = $("review-count");
  const unapplied = files.reduce((n, f) => n + ((f.unapplied || []).length), 0);
  if (count) count.textContent = files.length ? ` ${files.length}` : "";
  if (files.length === 0) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "This task has not written or patched a file.";
    out.appendChild(p);
    return;
  }
  for (const file of files) out.appendChild(renderReviewedFile(file));
  if (unapplied) {
    const note = document.createElement("div");
    note.className = "runapplied";
    note.textContent = `${unapplied} patch${unapplied === 1 ? "" : "es"} could not be replayed — shown on the file`;
    out.appendChild(note);
  }
}

function renderReviewedFile(file) {
  const details = document.createElement("details");
  details.className = "rfile";
  details.open = true;
  const summary = document.createElement("summary");
  const path = document.createElement("span");
  path.className = "rpath";
  path.textContent = file.path || "";
  const count = document.createElement("span");
  count.className = "rcount";
  const lines = file.diff || [];
  const added = lines.filter((l) => typeof l.Added === "string").length;
  const removed = lines.filter((l) => typeof l.Removed === "string").length;
  count.textContent = file.binary ? "binary" : `+${added} −${removed}`;
  summary.appendChild(path);
  summary.appendChild(count);
  details.appendChild(summary);
  if (file.binary) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "binary — not shown as text";
    details.appendChild(p);
    return details;
  }
  if (!lines.length) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "matches the file on disk";
    details.appendChild(p);
    return details;
  }
  for (const line of lines) {
    const el = document.createElement("div");
    let mark = " ", cls = "ctx", text = "";
    if (typeof line.Added === "string") { mark = "+"; cls = "add"; text = line.Added; }
    else if (typeof line.Removed === "string") { mark = "-"; cls = "del"; text = line.Removed; }
    else if (typeof line.Context === "string") { text = line.Context; }
    el.className = `dline ${cls}`;
    const m = document.createElement("span");
    m.className = "mark";
    m.textContent = mark;
    el.appendChild(m);
    el.appendChild(document.createTextNode(text));
    details.appendChild(el);
  }
  return details;
}

async function runReview() {
  if (!sessionId) { reviewError("open a task first"); return; }
  reviewError("");
  const note = $("review-note");
  if (note) note.textContent = "reading the transcript…";
  try {
    const res = await apiFetch(`${API}/v1/sessions/${sessionId}/review`);
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `${res.status}`);
    renderReview(body);
    if (note) note.textContent = "files this task's agent wrote or patched";
  } catch (e) {
    $("review-out").innerHTML = "";
    if (note) note.textContent = "";
    reviewError(`cannot review: ${e.message || e}`);
  }
}

