// ---------------------------------------------------------------------------------------------
// Diff / review
//
// Asks the daemon for a diff of a proposed change against the file's real current content. The daemon
// owns the file and its redaction; the pane only renders what it is sent. It never derives a diff from
// content it (or the approvals payload) does not have — that is the whole point of the `/v1/diff` route.

function diffError(msg) {
  $("diff-error").textContent = msg || "";
}

function renderDiff(body) {
  const out = $("diff-out");
  out.innerHTML = "";
  if (body.binary) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "The current file is binary; it cannot be diffed as text.";
    out.appendChild(p);
    return;
  }
  if (!body.diff || body.diff.length === 0) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "No difference.";
    out.appendChild(p);
    return;
  }
  for (const line of body.diff) {
    const el = document.createElement("div");
    let mark = " ", cls = "ctx", text = "";
    if (typeof line.Added === "string") { mark = "+"; cls = "add"; text = line.Added; }
    else if (typeof line.Removed === "string") { mark = "-"; cls = "del"; text = line.Removed; }
    else if (typeof line.Context === "string") { text = line.Context; }
    el.className = `dline ${cls}`;
    // textContent, not innerHTML: a diff line is file content and must not become markup.
    const m = document.createElement("span");
    m.className = "mark";
    m.textContent = mark;
    el.appendChild(m);
    el.appendChild(document.createTextNode(text));
    out.appendChild(el);
  }
}

async function runDiff() {
  const path = $("diff-path").value;
  const proposed = $("diff-proposed").value;
  if (!path.trim()) { diffError("enter a path to diff"); return; }
  diffError("");
  try {
    const res = await apiFetch(`${API}/v1/diff`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path: path.trim(), proposed }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `${res.status}`);
    renderDiff(body);
  } catch (e) {
    $("diff-out").innerHTML = "";
    diffError(`cannot diff ${path}: ${e.message || e}`);
  }
}

