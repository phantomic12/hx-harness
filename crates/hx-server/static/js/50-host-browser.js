// ---------------------------------------------------------------------------------------------
// Host browser
//
// One dialog, three jobs: list a directory, read and save a file, run a command. The host is held in
// `browseHost` so every request goes to the machine the person actually opened — reading it back out
// of the DOM would mean the dialog and the requests could disagree about which box they are on.

let browseHost = null;
let browsePath = null;
let browseFile = null;
// The encoding the file came back in, echoed on save. Sending a base64 file back as utf-8 would
// corrupt it, and the daemon cannot tell the difference — only this side knows what it received.
let browseEncoding = "utf-8";

function hostError(msg) {
  $("host-error").textContent = msg || "";
}

async function openHost(id) {
  if (!id) return;
  browseHost = id;
  browsePath = null;
  browseFile = null;
  browseEncoding = "utf-8";
  $("host-file").value = "";
  $("host-file-status").textContent = "";
  $("host-out").textContent = "";
  hostError("");
  $("host-modal-title").textContent = id;
  $("host-modal-meta").textContent = "";
  $("host-modal").hidden = false;

  // Describe the machine too, so the dialog can say what it is talking to rather than only its name.
  try {
    const res = await apiFetch(`${API}/v1/hosts/${encodeURIComponent(id)}`);
    const detail = await res.json();
    if (!res.ok) throw new Error(detail.error || `${res.status}`);
    const bits = [];
    if (detail.os) bits.push(detail.os);
    if (detail.shell) bits.push(`${detail.shell} shell`);
    if (detail.arch) bits.push(detail.arch);
    if (detail.home_dir) bits.push(`home ${detail.home_dir}`);
    $("host-modal-meta").textContent = bits.join(" · ");
    // A host the policy refuses, or one that will not connect, is shown with the reason instead of a
    // file list that would only fail. The message is the daemon's, verbatim.
    if (detail.denied || detail.unreachable) {
      hostError(detail.denied || detail.unreachable);
      $("host-entries").innerHTML = "";
      return;
    }
  } catch (e) {
    hostError(`could not describe ${id}: ${e.message || e}`);
  }
  await listDir(browsePath);
}

async function listDir(path) {
  if (!browseHost) return;
  hostError("");
  const query = path ? `?path=${encodeURIComponent(path)}` : "";
  try {
    const res = await apiFetch(`${API}/v1/hosts/${encodeURIComponent(browseHost)}/files${query}`);
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `${res.status}`);
    // The daemon echoes where it actually listed, which matters when nothing was asked for.
    browsePath = body.path;
    $("host-path").value = body.path;
    renderEntries(body.entries || []);
  } catch (e) {
    hostError(`cannot list ${path || "the home directory"}: ${e.message || e}`);
    $("host-entries").innerHTML = "";
  }
}

function renderEntries(entries) {
  const list = $("host-entries");
  list.innerHTML = "";
  if (entries.length === 0) {
    const p = document.createElement("div");
    p.className = "entry";
    p.textContent = "empty";
    list.appendChild(p);
    return;
  }
  // Directories first, then by name: the ordering a file manager uses, because that is what a person
  // is scanning for.
  const sorted = entries.slice().sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    return (a.name || "").localeCompare(b.name || "");
  });
  for (const entry of sorted) list.appendChild(renderEntry(entry));
}

function renderEntry(entry) {
  const el = document.createElement("div");
  el.className = "entry" + (entry.is_dir ? " dir" : "");

  const name = document.createElement("span");
  name.className = "ename";
  name.textContent = entry.is_dir ? `${entry.name}/` : entry.name;
  el.appendChild(name);

  if (!entry.is_dir) {
    const size = document.createElement("span");
    size.className = "esize";
    size.textContent = formatSize(entry.size);
    el.appendChild(size);
  }

  el.addEventListener("click", () => {
    if (entry.is_dir) {
      listDir(entry.path);
    } else {
      // Selection is visual only; the file that gets saved is `browseFile`, set by reading it back.
      for (const other of $("host-entries").children) other.classList.remove("selected");
      el.classList.add("selected");
      openFile(entry.path);
    }
  });
  return el;
}

function formatSize(bytes) {
  if (typeof bytes !== "number") return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function openFile(path) {
  hostError("");
  $("host-file-status").textContent = "loading…";
  try {
    const res = await apiFetch(
      `${API}/v1/hosts/${encodeURIComponent(browseHost)}/file?path=${encodeURIComponent(path)}`
    );
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `${res.status}`);
    browseFile = body.path;
    browseEncoding = body.encoding;

    if (body.encoding === "base64") {
      // Not rendered into the editor. Showing base64 and letting someone "edit" it would silently
      // corrupt the file on save, so the textarea stays empty and says why.
      $("host-file").value = "";
      $("host-file").disabled = true;
      $("host-file-status").textContent = `${formatSize(body.size)} binary — not editable here`;
    } else {
      $("host-file").value = body.contents;
      $("host-file").disabled = false;
      $("host-file-status").textContent = `${formatSize(body.size)} · ${body.path}`;
    }
  } catch (e) {
    $("host-file-status").textContent = "";
    browseFile = null;
    hostError(`cannot read ${path}: ${e.message || e}`);
  }
}

async function saveFile() {
  if (!browseFile) {
    hostError("open a file before saving");
    return;
  }
  hostError("");
  $("host-file-status").textContent = "saving…";
  try {
    const res = await apiFetch(`${API}/v1/hosts/${encodeURIComponent(browseHost)}/file`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        path: browseFile,
        contents: $("host-file").value,
        encoding: browseEncoding,
      }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `${res.status}`);
    $("host-file-status").textContent = `saved ${formatSize(body.written)}`;
    // The size on disk may have changed, so the listing is refreshed rather than left stale.
    listDir(browsePath);
  } catch (e) {
    $("host-file-status").textContent = "";
    hostError(`cannot save ${browseFile}: ${e.message || e}`);
  }
}

async function runOnHost() {
  const command = $("host-cmd").value;
  if (!command.trim()) return;
  hostError("");
  $("host-out").textContent = "running…";
  try {
    const res = await apiFetch(`${API}/v1/hosts/${encodeURIComponent(browseHost)}/exec`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ command }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `${res.status}`);
    // stdout and stderr are both shown, and the exit code with them: a command that wrote only to
    // stderr would otherwise look like it produced nothing.
    const parts = [];
    if (body.stdout) parts.push(body.stdout);
    if (body.stderr) parts.push(`--- stderr ---\n${body.stderr}`);
    parts.push(`--- exit ${body.exit_code === null ? "unknown" : body.exit_code} in ${body.duration_ms}ms`);
    $("host-out").textContent = parts.join("\n");
  } catch (e) {
    $("host-out").textContent = "";
    hostError(`cannot run on ${browseHost}: ${e.message || e}`);
  }
}

