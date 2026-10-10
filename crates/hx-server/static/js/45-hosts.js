// ---------------------------------------------------------------------------------------------
// Hosts

// A host's "capability summary" is not in the wire shape: `/v1/hosts` returns the id, kind,
// address and configured flag (see HostSummary in state.rs), not the probed os/shell/auth. So the
// pane renders exactly the fields the daemon actually answers with, and says plainly when a host is
// declared but not configured, rather than inventing a capability line the API never sent.
async function pollHosts() {
  const host = $("hosts");
  try {
    const res = await apiFetch(`${API}/v1/hosts`);
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    const items = await res.json();
    if (!Array.isArray(items)) throw new Error("hosts is not a list");
    renderHosts(items);
  } catch (e) {
    // A failed fetch must not read as an empty farm: say it broke, out loud.
    host.innerHTML = "";
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = `hosts unknown: ${e.message || e}`;
    host.appendChild(p);
    $("host-count").textContent = "";
  }
}

function renderHosts(items) {
  const host = $("hosts");
  $("host-count").textContent = items.length ? `${items.length}` : "";
  host.innerHTML = "";
  if (items.length === 0) {
    // The daemon always lists the local machine, so this is the daemon answering with nothing at
    // all — distinguished from "here are the hosts" by being explicit.
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "No hosts are configured.";
    host.appendChild(p);
    return;
  }
  for (const h of items) host.appendChild(renderHost(h));
}

function renderHost(h) {
  const el = document.createElement("div");
  el.className = "host";

  // The whole row opens the browser. A dedicated icon would be a smaller target for the most
  // common thing anyone wants to do with a host, and the id plus the kind already read as the
  // label for that action.
  const line = document.createElement("div");
  line.className = "row";
  line.title = `browse ${h.id || "this host"}`;
  line.addEventListener("click", () => openHost(h.id));
  const hid = document.createElement("span");
  hid.className = "hid";
  // textContent, not innerHTML: the id comes from config, and a hostname that reads like markup
  // must not become markup.
  hid.textContent = h.id || "(unnamed)";
  line.appendChild(hid);

  if (h.kind) {
    const kind = document.createElement("span");
    kind.className = "kind";
    kind.textContent = h.kind;
    line.appendChild(kind);
  }
  // Say what clicking does. A row that silently opens a dialog is a row nobody discovers.
  const open = document.createElement("span");
  open.className = "open";
  open.textContent = h.configured === false ? "" : "browse →";
  line.appendChild(open);
  el.appendChild(line);

  // `description` is a human-readable `user@host:port` for configured ssh/winrm hosts, or the
  // local machine's one-liner. Shown in place of a capability line because that is what the API
  // actually supplies.
  if (h.description && h.description !== "not configured") {
    const desc = document.createElement("div");
    desc.className = "desc";
    desc.textContent = h.description;
    el.appendChild(desc);
  }

  // `configured:false` means the host is declared in config but has no address, so it cannot be
  // connected to. Saying so beats showing a host that looks reachable.
  if (h.configured === false) {
    const unconf = document.createElement("div");
    unconf.className = "unconf";
    unconf.textContent = "declared but not configured — cannot connect";
    el.appendChild(unconf);
  }
  return el;
}

