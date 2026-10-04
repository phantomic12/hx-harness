// ---------------------------------------------------------------------------------------------
// Providers
//
// Lists the daemon's configured model providers and lets the owner add, edit or remove one at
// runtime. Every request goes through apiFetch, so the bearer token is sent exactly the way the
// rest of the page sends it. The daemon never returns a stored secret (GET answers with a
// summary), and this pane never asks for one: the api_key field is write-only — a non-empty
// value is sent on save, a blank value means "keep whatever the daemon already has".

function provMsg(text, ok) {
  const el = $("prov-msg");
  el.textContent = text || "";
  el.className = text ? (ok ? "ok" : "err") : "";
}

function provError(msg) {
  $("prov-error").textContent = msg || "";
}

function provListItems(body) {
  // Accept the planned `[{name, kind, ...}]` shape, and a `{providers: [...]}` or
  // `{name: config}` map defensively — the backend is landing alongside this pane.
  if (Array.isArray(body)) return body;
  if (body && Array.isArray(body.providers)) return body.providers;
  if (body && typeof body === "object") {
    return Object.entries(body).map(([name, cfg]) =>
      Object.assign({ name }, cfg && typeof cfg === "object" ? cfg : {})
    );
  }
  return [];
}

async function pollProviders() {
  const host = $("providers");
  try {
    const res = await apiFetch(`${API}/v1/providers`);
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    const items = provListItems(await res.json());
    renderProviders(items);
    provError("");
  } catch (e) {
    // A failed fetch must not read as "no providers configured": say it broke, out loud.
    host.innerHTML = "";
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = `providers unknown: ${e.message || e}`;
    host.appendChild(p);
    $("provider-count").textContent = "";
  }
}

function renderProviders(items) {
  const host = $("providers");
  $("provider-count").textContent = items.length ? `${items.length}` : "";
  host.innerHTML = "";
  if (items.length === 0) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "No providers are configured.";
    host.appendChild(p);
    return;
  }
  for (const p of items) host.appendChild(renderProvider(p));
}

function renderProvider(p) {
  const el = document.createElement("div");
  el.className = "provider";

  const line = document.createElement("div");
  const name = document.createElement("span");
  name.className = "pname";
  // textContent, not innerHTML: names come from daemon config and must not become markup.
  name.textContent = p.name || "(unnamed)";
  line.appendChild(name);
  if (p.kind) {
    const kind = document.createElement("span");
    kind.className = "pkind";
    kind.textContent = typeof p.kind === "string" ? p.kind : JSON.stringify(p.kind);
    line.appendChild(kind);
  }
  el.appendChild(line);

  // Only the non-secret fields the GET summary carries: kind, base_url, models, routing.
  // The daemon never sends a secret here, and nothing is rendered that could be one.
  const meta = [];
  if (p.base_url) meta.push(p.base_url);
  const models = Array.isArray(p.models) ? p.models.join(", ") : (p.models || "");
  if (models) meta.push(`models: ${models}`);
  if (p.routing) meta.push(`routing: ${typeof p.routing === "string" ? p.routing : JSON.stringify(p.routing)}`);
  if (meta.length) {
    const m = document.createElement("div");
    m.className = "pmeta";
    m.textContent = meta.join(" · ");
    el.appendChild(m);
  }

  if ("secret_set" in p) {
    const key = document.createElement("div");
    key.className = "pkey";
    key.textContent = p.secret_set ? "api key: set (write-only)" : "api key: not set";
    el.appendChild(key);
  }
  const opts = document.createElement("div");
  opts.className = "popts";
  const edit = document.createElement("button");
  edit.textContent = "edit";
  edit.addEventListener("click", () => fillProviderForm(p));
  opts.appendChild(edit);
  const del = document.createElement("button");
  del.textContent = "delete";
  del.className = "del";
  del.addEventListener("click", () => deleteProvider(p.name));
  opts.appendChild(del);
  el.appendChild(opts);
  return el;
}

function fillProviderForm(p) {
  $("prov-name").value = p.name || "";
  if (p.kind && typeof p.kind === "string") $("prov-kind").value = p.kind;
  $("prov-base-url").value = p.base_url || "";
  $("prov-models").value = Array.isArray(p.models) ? p.models.join(", ") : (p.models || "");
  // The stored secret is never displayed: the key field always starts blank, and a blank save
  // keeps whatever the daemon already has.
  $("prov-api-key").value = "";
  if (p.routing && typeof p.routing === "string") $("prov-routing").value = p.routing;
  provMsg("");
  $("prov-name").focus();
}

function clearProviderForm() {
  $("prov-name").value = "";
  $("prov-base-url").value = "";
  $("prov-models").value = "";
  $("prov-api-key").value = "";
  provMsg("");
  provError("");
}

async function saveProvider() {
  const name = $("prov-name").value.trim();
  if (!name) { provMsg("enter a provider name", false); return; }
  const models = $("prov-models").value.split(",").map((m) => m.trim()).filter((m) => m);
  const body = {
    kind: $("prov-kind").value,
    base_url: $("prov-base-url").value.trim() || undefined,
    models,
    routing: $("prov-routing").value,
  };
  // Write-only: only sent when the person typed one. Blank means "keep existing".
  const key = $("prov-api-key").value;
  if (key) body.api_key = key;
  provMsg("");
  provError("");
  try {
    const res = await apiFetch(`${API}/v1/providers/${encodeURIComponent(name)}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    $("prov-api-key").value = "";
    provMsg(`saved ${name}`, true);
    if (typeof toast === "function") toast(`saved provider ${name}`, "ok");
    await pollProviders();
  } catch (e) {
    provMsg(`could not save ${name}: ${e.message || e}`, false);
    if (typeof toast === "function") toast(`could not save ${name}`, "bad");
  }
}

async function deleteProvider(name) {
  if (!name) return;
  provMsg("");
  provError("");
  try {
    const res = await apiFetch(`${API}/v1/providers/${encodeURIComponent(name)}`, {
      method: "DELETE",
    });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    if ($("prov-name").value.trim() === name) clearProviderForm();
    provMsg(`deleted ${name}`, true);
    if (typeof toast === "function") toast(`deleted provider ${name}`, "info");
    await pollProviders();
  } catch (e) {
    provMsg(`could not delete ${name}: ${e.message || e}`, false);
    if (typeof toast === "function") toast(`could not delete ${name}`, "bad");
  }
}

