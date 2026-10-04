// ---------------------------------------------------------------------------------------------
// Fan-out
//
// Runs N child prompts across N pool members and renders one outcome per child. The daemon owns
// the pool, the run and the redaction; the pane only renders the `FanOutOutcome` it is sent —
// a completed child names the member it ran on and its recorded usage, and a failed child shows
// the (already redacted) error the daemon returned.

function fanoutError(msg) {
  $("fanout-error").textContent = msg || "";
}

function addFanoutRow() {
  const row = document.createElement("div");
  row.className = "fanout-row";
  const session = document.createElement("input");
  session.className = "fanout-session";
  session.placeholder = "session";
  session.autocomplete = "off";
  session.spellcheck = false;
  const prompt = document.createElement("input");
  prompt.className = "fanout-prompt";
  prompt.placeholder = "prompt…";
  prompt.autocomplete = "off";
  row.appendChild(session);
  row.appendChild(prompt);
  $("fanout-rows").appendChild(row);
  return row;
}

function renderFanout(body) {
  const out = $("fanout-out");
  out.innerHTML = "";
  const children = body.children || [];
  if (children.length === 0) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "No children ran.";
    out.appendChild(p);
    return;
  }
  const members = body.members || [];
  children.forEach((child, i) => {
    out.appendChild(renderFanoutChild(child, members[i], i));
  });
}

function renderFanoutChild(child, member, index) {
  const el = document.createElement("div");
  el.className = "child";

  // The outcome is externally tagged: `{"Ran": record}` or `{"Errored": {member, error}}`.
  const name = document.createElement("div");
  const id = document.createElement("span");
  id.className = "cmember";
  // textContent, not innerHTML: the member id comes from daemon config and must not become markup.
  id.textContent = member || `child ${index + 1}`;
  name.appendChild(id);
  const status = document.createElement("span");

  if (child && typeof child.Ran === "object" && child.Ran !== null) {
    const record = child.Ran;
    status.className = "cstatus ran";
    status.textContent = "ran";
    name.appendChild(status);
    el.appendChild(name);
    const usage = document.createElement("div");
    usage.className = "cusage";
    const u = record.usage || {};
    const input = typeof u.input_tokens === "number" ? u.input_tokens : "?";
    const output = typeof u.output_tokens === "number" ? u.output_tokens : "?";
    // The model is the member the child finished on, which can differ from the drawn member when
    // the run re-routed mid-child — so both are shown rather than one assumed to be the other.
    usage.textContent = `model ${record.model || "?"} · in ${input} / out ${output} tokens`;
    el.appendChild(usage);
  } else if (child && typeof child.Errored === "object" && child.Errored !== null) {
    status.className = "cstatus errored";
    status.textContent = "errored";
    name.appendChild(status);
    el.appendChild(name);
    const err = document.createElement("div");
    err.className = "cerror";
    // Already redacted by the daemon at the fan-out boundary; shown verbatim, as text.
    err.textContent = child.Errored.error || "the child failed with no reason given";
    el.appendChild(err);
  } else {
    // A shape this page does not recognise is shown rather than dropped: silently skipping an
    // outcome would read as a child that never ran.
    status.className = "cstatus errored";
    status.textContent = "unknown";
    name.appendChild(status);
    el.appendChild(name);
    const err = document.createElement("div");
    err.className = "cerror";
    err.textContent = "an unreadable child outcome came back — see the daemon log";
    el.appendChild(err);
  }
  return el;
}

async function runFanout() {
  const children = [];
  for (const row of $("fanout-rows").children) {
    const session = row.querySelector(".fanout-session").value.trim();
    const prompt = row.querySelector(".fanout-prompt").value.trim();
    // Empty rows are skipped so a spare blank row does not refuse the whole run; a half-filled
    // row is refused out loud, because silently dropping a prompt is how work never happens.
    if (!session && !prompt) continue;
    if (!session || !prompt) { fanoutError("each row needs both a session and a prompt"); return; }
    children.push({ session, prompt });
  }
  if (children.length === 0) { fanoutError("add at least one child: a session and a prompt"); return; }
  fanoutError("");
  try {
    const res = await apiFetch(`${API}/v1/fanout`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ children }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      // 400 (no children), 422 (the pool is short) and 503 (no member to draw) are the route's
      // own refusals; the message is the daemon's, shown as a sentence rather than raw JSON.
      const detail = body.error || body.message || `${res.status}`;
      throw new Error(`fan-out refused (${res.status}): ${detail}`);
    }
    renderFanout(body);
  } catch (e) {
    $("fanout-out").innerHTML = "";
    fanoutError(`cannot run the fan-out: ${e.message || e}`);
  }
}

