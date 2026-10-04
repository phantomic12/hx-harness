// ---------------------------------------------------------------------------------------------
// Prompting

// A run in flight on this page. The daemon serialises runs per session, so a prompt sent mid-run
// would sit unanswered on the session lock; queueing it here is what makes a follow-up *visible*
// instead of a request that silently waits.
let running = false;
let promptQueue = [];

// One path for every prompt this page sends: the composer, a queued follow-up, "ask again" on an
// old card. Mid-run prompts queue visibly and go out on their own when the run ends.
async function submitPrompt(prompt) {
  if (!sessionId || !prompt) return;
  if (running) {
    promptQueue.push(prompt);
    paintQueue();
    return;
  }
  running = true;
  activeRuns.add(sessionId);
  paintActivity();
  showError("");
  try {
    const res = await apiFetch(`${API}/v1/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session: sessionId,
        prompt,
        stream: false,
        // "plan" is the read-only autonomy: the policy refuses every write, so the agent can look
        // and say what it would change without changing it. "act" sends nothing, which is the
        // daemon's default and must stay the default — an older daemon that does not know the
        // field would otherwise reject the whole request.
        autonomy: modeOf(sessionId) === "plan" ? "read_only" : undefined,
      }),
    });
    if (!res.ok) throw new Error(`chat failed: ${res.status} ${await res.text()}`);
    // The answer's events arrive on the session socket like any other, so there is nothing to
    // render here — doing it here too would double every event.
  } catch (e) {
    showError(String(e.message || e));
  } finally {
    running = false;
    activeRuns.delete(sessionId);
    paintActivity();
    paintQueue();
    $("prompt").focus();
    // The next queued follow-up goes out on its own — that is what queueing one means.
    if (promptQueue.length) submitPrompt(promptQueue.shift());
  }
}

function sendPrompt() {
  const input = $("prompt");
  const prompt = input.value.trim();
  if (!prompt) return;
  input.value = "";
  submitPrompt(prompt);
}

// The queue is visible because it is not free: a follow-up typed while a run is going is intent
// with money attached, and it must not live somewhere the person who typed it cannot see it.
function paintQueue() {
  const host = $("queue");
  if (!host) return;
  host.innerHTML = "";
  promptQueue.forEach((text, index) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    const label = document.createElement("span");
    label.textContent = text.length > 60 ? text.slice(0, 60) + "…" : text;
    const drop = document.createElement("button");
    drop.textContent = "×";
    drop.title = "drop this queued prompt";
    drop.addEventListener("click", () => {
      promptQueue.splice(index, 1);
      paintQueue();
    });
    chip.appendChild(label);
    chip.appendChild(drop);
    host.appendChild(chip);
  });
}

// The brake. The daemon's `POST /v1/sessions/{id}/cancel` is cooperative — the run stops at its
// next safe boundary and answers with `stop: "cancelled"` — and it answers a question the run is
// parked on as denied, so "stop" works even while the run waits for an approval nobody wants to
// give.
async function stopRun() {
  if (!sessionId) return;
  const btn = $("stop");
  if (btn) btn.disabled = true;
  try {
    const res = await apiFetch(`${API}/v1/sessions/${sessionId}/cancel`, { method: "POST" });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    const body = await res.json();
    if (!body.cancelled) {
      // Said rather than silently done: the button was stale, and a stop that stopped nothing
      // must not read as one that did.
      activeRuns.delete(sessionId);
      paintActivity();
    }
  } catch (e) {
    showError(String(e.message || e));
  } finally {
    if (btn) btn.disabled = false;
  }
}

