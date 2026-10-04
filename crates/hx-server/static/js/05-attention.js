// ---------------------------------------------------------------------------------------------
// The surfaces that speak for the daemon: the attention strip, toasts, the connection bar, and
// the screen-reader live region. Everything here answers one question — "what does it want from
// me right now" — or reports that the page can still see the daemon at all.

// A quiet voice for assistive tech: same sentence the toast shows, through the polite live region.
function announce(text) {
  const el = $("sr-live");
  if (!el || !text) return;
  el.textContent = "";
  // Re-writing in a frame, not in place: a string that was already there announces twice at most
  // if the region is not cleared first.
  requestAnimationFrame(() => { el.textContent = text; });
}

// ---- toasts --------------------------------------------------------------------------------------
// One toast voice for every "it did the thing" / "that failed" that used to paint a bare line in
// an inline .error slot. Errors that belong to a field (login, provider form) still live beside
// the field; toasts are for events, not validation.
function toast(text, kind = "info", opts = {}) {
  const host = $("toasts");
  if (!host) return;
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.setAttribute("role", kind === "bad" ? "alert" : "status");
  const span = document.createElement("span");
  span.textContent = text;
  el.appendChild(span);
  if (opts.label && typeof opts.action === "function") {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = opts.label;
    btn.addEventListener("click", () => { opts.action(); dismiss(); });
    el.appendChild(btn);
  }
  const dismiss = () => { el.classList.add("leaving"); setTimeout(() => el.remove(), 200); };
  host.appendChild(el);
  while (host.childElementCount > 4) host.firstElementChild.remove();
  setTimeout(dismiss, opts.ttl ?? 6000);
  announce(text);
}

// ---- connection bar ------------------------------------------------------------------------------
// Silent failure is the one state this page must never have. Any apiFetch that throws (the daemon
// is gone, the network is down) or a session socket that keeps dropping lands here: a pill under
// the header that says so and counts attempts. Any request that *arrives* clears it.
let netDownCount = 0;
let netDownWhat = "connection lost — retrying";
function netDown(what) {
  netDownCount++;
  netDownWhat = what || netDownWhat;
  paintConnbar();
}
function netUp() {
  if (!netDownCount) return;
  netDownCount = 0;
  paintConnbar();
  toast("reconnected to the daemon", "ok");
}
function paintConnbar() {
  const bar = $("connbar");
  if (!bar) return;
  if (!netDownCount) { bar.hidden = true; return; }
  bar.hidden = false;
  $("connbar-text").textContent =
    netDownCount > 1 ? `${netDownWhat} (attempt ${netDownCount})` : netDownWhat;
}

// ---- the attention strip --------------------------------------------------------------------------
// A window onto the queues the panes own: pending approvals and a live challenge each get a row.
// Answering here is answering there — the rows call the same handlers, so the strip and the panes
// cannot disagree about what is still waiting.
let attnApprovals = [];
let attnChallenge = null;

function paintAttention() {
  const host = $("attention");
  if (!host) return;
  host.innerHTML = "";

  if (attnChallenge) {
    const row = document.createElement("div");
    row.className = "attn";
    const text = document.createElement("span");
    text.className = "attn-text";
    const b = document.createElement("b");
    b.textContent = attnChallenge.session || "a task";
    text.append(b, ` is blocked — a site needs a person (${attnChallenge.url || "?"})`);
    row.appendChild(text);
    const sub = document.createElement("span");
    sub.className = "attn-sub";
    sub.textContent = attnChallenge.seconds_left > 0 ? `${attnChallenge.seconds_left}s left` : "the budget is up";
    row.appendChild(sub);
    const acts = document.createElement("span");
    acts.className = "attn-acts";
    const watch = document.createElement("button");
    watch.type = "button";
    watch.textContent = `watch ${attnChallenge.screen || "it"}`;
    watch.addEventListener("click", () => {
      // Reveal the pane first — the person clears the wall in the screen, not in this row.
      const btn = document.querySelector('.top-views button[data-view="screen"]');
      const pane = $("dp-screen");
      if (btn && ($("drawer").hidden || (pane && pane.hidden))) btn.click();
      watchChallenge();
    });
    acts.appendChild(watch);
    row.appendChild(acts);
    host.appendChild(row);
  }

  if (attnApprovals.length) {
    const first = attnApprovals[0];
    const row = document.createElement("div");
    row.className = "attn";
    const text = document.createElement("span");
    text.className = "attn-text";
    const b = document.createElement("b");
    b.textContent = first.tool || "tool";
    text.append(b, ` — ${first.summary || first.reason || "approval requested"}`);
    row.appendChild(text);
    if (attnApprovals.length > 1) {
      const sub = document.createElement("span");
      sub.className = "attn-sub";
      sub.textContent = `${attnApprovals.length} waiting`;
      row.appendChild(sub);
    }
    const acts = document.createElement("span");
    acts.className = "attn-acts";
    const allow = document.createElement("button");
    allow.type = "button";
    allow.textContent = "allow once";
    allow.addEventListener("click", () => answerApproval(first.id, "once"));
    const deny = document.createElement("button");
    deny.type = "button";
    deny.className = "deny";
    deny.textContent = "deny";
    deny.addEventListener("click", () => answerApproval(first.id, "deny"));
    acts.append(allow, deny);
    if (attnApprovals.length > 1) {
      const more = document.createElement("button");
      more.type = "button";
      more.textContent = "queue";
      more.addEventListener("click", () => {
        const side = $("side");
        const btn = document.querySelector('.top-views button[data-view="side"]');
        if (side.hidden && btn) btn.click();
        $("approvals").scrollIntoView({ block: "nearest", behavior: "smooth" });
      });
      acts.appendChild(more);
    }
    row.appendChild(acts);
    host.appendChild(row);
  }

  host.hidden = !host.childElementCount;
  paintTitle();
}

// The title bar joins in only when the page is in the background — the strip is the foreground
// answer and a tab a person is looking at does not also need to blink. One painter for every
// waiting state, so approvals and challenges share the mark rather than each inventing one.
function paintTitle() {
  if (!document.hidden) { document.title = titleBase; return; }
  if (attnChallenge) {
    document.title = `● a site needs you — ${titleBase}`;
  } else if (attnApprovals.length) {
    document.title = `● ${attnApprovals.length} approval${attnApprovals.length > 1 ? "s" : ""} — ${titleBase}`;
  } else {
    document.title = titleBase;
  }
}
document.addEventListener("visibilitychange", paintTitle);
