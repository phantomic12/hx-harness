// ---------------------------------------------------------------------------------------------
// The human in the loop.
//
// A site refused the plain fetch and a real browser, so the daemon handed the wall to a *person*: it
// launched the browser this pane draws and is holding the fetch until somebody answers. That makes
// this the one surface in the page where doing nothing has a cost — the fetch waits for its budget
// and then gives up — so the banner is loud, it is polled rather than pushed (there is no event,
// the fetch is not this tab's), and the tab that hides it says something when the page is not
// looking.
//
// Answering is the person's word and nothing else: "cleared it" is not a check that the wall is gone,
// and the pane says so where a person will read it, because the fetch it unblocks is about to report
// exactly that to whoever asked for the page.
// ---------------------------------------------------------------------------------------------

let pendingChallenge = null;

async function pollChallenges() {
  let challenges = [];
  try {
    const res = await apiFetch(`${API}/v1/challenges`);
    if (res.ok) challenges = (await res.json()).challenges || [];
    else { paintChallengeStale(); return; }
  } catch (_) {
    // Unreachable daemon: the banner stays (hiding it would throw away the person's chance to answer
    // a challenge that is probably still live) and stops counting down, because a countdown that
    // keeps ticking through a failed poll is a number nobody measured.
    paintChallengeStale();
    return;
  }
  paintChallenge(challenges[0] || null);
}

/// Show the challenge the daemon is waiting on, or hide the banner when there is none.
function paintChallenge(challenge) {
  const host = $("challenge");
  if (!host) return;
  const watcher = screenId === (challenge && challenge.screen) &&
    screenSocket && screenSocket.readyState === WebSocket.OPEN;
  pendingChallenge = challenge;
  host.hidden = !challenge;
  markChallengeTabs(!!challenge);
  // The strip and the title read the same fact the banner does — one waiting state, painted
  // everywhere it can be seen (the shared painter replaced paintChallengeTitle's per-pane prefix).
  attnChallenge = challenge;
  paintAttention();
  if (challenge && challenge.id !== lastAnnouncedChallenge) {
    lastAnnouncedChallenge = challenge.id;
    announce(`a site needs a person — ${challenge.session || "a task"} is blocked`);
  }
  if (!challenge) { lastAnnouncedChallenge = null; return; }

  $("challenge-what").textContent = `${challenge.session} is blocked on ${challenge.url}`;
  $("challenge-left").textContent = challenge.seconds_left > 0
    ? `${challenge.seconds_left}s left`
    : "the budget is up";
  // Addressed to one operator, and the daemon says whether it managed to tell *that* operator. A
  // roster can hold people with a channel of their own and people without, so "was anybody told" is
  // the wrong question — the honest one is about the name on the challenge. "Someone has this" and
  // "you are the only chance this run has" are different instructions to the person reading them, and
  // on a daemon with several operators the banner is also what tells the *wrong* person to stay put.
  const who = $("challenge-for");
  if (who) {
    const name = challenge.operator || "the operator";
    who.textContent = "";
    const line = document.createElement("span");
    const bold = document.createElement("b");
    bold.textContent = name;
    line.append("for ", bold);
    if (challenge.notified) {
      line.append(" — told on their own channel");
    } else {
      const unheard = document.createElement("span");
      unheard.className = "unheard";
      unheard.textContent =
        " — nobody was told (no push_url for that operator), so this page is the only place to answer";
      line.append(unheard);
    }
    who.append(line);
  }
  $("challenge-why").textContent = challenge.reason;
  // The person has to be looking at *this* screen to clear the wall in it. When they are watching a
  // different one, the banner offers the switch rather than taking it: moving the pane under someone
  // who is mid-click is worse than asking.
  const watch = $("challenge-watch");
  watch.hidden = !!watcher;
  watch.textContent = `watch ${challenge.screen}`;
}

function paintChallengeStale() {
  const left = $("challenge-left");
  if (left && !$("challenge").hidden) left.textContent = "checking…";
}

/// Say so on the tab that is hiding the banner.
function markChallengeTabs(needed) {
  document.querySelectorAll('[data-view="screen"], [data-tab="screen"]').forEach((el) => {
    el.classList.toggle("need", needed);
  });
}

// Announce each live challenge once to the screen-reader region.
let lastAnnouncedChallenge = null;

/// Answer the challenge the banner is showing.
async function answerChallenge(outcome, note) {
  const challenge = pendingChallenge;
  if (!challenge) return;
  $("screen-error").textContent = "";
  const body = note ? { outcome, note } : { outcome };
  try {
    const res = await apiFetch(`${API}/v1/challenges/${encodeURIComponent(challenge.id)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      // The daemon's own sentence: a decline with no note is refused by name, and a challenge that
      // ended while the person was typing says so rather than pretending the click landed.
      const msg = `could not answer ${challenge.id}: ${await res.text()}`;
      $("screen-error").textContent = msg;
      if (typeof toast === "function") toast(msg, "bad");
      await pollChallenges();
      return;
    }
    $("challenge-note").value = "";
    paintChallenge(null);
    paintScreenWhere(`${outcome === "solved" ? "cleared" : "declined"} ${challenge.id}`);
    if (typeof toast === "function") toast(outcome === "solved" ? "marked cleared — the fetch re-runs" : "challenge declined", outcome === "solved" ? "ok" : "warn");
  } catch (e) {
    $("screen-error").textContent = `could not answer ${challenge.id}: ${e.message || e}`;
  }
}

/// Attach this pane to the screen a pending challenge is presented on.
/// Follow the daemon's own deep link: `#screen=<id>`, which is what a challenge notification carries.
///
/// The pane is revealed before the socket is attached: a URL that opened a browser nobody can see
/// would be a link that does nothing, and the whole point of the notification is that it takes a
/// person to the screen they have to clear the wall in.
///
async function followScreenLink() {
  const raw = (location.hash || "").replace(/^#/, "");
  if (!raw.startsWith("screen=")) return false;
  const id = decodeURIComponent(raw.slice("screen=".length)).trim();
  if (!id) return false;
  const drawer = $("drawer");
  const pane = $("dp-screen");
  if (drawer && (drawer.hidden || (pane && pane.hidden))) {
    const button = document.querySelector('.top-views button[data-view="screen"]');
    if (button) button.click();
  }
  screenEnded = false;
  screenId = id;
  try {
    await attachScreen();
    return true;
  } catch (e) {
    $("screen-error").textContent = `could not open ${id}: ${e.message || e}`;
    return false;
  }
}

async function watchChallenge() {
  const challenge = pendingChallenge;
  if (!challenge) return;
  screenEnded = false;
  screenId = challenge.screen;
  screenURL = challenge.url;
  $("screen-url").value = challenge.url;
  $("screen-error").textContent = "";
  try {
    attachScreen();
    paintChallenge(challenge);
  } catch (e) {
    $("screen-error").textContent = String(e.message || e);
  }
}

/// Paint one frame, coalescing: a draw is asynchronous, so only the newest waiting frame is kept.
function drawScreenFrame(frame) {
  if (screenDrawing) { screenPending = frame; return; }
  screenDrawing = true;
  let bytes;
  try { bytes = b64decodeToBytes(frame.data); } catch (_) { screenDrawing = false; return; }
  const blob = new Blob([bytes], { type: "image/jpeg" });
  createImageBitmap(blob)
    .then((bitmap) => {
      const canvas = $("screen-canvas");
      // The canvas takes the *frame's* size, so what is drawn is what was rendered: a canvas sized to
      // the request instead would letterbox a page that came back a different shape.
      if (canvas.width !== frame.width || canvas.height !== frame.height) {
        canvas.width = frame.width;
        canvas.height = frame.height;
      }
      const ctx = canvas.getContext("2d");
      ctx.drawImage(bitmap, 0, 0, frame.width, frame.height);
      bitmap.close();
      screenDrawing = false;
      const pending = screenPending;
      screenPending = null;
      if (pending) drawScreenFrame(pending);
    })
    .catch(() => {
      // A frame that will not decode is one frame; the next one usually will. Reported once, not
      // per frame, because a broken stream would otherwise fill the error line.
      screenDrawing = false;
      screenPending = null;
    });
}

