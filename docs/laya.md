# Laya: a fast local decision layer for hx

Laya (<https://brainfunctioncollapse.com/laya>) is the open-source (Apache-2.0) alternative to
**TypeSafe Jev**: a 322M-param, non-autoregressive "System 1" decision model. It answers
**typed questions** about a piece of text and returns **probabilities** — never generated text — in
roughly 21–35 ms on a laptop GPU, $0, fully offline, with your data going nowhere.

hx integrates Laya as a **local runtime helper**. hx is Rust and never embeds Python; it talks to a
small loopback HTTP **sidecar** (the only process that imports `laya`). The Rust side is
`crates/hx-decision` (typed schema + `LayaClient`), the CLI surface is `hx decision`, and the
self-check is the `hx doctor` Laya probe.

> Milestone scope: the decision substrate plus the first consumer rung — `hx drive` senses a tmux
> pane each tick and presses keys from Laya's answers (below). Browser/desktop control and faster
> frame rates remain the follow-up (see ROADMAP).

## What Laya is not

Use Laya for a **decision**, not a sentence: which queue, is this spam, how urgent, should the agent
stop. Do **not** reach for it for multi-step reasoning, arithmetic, free-form extraction, or any generated
text — keep the LLM for those and put Laya in front of it as a cheap first pass (the "cascade" below).

## Running the sidecar

The recipe is `examples/laya-sidecar.py`.

```bash
pip install laya fastapi uvicorn
# one-time weights download (cached under $HF_HOME / ~/.cache/huggingface)
python -c "from laya import download_weights; download_weights()"
uvicorn laya-sidecar:app --host 127.0.0.1 --port 8770
```

* First start downloads ~2.3 GB of open weights and takes ~90 s to load them.
* If a download hangs at 0 bytes, set `HF_HUB_DISABLE_XET=1` (plain HTTPS fallback). Once
  cached, set `HF_HUB_OFFLINE=1` to skip network checks.
* The two `ADAPTER` lines in the sidecar are the only ones tied to the upstream `laya` repo layout; if
  the package API moves, only those change. The HTTP contract stays fixed.

### HTTP contract

* `GET /health` → `{"ok": true, "model": "<id>"}`
* `POST /predict` body `{"state": "<text>", "questions": { ... }}` → the agent's predict result as
  JSON (answers carry probabilities, confidence, `action.act_probability`; result carries
  `usage.input_tokens`).

Concurrency: the agent is loaded **once** and shared behind a `threading.Lock`. Every `predict` takes
*all* questions in one forward pass — never loop one question per request; that throws away Laya's batching.

## The three question types

| type | `criteria` | what comes back in `answers[id]` |
|---|---|---|
| `choice` | dict `{option: description}` or list of names | `choice` (winner), `probabilities` per option, `confidence` |
| `score` | ordered list of level descriptions, lowest first | `score` (float), `probabilities` per level, `legend`, `confidence` |
| `noul` | optional `{"true": "...", "false": "..."}` | `noul` = P(true), `confidence` |

Every answer also carries `action.act_probability`. `confidence` is one minus the normalised entropy of
the distribution, so it is *low whenever probability is spread out*, even if the top option is right.

## Writing questions that work

This matters more than anything else. Laya is an encoder doing close-to-textual-entailment, and it
rewards questions shaped like that:

* **Ask what the text says, not what to do.** "Where is the bird relative to the gap?" gives clean
  probabilities; "Which way must the bird move?" came out inverted, because the option word "up" is pulled
  to "above" in the state. Ask a perception question, then map the answer to an action in code.
* **Put the state into words, never numbers.** "Altitude: 20. Gap: 60." — Laya can't tell which is
  lower. Compute comparisons in code and hand it the conclusion ("the bird is far below the gap").
* **Describe each option.** `{"billing": "invoices, payments, refunds"}` beats a bare list.
* **Keep option lists short.** Entries truncate at 48 tokens and share a budget per question (~192 tokens
  on the English checkpoint). Past ~20 options accuracy degrades.
* **Try two or three phrasings and measure.** Small wording moves results a lot.

## Thresholds and cascade

`crates/hx-core`'s decision helper (`DecisionGate` / `Threshold`) reports whether each answer's top
probability cleared a threshold:

* Act if `prob >= threshold` and confidence is not too flat.
* Escalate (to an LLM or a person) below the threshold or when confidence is too flat.

Pick the threshold to reflect the cost of being wrong: a guardrail (a miss is expensive) gets a low
threshold; an auto-action (a false alarm is expensive) gets a high one. A good default architecture: Laya
handles every request, and only the below-threshold share goes to the LLM — the escalation rate is what you
pay LLM latency and cost on, so measure it.

## Calibration caveats

* The **English** checkpoint is temperature-calibrated. **`multilingual`** ships uncalibrated
  (temperature 1.0): it reports 100%/0% readily — don't read those as certainty — and it missed
  explicit cancellation threats the English checkpoint caught.
* Ordinal `score` questions are the **weakest** type out of the box.
* Zero-shot quality varies by task: simple classification is strong (93% news-topic, 96% SMS spam),
  subtle/graded ones are not (35% five-level star rating).
* Measure before shipping: run 50–200 real examples, record accuracy per question and how often the top
  probability clears your threshold and is right when it does.

## `hx drive` — terminal control

`hx drive <task.json>` runs the loop: sense the last N lines of a tmux pane → ask the sidecar one
question set → press the winning action's keys (`tmux send-keys`) → repeat until the done question
fires, the gate escalates too many times in a row, or `max_steps` is hit.

```json
{
  "tmux": { "target": "hx-ops", "lines": 40 },
  "actions": { "confirm": "y Enter", "decline": "n Enter", "wait": null },
  "questions": {
    "step_pending":  { "type": "noul", "instructions": "A runbook step waits for a yes or no keypress." },
    "mentions_delete": { "type": "noul", "instructions": "The pending step's text asks to drop, delete, destroy, wipe, or recreate a database or volume." },
    "finished":      { "type": "noul", "instructions": "The pane shows RUNBOOK COMPLETE or DECLINED and a shell prompt." }
  },
  "action_question": "step_pending",
  "on_true": "confirm", "on_false": "wait",
  "guard_question": "mentions_delete", "guard_action": "decline", "guard_threshold": 0.8,
  "done_question": "finished", "done_threshold": 0.8,
  "threshold": 0.7, "tick_ms": 800, "max_steps": 40, "max_escalations": 3
}
```

* `actions` maps action ids to tmux keyspecs (`"y Enter"`, `"C-c"`); `null` means press nothing.
  Interactive prompts often line-buffer — send `y Enter`, not `y`.
* `action_question` may be a `choice` (winner's option id runs) or a `noul` (confident side runs
  `on_true`/`on_false`; an ambiguous middle escalates). Binary nouls read much sharper than
  two-option choices — prefer them.
* `guard_question` + `guard_action` + `guard_threshold`: a veto checked before the action answer
  each tick — when P(guard) clears its threshold the guard action runs *instead of* the model's
  pick. This is the deny-list layer: a confident-but-wrong pick cannot override it.
* `done_question`/`done_threshold`: a noul that ends the drive early when the program exits.
* `threshold`/`min_confidence`/`tick_ms`/`max_steps`/`max_escalations` bound the loop; the last
  escalation stops the drive rather than guessing.

Two worked specs ship in `examples/laya-drive/` (`ops-console` — a runbook whose destructive step
gets vetoed; `git-add-p` — stage hunks but skip ones adding secrets), with the live traces in
TESTING.md. What they teach:

* **Keep the sense window tight** (`lines`: 10–20). Scrollback dilutes every question — a veto that
  reads 0.80 on the live hunk can fall to 0.63 under a screen of history, and a done question can
  misfire on an old prompt line. Aim the window at where the live decision text sits.
* **Quote the literal prompt shape** in questions. "A shell prompt ending in a dollar sign"
  separates cleanly where "the program finished" does not — the model reads scrollback, not just
  the last line, so name the visible cue.
* **Veto phrasing is mention-detection, not judgment.** "asks to drop, delete, destroy…" scored
  0.87 where "permanently destroys data" scored 0.22 on the same screen.
* **CPU is too slow for real-time games.** At ~0.5–1.5 s/tick, prompt-driven and turn-based
  programs drive correctly; moon-buggy crashes on the first crater while `obstacle_ahead` can't
  read ASCII art. Frame-rate play needs the GPU path and a prose state encoder.

## `hx drive` on the desktop — GUI control

The same loop drives real windows: instead of a pane's text, each tick senses the app's
**accessibility tree** (AT-SPI) — every actionable widget as `[e3] push button 'Save' at
(728,579)` plus readable labels — and acts through **xdotool** (`mousemove`/`click`/`type`/`key`),
i.e. a real mouse and keyboard. `hx` never embeds Python: the sense helper is a small pyatspi
script (`apps/hx/src/atspi_sense.py`, materialized to the cache dir on first run), same pattern
as the sidecar.

```jsonc
{
  "gui": { "app": "kwrite", "max_elements": 24, "coord_scale": 2.0 },
  "actions": {
    "click_save": "click:Save",
    "close_doc": "ctrl+w",
    "wait": null
  },
  "questions": {
    "save_dialog":    { "type": "noul", "instructions": "A dialog offers 'Save', 'Discard' and 'Cancel' — the document wants to be saved or discarded before closing." },
    "document_gone":  { "type": "noul", "instructions": "The document 'gui-demo.txt' is no longer open." }
  },
  "action_question": "save_dialog", "on_true": "click_save", "on_false": "close_doc",
  "done_question": "document_gone", "done_threshold": 0.6,
  "threshold": 0.6, "tick_ms": 800, "max_steps": 10
}
```

* `gui.app` is a substring of the app's a11y name; the window is raised (`wmctrl -a`) at start.
  `coord_scale` converts a11y logical pixels to real display pixels (2.0 on 200%-scaled desktops).
* Bindings: `click:<name>` clicks the element whose a11y name matches — **last** match wins
  (modal dialogs append after toolbars, so `'Save'` resolves to the dialog's button);
  `text:<s>` types; `seq:a|b|c` runs a chord (click to focus → type); a bare keyspec goes to
  `xdotool key`; `e<N>` clicks element N's centre; `null` waits.
* Apps must launch with accessibility on: `QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 QT_ACCESSIBILITY=1`
  and a live at-spi bus (`DBUS_SESSION_BUS_ADDRESS`, `/usr/libexec/at-spi-bus-launcher`).

What the live suite taught (all runs on this box, kwrite/kcalc on a 3200×2400 KDE desktop):

* **The reactive shape is the one that works**: a noul detects the *state* ("a dialog offers
  'Save', 'Discard' and 'Cancel'" — 0.93 when up), and the two bound actions cover both worlds —
  e.g. "menu open?" → `click:Save As...` : `click:File` walks open-menu→pick-item across ticks.
  The `kwrite-close-save` spec ran dialog-detect→click-Save→document-gone→done in 3.2 s and the
  file hit disk.
* **Detection beats intention**: ask what IS on screen, not what SHOULD happen. Forward
  statements score sharply ("the document mentions X" → 0.05 false / 0.81 true); negations
  ("does not contain") collapse to ~0 — invert the noul so detection is the true side.
* **A choice across screen elements does not plan**: 'pick which button next' across calculator
  keys stays under 0.55 with a persistent `AC`-then-`=` bias regardless of history — multi-step
  sequencing is out of 322M's reach (same ceiling as real-time games). The drive escalates
  instead of clicking wrong — safe failure.
* **Only SHOWING widgets are offered** — Qt pre-creates menu items offscreen; without the
  SHOWING-state filter a closed menu looks open.
* **Hidden state traps**: windows stacked under others take stale clicks — click-to-focus raises
  whatever's topmost at the point, which is why the drive raises the target app at start.
* **Sense filters keep the state small**: `gui.window` restricts sensing to frames whose name
  contains it (e.g. `"Save File"` — the save dialog subtree, ~11 elements instead of ~70);
  while no such frame exists the whole app is sensed, so a stage aimed at a dialog still sees
  the toolbar before it opens and the editor after it closes. `gui.skip_roles` drops uniform
  grid roles (`["table cell", "list item"]`) so a file chooser's rows don't eat the element
  cap. The model degrades on long states — a save dialog unfiltered is ~70 elements and
  pushes the 512-token state past `truncated_questions`.

### Multi-phase tasks — `stages`

A single `action_question`/`done_question` pair is one reactive loop. `stages` composes
several in order — each stage runs its own sense→decide→act drive and ends when its
`done_question` clears; the next starts on the state it left behind. The model still makes
every decision — stages compose reactive steps, they do not plan. Every field except
`action_question` falls back to the task-level value; middle stages must declare their own
`done_question` (the last may inherit the task's).

```jsonc
"stages": [
  // type text into a fresh document until it's in the buffer
  { "action_question": "has_greeting", "on_true": "wait", "on_false": "type_greeting",
    "done_question": "has_greeting", "done_threshold": 0.5 },
  // no save dialog yet? click 'Save As...'; stop when it is up
  { "action_question": "chooser", "on_true": "wait", "on_false": "open_saveas",
    "done_question": "chooser", "done_threshold": 0.7, "window": "Save File" },
  // dialog up → fill the name field and click Save; stop when the title flips
  { "action_question": "chooser", "on_true": "fill_and_save", "on_false": "wait",
    "done_question": "named_doc", "done_threshold": 0.6, "window": "Save File" }
]
```

`examples/laya-drive/kwrite-save-as.task.json` runs this end-to-end on a real desktop —
type → Save As → fill Name → click Save — five GUI states, 6 steps, ~12 s, and the file
lands on disk.

What tuning it taught:

* **Detection only separates on unique tokens**. Laya does lexical presence-matching: a
  question's phrasing overlaps the menubar/statusbar words, so "is the File menu open"
  reads ~0.7 on both states. Signals that split cleanly name a widget that exists in
  exactly one state — `'Parent Directory'` (0.52 closed / 0.87 dialog), `'Discard'`
  (0.31 / 0.86), the saved doc's title (0.89). Nothing in a spec should hinge on verbs
  like "open"/"closed" — the drop-down marker the sensor emits (`drop-down menu under
  File is open:`) helps the human reading the trace, but the model still keys on the
  unique item names.
* **The same question can drive opposite stages** — `chooser` is "open the dialog" in
  stage 2 (fire when absent) and "fill it" in stage 3 (fire when present): noul sides
  do the inverting, no new phrasing needed.
* **`seq:` resolves against the sensed table at fire time** — a chord like
  `click:File name:|ctrl+a|text:devin-note.txt|click:Save` is deterministic inside the
  tick; the model only decides whether to fire it. Multi-tick sequencing across element
  picks stays out of reach (the kcalc ceiling), but a chord covering click→select→type
  →click is fine because every binding lands on a name that exists in one state only.
* **Batched decode shifts probabilities ~0.18** vs single-question probes — probe to find
  which phrasings separate, then set thresholds from live ticks, not the probe numbers.

## The OSWorld-adapted queue — `examples/laya-drive/queue/`

Ten tasks shaped like OSWorld's own harness — a `setup.sh` fixture, the `hx drive`
agent phase, and a `verify.sh` execution check that reads the filesystem (never the
agent's claim). `run_queue.py` runs them in order and writes `scorecard.md`.

Latest full run: **10/10 verified** (9 ended `done`, one ended `stopped` but still
passed verify — a conservative done-read, not a task failure). Per-task logs sit next
to each spec. See TESTING.md for the scorecard.

What the queue taught — the hard-won spec rules:

* **Claim on the CURRENT state, not the goal state.** "the last line is plain
  `gamma`" / "the command `failed.ipynb` is visible in the terminal" separates far
  better than "the edit is applied" — goal-state claims invite confabulation ~0.5–0.7
  on unedited screens. Action question = "the work still needs doing" → `on_true` fires
  the work, `on_false` waits.
* **`warmup: 1`** (task or per-stage) skips the done check until an action has fired —
  kills tick-0 "done" reads on blank screens (observed 0.82 on a fresh prompt).
* **Markers must differ from their own command text.** `echo ==BENCH-DO""NE==` renders
  as `==BENCH-DONE==` in output but the typed line visibly contains `DO""NE` — a marker
  that literally appears inside its own `echo` command confabulates "it printed".
  Better still: phrase done on *prompt-below-output* — "a new `ubuntu@devin-box`
  prompt sits below the command's output" — because the prompt always returns, even on
  error, while `&&`-chained markers don't.
* **Window titles and tab labels are the best anchors.** The sensor now emits
  `window titled '<frame name>'` lines: KWrite's `br-doc.txt *` dirty marker and
  Konsole's `bench : nano` program label are states the model can actually verify —
  `'GNU nano'` as text was unreadable (0.5–0.6 both ways) but `: nano` in the title
  split cleanly.
* **The terminal text is head+tail, not a scrollback.** Konsole's a11y buffer only
  exposes the visible screen — and its first ~80 chars used to cut the output line off
  entirely. The sensor reads the last 600 chars and shows head 110 + tail 110 joined
  with `…` — enough for prompt-return detection and app banners (`GNU nano`, TUI
  status bars like nano's `^X Exit`).
* **Idempotent `seq:` beats a fragile gate.** For the nano save, `seq:ctrl+o|Return`
  re-firing harmlessly (re-save is a no-op) mattered more than detecting "already
  written" — when a claim can't separate, make the action safe to repeat and let the
  done-check own the truth.
* **File pickers flood the element cap head-first.** The dialog's ~40 file rows eat
  `max_elements` before `File name:`/`Save` are ever sensed — `skip_roles:
  ["table cell","list item"]` keeps the controls reachable (used in save-as and the
  chooser stages).
* **`text:` goes to whichever window has focus** — launch apps with the a11y env in
  `setup.sh` and wait for the window (`wmctrl -l | grep`) before driving; a spec
  racing a not-yet-open app confabulates "already sent" on an empty screen.

## How it fits hx

* `crates/hx-decision` — typed question/answer schema + `LayaClient` (HTTP to the sidecar).
* `crates/hx-core` — `decision` module: threshold/cascade gate over the typed answers.
* `apps/hx` `hx decision` — CLI: point it at a running sidecar, load a question set, print typed
  answers + probabilities + whether each cleared a threshold.
* `hx doctor` — Laya probe: if `HX_LAYA_URL` (or the config default) is set, probe `/health`;
  skip gracefully when unset.

## Cross-app research task (news-research)

`queue/news-research/` — a 5-stage research drive: search HN front page → fetch
top story + comments into `/tmp/digest.txt` → switch to KWrite and type the
digest → `ctrl+s` → shell-side `[ -s file ] && echo marker` verify. It found
three drive bugs and taught four spec rules:

- **Terminal text lives in the whole visible buffer, not the first 600 chars.**
  `getText(0, 600)` read only the top of the screen — a marker/prompt past
  offset 600 was invisible and every done check stalled. The sensor now pulls
  `characterCount` (bounded at 4000) before head+tail trimming.
- **Markers must be per-stage distinct.** Stage 2's done check fired on
  stage 1's `==BENCH-DONE==` still on screen — stale markers satisfy
  identical claims. Use `==NEWS1-DONE==`, `==NEWS2-DONE==`, …
- **`actions already taken:` history shifts probabilities ~0.1.** A done claim
  at 0.72 bare read 0.62 with the prefix — tune thresholds with the prefix in
  place, and prefer presence claims over absence ("title ends with X").
- **Stage app-switch needs a raise.** `app` on a stage now re-scopes the sense
  AND runs `wmctrl -a` — without it, `click:` lands on whatever's topmost
  (the digest was once typed into the konsole prompt instead of the doc).
- **`typefile:<path>`** types a file's current contents — the mechanism that
  lets a fetch stage hand live findings to a write stage. Newlines land via
  real Return presses; a `--` guard keeps `-`-leading lines out of xdotool's
  option parser.
- **Deterministic-save pattern**: fire the idempotent action every tick
  (`ctrl+s` on both sides) so one real save always lands before done can
  fire, then let a shell `[ -s file ] && echo marker` stage vouch — the
  filesystem answers the question the title can't.

Result: 18 steps, ~3 min — live HN front page searched, top story + comments
fetched, digest written into KWrite, saved, marker-verified.

## Containerized browser (fox-nyt-nav)

`queue/fox-nyt-nav/` — a 4-stage drive against **nytimes.com, which 403s
curl**, running in `examples/laya-drive/kasm-fox` — a Kasm-style container:
firefox-esr in debian on the host X server + a11y bus. `hx drive` senses and
clicks it exactly like a local app; see the image README for the docker run
recipe and the `xprop -root AT_SPI_BUS` socket discovery (the a11y bus is not
the session bus — the session bus is AppArmor-mediated and rejects the
container). Stages: `ctrl+l|type|Return` to the homepage → **choice pick of a
headline link** → Back → Forward. Verify greps the live a11y tree for an
article tab/doc pair that is not the homepage.

Findings that earned new spec machinery:

- **The model's real ceiling is a ~512-token state budget, not option count.**
  Sidecar `/predict` responses carry `state_tokens_dropped` + a
  `truncated_questions` list — at ~85 options the criteria dict was clipped
  mid-range and the article links were literally invisible to the model
  (it had ranked `go_back` because it could only see bound actions). Probe
  with the real option list before blaming phrasing.
- **`pick_roles`** (gui spec) — restricts choice options to element roles;
  `["link"]` on a news page drops buttons/paragraphs.
- **`pick_min_len`** (gui spec) — restricts options to names ≥ N chars; on a
  news page the story links are the long-named ones and the one-word nav
  items drop out, taking the criteria under the token clip.
- **`choice_actions`** (stage spec) — whitelist of bound action ids offered
  alongside element picks. Bound ops read as verbs and outbid element ids
  (`go_back` beat `e66` at 0.57 vs 0.30); offer only `["scroll_down","wait"]`
  during a pick stage.
- **Pick-any tasks split the vote.** Six equivalent headline candidates put
  the top pick at ~0.30 — below the 0.45 gate but perfectly correct. Threshold
  for "pick any" stages belongs at ~0.18, not ~0.5.
- **`click_roles`** (gui spec) — extra roles offered as click targets when a
  page exposes tappable text (`paragraph`/`static`) instead of link elements;
  NYT doesn't need it (headlines are named `link` nodes once maximized) but
  it's available for sites that don't expose anchors.
- **`click:` names fall back to substring match** — Firefox renames the
  address bar per page ('Search or enter address' → 'Search with Google or
  enter address'); exact-match died on the rename, so matching degrades to a
  shared-substring lookup. Prefer `ctrl+l` for the address bar anyway.
- **Maximize the container window** — article links stay virtual/not-SHOWING
  (zero extents, dropped by the sensor) until rendered; a maximized viewport
  renders ~6 headline links on the NYT homepage.
- **Container setup needs an a11y-registration wait** — the window appears in
  `wmctrl -l` seconds before its tree registers; a tick-0 empty sense makes
  the model fire actions at a lookup table of zero.
- Fresh profiles open **Welcome + Privacy Notice tabs** — denylist them in
  verify scripts or they false-positive "not homepage" checks.
