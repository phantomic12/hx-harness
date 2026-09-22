# Laya: a fast local decision layer for hx

Laya (<https://brainfunctioncollapse.com/laya>) is the open-source (Apache-2.0) alternative to
**TypeSafe Jev**: a 322M-param, non-autoregressive "System 1" decision model. It answers
**typed questions** about a piece of text and returns **probabilities** — never generated text — in
roughly 21–35 ms on a laptop GPU, $0, fully offline, with your data going nowhere.

hx integrates Laya as a **local runtime helper**. hx is Rust and never embeds Python; it talks to a
small loopback HTTP **sidecar** (the only process that imports `laya`). The Rust side is
`crates/hx-decision` (typed schema + `LayaClient`), the CLI surface is `hx decision`, and the
self-check is the `hx doctor` Laya probe.

> Milestone scope: this is the **decision substrate**. Laya is *not* yet wired as a screen/browser
> rung — that is the documented follow-up (see ROADMAP). This milestone gives you a typed decision layer in
> front of LLMs and a CLI to drive it.

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

## How it fits hx

* `crates/hx-decision` — typed question/answer schema + `LayaClient` (HTTP to the sidecar).
* `crates/hx-core` — `decision` module: threshold/cascade gate over the typed answers.
* `apps/hx` `hx decision` — CLI: point it at a running sidecar, load a question set, print typed
  answers + probabilities + whether each cleared a threshold.
* `hx doctor` — Laya probe: if `HX_LAYA_URL` (or the config default) is set, probe `/health`;
  skip gracefully when unset.
