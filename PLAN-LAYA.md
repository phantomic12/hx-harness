# Laya computer-use / decision milestone

## Context

Laya (https://brainfunctioncollapse.com/laya) is the open-source (Apache-2.0) alternative to
TypeSafe Jev: a 322M-param, non-autoregressive "System 1" decision model. It answers **typed
questions** about a piece of text and returns **probabilities**, never generated text. Runs on your own
machine, ~21-35 ms per decision, $0, offline.

- Model server + games + benchmark live in one Python repo. `pip install laya`, then `python
  server.py` serves `http://127.0.0.1:8770/playground`.
- **Non-Python integration is a small HTTP sidecar** (FastAPI) over loopback `127.0.0.1`:
  `POST /predict` with body `{"state": ..., "questions": {...}}` → returns agent `predict` result as JSON.
- The three question types:
  - `choice` — criteria = dict/option list → `answers[id] = {choice, probabilities, confidence}`
  - `score` — criteria = ordered level list → `answers[id] = {score, probabilities, legend, confidence}`
  - `noul` — optional true/false criteria → `answers[id] = {noul: P(true), confidence}`
  - every answer also has `action.act_probability`; `usage.input_tokens` on the result.
- Every `predict` requests all questions in one forward pass (do not loop).

This repo (hx-harness) is **Rust**. We integrate Laya as a **local runtime helper** that talks to
the Python sidecar. `reqwest` is already a workspace dep (vendored, offline-available) so a sidecar
client needs no new crate in the graph.

## What we are building (this milestone)

A new crate `hx-decision` (or an `hx-core` module — see decision below) providing:

1. **Typed question schema** mirrored from Laya: `Question::{Choice, Score, Noul}` with criteria
   types, plus a `Result`/`Answer` set (probabilities, confidence, choice/score/noul).
2. **Sidecar client** (`LayaClient`) over loopback HTTP: `new(base_url)`, `predict(state,
   &[Question]) -> LayaResult`. Uses `reqwest` (reuse workspace dep). `POST /predict`. Strong
   typing on the JSON round-trip; no new deps.
3. **Health/probe**: `LayaClient::health()` / a `probe()` that checks the sidecar answers a
   representative question → used by `hx doctor` and as a first-rung guard.
4. **Decision helper** (`hx-core`) that consumes the client: given a text state + a question set,
   returns a typed decision and whether confidence cleared a threshold. This is the "slots in as an
   hx-core decision helper" line from ROADMAP.
5. **CLI surface** in `apps/hx`: `hx decision` subcommand that talks to a running sidecar
   (`--url http://127.0.0.1:8770`), loads a question set from a small YAML/JSON, prints typed
   answers + probabilities.
6. **Docs**: `docs/laya.md` (how to run the sidecar, wire it, thresholds, traps), and a ROADMAP.md
   update moving the entry out of "deliberately deferred" into a "built" milestone with honest
   verification notes.
7. **Tests** throughout; mark anything not locally runnable (needs the Python sidecar) with a
   `#[ignore]`/skip guard + a documented live test, so the offline CI gate stays green.

### Scope decisions (agreed)

- Python sidecar is a **host component**, not vendored here. We talk to it over HTTP; we do not
  embed Python. The crate ships a documented sidecar recipe + `examples/sidecar.py`.
- The `hx-browser` rung / `hx-core` decision helper per ROADMAP: we implement the **decision
  helper in `hx-core`** (no screen/Vision here — "computer use" via screen input is not in this
  milestone; we build the decision substrate Laya provides). A follow-up milestone adds the browser/OS
  rung that uses it.
- Keep it self-contained, minimal deps, $0.

## Repository locations

- Rust workspace root: `/home/yoav/projects/hx-harness` (main, HEAD `58437db`).
- Tests must run with `cargo test --workspace --offline` (offline gate).
- Existing relevant crates: `crates/hx-core` (error, api_auth, capability, pool, ids —
  `HxError`, `Result`), `crates/hx-browser` (rung ladder; reqwest usage), `apps/hx` (CLI, doctor).

## Reference: existing HxError / patterns

- `hx_core::error::{HxError, Result}`. Errors are `HxError::...` variants (e.g. `TooLarge`).
  New remote-call errors should map onto existing variants or a documented new one.
- `apps/hx/src/doctor.rs` runs self-checks — add a Laya probe there if a sidecar is configured.
- Offline gate: no crates.io fetches. Use only already-vendored deps (reqwest, serde, serde_json,
  tokio are all workspace deps).

## Team (subagents) — one per chunk

- S1 `hx-decision` crate scaffold: Cargo.toml + typed question/answer schema + serde + unit tests.
- S2 `LayaClient` HTTP sidecar transport (reqwest POST /predict, health, error mapping) + unit tests
  with a mock sidecar (axum/hyper or a local TCP listener) so no Python needed.
- S3 decision helper in `hx-core` (consume client, threshold confidence, cascade decision) + tests.
- S4 `apps/hx` `decision` CLI subcommand + doctor Laya probe + docs example.
- S5 docs + `examples/sidecar.py` + ROADMAP.md update + `docs/laya.md` + wire everything together
  and run the full offline test gate.
