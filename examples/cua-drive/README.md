# cua-drive — computer use on the trycua sandbox

A thin computer-use loop built on the [trycua/cua](https://github.com/trycua/cua)
SDK: the sandbox IS the kasm-style container — a full Ubuntu 24.04 desktop with
its own display, driven through the SDK's screenshot/mouse/keyboard API.
Nothing touches the host desktop (no X11 sharing, no a11y bus, no focus
stealing), which removes the biggest wart of the `hx drive` host-screen
approach.

Verified live (2026-10-08): firefox → nytimes.com → click the top headline →
scroll the article — 14 steps, ~3 min, DONE.

## Stack

- **Sandbox** — `cua.sandbox(image=Image.linux(), local=True, ephemeral=True)`.
  Ubuntu 24.04, 1280x800, firefox + chromium preinstalled. `sb.screenshot()`,
  `sb.mouse.*`, `sb.keyboard.*`, `sb.shell.run()`, `await sb.get_display_url()`
  (short-lived noVNC ticket), `cua.sandbox(on='local', name=...)` attaches a
  second client for side-channel screenshot polling.
- **Model** — `step-5-preview-free` on the keyless opencode zen endpoint
  (`127.0.0.1:8399` shim). Vision-capable, emits native `tool_calls`, uses
  absolute pixels (longcat-2.5-preview-free also works but emits 0-1000
  normalized coords — `_scale()` handles that).
- **Loop** — `cua_drive.py`: screenshot → `chat.completions` with a forced
  `computer` function tool → execute the call in the sandbox → attach a fresh
  screenshot as the tool result. Stops when the model answers in text.

We deliberately did NOT use cua's `ComputerAgent`: its `generic_vlm` loop
expects the model to emit Hermes-style `<tool_call>` text (Qwen convention),
which the free models don't produce — but they DO emit native `tool_calls`,
which this driver uses. (Their anthropic/openai/gemini CU loops are the paid
path if a real key lands.)

## Setup

```sh
python3.12 -m venv ~/cua-venv
~/cua-venv/bin/pip install 'cua[sandbox]' 'cua[agent]' qwen-agent numpy pillow \
    soundfile python-dateutil json5
# qwen_vl_utils is only needed for ComputerAgent's generic loop; our driver
# doesn't need it. If you do: it imports torch — a pure-python smart_resize
# stub in site-packages/qwen_vl_utils/__init__.py avoids the 2GB dep.

# zen shim (makes opencode.ai/zen/v1 keyless; v2 folds streamed tool_calls
# back into the completion — required for native function calling)
python3 ~/zen_shim/shim.py 8399 &
```

## Run

```sh
~/cua-venv/bin/python cua_drive.py \
  "Open Firefox, go to nytimes.com, click the top headline, scroll once." \
  --max-steps 30 --shots shots
```

`--shots` saves a screenshot per step (also a side-channel video source:
attach to the same sandbox by name and poll `sb.screenshot()` at ~1fps, then
`ffmpeg -framerate 6 -i f%04d.png`).

## Findings

- The sandbox's `keyboard.keypress()` takes a key LIST (`["alt","f4"]`), not a
  chord string — `_chord()` splits `alt+F4`/`ctrl+l` and maps aliases
  (Return→enter).
- The free models do real function calling over the zen shim, but only if the
  shim accumulates streamed `delta.tool_calls` deltas into the collapsed
  completion — first shipped shim dropped them (empty content +
  `finish_reason: tool_calls`).
- `tool_choice` forced to the `computer` function keeps the loop
  deterministic — with `auto` the model may narrate intent instead of calling.
- Generic VLMs (vs CU-tuned models) work but each step is a full API
  round-trip (~10s on zen) and coordinate guesses occasionally need a retry —
  the loop tolerates it because every action returns a fresh screenshot.
- cua's `Sandbox.ephemeral(...)` class API changed in SDK 0.4.x — use
  `cua.sandbox(image=Image.linux(), local=True, ephemeral=True)` instead.
