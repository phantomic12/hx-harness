#!/usr/bin/env python3
"""cua-drive — computer-use loop on top of the trycua SDK sandbox.

The sandbox (cua.sandbox, local ephemeral Linux image) is the kasm-style
container: a full Ubuntu 24.04 desktop with its own display, driven through
the SDK's screenshot/mouse/keyboard API — nothing on the host screen.

The loop itself is intentionally thin: screenshot -> chat.completions with a
`computer` function tool (forced) -> execute the call inside the sandbox ->
feed the new screenshot back as the tool result. The model loop stops when
the model emits text instead of a tool call, or says done.

Model endpoint: the local zen shim (127.0.0.1:8399), which makes
opencode.ai/zen/v1 work keyless. step-5-preview-free is the default: it is
vision-capable and emits absolute pixel coordinates.

Usage:
    python3 cua_drive.py "task description" [--model step-5-preview-free]
                                            [--max-steps 40] [--shots dir]
"""
import argparse
import asyncio
import base64
import json
import sys
import time
import urllib.request

SHIM = "http://127.0.0.1:8399/v1/chat/completions"

COMPUTER_TOOL = {
    "type": "function",
    "function": {
        "name": "computer",
        "description": (
            "Operate a desktop GUI with mouse and keyboard. The screen is "
            "1280x800 pixels; coordinates are absolute pixels. Actions:\n"
            "- left_click / double_click / right_click / middle_click at "
            "coordinate [x,y]\n"
            "- mouse_move to coordinate\n"
            "- left_click_drag from coordinate to end_coordinate\n"
            "- scroll at coordinate with scroll_y (negative = down, positive = up)\n"
            "- type: type `text`\n"
            "- key: press key chord in `text`, e.g. 'ctrl+l', 'Return', 'Tab'\n"
            "- wait: wait `ms` milliseconds\n"
            "- screenshot: take a fresh screenshot"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "left_click", "double_click", "right_click",
                        "middle_click", "mouse_move", "left_click_drag",
                        "scroll", "type", "key", "wait", "screenshot",
                    ],
                },
                "coordinate": {
                    "type": "array",
                    "items": {"type": "number"},
                    "description": "[x, y] absolute pixels",
                },
                "end_coordinate": {
                    "type": "array",
                    "items": {"type": "number"},
                },
                "text": {"type": "string"},
                "scroll_y": {"type": "number"},
                "ms": {"type": "number"},
            },
            "required": ["action"],
        },
    },
}

SYSTEM = (
    "You are a computer-use agent operating a real Linux desktop. You receive "
    "screenshots and must drive the GUI with the `computer` tool to accomplish "
    "the user's task. Rules:\n"
    "- Emit exactly ONE computer tool call per turn.\n"
    "- Look at the latest screenshot before deciding; never guess coordinates "
    "blindly.\n"
    "- After an action whose result matters (open an app, load a page), take a "
    "screenshot action to observe the result.\n"
    "- When the task is complete, reply with plain text starting with 'DONE' "
    "and a one-line summary. Do not call the tool when done.\n"
    "- If you are stuck after several attempts, reply 'STUCK' with the reason."
)


def _post(body: dict) -> dict:
    req = urllib.request.Request(
        SHIM,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.load(urllib.request.urlopen(req, timeout=300))


def _b64(png: bytes) -> str:
    return base64.b64encode(png).decode()


def _scale(coord, dims=(1280, 800)):
    """Models sometimes emit normalized 0-1000 coords. If a value is out of
    screen range, rescale both axes from 1000-space to pixels."""
    if len(coord) < 2:
        return coord
    x, y = float(coord[0]), float(coord[1])
    if x > dims[0] or y > dims[1]:
        x = x / 1000.0 * dims[0]
        y = y / 1000.0 * dims[1]
    return [int(round(x)), int(round(y))]


_KEY_ALIASES = {
    "return": "enter", "esc": "escape", "pgup": "pageup", "pgdn": "pagedown",
    "del": "delete", "cmd": "meta", "win": "meta", "option": "alt",
    "control": "ctrl", " ": "space",
}


def _chord(text: str):
    """'ctrl+l' -> ['ctrl','l']; 'alt+F4' -> ['alt','f4']; 'Return' -> ['enter']."""
    parts = [p.strip().lower() for p in text.replace("-", "+").split("+") if p.strip()]
    return [_KEY_ALIASES.get(p, p) for p in parts]


async def _exec(sb, args: dict) -> str:
    """Run one computer-tool action inside the sandbox; return a short result note."""
    action = args.get("action")
    coord = _scale(args.get("coordinate") or [])
    x = int(coord[0]) if len(coord) > 0 else 0
    y = int(coord[1]) if len(coord) > 1 else 0
    text = args.get("text") or ""
    try:
        if action == "left_click":
            await sb.mouse.click(x, y)
        elif action == "double_click":
            await sb.mouse.double_click(x, y)
        elif action == "right_click":
            await sb.mouse.right_click(x, y)
        elif action == "middle_click":
            await sb.mouse.click(x, y, button="middle")
        elif action == "mouse_move":
            await sb.mouse.move(x, y)
        elif action == "left_click_drag":
            end = _scale(args.get("end_coordinate") or [])
            await sb.mouse.move(x, y)
            await sb.mouse.mouse_down(x, y)
            await sb.mouse.move(int(end[0]), int(end[1]))
            await sb.mouse.mouse_up(int(end[0]), int(end[1]))
        elif action == "scroll":
            await sb.mouse.scroll(x, y, scroll_y=int(args.get("scroll_y") or -500))
        elif action == "type":
            await sb.keyboard.type(text)
        elif action == "key":
            await sb.keyboard.keypress(_chord(text))
        elif action == "wait":
            await asyncio.sleep(min((args.get("ms") or 1000) / 1000.0, 10.0))
        elif action == "screenshot":
            pass  # fresh shot is always attached to the tool result
        else:
            return f"unknown action {action!r}"
        return f"{action} ok"
    except Exception as e:
        return f"{action} FAILED: {e}"


async def drive(task: str, model: str, max_steps: int, shots_dir: str | None):
    import cua
    from cua import Image

    log = lambda *a: print(*a, flush=True)
    async with cua.sandbox(image=Image.linux(), local=True, ephemeral=True) as sb:
        display = await sb.get_display_url()
        log(f"[sandbox up] {sb.name} display: {display}")

        async def shot_b64() -> str:
            png = await sb.screenshot()
            return _b64(png)

        async def save_shot(tag: str):
            if not shots_dir:
                return
            png = await sb.screenshot()
            p = f"{shots_dir}/{tag}.png"
            with open(p, "wb") as f:
                f.write(png)

        messages = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": [
                {"type": "text", "text": task},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{await shot_b64()}"}},
            ]},
        ]

        steps = 0
        t0 = time.time()
        while steps < max_steps:
            body = {
                "model": model,
                "stream": False,
                "max_tokens": 600,
                "tools": [COMPUTER_TOOL],
                "tool_choice": {"type": "function", "function": {"name": "computer"}},
                "messages": messages,
            }
            try:
                resp = _post(body)
            except Exception as e:
                log(f"[model error] {e}; retrying in 3s")
                await asyncio.sleep(3)
                continue
            msg = resp["choices"][0]["message"]
            calls = msg.get("tool_calls") or []
            if not calls:
                text = (msg.get("content") or "").strip()
                log(f"[final @{steps} steps {time.time()-t0:.0f}s] {text[:400]}")
                await save_shot("final")
                return text
            for tc in calls:
                fn = tc["function"]
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                steps += 1
                log(f"[{steps:02d}] {fn['name']} {json.dumps(args)[:160]}")
                note = await _exec(sb, args)
                await asyncio.sleep(0.4)  # let the UI settle
                shot = await shot_b64()
                await save_shot(f"step{steps:02d}")
                messages.append({
                    "role": "assistant",
                    "content": msg.get("content") or "",
                    "tool_calls": [tc],
                })
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": [
                        {"type": "text", "text": note},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{shot}"}},
                    ],
                })
                # keep only the last screenshot to bound tokens — drop the image
                # part entirely (an empty `url` gets a 400 upstream)
                imgs = 0
                for m in reversed(messages):
                    c = m.get("content")
                    if isinstance(c, list):
                        for p in c:
                            if p.get("type") == "image_url":
                                imgs += 1
                                if imgs > 2:
                                    c.remove(p)
                                    break
        log(f"[max steps {max_steps} reached]")
        await save_shot("maxsteps")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("task")
    ap.add_argument("--model", default="step-5-preview-free")
    ap.add_argument("--max-steps", type=int, default=40)
    ap.add_argument("--shots", default=None)
    args = ap.parse_args()
    if args.shots:
        import os
        os.makedirs(args.shots, exist_ok=True)
    asyncio.run(drive(args.task, args.model, args.max_steps, args.shots))


if __name__ == "__main__":
    main()
