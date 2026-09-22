"""Laya loopback sidecar — the documented recipe for running Laya next to hx.

hx (Rust) never embeds Python. It talks to this sidecar over loopback HTTP,
and this sidecar is the only process that imports ``laya``.

Run it::

    pip install laya fastapi uvicorn
    # one-time weights download (cached under $HF_HOME / ~/.cache/huggingface)
    python -c "from laya import download_weights; download_weights()"
    uvicorn laya-sidecar:app --host 127.0.0.1 --port 8770

Contract (this is what ``hx-decision``'s ``LayaClient`` speaks):

* ``GET /health``  -> ``{"ok": true, "model": "<id>"}``
* ``POST /predict`` with body ``{"state": "<text>", "questions": {...}}``
  -> the agent's ``predict`` result as JSON (answers carry probabilities,
  confidence, and ``action.act_probability``; the result carries
  ``usage.input_tokens``).

Concurrency: the agent is loaded **once** at startup and shared behind a
single ``threading.Lock``. Every ``predict`` takes *all* questions in one
forward pass — never loop one-question-per-request; that throws away the
batching Laya is built for and multiplies latency.

The two lines marked ADAPTER below are the only ones tied to the upstream
``laya`` repo layout (mirroring its ``server.py``). If the package API
moves, only those lines change; the HTTP contract above stays fixed.
"""

from __future__ import annotations

import os
import threading

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# --- ADAPTER: mirrors upstream laya server.py --------------------------------
# Upstream publishes the model + a playground via `python server.py`.
# Import the agent class from wherever that server gets it and construct it
# once here. Exact names follow the laya repo; adjust to match the release
# you installed.
try:
    from laya import LayaAgent  # type: ignore  # ADAPTER: import path

    _AGENT = LayaAgent()  # ADAPTER: construction / weights dir / device
    _MODEL_ID = type(_AGENT).__name__
except Exception as exc:  # pragma: no cover - import-time, no sidecar without it
    raise RuntimeError(
        "Could not construct LayaAgent. Install with `pip install laya`, "
        "download the weights once, and check the ADAPTER lines in this file "
        "against the laya release you installed."
    ) from exc
# -----------------------------------------------------------------------------

_lock = threading.Lock()

app = FastAPI(title="laya-sidecar")


class PredictRequest(BaseModel):
    state: str = Field(description="The text state the questions are about")
    questions: dict = Field(
        description="Question set keyed by id: choice/score/noul, per docs/laya.md"
    )


@app.get("/health")
def health() -> dict:
    return {"ok": True, "model": _MODEL_ID}


@app.post("/predict")
def predict(req: PredictRequest) -> dict:
    if not req.state:
        raise HTTPException(status_code=422, detail="state must not be empty")
    if not req.questions:
        raise HTTPException(status_code=422, detail="questions must not be empty")
    # One shared agent, one lock: the model is not re-entrant, and batching
    # all questions into this single call is the whole point of the API.
    with _lock:
        try:
            result = _AGENT.predict(req.state, req.questions)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"predict failed: {exc}") from exc
    if hasattr(result, "model_dump"):
        return result.model_dump()
    if hasattr(result, "dict"):
        return result.dict()
    if isinstance(result, dict):
        return result
    raise HTTPException(
        status_code=500, detail=f"unexpected predict result type: {type(result)}"
    )


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("LAYA_HOST", "127.0.0.1"),
        port=int(os.environ.get("LAYA_PORT", "8770")),
    )
