"""REST API for the guardrail, built with FastAPI.

Run with:  guardrail serve      (or: uvicorn guardrail.api:app --reload)
Docs at:   http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import os
from importlib import resources
from typing import Literal

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from guardrail import __version__
from guardrail.engine import Guardrail

guard = Guardrail(
    policy=os.environ.get("GUARDRAIL_POLICY") or None,
    audit_log=os.environ.get("GUARDRAIL_AUDIT_LOG") or None,
)

app = FastAPI(
    title="Mini Guardrail",
    version=__version__,
    description="Policy-driven input/output safety checks for LLM applications.",
)


class CheckRequest(BaseModel):
    text: str = Field(..., max_length=100_000, examples=["My email is jane@example.com"])
    direction: Literal["input", "output"] = "input"


class FindingOut(BaseModel):
    detector: str
    category: str
    message: str
    action: str
    start: int | None = None
    end: int | None = None
    score: float | None = None


class CheckResponse(BaseModel):
    allowed: bool
    action: str
    direction: str
    text: str | None
    findings: list[FindingOut]
    latency_ms: float
    policy: str


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def playground() -> str:
    return resources.files("guardrail").joinpath("static/index.html").read_text(encoding="utf-8")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "policy": guard.policy.name}


@app.post("/v1/check", response_model=CheckResponse)
def check(req: CheckRequest) -> dict:
    return guard.check(req.text, req.direction).to_dict()


@app.get("/v1/policy")
def policy() -> dict:
    return {
        "name": guard.policy.name,
        "detectors": {
            name: {
                "enabled": cfg.enabled,
                "action": cfg.action.value,
                "applies_to": [d.value for d in cfg.applies_to],
            }
            for name, cfg in guard.policy.detectors.items()
        },
    }
