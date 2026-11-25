"""Core data types shared across the guardrail engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Action(str, Enum):
    """What the guardrail does with a piece of text, from least to most severe."""

    ALLOW = "allow"    # nothing found
    FLAG = "flag"      # let it through, but record the finding
    REDACT = "redact"  # mask the offending span and let the rest through
    BLOCK = "block"    # reject the whole text

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Action.ALLOW: 0, Action.FLAG: 1, Action.REDACT: 2, Action.BLOCK: 3}


class Direction(str, Enum):
    """Whether the text is going *to* the model (input) or coming *from* it (output)."""

    INPUT = "input"
    OUTPUT = "output"


@dataclass
class Finding:
    """A single issue a detector found in the text."""

    detector: str
    category: str
    message: str
    start: int | None = None          # character span, when the issue is localised
    end: int | None = None
    replacement: str | None = None    # mask to use if the span is redacted
    score: float | None = None        # confidence, for score-based detectors
    action: Action = Action.FLAG      # filled in by the engine from the policy

    def to_dict(self) -> dict:
        data = asdict(self)
        data["action"] = self.action.value
        return {k: v for k, v in data.items() if v is not None}


@dataclass
class GuardrailResult:
    """The engine's verdict on one piece of text."""

    action: Action
    direction: Direction
    text: str | None                  # sanitised text; None when blocked
    findings: list[Finding] = field(default_factory=list)
    latency_ms: float = 0.0
    policy: str = "default"

    @property
    def allowed(self) -> bool:
        return self.action is not Action.BLOCK

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "action": self.action.value,
            "direction": self.direction.value,
            "text": self.text,
            "findings": [f.to_dict() for f in self.findings],
            "latency_ms": round(self.latency_ms, 3),
            "policy": self.policy,
        }
