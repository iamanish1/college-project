"""Policy loading: which detectors run, on which direction, and what action they trigger."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from guardrail.models import Action, Direction

_RESERVED = {"enabled", "action", "applies_to"}


@dataclass
class DetectorConfig:
    enabled: bool = True
    action: Action = Action.BLOCK
    applies_to: tuple[Direction, ...] = (Direction.INPUT, Direction.OUTPUT)
    options: dict = field(default_factory=dict)  # passed to the detector's constructor

    @classmethod
    def from_dict(cls, raw: dict | None) -> DetectorConfig:
        raw = dict(raw or {})
        applies_to = raw.get("applies_to", ["input", "output"])
        if isinstance(applies_to, str):
            applies_to = [applies_to]
        return cls(
            enabled=bool(raw.get("enabled", True)),
            action=Action(raw.get("action", "block")),
            applies_to=tuple(Direction(d) for d in applies_to),
            options={k: v for k, v in raw.items() if k not in _RESERVED},
        )


@dataclass
class Policy:
    name: str
    detectors: dict[str, DetectorConfig]

    @classmethod
    def from_dict(cls, raw: dict) -> Policy:
        from guardrail.detectors import REGISTRY

        detectors = {}
        for det_name, det_raw in (raw.get("detectors") or {}).items():
            if det_name not in REGISTRY:
                raise ValueError(f"Unknown detector '{det_name}'. Known: {sorted(REGISTRY)}")
            detectors[det_name] = DetectorConfig.from_dict(det_raw)
        return cls(name=raw.get("name", "custom"), detectors=detectors)

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})

    @classmethod
    def default(cls) -> Policy:
        text = resources.files("guardrail").joinpath("policies/default.yaml").read_text(encoding="utf-8")
        return cls.from_dict(yaml.safe_load(text))
