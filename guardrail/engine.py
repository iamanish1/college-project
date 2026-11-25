"""The guardrail engine: runs the policy's detectors and combines their findings into a verdict."""

from __future__ import annotations

import time
from pathlib import Path

from guardrail.audit import AuditLogger
from guardrail.detectors import REGISTRY, Detector
from guardrail.models import Action, Direction, Finding, GuardrailResult
from guardrail.policy import DetectorConfig, Policy


class Guardrail:
    """Checks text going to an LLM (input) or coming back from it (output).

    >>> g = Guardrail()
    >>> g.check_input("My email is jane@example.com").text
    'My email is [EMAIL]'
    """

    def __init__(self, policy: Policy | str | Path | None = None, audit_log: str | Path | None = None):
        if policy is None:
            policy = Policy.default()
        elif not isinstance(policy, Policy):
            policy = Policy.from_file(policy)
        self.policy = policy
        self.audit = AuditLogger(audit_log) if audit_log else None
        self._detectors: list[tuple[Detector, DetectorConfig]] = [
            (REGISTRY[name](**cfg.options), cfg)
            for name, cfg in policy.detectors.items()
            if cfg.enabled
        ]

    # -- public API -----------------------------------------------------------

    def check_input(self, text: str) -> GuardrailResult:
        return self.check(text, Direction.INPUT)

    def check_output(self, text: str) -> GuardrailResult:
        return self.check(text, Direction.OUTPUT)

    def check(self, text: str, direction: Direction | str = Direction.INPUT) -> GuardrailResult:
        direction = Direction(direction)
        started = time.perf_counter()

        findings: list[Finding] = []
        for detector, cfg in self._detectors:
            if direction not in cfg.applies_to:
                continue
            for finding in detector.scan(text):
                finding.action = cfg.action
                # Redaction needs a span; without one, fall back to just flagging.
                if finding.action is Action.REDACT and finding.start is None:
                    finding.action = Action.FLAG
                findings.append(finding)

        action = max((f.action for f in findings), key=lambda a: a.rank, default=Action.ALLOW)
        sanitized = None if action is Action.BLOCK else redact(text, findings)

        result = GuardrailResult(
            action=action,
            direction=direction,
            text=sanitized,
            findings=findings,
            latency_ms=(time.perf_counter() - started) * 1000,
            policy=self.policy.name,
        )
        if self.audit:
            self.audit.record(text, result)
        return result


def redact(text: str, findings: list[Finding]) -> str:
    """Replace every REDACT finding's span with its mask. Overlapping spans are merged."""
    spans = sorted(
        (f for f in findings if f.action is Action.REDACT and f.start is not None),
        key=lambda f: (f.start, -(f.end - f.start)),
    )
    out: list[str] = []
    pos = 0
    for f in spans:
        if f.start < pos:  # overlaps a span we already masked
            continue
        out.append(text[pos:f.start])
        out.append(f.replacement or "[REDACTED]")
        pos = f.end
    out.append(text[pos:])
    return "".join(out)
