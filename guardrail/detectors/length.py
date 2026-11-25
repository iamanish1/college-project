"""Rejects text that is too long (a cheap defence against prompt stuffing and cost abuse)."""

from __future__ import annotations

from guardrail.detectors.base import Detector
from guardrail.models import Finding


class LengthDetector(Detector):
    name = "length"

    def __init__(self, max_chars: int = 8000):
        if max_chars <= 0:
            raise ValueError("max_chars must be positive")
        self.max_chars = max_chars

    def scan(self, text: str) -> list[Finding]:
        if len(text) <= self.max_chars:
            return []
        return [
            Finding(
                detector=self.name,
                category="too_long",
                message=f"Text is {len(text)} characters (limit {self.max_chars})",
            )
        ]
