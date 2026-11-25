"""Base class and helpers for detectors."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from guardrail.models import Finding


class Detector(ABC):
    """A detector scans text and returns zero or more findings.

    Detectors only *find* problems. Deciding what to do about them
    (allow / flag / redact / block) is the policy's job, handled by the engine.
    """

    name: str = "base"

    @abstractmethod
    def scan(self, text: str) -> list[Finding]:
        raise NotImplementedError


def phrase_pattern(phrase: str) -> re.Pattern[str]:
    """Compile a case-insensitive, whole-word pattern for a phrase.

    Any run of whitespace in the phrase matches any run of whitespace in the
    text, so "build  a\\nbomb" still matches "build a bomb".
    """
    words = [re.escape(w) for w in phrase.split()]
    return re.compile(r"\b" + r"\s+".join(words) + r"\b", re.IGNORECASE)
