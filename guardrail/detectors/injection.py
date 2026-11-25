"""Heuristic prompt-injection / jailbreak detection.

Each rule that matches adds its weight to a risk score (capped at 1.0). If the
score reaches the threshold, the text is reported. Weighted rules let several
weak signals add up while a single strong signal is enough on its own.
"""

from __future__ import annotations

import re
import unicodedata

from guardrail.detectors.base import Detector
from guardrail.models import Finding

# (rule name, weight, pattern)
INJECTION_RULES: list[tuple[str, float, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        0.9,
        re.compile(
            r"\b(?:ignore|disregard|forget|skip|override)\b.{0,30}?"
            r"\b(?:previous|prior|above|earlier|all|any|your|the|system)\b.{0,20}?"
            r"\b(?:instructions?|prompts?|rules|directions|guidelines|context)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "reveal_system_prompt",
        0.8,
        re.compile(
            r"\b(?:reveal|show|print|repeat|leak|output|tell me|what (?:is|are))\b.{0,30}?"
            r"\b(?:system prompt|hidden (?:prompt|instructions)|initial (?:prompt|instructions)"
            r"|your (?:instructions|rules|prompt))\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "persona_override",
        0.6,
        re.compile(
            r"\b(?:you are now|from now on,? you are|act as|pretend (?:to be|you are)|roleplay as)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "no_restrictions",
        0.5,
        re.compile(
            r"\b(?:no|without|free of|ignore (?:all|any|your))\b.{0,15}?"
            r"\b(?:restrictions|limits|limitations|filters|rules|guidelines|censorship)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "jailbreak_keywords",
        0.6,
        re.compile(r"\b(?:DAN|do anything now|jailbreak(?:ed)?|developer mode|god mode)\b", re.IGNORECASE),
    ),
    (
        "bypass_safety",
        0.7,
        re.compile(
            r"\b(?:bypass|disable|turn off|circumvent|evade)\b.{0,20}?"
            r"\b(?:safety|guardrails?|filters?|moderation|content policy)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "fake_role_marker",
        0.5,
        re.compile(r"(?:</?system>|\[/?system\]|^#{2,}\s*system\s*:|<\|im_start\|>)", re.IGNORECASE | re.MULTILINE),
    ),
]

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿"))


def normalize(text: str) -> str:
    """Undo common obfuscation: full-width/stylised letters and zero-width characters."""
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


class PromptInjectionDetector(Detector):
    """Flags attempts to override the model's instructions or extract its system prompt."""

    name = "prompt_injection"

    def __init__(self, threshold: float = 0.7):
        if not 0 < threshold <= 1:
            raise ValueError("threshold must be in (0, 1]")
        self.threshold = threshold

    def score(self, text: str) -> tuple[float, list[str]]:
        clean = normalize(text)
        matched = [name for name, _, pattern in INJECTION_RULES if pattern.search(clean)]
        weights = {name: w for name, w, _ in INJECTION_RULES}
        total = min(1.0, sum(weights[n] for n in matched))
        return total, matched

    def scan(self, text: str) -> list[Finding]:
        total, matched = self.score(text)
        if total < self.threshold:
            return []
        return [
            Finding(
                detector=self.name,
                category="prompt_injection",
                message=f"Prompt injection suspected (rules: {', '.join(matched)})",
                score=round(total, 2),
            )
        ]
