"""Phrase-list detectors: toxic language and denied topics.

Both work the same way: the policy supplies categories, each with a list of
phrases, and any whole-word match is reported under that category.
"""

from __future__ import annotations

from guardrail.detectors.base import Detector, phrase_pattern
from guardrail.models import Finding


class PhraseListDetector(Detector):
    name = "phrases"
    label = "phrase"

    def __init__(self, categories: dict[str, list[str]] | None = None):
        self.categories = {
            category: [(p, phrase_pattern(p)) for p in phrases]
            for category, phrases in (categories or {}).items()
        }

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for category, phrases in self.categories.items():
            for phrase, pattern in phrases:
                m = pattern.search(text)
                if m:
                    findings.append(
                        Finding(
                            detector=self.name,
                            category=category,
                            message=f"{self.label} matched: {category.replace('_', ' ')}",
                            start=m.start(),
                            end=m.end(),
                            replacement="[REMOVED]",
                        )
                    )
                    break  # one finding per category is enough
        return findings


class ToxicityDetector(PhraseListDetector):
    """Insults, threats, harassment and self-harm language."""

    name = "toxicity"
    label = "Toxic language"


class TopicDetector(PhraseListDetector):
    """Topics the application should refuse to discuss (weapons, malware, ...)."""

    name = "topics"
    label = "Denied topic"
