"""Detector registry: maps the names used in policy files to detector classes."""

from guardrail.detectors.base import Detector
from guardrail.detectors.injection import PromptInjectionDetector
from guardrail.detectors.keywords import TopicDetector, ToxicityDetector
from guardrail.detectors.length import LengthDetector
from guardrail.detectors.pii import PIIDetector
from guardrail.detectors.secrets import SecretsDetector

REGISTRY: dict[str, type[Detector]] = {
    cls.name: cls
    for cls in (
        LengthDetector,
        PromptInjectionDetector,
        SecretsDetector,
        PIIDetector,
        ToxicityDetector,
        TopicDetector,
    )
}

__all__ = [
    "REGISTRY",
    "Detector",
    "LengthDetector",
    "PIIDetector",
    "PromptInjectionDetector",
    "SecretsDetector",
    "TopicDetector",
    "ToxicityDetector",
]
