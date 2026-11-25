"""Personally identifiable information (PII) detection."""

from __future__ import annotations

import ipaddress
import re

from guardrail.detectors.base import Detector
from guardrail.models import Finding


def luhn_valid(number: str) -> bool:
    """Return True if the digit string passes the Luhn checksum used by card numbers."""
    digits = [int(d) for d in number]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _valid_card(match: str) -> bool:
    digits = re.sub(r"\D", "", match)
    return 13 <= len(digits) <= 19 and luhn_valid(digits)


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    """Return True if the digit string passes the Verhoeff checksum used by Aadhaar numbers."""
    c = 0
    for i, d in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(d)]]
    return c == 0


def _valid_aadhaar(match: str) -> bool:
    return verhoeff_valid(re.sub(r"\D", "", match))


def _valid_ip(match: str) -> bool:
    try:
        ipaddress.IPv4Address(match)
    except ValueError:
        return False
    return True


# name -> (pattern, mask, optional validator)
PII_PATTERNS: dict[str, tuple[re.Pattern[str], str, object]] = {
    "email": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[EMAIL]",
        None,
    ),
    "credit_card": (
        re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
        "[CREDIT_CARD]",
        _valid_card,
    ),
    "ssn": (
        re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        "[SSN]",
        None,
    ),
    "aadhaar": (
        re.compile(r"(?<!\d)(?<!\d[ -])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)"),
        "[AADHAAR]",
        _valid_aadhaar,
    ),
    "pan": (
        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        "[PAN]",
        None,
    ),
    "phone": (
        re.compile(
            r"(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
            r"|(?<![\w+])(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"
        ),
        "[PHONE]",
        None,
    ),
    "ip_address": (
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "[IP_ADDRESS]",
        _valid_ip,
    ),
}


class PIIDetector(Detector):
    """Finds emails, phone numbers, card numbers, government IDs and IP addresses."""

    name = "pii"

    def __init__(self, types: list[str] | None = None):
        types = types or list(PII_PATTERNS)
        unknown = set(types) - set(PII_PATTERNS)
        if unknown:
            raise ValueError(f"Unknown PII types: {sorted(unknown)}")
        self.types = types

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        taken: list[tuple[int, int]] = []  # spans already claimed by an earlier type

        for pii_type in self.types:
            pattern, mask, validator = PII_PATTERNS[pii_type]
            for m in pattern.finditer(text):
                if validator and not validator(m.group()):
                    continue
                if any(m.start() < e and s < m.end() for s, e in taken):
                    continue
                taken.append((m.start(), m.end()))
                findings.append(
                    Finding(
                        detector=self.name,
                        category=pii_type,
                        message=f"Detected {pii_type.replace('_', ' ')}",
                        start=m.start(),
                        end=m.end(),
                        replacement=mask,
                    )
                )
        return findings
