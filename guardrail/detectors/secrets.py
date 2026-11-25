"""Detection of leaked credentials: API keys, tokens and private keys."""

from __future__ import annotations

import re

from guardrail.detectors.base import Detector
from guardrail.models import Finding

# name -> pattern. If the pattern has a group named "value", only that group is
# masked (so "password=hunter22" becomes "password=[SECRET]").
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        r"[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|$)"
    ),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "llm_api_key": re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "generic_secret": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key)\b"
        r"\s*[:=]\s*['\"]?(?P<value>[^\s'\"]{6,})"
    ),
}


class SecretsDetector(Detector):
    """Finds credentials that should never be sent to (or returned by) a model."""

    name = "secrets"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        taken: list[tuple[int, int]] = []

        for kind, pattern in SECRET_PATTERNS.items():
            for m in pattern.finditer(text):
                group = "value" if "value" in pattern.groupindex else 0
                start, end = m.span(group)
                if any(start < e and s < end for s, e in taken):
                    continue
                taken.append((start, end))
                findings.append(
                    Finding(
                        detector=self.name,
                        category=kind,
                        message=f"Possible {kind.replace('_', ' ')} detected",
                        start=start,
                        end=end,
                        replacement="[SECRET]",
                    )
                )
        return findings
