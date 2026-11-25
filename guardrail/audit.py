"""Append-only JSON Lines audit log of guardrail decisions.

The raw text is never written to the log, only a SHA-256 hash of it, so the
audit trail does not itself become a store of the PII it was meant to protect.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from guardrail.models import GuardrailResult


class AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, text: str, result: GuardrailResult) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy": result.policy,
            "direction": result.direction.value,
            "action": result.action.value,
            "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "text_length": len(text),
            "findings": [
                {"detector": f.detector, "category": f.category, "action": f.action.value}
                for f in result.findings
            ],
            "latency_ms": round(result.latency_ms, 3),
        }
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
