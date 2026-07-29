"""Structured audit logger with PII redaction."""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("ip_private", re.compile(r"\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b")),
]


def _redact_pii(text: str) -> str:
    """Redact PII patterns from text."""
    result = text
    for pii_type, pattern in _PII_PATTERNS:
        result = pattern.sub(f"[REDACTED_{pii_type.upper()}]", result)
    return result


def _redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact PII from dict values."""
    redacted: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str):
            redacted[k] = _redact_pii(v)
        elif isinstance(v, dict):
            redacted[k] = _redact_dict(v)
        elif isinstance(v, list):
            redacted[k] = [_redact_pii(item) if isinstance(item, str) else item for item in v]
        else:
            redacted[k] = v
    return redacted


class AuditLogger:
    """Structured JSON audit logger with PII redaction."""

    def __init__(self, log_path: str | Path | None = None) -> None:
        self._logger = logging.getLogger("ragin.audit")
        if log_path:
            handler = logging.FileHandler(str(log_path))
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)
        self._events: list[dict[str, Any]] = []

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            **_redact_dict(data),
        }
        self._events.append(event)
        self._logger.info(json.dumps(event))

    def log_classification(self, session_id: str, result: dict[str, Any]) -> None:
        self._emit("classification", {"session_id": session_id, **result})

    def log_analysis(self, session_id: str, analysis: dict[str, Any]) -> None:
        self._emit("analysis", {"session_id": session_id, **analysis})

    def log_deception(self, session_id: str, response: dict[str, Any]) -> None:
        self._emit("deception", {"session_id": session_id, **response})

    def log_evasion(self, session_id: str, detection: dict[str, Any]) -> None:
        self._emit("evasion", {"session_id": session_id, **detection})

    def log_cost_event(self, component: str, model: str, cost: float) -> None:
        self._emit("cost", {"component": component, "model": model, "cost_usd": cost})

    def log_security_event(self, event_type: str, details: dict[str, Any]) -> None:
        self._emit("security", {"event_type": event_type, **details})
