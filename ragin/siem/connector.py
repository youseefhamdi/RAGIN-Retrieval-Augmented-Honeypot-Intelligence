"""Base SIEM connector and shared event model."""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SIEMSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def to_cef_severity(self) -> int:
        return {
            SIEMSeverity.INFO: 0,
            SIEMSeverity.LOW: 3,
            SIEMSeverity.MEDIUM: 5,
            SIEMSeverity.HIGH: 8,
            SIEMSeverity.CRITICAL: 10,
        }[self]


@dataclass
class SIEMEvent:
    event_id: str
    event_type: str
    severity: SIEMSeverity
    source_ip: str = ""
    session_id: str = ""
    tenant_id: str = ""
    timestamp: float = field(default_factory=time.time)
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    honeytoken_triggered: bool = False
    component: str = "ragin"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "message": self.message,
            "details": self.details,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "honeytoken_triggered": self.honeytoken_triggered,
            "component": self.component,
        }


class SIEMConnector(abc.ABC):
    def __init__(self, name: str, enabled: bool = True) -> None:
        self.name = name
        self.enabled = enabled
        self._sent_count = 0
        self._error_count = 0

    @abc.abstractmethod
    def send(self, event: SIEMEvent) -> bool: ...

    def send_batch(self, events: list[SIEMEvent]) -> int:
        sent = 0
        for event in events:
            if self.send(event):
                sent += 1
        return sent

    @property
    def stats(self) -> dict[str, int]:
        return {"sent": self._sent_count, "errors": self._error_count}
