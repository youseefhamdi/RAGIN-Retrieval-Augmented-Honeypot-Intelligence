"""Alert management for RAGIN monitoring."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ragin.monitoring.metrics import MetricsSummary


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    """A monitoring alert."""

    rule_name: str
    severity: AlertSeverity
    message: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertRule:
    """Definition of an alert condition."""

    name: str
    severity: AlertSeverity
    description: str
    enabled: bool = True


_DEFAULT_RULES: list[AlertRule] = [
    AlertRule("error_rate", AlertSeverity.CRITICAL, "Error rate > 5% over window"),
    AlertRule("latency_p99", AlertSeverity.WARNING, "P99 latency > 2000ms"),
    AlertRule("memory_usage", AlertSeverity.WARNING, "Memory usage > 80%"),
    AlertRule("cost_daily_warning", AlertSeverity.WARNING, "Daily cost > $20"),
    AlertRule("cost_daily_critical", AlertSeverity.CRITICAL, "Daily cost > $50"),
    AlertRule("evasion_rate", AlertSeverity.INFO, "Evasion detections > 10/hour"),
    AlertRule("session_count", AlertSeverity.WARNING, "Concurrent sessions > 1000"),
]


class AlertManager:
    """Evaluates alert rules against metrics and dispatches to handlers."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._handlers: list[Callable[[Alert], None]] = []
        self._rules: list[AlertRule] = list(_DEFAULT_RULES)

    def add_handler(self, handler: Callable[[Alert], None]) -> None:
        """Register an alert handler (webhook, log, custom)."""
        self._handlers.append(handler)

    def check_alerts(self, metrics_summary: MetricsSummary) -> list[Alert]:
        """Evaluate all rules against current metrics, return triggered alerts."""
        alerts: list[Alert] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            alert = self.evaluate_rule(rule, metrics_summary)
            if alert is not None:
                alerts.append(alert)
                for handler in self._handlers:
                    handler(alert)
        return alerts

    def evaluate_rule(self, rule: AlertRule, metrics: MetricsSummary) -> Alert | None:
        """Evaluate a single rule against metrics."""
        if rule.name == "error_rate":
            if metrics.error_rate > 0.05:
                return Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Error rate {metrics.error_rate:.1%} exceeds 5% threshold",
                    metadata={"error_rate": metrics.error_rate},
                )
        elif rule.name == "latency_p99":
            if metrics.latency_p99_ms > 2000:
                return Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"P99 latency {metrics.latency_p99_ms:.0f}ms exceeds 2000ms",
                    metadata={"latency_p99_ms": metrics.latency_p99_ms},
                )
        elif rule.name == "memory_usage":
            import os

            try:
                import psutil

                mem_pct = psutil.Process(os.getpid()).memory_percent()
            except ImportError:
                mem_pct = 0.0
            if mem_pct > 80:
                return Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Memory usage {mem_pct:.1f}% exceeds 80%",
                    metadata={"memory_pct": mem_pct},
                )
        elif rule.name == "cost_daily_warning":
            if metrics.total_cost_usd > 20:
                return Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Daily cost ${metrics.total_cost_usd:.2f} exceeds $20",
                    metadata={"cost_usd": metrics.total_cost_usd},
                )
        elif rule.name == "cost_daily_critical":
            if metrics.total_cost_usd > 50:
                return Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Daily cost ${metrics.total_cost_usd:.2f} exceeds $50",
                    metadata={"cost_usd": metrics.total_cost_usd},
                )
        elif rule.name == "evasion_rate":
            if metrics.evasion_detections > 10:
                return Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"{metrics.evasion_detections} evasion detections exceeds 10/hour",
                    metadata={"evasion_count": metrics.evasion_detections},
                )
        elif rule.name == "session_count" and metrics.active_sessions > 1000:
            return Alert(
                rule_name=rule.name,
                severity=rule.severity,
                message=f"{metrics.active_sessions} sessions exceeds 1000",
                metadata={"session_count": metrics.active_sessions},
            )
        return None
