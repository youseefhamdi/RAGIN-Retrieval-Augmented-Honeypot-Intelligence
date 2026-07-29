"""In-memory metrics collector for RAGIN components."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class MetricsSummary:
    """Aggregated metrics over a time window."""

    window_minutes: int
    total_requests: int = 0
    error_count: int = 0
    error_rate: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p99_ms: float = 0.0
    latency_mean_ms: float = 0.0
    total_classifications: int = 0
    skill_level_distribution: dict[str, int] = field(default_factory=dict)
    total_threats: int = 0
    total_deceptions: int = 0
    avg_dwell_time_s: float = 0.0
    avg_engagement_score: float = 0.0
    evasion_detections: int = 0
    total_cost_usd: float = 0.0
    cost_by_component: dict[str, float] = field(default_factory=dict)
    active_sessions: int = 0


class MetricsCollector:
    """Thread-safe in-memory time-series metrics store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: list[dict] = []
        self._classifications: list[dict] = []
        self._threats: list[dict] = []
        self._deceptions: list[dict] = []
        self._evasion_detections: list[dict] = []
        self._costs: list[dict] = []

    def record_request(self, component: str, method: str, status: str, latency_ms: float) -> None:
        """Record an API request event."""
        with self._lock:
            self._requests.append(
                {
                    "timestamp": time.time(),
                    "component": component,
                    "method": method,
                    "status": status,
                    "latency_ms": latency_ms,
                }
            )

    def record_classification(self, skill_level: str, confidence: float) -> None:
        """Record a classification result."""
        with self._lock:
            self._classifications.append(
                {
                    "timestamp": time.time(),
                    "skill_level": skill_level,
                    "confidence": confidence,
                }
            )

    def record_threat(self, severity: str, tactics: list[str]) -> None:
        """Record a threat detection."""
        with self._lock:
            self._threats.append(
                {
                    "timestamp": time.time(),
                    "severity": severity,
                    "tactics": tactics,
                }
            )

    def record_deception(self, session_id: str, dwell_time: float, engagement_score: float) -> None:
        """Record a deception engagement event."""
        with self._lock:
            self._deceptions.append(
                {
                    "timestamp": time.time(),
                    "session_id": session_id,
                    "dwell_time": dwell_time,
                    "engagement_score": engagement_score,
                }
            )

    def record_evasion_detection(self, detection_type: str, confidence: float) -> None:
        """Record an evasion detection event."""
        with self._lock:
            self._evasion_detections.append(
                {
                    "timestamp": time.time(),
                    "detection_type": detection_type,
                    "confidence": confidence,
                }
            )

    def record_cost(self, component: str, model: str, tokens: int, cost_usd: float) -> None:
        """Record an LLM cost event."""
        with self._lock:
            self._costs.append(
                {
                    "timestamp": time.time(),
                    "component": component,
                    "model": model,
                    "tokens": tokens,
                    "cost_usd": cost_usd,
                }
            )

    def get_summary(self, window_minutes: int = 60) -> MetricsSummary:
        """Compute aggregated metrics over a time window."""
        cutoff = time.time() - (window_minutes * 60)
        with self._lock:
            reqs = [r for r in self._requests if r["timestamp"] >= cutoff]
            cls = [c for c in self._classifications if c["timestamp"] >= cutoff]
            threats = [t for t in self._threats if t["timestamp"] >= cutoff]
            decep = [d for d in self._deceptions if d["timestamp"] >= cutoff]
            evasions = [e for e in self._evasion_detections if e["timestamp"] >= cutoff]
            costs = [c for c in self._costs if c["timestamp"] >= cutoff]

        summary = MetricsSummary(window_minutes=window_minutes)
        summary.total_requests = len(reqs)
        summary.error_count = sum(1 for r in reqs if r["status"] != "ok")
        summary.error_rate = summary.error_count / summary.total_requests if summary.total_requests > 0 else 0.0

        if reqs:
            latencies = sorted(r["latency_ms"] for r in reqs)
            summary.latency_mean_ms = sum(latencies) / len(latencies)
            summary.latency_p50_ms = latencies[len(latencies) // 2]
            p99_idx = max(0, int(len(latencies) * 0.99) - 1)
            summary.latency_p99_ms = latencies[p99_idx]

        summary.total_classifications = len(cls)
        for c in cls:
            level = c["skill_level"]
            summary.skill_level_distribution[level] = summary.skill_level_distribution.get(level, 0) + 1

        summary.total_threats = len(threats)
        summary.total_deceptions = len(decep)
        if decep:
            summary.avg_dwell_time_s = sum(d["dwell_time"] for d in decep) / len(decep)
            summary.avg_engagement_score = sum(d["engagement_score"] for d in decep) / len(decep)

        summary.evasion_detections = len(evasions)
        summary.total_cost_usd = sum(c["cost_usd"] for c in costs)
        for c in costs:
            comp = c["component"]
            summary.cost_by_component[comp] = summary.cost_by_component.get(comp, 0.0) + c["cost_usd"]

        return summary
