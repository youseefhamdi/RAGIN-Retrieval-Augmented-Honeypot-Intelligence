"""Dwell time tracking for Hisoka — measures deception effectiveness."""

from __future__ import annotations

import logging
import time
from typing import Any

from ragin.hisoka.models import DwellMetrics

logger = logging.getLogger(__name__)

BASELINE_DWELL_SECONDS = 45.0  # typical honeypot without deception
TARGET_MULTIPLIER = 4.1


class DwellTimeTracker:
    """Tracks and compares dwell time against the 4.1× improvement target."""

    def __init__(self, baseline_seconds: float = BASELINE_DWELL_SECONDS) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._baseline = baseline_seconds

    def start_session(self, session_id: str) -> None:
        """Begin tracking dwell time for a session."""
        self._sessions[session_id] = {
            "start": time.monotonic(),
            "last": time.monotonic(),
            "interactions": 0,
        }

    def record_interaction(self, session_id: str) -> None:
        """Record an interaction, updating the last-activity timestamp."""
        if session_id in self._sessions:
            self._sessions[session_id]["last"] = time.monotonic()
            self._sessions[session_id]["interactions"] += 1

    def get_dwell_time(self, session_id: str) -> float:
        """Return elapsed wall-clock seconds since session start."""
        sess = self._sessions.get(session_id)
        if sess is None:
            return 0.0
        return time.monotonic() - sess["start"]

    def get_metrics(self) -> DwellMetrics:
        """Aggregate dwell metrics across all tracked sessions."""
        dwell_times = [time.monotonic() - s["start"] for s in self._sessions.values()]
        if not dwell_times:
            return DwellMetrics(baseline_dwell_time=self._baseline)

        avg = sum(dwell_times) / len(dwell_times)
        multiplier = avg / self._baseline if self._baseline > 0 else 0.0
        return DwellMetrics(
            total_sessions=len(dwell_times),
            active_sessions=len(dwell_times),
            avg_dwell_time=avg,
            max_dwell_time=max(dwell_times),
            min_dwell_time=min(dwell_times),
            target_multiplier=TARGET_MULTIPLIER,
            current_multiplier=multiplier,
            baseline_dwell_time=self._baseline,
        )

    def compare_baseline(self) -> dict[str, Any]:
        """Compare current performance vs the 4.1× target."""
        metrics = self.get_metrics()
        return {
            "target_multiplier": TARGET_MULTIPLIER,
            "current_multiplier": metrics.current_multiplier,
            "target_met": metrics.current_multiplier >= TARGET_MULTIPLIER,
            "avg_dwell_seconds": metrics.avg_dwell_time,
            "baseline_seconds": self._baseline,
            "total_sessions": metrics.total_sessions,
        }
