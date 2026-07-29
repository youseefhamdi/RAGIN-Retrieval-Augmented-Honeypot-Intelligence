"""Metrics tracking for the Harness/Loop — MTTA and session analytics.

Design references:
- VVAH Harness: MTTA as primary metric
- Loop Engineering: observability as a production pattern

MTTA (Mean Time to Act) measures the average time from attacker input
to system response across all pipeline stages. This is the key metric
for evaluating deception system responsiveness.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class StageTiming:
    """Timing for a single pipeline stage."""

    stage: str
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class InteractionMetrics:
    """Metrics for a single attacker interaction (one command → one response)."""

    interaction_id: str = ""
    session_id: str = ""
    attacker_input: str = ""
    total_duration_ms: float = 0.0
    stages: list[StageTiming] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def stage_count(self) -> int:
        return len(self.stages)

    @property
    def slowest_stage(self) -> StageTiming | None:
        if not self.stages:
            return None
        return max(self.stages, key=lambda s: s.duration_ms)

    @property
    def fastest_stage(self) -> StageTiming | None:
        if not self.stages:
            return None
        return min(self.stages, key=lambda s: s.duration_ms)

    def to_dict(self) -> dict[str, Any]:
        return {
            "interaction_id": self.interaction_id,
            "session_id": self.session_id,
            "attacker_input": self.attacker_input[:128],
            "total_duration_ms": round(self.total_duration_ms, 2),
            "stages": [s.to_dict() for s in self.stages],
            "timestamp": self.timestamp.isoformat(),
            "stage_count": self.stage_count,
            "slowest_stage": self.slowest_stage.stage if self.slowest_stage else None,
        }


@dataclass
class SessionMetrics:
    """Aggregated metrics for an entire session."""

    session_id: str = ""
    interaction_count: int = 0
    total_duration_ms: float = 0.0
    avg_interaction_ms: float = 0.0
    max_interaction_ms: float = 0.0
    min_interaction_ms: float = float("inf")
    mtta_ms: float = 0.0  # Mean Time to Act
    stage_averages: dict[str, float] = field(default_factory=dict)
    findings_count: int = 0
    high_risk_count: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "interaction_count": self.interaction_count,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "avg_interaction_ms": round(self.avg_interaction_ms, 2),
            "max_interaction_ms": round(self.max_interaction_ms, 2),
            "min_interaction_ms": round(self.min_interaction_ms, 2) if self.min_interaction_ms != float("inf") else 0,
            "mtta_ms": round(self.mtta_ms, 2),
            "stage_averages": {k: round(v, 2) for k, v in self.stage_averages.items()},
            "findings_count": self.findings_count,
            "high_risk_count": self.high_risk_count,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class StageTimer:
    """Context manager for timing pipeline stages.

    Usage::

        timer = StageTimer()
        with timer.track("classification"):
            result = classifier.classify(input)
        with timer.track("cti_lookup"):
            result = cti_engine.analyze(input)
        print(timer.timings)
    """

    def __init__(self) -> None:
        self._timings: list[StageTiming] = []
        self._current: StageTiming | None = None

    def track(self, stage: str) -> StageTimer:
        """Start timing a stage. Returns self for use as context manager."""
        self._current = StageTiming(stage=stage, start_time=time.monotonic())
        return self

    def __enter__(self) -> StageTimer:
        return self

    def __exit__(self, *args: Any) -> None:
        if self._current:
            self._current.end_time = time.monotonic()
            self._current.duration_ms = (self._current.end_time - self._current.start_time) * 1000
            self._timings.append(self._current)
            self._current = None

    @property
    def timings(self) -> list[StageTiming]:
        return list(self._timings)

    @property
    def total_ms(self) -> float:
        return sum(t.duration_ms for t in self._timings)

    def reset(self) -> None:
        self._timings.clear()
        self._current = None


class MTTATracker:
    """Tracks Mean Time to Act across all interactions.

    MTTA is the primary metric from VVAH Harness — it measures how quickly
    the deception system responds to attacker actions. Lower is better.

    Tracks per-interaction metrics, per-session aggregates, and global
    statistics across all observed sessions.

    Usage::

        tracker = MTTATracker()

        # Record an interaction
        timer = StageTimer()
        with timer.track("classification"):
            classifier.classify(input)
        with timer.track("response"):
            deceiver.generate_response(input)

        tracker.record_interaction(
            interaction_id="int-001",
            session_id="ses-123",
            attacker_input="whoami",
            stages=timer.timings,
            total_duration_ms=timer.total_ms,
        )

        # Get session summary
        summary = tracker.get_session_metrics("ses-123")
        print(summary.mtta_ms)

        # Get global stats
        global_stats = tracker.get_global_metrics()
    """

    def __init__(self) -> None:
        self._interactions: dict[str, list[InteractionMetrics]] = {}  # session_id → interactions
        self._all_interactions: list[InteractionMetrics] = []
        logger.info("MTTATracker initialized")

    def record_interaction(
        self,
        interaction_id: str,
        session_id: str,
        attacker_input: str,
        stages: list[StageTiming],
        total_duration_ms: float,
        metadata: dict[str, Any] | None = None,
    ) -> InteractionMetrics:
        """Record metrics for a single interaction."""
        metrics = InteractionMetrics(
            interaction_id=interaction_id,
            session_id=session_id,
            attacker_input=attacker_input,
            total_duration_ms=total_duration_ms,
            stages=list(stages),
            metadata=metadata or {},
        )

        self._interactions.setdefault(session_id, []).append(metrics)
        self._all_interactions.append(metrics)

        logger.debug(
            "Recorded interaction %s for session %s: %.1fms across %d stages",
            interaction_id,
            session_id,
            total_duration_ms,
            len(stages),
        )
        return metrics

    def get_session_stats(self, session_id: str) -> SessionMetrics:
        """Alias for get_session_metrics (backwards compat)."""
        return self.get_session_metrics(session_id)

    def get_session_metrics(self, session_id: str) -> SessionMetrics:
        """Compute aggregated metrics for a session."""
        interactions = self._interactions.get(session_id, [])

        if not interactions:
            return SessionMetrics(session_id=session_id)

        durations = [i.total_duration_ms for i in interactions]
        stage_totals: dict[str, list[float]] = {}

        for interaction in interactions:
            for stage in interaction.stages:
                stage_totals.setdefault(stage.stage, []).append(stage.duration_ms)

        stage_averages = {stage: sum(times) / len(times) for stage, times in stage_totals.items()}

        return SessionMetrics(
            session_id=session_id,
            interaction_count=len(interactions),
            total_duration_ms=sum(durations),
            avg_interaction_ms=sum(durations) / len(durations),
            max_interaction_ms=max(durations),
            min_interaction_ms=min(durations),
            mtta_ms=sum(durations) / len(durations),  # MTTA = avg interaction time
            stage_averages=stage_averages,
            start_time=interactions[0].timestamp if interactions else None,
            end_time=interactions[-1].timestamp if interactions else None,
        )

    def get_global_metrics(self) -> dict[str, Any]:
        """Compute global statistics across all sessions."""
        if not self._all_interactions:
            return {
                "total_interactions": 0,
                "total_sessions": 0,
                "global_mtta_ms": 0.0,
            }

        durations = [i.total_duration_ms for i in self._all_interactions]
        session_ids = {i.session_id for i in self._all_interactions}

        stage_totals: dict[str, list[float]] = {}
        for interaction in self._all_interactions:
            for stage in interaction.stages:
                stage_totals.setdefault(stage.stage, []).append(stage.duration_ms)

        return {
            "total_interactions": len(self._all_interactions),
            "total_sessions": len(session_ids),
            "global_mtta_ms": round(sum(durations) / len(durations), 2),
            "global_max_ms": round(max(durations), 2),
            "global_min_ms": round(min(durations), 2),
            "stage_averages": {stage: round(sum(times) / len(times), 2) for stage, times in stage_totals.items()},
        }

    def record_finding(self, session_id: str, severity: str) -> None:
        """Record that a finding was generated for a session."""
        # Update the session's last interaction with finding metadata
        interactions = self._interactions.get(session_id, [])
        if interactions:
            interactions[-1].metadata["finding_generated"] = True
            interactions[-1].metadata["finding_severity"] = severity

    def reset(self) -> None:
        """Clear all tracked metrics."""
        self._interactions.clear()
        self._all_interactions.clear()
