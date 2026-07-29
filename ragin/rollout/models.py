"""Data models for rollout infrastructure."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class RolloutStage(str, Enum):
    """Stages of a gradual rollout."""

    SHADOW = "shadow"
    CANAL = "canal"
    HALF = "half"
    FULL = "full"
    CLEANUP = "cleanup"

    @classmethod
    def order(cls) -> list[RolloutStage]:
        return [cls.SHADOW, cls.CANAL, cls.HALF, cls.FULL, cls.CLEANUP]

    def next(self) -> RolloutStage | None:
        stages = self.order()
        idx = stages.index(self)
        if idx + 1 < len(stages):
            return stages[idx + 1]
        return None

    def previous(self) -> RolloutStage | None:
        stages = self.order()
        idx = stages.index(self)
        if idx > 0:
            return stages[idx - 1]
        return None


@dataclass
class RolloutHealth:
    """Health status of the current rollout."""

    stage: RolloutStage
    stable_healthy: bool = True
    canary_healthy: bool = True
    error_rate_delta: float = 0.0
    latency_p99_delta_ms: float = 0.0
    cost_delta_usd: float = 0.0
    sample_size: int = 0
    elapsed_hours: float = 0.0
    started_at: float = field(default_factory=time.time)
    issues: list[str] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        return self.stable_healthy and self.canary_healthy and len(self.issues) == 0


@dataclass
class MetricComparison:
    """Comparison of a single metric between two groups."""

    metric_name: str
    control_mean: float
    treatment_mean: float
    delta: float
    delta_percent: float
    p_value: float = 1.0
    confidence_interval: tuple[float, float] = (0.0, 0.0)
    significant: bool = False

    @property
    def improved(self) -> bool:
        return self.delta < 0


@dataclass
class ComparisonResult:
    """Full comparison result between stable and canary."""

    stage: RolloutStage
    timestamp: float = field(default_factory=time.time)
    metrics: list[MetricComparison] = field(default_factory=list)
    sample_size_stable: int = 0
    sample_size_canary: int = 0
    ready_to_advance: bool = False
    rollback_recommended: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def all_significant(self) -> bool:
        return all(m.significant for m in self.metrics)

    @property
    def any_regression(self) -> bool:
        return any(
            m.delta > 0 and m.significant
            for m in self.metrics
            if "error" in m.metric_name or "latency" in m.metric_name
        )
