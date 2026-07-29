"""Deception effectiveness metrics, scoring, and comparative benchmarks."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EffectivenessMetrics:
    honeytoken_triggers: int = 0
    honeytokens_deployed: int = 0
    total_sessions: int = 0
    sessions_with_engagement: int = 0
    persona_correct_assignments: int = 0
    persona_total_assignments: int = 0
    ttps_detected: int = 0
    ttps_detected_unique: int = 0
    cti_alerts_generated: int = 0
    false_positives: int = 0
    true_positives: int = 0
    attacker_retention_turns: float = 0.0
    max_retention_turns: int = 0
    mean_session_duration_s: float = 0.0
    deception_artifacts_deployed: int = 0
    deception_artifacts_accessed: int = 0
    strategy_adaptations: int = 0
    avg_response_time_ms: float = 0.0

    @property
    def honeytoken_trigger_rate(self) -> float:
        if self.honeytokens_deployed == 0:
            return 0.0
        return self.honeytoken_triggers / self.honeytokens_deployed

    @property
    def engagement_rate(self) -> float:
        if self.total_sessions == 0:
            return 0.0
        return self.sessions_with_engagement / self.total_sessions

    @property
    def persona_accuracy(self) -> float:
        if self.persona_total_assignments == 0:
            return 0.0
        return self.persona_correct_assignments / self.persona_total_assignments

    @property
    def detection_precision(self) -> float:
        total = self.true_positives + self.false_positives
        if total == 0:
            return 0.0
        return self.true_positives / total

    @property
    def detection_recall(self) -> float:
        if self.ttps_detected == 0:
            return 0.0
        relevant = self.true_positives + self.false_positives
        return self.true_positives / relevant if relevant > 0 else 0.0

    @property
    def artifact_access_rate(self) -> float:
        if self.deception_artifacts_deployed == 0:
            return 0.0
        return self.deception_artifacts_accessed / self.deception_artifacts_deployed

    def composite_score(self) -> float:
        weights = {
            "honeytoken": 0.25,
            "engagement": 0.20,
            "persona": 0.15,
            "detection": 0.25,
            "artifact": 0.15,
        }
        score = (
            weights["honeytoken"] * self.honeytoken_trigger_rate
            + weights["engagement"] * self.engagement_rate
            + weights["persona"] * self.persona_accuracy
            + weights["detection"] * self.detection_precision
            + weights["artifact"] * self.artifact_access_rate
        )
        return round(score, 4)

    def baseline_adjusted_composite(self) -> float:
        zeroed = []
        weights = {"honeytoken": 0.25, "engagement": 0.20, "persona": 0.15, "detection": 0.25, "artifact": 0.15}
        rates = {
            "honeytoken": self.honeytoken_trigger_rate,
            "engagement": self.engagement_rate,
            "persona": self.persona_accuracy,
            "detection": self.detection_precision,
            "artifact": self.artifact_access_rate,
        }
        for k in ("honeytoken", "artifact"):
            if rates[k] <= 0.01:
                zeroed.append(k)
        if not zeroed:
            return self.composite_score()
        active_weights = {k: v for k, v in weights.items() if k not in zeroed}
        total_active = sum(active_weights.values())
        if total_active == 0:
            return 0.0
        score = sum((v / total_active) * rates[k] for k, v in active_weights.items())
        return round(score, 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "honeytoken_triggers": self.honeytoken_triggers,
            "honeytokens_deployed": self.honeytokens_deployed,
            "honeytoken_trigger_rate": round(self.honeytoken_trigger_rate, 4),
            "total_sessions": self.total_sessions,
            "sessions_with_engagement": self.sessions_with_engagement,
            "engagement_rate": round(self.engagement_rate, 4),
            "persona_correct_assignments": self.persona_correct_assignments,
            "persona_total_assignments": self.persona_total_assignments,
            "persona_accuracy": round(self.persona_accuracy, 4),
            "ttps_detected": self.ttps_detected,
            "ttps_detected_unique": self.ttps_detected_unique,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "detection_precision": round(self.detection_precision, 4),
            "attacker_retention_turns": round(self.attacker_retention_turns, 2),
            "max_retention_turns": self.max_retention_turns,
            "mean_session_duration_s": round(self.mean_session_duration_s, 2),
            "deception_artifacts_deployed": self.deception_artifacts_deployed,
            "deception_artifacts_accessed": self.deception_artifacts_accessed,
            "artifact_access_rate": round(self.artifact_access_rate, 4),
            "strategy_adaptations": self.strategy_adaptations,
            "composite_score": self.composite_score(),
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
        }


@dataclass
class EffectivenessComparison:
    benchmark_id: str
    name: str
    description: str
    baseline_metrics: EffectivenessMetrics
    current_metrics: EffectivenessMetrics
    improvement_pct: dict[str, float] = field(default_factory=dict)
    grade: str = ""
    timestamp: float = field(default_factory=time.time)

    def compute_improvement(self) -> dict[str, float]:
        b = self.baseline_metrics.to_dict()
        c = self.current_metrics.to_dict()
        self.improvement_pct = {}
        for key in b:
            if isinstance(b[key], (int, float)) and b[key] != 0:
                delta = ((c[key] - b[key]) / abs(b[key])) * 100
                self.improvement_pct[key] = round(delta, 2)
        return self.improvement_pct

    def assign_grade(self) -> str:
        score = self.current_metrics.composite_score()
        if score >= 0.8:
            self.grade = "A"
        elif score >= 0.6:
            self.grade = "B"
        elif score >= 0.4:
            self.grade = "C"
        elif score >= 0.2:
            self.grade = "D"
        else:
            self.grade = "F"
        return self.grade

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "name": self.name,
            "description": self.description,
            "baseline": self.baseline_metrics.to_dict(),
            "current": self.current_metrics.to_dict(),
            "improvement_pct": self.improvement_pct,
            "grade": self.grade,
            "timestamp": self.timestamp,
        }


@dataclass
class EffectivenessReport:
    report_id: str
    title: str
    metrics: EffectivenessMetrics
    benchmarks: list[EffectivenessComparison] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    period_start: float = field(default_factory=time.time)
    period_end: float = field(default_factory=time.time)
    generated_at: float = field(default_factory=time.time)

    def add_recommendation(self, finding: str, threshold: float, current: float, direction: str = "above") -> None:
        if direction == "above" and current < threshold:
            self.recommendations.append(
                f"{finding}: {current:.2%} < {threshold:.2%} threshold — consider increasing deployment"
            )
        elif direction == "below" and current > threshold:
            self.recommendations.append(f"{finding}: {current:.2%} > {threshold:.2%} threshold — investigate reduction")

    def generate_recommendations(self) -> list[str]:
        self.recommendations.clear()
        self.add_recommendation("Honeytoken trigger rate", 0.05, self.metrics.honeytoken_trigger_rate)
        self.add_recommendation("Engagement rate", 0.30, self.metrics.engagement_rate)
        self.add_recommendation("Persona accuracy", 0.70, self.metrics.persona_accuracy)
        self.add_recommendation("Detection precision", 0.80, self.metrics.detection_precision)
        self.add_recommendation("Artifact access rate", 0.10, self.metrics.artifact_access_rate)

        if self.metrics.false_positives > self.metrics.true_positives:
            self.recommendations.append(
                f"False positive ratio ({self.metrics.false_positives}/{self.metrics.true_positives + self.metrics.false_positives}) is high — tune TTP extraction confidence threshold"
            )
        if self.metrics.avg_response_time_ms > 500:
            self.recommendations.append(
                f"Average response time ({self.metrics.avg_response_time_ms:.0f}ms) exceeds 500ms — profile cycle latency"
            )
        if self.metrics.attacker_retention_turns < 3.0:
            self.recommendations.append(
                f"Attacker retention ({self.metrics.attacker_retention_turns:.1f} turns) is low — deploy more compelling artifacts"
            )
        return self.recommendations

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "metrics": self.metrics.to_dict(),
            "benchmarks": [b.to_dict() for b in self.benchmarks],
            "recommendations": self.recommendations,
            "period": {"start": self.period_start, "end": self.period_end},
            "generated_at": self.generated_at,
        }

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


class EffectivenessBenchmark:
    def __init__(self) -> None:
        self._baselines: dict[str, EffectivenessMetrics] = {}
        self._results: list[EffectivenessComparison] = []

    def register_baseline(self, name: str, metrics: EffectivenessMetrics) -> None:
        self._baselines[name] = metrics

    def run_benchmark(
        self,
        name: str,
        baseline_name: str,
        current_metrics: EffectivenessMetrics,
        description: str = "",
    ) -> EffectivenessComparison:
        if baseline_name not in self._baselines:
            raise KeyError(f"Baseline '{baseline_name}' not registered")
        result = EffectivenessComparison(
            benchmark_id=f"bench_{name}_{int(time.time())}",
            name=name,
            description=description,
            baseline_metrics=self._baselines[baseline_name],
            current_metrics=current_metrics,
        )
        result.compute_improvement()
        result.assign_grade()
        self._results.append(result)
        return result

    def get_results(self) -> list[EffectivenessComparison]:
        return list(self._results)

    def compare_baselines(self) -> dict[str, dict[str, float]]:
        comparison: dict[str, dict[str, float]] = {}
        for name, baseline in self._baselines.items():
            comparison[name] = baseline.to_dict()
        return comparison
