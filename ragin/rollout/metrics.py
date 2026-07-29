"""Metrics collection and statistical comparison for rollout decisions."""

from __future__ import annotations

import math
from dataclasses import dataclass

from ragin.rollout.models import MetricComparison


@dataclass
class GroupMetrics:
    """Aggregated metrics for a traffic group."""

    error_count: int = 0
    total_requests: int = 0
    latency_p50_ms: float = 0.0
    latency_p99_ms: float = 0.0
    latency_mean_ms: float = 0.0
    cost_usd: float = 0.0
    sample_size: int = 0

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.error_count / self.total_requests


class RolloutMetrics:
    """Collect and compare metrics between stable and canary groups."""

    def __init__(self, prometheus_url: str = "http://localhost:9090") -> None:
        self.prometheus_url = prometheus_url
        self._control: list[GroupMetrics] = []
        self._treatment: list[GroupMetrics] = []

    def record_control(self, metrics: GroupMetrics) -> None:
        self._control.append(metrics)

    def record_treatment(self, metrics: GroupMetrics) -> None:
        self._treatment.append(metrics)

    def get_control_total(self) -> GroupMetrics:
        return self._aggregate(self._control)

    def get_treatment_total(self) -> GroupMetrics:
        return self._aggregate(self._treatment)

    def compare_groups(self, control: GroupMetrics, treatment: GroupMetrics) -> list[MetricComparison]:
        """Compare control vs treatment on all key metrics."""
        comparisons: list[MetricComparison] = []

        # Error rate comparison
        ctrl_err = control.error_rate
        treat_err = treatment.error_rate
        err_delta = treat_err - ctrl_err
        err_delta_pct = (err_delta / ctrl_err * 100) if ctrl_err > 0 else 0.0
        err_p = self._proportion_z_test(
            control.error_count,
            control.total_requests,
            treatment.error_count,
            treatment.total_requests,
        )
        comparisons.append(
            MetricComparison(
                metric_name="error_rate",
                control_mean=ctrl_err,
                treatment_mean=treat_err,
                delta=err_delta,
                delta_percent=err_delta_pct,
                p_value=err_p,
                significant=err_p < 0.05,
            )
        )

        # Latency p99 comparison
        lat_delta = treatment.latency_p99_ms - control.latency_p99_ms
        lat_pct = (lat_delta / control.latency_p99_ms * 100) if control.latency_p99_ms > 0 else 0.0
        lat_p = self._welch_t_test_p_value(
            control.latency_mean_ms,
            control.sample_size,
            treatment.latency_mean_ms,
            treatment.sample_size,
        )
        comparisons.append(
            MetricComparison(
                metric_name="latency_p99_ms",
                control_mean=control.latency_p99_ms,
                treatment_mean=treatment.latency_p99_ms,
                delta=lat_delta,
                delta_percent=lat_pct,
                p_value=lat_p,
                significant=lat_p < 0.05,
            )
        )

        # Cost comparison
        cost_delta = treatment.cost_usd - control.cost_usd
        cost_pct = (cost_delta / control.cost_usd * 100) if control.cost_usd > 0 else 0.0
        comparisons.append(
            MetricComparison(
                metric_name="cost_usd",
                control_mean=control.cost_usd,
                treatment_mean=treatment.cost_usd,
                delta=cost_delta,
                delta_percent=cost_pct,
                p_value=1.0,
                significant=False,
            )
        )

        return comparisons

    def _aggregate(self, samples: list[GroupMetrics]) -> GroupMetrics:
        if not samples:
            return GroupMetrics()
        total_req = sum(s.total_requests for s in samples)
        total_err = sum(s.error_count for s in samples)
        total_cost = sum(s.cost_usd for s in samples)
        total_samples = sum(s.sample_size for s in samples)
        weighted_lat_p50 = (
            sum(s.latency_p50_ms * s.sample_size for s in samples) / total_samples if total_samples else 0.0
        )
        weighted_lat_p99 = max((s.latency_p99_ms for s in samples), default=0.0)
        weighted_lat_mean = (
            sum(s.latency_mean_ms * s.sample_size for s in samples) / total_samples if total_samples else 0.0
        )
        return GroupMetrics(
            error_count=total_err,
            total_requests=total_req,
            latency_p50_ms=weighted_lat_p50,
            latency_p99_ms=weighted_lat_p99,
            latency_mean_ms=weighted_lat_mean,
            cost_usd=total_cost,
            sample_size=total_samples,
        )

    @staticmethod
    def _proportion_z_test(x1: int, n1: int, x2: int, n2: int) -> float:
        """Two-proportion z-test. Returns p-value (two-tailed)."""
        if n1 == 0 or n2 == 0:
            return 1.0
        p1 = x1 / n1
        p2 = x2 / n2
        p_pool = (x1 + x2) / (n1 + n2)
        if p_pool == 0 or p_pool == 1:
            return 1.0
        se = math.sqrt(p_pool * (1 - p_pool) * (1 / n1 + 1 / n2))
        if se == 0:
            return 1.0
        z = abs(p1 - p2) / se
        # Approximate two-tailed p-value from z using the error function approximation
        return RolloutMetrics._normal_sf(z) * 2

    @staticmethod
    def _welch_t_test_p_value(mean1: float, n1: int, mean2: float, n2: int) -> float:
        """Simplified Welch's t-test. Uses sample std ≈ mean * 0.3 as estimate."""
        if n1 == 0 or n2 == 0:
            return 1.0
        # Estimate std from mean (coefficient of variation ≈ 0.3)
        std1 = abs(mean1) * 0.3 if mean1 != 0 else 1.0
        std2 = abs(mean2) * 0.3 if mean2 != 0 else 1.0
        se = math.sqrt(std1**2 / n1 + std2**2 / n2)
        if se == 0:
            return 1.0
        t = abs(mean1 - mean2) / se
        # Approximate p-value using normal approximation for large samples
        return RolloutMetrics._normal_sf(t) * 2

    @staticmethod
    def _normal_sf(x: float) -> float:
        """Approximate survival function (1 - CDF) of standard normal."""
        # Abramowitz and Stegun approximation
        if x < 0:
            return 1.0 - RolloutMetrics._normal_sf(-x)
        t = 1.0 / (1.0 + 0.2316419 * x)
        d = 0.3989422804014327  # 1/sqrt(2*pi)
        p = (
            d
            * math.exp(-x * x / 2)
            * (t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429)))))
        )
        return min(p, 1.0)
