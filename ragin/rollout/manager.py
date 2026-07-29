"""Rollout manager — orchestrates gradual deployment stages."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import yaml

from ragin.rollout.metrics import GroupMetrics, RolloutMetrics
from ragin.rollout.models import ComparisonResult, RolloutHealth, RolloutStage

ROLLOUT_DIR = Path(__file__).resolve().parent.parent / "config" / "rollout"
STATE_FILE = ROLLOUT_DIR / "rollout_state.json"


class RolloutManager:
    """Manages the gradual rollout lifecycle: advance, rollback, health checks."""

    def __init__(self, config_path: str | Path | None = None, state_path: str | Path | None = None) -> None:
        self.config_dir = Path(config_path) if config_path else ROLLOUT_DIR
        self.state_path = Path(state_path) if state_path else STATE_FILE
        self.metrics = RolloutMetrics()
        self._state = self._load_state()
        self._thresholds = self._load_thresholds()

    # ── Public API ────────────────────────────────────────────────────────────

    def get_current_stage(self) -> RolloutStage:
        return RolloutStage(self._state["stage"])

    def advance_stage(self) -> tuple[bool, list[str]]:
        """Check criteria and advance if met. Returns (success, reasons)."""
        current = self.get_current_stage()
        next_stage = current.next()
        if next_stage is None:
            return False, [f"Already at {current.value} stage (final)"]

        ready, reasons = self.is_ready_to_advance()
        if not ready:
            return False, reasons

        self._state["stage"] = next_stage.value
        self._state["stage_started_at"] = time.time()
        self._state["history"].append(
            {
                "action": "advance",
                "from": current.value,
                "to": next_stage.value,
                "timestamp": time.time(),
                "reasons": reasons,
            }
        )
        self._save_state()
        return True, [f"Advanced from {current.value} to {next_stage.value}"]

    def rollback(self, reason: str) -> RolloutStage:
        """Roll back to the previous stage."""
        current = self.get_current_stage()
        prev = current.previous()
        if prev is None:
            return current

        self._state["stage"] = prev.value
        self._state["stage_started_at"] = time.time()
        self._state["history"].append(
            {
                "action": "rollback",
                "from": current.value,
                "to": prev.value,
                "timestamp": time.time(),
                "reason": reason,
            }
        )
        self._save_state()
        return prev

    def check_health(self) -> RolloutHealth:
        """Check health of both stable and canary."""
        stable = self._check_backend_health("stable")
        canary = self._check_backend_health("canary")
        elapsed = (time.time() - self._state["stage_started_at"]) / 3600

        return RolloutHealth(
            stage=self.get_current_stage(),
            stable_healthy=stable,
            canary_healthy=canary,
            error_rate_delta=self._state.get("current_error_rate_delta", 0.0),
            latency_p99_delta_ms=self._state.get("current_latency_p99_delta_ms", 0.0),
            cost_delta_usd=self._state.get("current_cost_delta_usd", 0.0),
            sample_size=self._state.get("current_sample_size", 0),
            elapsed_hours=elapsed,
            started_at=self._state["stage_started_at"],
        )

    def compare_versions(self, stable_metrics: GroupMetrics, canary_metrics: GroupMetrics) -> ComparisonResult:
        """Compare stable vs canary and produce a ComparisonResult."""
        comparisons = self.metrics.compare_groups(stable_metrics, canary_metrics)
        stage = self.get_current_stage()
        thresholds = self._thresholds.get(stage.value, {})

        reasons: list[str] = []
        rollback_recommended = False

        for mc in comparisons:
            if "error" in mc.metric_name:
                max_delta = thresholds.get("max_error_rate_delta", thresholds.get("max_error_rate", 0.01))
                if mc.delta > max_delta:
                    reasons.append(f"Error rate delta {mc.delta:.4f} exceeds threshold {max_delta}")
                    rollback_recommended = True
            elif "latency" in mc.metric_name:
                max_delta = thresholds.get("max_latency_p99_delta_ms", thresholds.get("max_latency_p99_ms", 500))
                if mc.delta > max_delta:
                    reasons.append(f"Latency p99 delta {mc.delta:.1f}ms exceeds threshold {max_delta}ms")
                    rollback_recommended = True

        min_samples = thresholds.get("min_sample_size", 1000)
        total_samples = stable_metrics.sample_size + canary_metrics.sample_size
        if total_samples < min_samples:
            reasons.append(f"Sample size {total_samples} below minimum {min_samples}")

        return ComparisonResult(
            stage=stage,
            metrics=comparisons,
            sample_size_stable=stable_metrics.sample_size,
            sample_size_canary=canary_metrics.sample_size,
            ready_to_advance=not rollback_recommended and total_samples >= min_samples,
            rollback_recommended=rollback_recommended,
            reasons=reasons,
        )

    def is_ready_to_advance(self) -> tuple[bool, list[str]]:
        """Check if current stage criteria are met for advancement."""
        stage = self.get_current_stage()
        if stage == RolloutStage.CLEANUP:
            return False, ["Already at cleanup stage"]

        thresholds = self._thresholds.get(stage.value, {})
        duration_hours = thresholds.get("duration_hours", 24)
        elapsed = (time.time() - self._state["stage_started_at"]) / 3600

        reasons: list[str] = []
        ready = True

        if elapsed < duration_hours:
            ready = False
            reasons.append(f"Duration {elapsed:.1f}h < required {duration_hours}h")

        if self._state.get("rollback_recommended", False):
            ready = False
            reasons.append("Rollback is currently recommended")

        if self._state.get("current_sample_size", 0) < thresholds.get("min_sample_size", 0):
            ready = False
            reasons.append("Minimum sample size not reached")

        return ready, reasons

    def update_metrics(self, stable: GroupMetrics, canary: GroupMetrics) -> None:
        """Update state with latest metrics comparison."""
        result = self.compare_versions(stable, canary)
        self._state["current_error_rate_delta"] = result.metrics[0].delta if result.metrics else 0.0
        self._state["current_latency_p99_delta_ms"] = result.metrics[1].delta if len(result.metrics) > 1 else 0.0
        self._state["current_cost_delta_usd"] = result.metrics[2].delta if len(result.metrics) > 2 else 0.0
        self._state["current_sample_size"] = stable.sample_size + canary.sample_size
        self._state["rollback_recommended"] = result.rollback_recommended
        self._save_state()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _load_state(self) -> dict[str, Any]:
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {
            "stage": "shadow",
            "stage_started_at": time.time(),
            "history": [],
        }

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self._state, indent=2))

    def _load_thresholds(self) -> dict[str, Any]:
        thresholds_file = self.config_dir / "thresholds.yml"
        if thresholds_file.exists():
            try:
                data = yaml.safe_load(thresholds_file.read_text())
                return data.get("stages", {}) if data else {}
            except (yaml.YAMLError, OSError):
                pass
        return {
            "shadow": {
                "max_error_rate_delta": 0.01,
                "max_latency_p99_delta_ms": 200,
                "min_sample_size": 1000,
                "duration_hours": 24,
            },
            "canal": {
                "max_error_rate_delta": 0.005,
                "max_latency_p99_delta_ms": 100,
                "min_sample_size": 5000,
                "duration_hours": 48,
            },
            "half": {
                "max_error_rate_delta": 0.002,
                "max_latency_p99_delta_ms": 50,
                "min_sample_size": 10000,
                "duration_hours": 72,
            },
            "full": {"max_error_rate": 0.01, "max_latency_p99_ms": 500, "min_sample_size": 20000, "duration_hours": 72},
        }

    def _check_backend_health(self, backend: str) -> bool:
        """Check if a backend is healthy. In production this would call the health endpoint."""
        # For unit tests, always return True. Real implementation would use httpx.
        return True
