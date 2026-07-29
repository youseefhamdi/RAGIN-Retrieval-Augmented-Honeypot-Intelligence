"""Unit tests for ragin.rollout module."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ragin.rollout.manager import RolloutManager
from ragin.rollout.metrics import GroupMetrics, RolloutMetrics
from ragin.rollout.models import ComparisonResult, RolloutHealth, RolloutStage

# ── RolloutStage model ───────────────────────────────────────────────────────


class TestRolloutStage:
    def test_valid_progression(self) -> None:
        assert RolloutStage.SHADOW.next() == RolloutStage.CANAL
        assert RolloutStage.CANAL.next() == RolloutStage.HALF
        assert RolloutStage.HALF.next() == RolloutStage.FULL
        assert RolloutStage.FULL.next() == RolloutStage.CLEANUP
        assert RolloutStage.CLEANUP.next() is None

    def test_previous(self) -> None:
        assert RolloutStage.CANAL.previous() == RolloutStage.SHADOW
        assert RolloutStage.SHADOW.previous() is None

    def test_order(self) -> None:
        order = RolloutStage.order()
        assert order == [
            RolloutStage.SHADOW,
            RolloutStage.CANAL,
            RolloutStage.HALF,
            RolloutStage.FULL,
            RolloutStage.CLEANUP,
        ]


# ── RolloutManager ───────────────────────────────────────────────────────────


class TestRolloutManager:
    def test_rollout_stage_transitions(self, tmp_path: Path) -> None:
        # Write thresholds BEFORE creating manager so they're loaded at init
        thresholds = {
            "stages": {
                "shadow": {"duration_hours": 0, "min_sample_size": 0},
                "canal": {"duration_hours": 0, "min_sample_size": 0},
                "half": {"duration_hours": 0, "min_sample_size": 0},
                "full": {"duration_hours": 0, "min_sample_size": 0},
            }
        }
        (tmp_path / "thresholds.yml").write_text(yaml.dump(thresholds))

        state_path = tmp_path / "state.json"
        manager = RolloutManager(config_path=tmp_path, state_path=state_path)
        assert manager.get_current_stage() == RolloutStage.SHADOW

        # Advance through all stages
        ok, reasons = manager.advance_stage()
        assert ok
        assert manager.get_current_stage() == RolloutStage.CANAL

        ok, _ = manager.advance_stage()
        assert ok
        assert manager.get_current_stage() == RolloutStage.HALF

        ok, _ = manager.advance_stage()
        assert ok
        assert manager.get_current_stage() == RolloutStage.FULL

        ok, _ = manager.advance_stage()
        assert ok
        assert manager.get_current_stage() == RolloutStage.CLEANUP

        # Cannot advance past cleanup
        ok, reasons = manager.advance_stage()
        assert not ok
        assert "final" in reasons[0].lower()

    def test_rollback_on_high_errors(self, tmp_path: Path) -> None:
        manager = RolloutManager(config_path=tmp_path, state_path=tmp_path / "state.json")

        # Simulate high error rate
        stable = GroupMetrics(error_count=10, total_requests=1000, sample_size=500)
        canary = GroupMetrics(error_count=50, total_requests=500, sample_size=500)
        result = manager.compare_versions(stable, canary)

        assert result.rollback_recommended
        assert result.metrics[0].delta > 0  # error rate increased

        # Rollback
        prev = manager.rollback("High error rate in canary")
        assert prev == RolloutStage.SHADOW

    def test_rollback_on_high_latency(self, tmp_path: Path) -> None:
        manager = RolloutManager(config_path=tmp_path, state_path=tmp_path / "state.json")

        stable = GroupMetrics(
            latency_p99_ms=100,
            latency_mean_ms=50,
            total_requests=1000,
            sample_size=1000,
        )
        canary = GroupMetrics(
            latency_p99_ms=500,
            latency_mean_ms=300,
            total_requests=1000,
            sample_size=1000,
        )
        result = manager.compare_versions(stable, canary)

        assert result.rollback_recommended
        lat_comparison = [m for m in result.metrics if "latency" in m.metric_name][0]
        assert lat_comparison.delta > 0

    def test_advance_requires_min_samples(self, tmp_path: Path) -> None:
        thresholds = {
            "stages": {
                "shadow": {"duration_hours": 0, "min_sample_size": 10000},
            }
        }
        (tmp_path / "thresholds.yml").write_text(yaml.dump(thresholds))

        manager = RolloutManager(config_path=tmp_path, state_path=tmp_path / "state.json")
        manager._state["current_sample_size"] = 100

        ok, reasons = manager.is_ready_to_advance()
        assert not ok
        assert any("sample size" in r.lower() for r in reasons)

    def test_health_check(self, tmp_path: Path) -> None:
        manager = RolloutManager(config_path=tmp_path, state_path=tmp_path / "state.json")
        health = manager.check_health()
        assert isinstance(health, RolloutHealth)
        assert health.stage == RolloutStage.SHADOW
        assert health.is_healthy

    def test_compare_versions(self, tmp_path: Path) -> None:
        manager = RolloutManager(config_path=tmp_path, state_path=tmp_path / "state.json")

        stable = GroupMetrics(
            error_count=50,
            total_requests=10000,
            latency_p99_ms=200,
            latency_mean_ms=100,
            cost_usd=1.0,
            sample_size=5000,
        )
        canary = GroupMetrics(
            error_count=48,
            total_requests=10000,
            latency_p99_ms=190,
            latency_mean_ms=95,
            cost_usd=1.05,
            sample_size=5000,
        )

        result = manager.compare_versions(stable, canary)
        assert isinstance(result, ComparisonResult)
        assert len(result.metrics) == 3
        assert result.metrics[0].metric_name == "error_rate"
        assert result.metrics[1].metric_name == "latency_p99_ms"
        assert result.metrics[2].metric_name == "cost_usd"
        # Canary is slightly better, no rollback
        assert not result.rollback_recommended


# ── RolloutMetrics ───────────────────────────────────────────────────────────


class TestRolloutMetrics:
    def test_metric_comparison(self) -> None:
        rm = RolloutMetrics()
        control = GroupMetrics(error_count=10, total_requests=1000, sample_size=1000)
        treatment = GroupMetrics(error_count=10, total_requests=1000, sample_size=1000)

        comparisons = rm.compare_groups(control, treatment)
        assert len(comparisons) == 3
        # Same groups → delta should be ~0
        assert abs(comparisons[0].delta) < 0.001

    def test_proportion_z_test_equal(self) -> None:
        p = RolloutMetrics._proportion_z_test(50, 1000, 50, 1000)
        assert p > 0.05  # not significant

    def test_proportion_z_test_different(self) -> None:
        p = RolloutMetrics._proportion_z_test(5, 1000, 50, 1000)
        assert p < 0.05  # significant

    def test_normal_sf(self) -> None:
        # At z=0, survival = 0.5
        assert abs(RolloutMetrics._normal_sf(0) - 0.5) < 0.01
        # At z=3, survival ≈ 0.0013
        assert RolloutMetrics._normal_sf(3) < 0.01


# ── Shadow mode ──────────────────────────────────────────────────────────────


class TestShadowMode:
    def test_shadow_mode_no_traffic(self, tmp_path: Path) -> None:
        """Shadow mode: canary_percent=0, shadow_percent=100. Responses discarded."""
        stage_file = tmp_path / "stage-0-shadow.yml"
        stage_file.write_text(
            yaml.dump(
                {
                    "stage": "shadow",
                    "traffic_split": {
                        "stable_percent": 100,
                        "canary_percent": 0,
                        "shadow_percent": 100,
                    },
                    "monitoring": {"response_discarded": True},
                }
            )
        )

        data = yaml.safe_load(stage_file.read_text())
        assert data["traffic_split"]["canary_percent"] == 0
        assert data["traffic_split"]["shadow_percent"] == 100
        assert data["monitoring"]["response_discarded"] is True


# ── Canary weight distribution ───────────────────────────────────────────────


class TestCanaryWeight:
    def test_canary_weight_distribution(self) -> None:
        """Nginx weighted upstream: 90% stable, 10% canary."""
        nginx_conf = Path(__file__).resolve().parent.parent.parent / "ragin" / "config" / "nginx-canary.conf"
        if not nginx_conf.exists():
            pytest.skip("nginx-canary.conf not found")
        content = nginx_conf.read_text()
        assert "weight=90" in content
        assert "weight=10" in content
        assert "hisoka-stable" in content
        assert "hisoka-canary" in content


# ── Sticky sessions ──────────────────────────────────────────────────────────


class TestStickySessions:
    def test_sticky_sessions(self) -> None:
        """Cookie-based sticky sessions: users stay on same version."""
        nginx_conf = Path(__file__).resolve().parent.parent.parent / "ragin" / "config" / "nginx-canary.conf"
        if not nginx_conf.exists():
            pytest.skip("nginx-canary.conf not found")
        content = nginx_conf.read_text()
        assert "ragin_canary" in content
        assert "$cookie_ragin_canary" in content


# ── YAML validation ──────────────────────────────────────────────────────────


class TestYAMLConfigs:
    def test_all_stage_yamls_valid(self) -> None:
        rollout_dir = Path(__file__).resolve().parent.parent.parent / "ragin" / "config" / "rollout"
        for name in [
            "stage-0-shadow.yml",
            "stage-1-canal.yml",
            "stage-2-half.yml",
            "stage-3-full.yml",
            "stage-4-cleanup.yml",
            "thresholds.yml",
        ]:
            path = rollout_dir / name
            assert path.exists(), f"Missing {name}"
            data = yaml.safe_load(path.read_text())
            assert data is not None, f"Empty YAML: {name}"

    def test_thresholds_yaml_structure(self) -> None:
        rollout_dir = Path(__file__).resolve().parent.parent.parent / "ragin" / "config" / "rollout"
        data = yaml.safe_load((rollout_dir / "thresholds.yml").read_text())
        assert "stages" in data
        for stage in ["shadow", "canal", "half", "full"]:
            assert stage in data["stages"]
            assert "duration_hours" in data["stages"][stage]
