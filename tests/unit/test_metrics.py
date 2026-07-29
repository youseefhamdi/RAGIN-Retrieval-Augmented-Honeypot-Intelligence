"""Tests for ragin/cycle/metrics.py — StageTiming, StageTimer, InteractionMetrics,
SessionMetrics, MTTATracker."""

from __future__ import annotations

import time

from ragin.cycle.metrics import (
    InteractionMetrics,
    MTTATracker,
    SessionMetrics,
    StageTimer,
    StageTiming,
)

# ── StageTiming ────────────────────────────────────────────────────────────────


class TestStageTiming:
    def test_defaults(self) -> None:
        st = StageTiming(stage="classify")
        assert st.stage == "classify"
        assert st.start_time == 0.0
        assert st.end_time == 0.0
        assert st.duration_ms == 0.0

    def test_to_dict_rounds_duration(self) -> None:
        st = StageTiming(stage="detect", duration_ms=12.3456)
        d = st.to_dict()
        assert d["stage"] == "detect"
        assert d["duration_ms"] == 12.35

    def test_to_dict_keys(self) -> None:
        st = StageTiming(stage="respond")
        assert set(st.to_dict().keys()) == {"stage", "duration_ms"}


# ── StageTimer ─────────────────────────────────────────────────────────────────


class TestStageTimer:
    def test_track_context_manager(self) -> None:
        timer = StageTimer()
        with timer.track("fast_stage"):
            time.sleep(0.01)
        assert len(timer.timings) == 1
        assert timer.timings[0].stage == "fast_stage"
        assert timer.timings[0].duration_ms > 5  # at least ~5ms

    def test_multiple_stages(self) -> None:
        timer = StageTimer()
        with timer.track("a"):
            time.sleep(0.005)
        with timer.track("b"):
            time.sleep(0.005)
        assert len(timer.timings) == 2
        assert timer.timings[0].stage == "a"
        assert timer.timings[1].stage == "b"

    def test_total_ms(self) -> None:
        timer = StageTimer()
        with timer.track("x"):
            time.sleep(0.01)
        with timer.track("y"):
            time.sleep(0.01)
        assert timer.total_ms > 10

    def test_total_ms_empty(self) -> None:
        timer = StageTimer()
        assert timer.total_ms == 0.0

    def test_timings_returns_copy(self) -> None:
        timer = StageTimer()
        with timer.track("z"):
            pass
        t1 = timer.timings
        t2 = timer.timings
        assert t1 is not t2  # new list each time
        assert t1 == t2

    def test_reset_clears(self) -> None:
        timer = StageTimer()
        with timer.track("r"):
            pass
        timer.reset()
        assert timer.timings == []
        assert timer.total_ms == 0.0


# ── InteractionMetrics ────────────────────────────────────────────────────────


class TestInteractionMetrics:
    def test_defaults(self) -> None:
        im = InteractionMetrics()
        assert im.interaction_id == ""
        assert im.total_duration_ms == 0.0
        assert im.stages == []

    def test_stage_count(self) -> None:
        stages = [StageTiming(stage="a", duration_ms=1), StageTiming(stage="b", duration_ms=2)]
        im = InteractionMetrics(stages=stages)
        assert im.stage_count == 2

    def test_slowest_stage(self) -> None:
        stages = [
            StageTiming(stage="fast", duration_ms=10),
            StageTiming(stage="slow", duration_ms=100),
            StageTiming(stage="mid", duration_ms=50),
        ]
        im = InteractionMetrics(stages=stages)
        assert im.slowest_stage is not None
        assert im.slowest_stage.stage == "slow"

    def test_fastest_stage(self) -> None:
        stages = [
            StageTiming(stage="fast", duration_ms=10),
            StageTiming(stage="slow", duration_ms=100),
        ]
        im = InteractionMetrics(stages=stages)
        assert im.fastest_stage is not None
        assert im.fastest_stage.stage == "fast"

    def test_slowest_fastest_empty(self) -> None:
        im = InteractionMetrics()
        assert im.slowest_stage is None
        assert im.fastest_stage is None

    def test_to_dict(self) -> None:
        stages = [StageTiming(stage="s1", duration_ms=42.5)]
        im = InteractionMetrics(
            interaction_id="int-1",
            session_id="ses-1",
            attacker_input="whoami",
            total_duration_ms=42.5,
            stages=stages,
        )
        d = im.to_dict()
        assert d["interaction_id"] == "int-1"
        assert d["session_id"] == "ses-1"
        assert d["attacker_input"] == "whoami"
        assert d["total_duration_ms"] == 42.5
        assert d["stage_count"] == 1
        assert d["slowest_stage"] == "s1"
        assert d["stages"] == [{"stage": "s1", "duration_ms": 42.5}]

    def test_to_dict_long_input_truncated(self) -> None:
        im = InteractionMetrics(attacker_input="x" * 200)
        assert len(im.to_dict()["attacker_input"]) == 128

    def test_to_dict_no_stages(self) -> None:
        im = InteractionMetrics()
        d = im.to_dict()
        assert d["slowest_stage"] is None
        assert d["stages"] == []


# ── SessionMetrics ─────────────────────────────────────────────────────────────


class TestSessionMetrics:
    def test_constructor(self) -> None:
        sm = SessionMetrics(session_id="s1")
        assert sm.session_id == "s1"
        assert sm.interaction_count == 0

    def test_to_dict_empty(self) -> None:
        sm = SessionMetrics(session_id="s2")
        d = sm.to_dict()
        assert d["session_id"] == "s2"
        assert d["interaction_count"] == 0
        assert d["min_interaction_ms"] == 0  # inf → 0
        assert d["start_time"] is None
        assert d["end_time"] is None

    def test_to_dict_populated(self) -> None:
        sm = SessionMetrics(
            session_id="s3",
            interaction_count=5,
            total_duration_ms=500,
            avg_interaction_ms=100,
            max_interaction_ms=200,
            min_interaction_ms=50,
            mtta_ms=100,
        )
        d = sm.to_dict()
        assert d["interaction_count"] == 5
        assert d["mtta_ms"] == 100
        assert d["min_interaction_ms"] == 50

    def test_stage_averages_in_dict(self) -> None:
        sm = SessionMetrics(session_id="s4", stage_averages={"classify": 12.345})
        d = sm.to_dict()
        assert d["stage_averages"]["classify"] == 12.35


# ── MTTATracker ───────────────────────────────────────────────────────────────


def _make_stages(durations: list[float]) -> list[StageTiming]:
    return [StageTiming(stage=f"stage_{i}", duration_ms=d) for i, d in enumerate(durations)]


class TestMTTATracker:
    def test_init(self) -> None:
        t = MTTATracker()
        assert t.get_global_metrics()["total_interactions"] == 0
        assert t.get_global_metrics()["total_sessions"] == 0

    def test_record_interaction(self) -> None:
        t = MTTATracker()
        im = t.record_interaction(
            interaction_id="int-1",
            session_id="ses-1",
            attacker_input="ls -la",
            stages=_make_stages([10, 20, 30]),
            total_duration_ms=60,
        )
        assert im.interaction_id == "int-1"
        assert im.total_duration_ms == 60
        assert im.stage_count == 3

    def test_get_session_metrics_unknown(self) -> None:
        t = MTTATracker()
        sm = t.get_session_metrics("nonexistent")
        assert sm.session_id == "nonexistent"
        assert sm.interaction_count == 0

    def test_get_session_metrics_one_interaction(self) -> None:
        t = MTTATracker()
        t.record_interaction("int-1", "ses-1", "whoami", _make_stages([10, 20]), 30)
        sm = t.get_session_metrics("ses-1")
        assert sm.interaction_count == 1
        assert sm.mtta_ms == 30.0
        assert sm.total_duration_ms == 30
        assert sm.start_time is not None
        assert sm.end_time is not None

    def test_get_session_metrics_multiple(self) -> None:
        t = MTTATracker()
        t.record_interaction("i1", "s1", "a", _make_stages([10]), 10)
        t.record_interaction("i2", "s1", "b", _make_stages([30]), 30)
        sm = t.get_session_metrics("s1")
        assert sm.interaction_count == 2
        assert sm.avg_interaction_ms == 20.0
        assert sm.max_interaction_ms == 30
        assert sm.min_interaction_ms == 10
        assert sm.mtta_ms == 20.0

    def test_get_session_metrics_stage_averages(self) -> None:
        t = MTTATracker()
        s1 = [StageTiming(stage="detect", duration_ms=10), StageTiming(stage="respond", duration_ms=50)]
        s2 = [StageTiming(stage="detect", duration_ms=20), StageTiming(stage="respond", duration_ms=40)]
        t.record_interaction("i1", "s1", "x", s1, 60)
        t.record_interaction("i2", "s1", "y", s2, 60)
        sm = t.get_session_metrics("s1")
        assert sm.stage_averages["detect"] == 15.0
        assert sm.stage_averages["respond"] == 45.0

    def test_get_global_metrics_empty(self) -> None:
        t = MTTATracker()
        g = t.get_global_metrics()
        assert g["total_interactions"] == 0
        assert g["global_mtta_ms"] == 0.0

    def test_get_global_metrics(self) -> None:
        t = MTTATracker()
        t.record_interaction("i1", "s1", "a", _make_stages([10]), 10)
        t.record_interaction("i2", "s2", "b", _make_stages([20]), 20)
        g = t.get_global_metrics()
        assert g["total_interactions"] == 2
        assert g["total_sessions"] == 2
        assert g["global_mtta_ms"] == 15.0
        assert g["global_min_ms"] == 10
        assert g["global_max_ms"] == 20

    def test_global_metrics_stage_averages(self) -> None:
        t = MTTATracker()
        s1 = [StageTiming(stage="a", duration_ms=100), StageTiming(stage="b", duration_ms=50)]
        t.record_interaction("i1", "s1", "x", s1, 150)
        g = t.get_global_metrics()
        assert g["stage_averages"]["a"] == 100
        assert g["stage_averages"]["b"] == 50

    def test_record_finding(self) -> None:
        t = MTTATracker()
        t.record_interaction("i1", "s1", "cmd", _make_stages([10]), 10)
        t.record_finding("s1", "HIGH")
        im = t._interactions["s1"][0]
        assert im.metadata["finding_generated"] is True
        assert im.metadata["finding_severity"] == "HIGH"

    def test_record_finding_no_interactions(self) -> None:
        t = MTTATracker()
        t.record_finding("empty", "LOW")  # should not raise

    def test_record_interaction_with_metadata(self) -> None:
        t = MTTATracker()
        im = t.record_interaction("i1", "s1", "test", _make_stages([5]), 5, metadata={"key": "val"})
        assert im.metadata == {"key": "val"}
        assert im.interaction_id == "i1"

    def test_reset(self) -> None:
        t = MTTATracker()
        t.record_interaction("i1", "s1", "a", _make_stages([10]), 10)
        t.reset()
        g = t.get_global_metrics()
        assert g["total_interactions"] == 0
        sm = t.get_session_metrics("s1")
        assert sm.interaction_count == 0

    def test_multiple_sessions(self) -> None:
        t = MTTATracker()
        t.record_interaction("i1", "s1", "a", _make_stages([10]), 10)
        t.record_interaction("i2", "s2", "b", _make_stages([20]), 20)
        t.record_interaction("i3", "s1", "c", _make_stages([30]), 30)
        assert t.get_global_metrics()["total_sessions"] == 2
        assert t.get_session_metrics("s1").interaction_count == 2
        assert t.get_session_metrics("s2").interaction_count == 1

    def test_metadata_defaults_to_empty_dict(self) -> None:
        t = MTTATracker()
        im = t.record_interaction("i1", "s1", "x", _make_stages([1]), 1)
        assert im.metadata == {}
