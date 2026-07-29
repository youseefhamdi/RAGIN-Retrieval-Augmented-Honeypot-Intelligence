"""Tests for MultiTurnTracker — session-level TTP accumulation, evolution, escalation."""

from ragin.cycle.multi_turn import MultiTurnTracker


class TestMultiTurnTrackerBasics:
    def test_empty_session_summary(self):
        tracker = MultiTurnTracker("s1")
        s = tracker.get_summary()
        assert s.session_id == "s1"
        assert s.total_turns == 0
        assert s.unique_ttps == set()
        assert s.ttp_diversity_ratio == 0.0

    def test_single_turn(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059", "T1071"}, severity="info")
        s = tracker.get_summary()
        assert s.total_turns == 1
        assert s.unique_ttps == {"T1059", "T1071"}
        assert s.total_ttp_detections == 2
        assert s.escalation_detected is False
        assert s.persistent_ttps == []

    def test_multiple_turns_accumulate_ttps(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"})
        tracker.record_turn(2, ttps={"T1059", "T1021"})
        tracker.record_turn(3, ttps={"T1021", "T1190"})
        s = tracker.get_summary()
        assert s.total_turns == 3
        assert s.unique_ttps == {"T1059", "T1021", "T1190"}
        assert s.total_ttp_detections == 5

    def test_diversity_ratio(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"})
        tracker.record_turn(2, ttps={"T1059"})
        s = tracker.get_summary()
        assert s.ttp_diversity_ratio == 0.5  # 1 unique / 2 turns


class TestEscalationDetection:
    def test_no_escalation(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"}, severity="medium")
        tracker.record_turn(2, ttps={"T1059"}, severity="medium")
        s = tracker.get_summary()
        assert s.escalation_detected is False

    def test_escalation_detected(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"}, severity="info")
        tracker.record_turn(2, ttps={"T1059"}, severity="medium")
        s = tracker.get_summary()
        assert s.escalation_detected is True
        assert s.escalation_turn == 2
        assert s.escalation_from == "info"
        assert s.escalation_to == "medium"

    def test_high_to_critical_escalation(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1190"}, severity="high")
        tracker.record_turn(2, ttps={"T1021"}, severity="critical")
        s = tracker.get_summary()
        assert s.escalation_detected is True
        assert s.escalation_from == "high"
        assert s.escalation_to == "critical"

    def test_deescalation_not_flagged(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"}, severity="high")
        tracker.record_turn(2, ttps={"T1059"}, severity="medium")
        s = tracker.get_summary()
        assert s.escalation_detected is False


class TestPersistentTTPs:
    def test_persistent_ttp(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059", "T1071"})
        tracker.record_turn(2, ttps={"T1059", "T1021"})
        tracker.record_turn(3, ttps={"T1059"})
        s = tracker.get_summary()
        assert "T1059" in s.persistent_ttps
        assert "T1071" not in s.persistent_ttps
        assert "T1021" not in s.persistent_ttps

    def test_no_persistent_when_all_unique(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"})
        tracker.record_turn(2, ttps={"T1021"})
        tracker.record_turn(3, ttps={"T1190"})
        s = tracker.get_summary()
        assert s.persistent_ttps == []


class TestNewTTPsPerTurn:
    def test_new_ttps_tracking(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059", "T1071"})
        tracker.record_turn(2, ttps={"T1059", "T1021"})
        tracker.record_turn(3, ttps={"T1021", "T1190"})
        s = tracker.get_summary()
        assert s.new_ttps_per_turn == [2, 1, 1]


class TestTTPEvolution:
    def test_evolution_records_appearances(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"}, severity="info")
        tracker.record_turn(2, ttps={"T1059"}, severity="medium")
        tracker.record_turn(3, ttps={"T1059"}, severity="high")
        evo = tracker.get_ttp_evolution("T1059")
        assert evo is not None
        assert evo.appearances == 3
        assert evo.peak_severity == "high"
        assert evo.first_seen_turn == 1
        assert evo.last_seen_turn == 3

    def test_evolution_streak_break(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"})
        tracker.record_turn(2, ttps={"T1021"})
        tracker.record_turn(3, ttps={"T1059"})
        evo = tracker.get_ttp_evolution("T1059")
        assert evo is not None
        assert evo.appearances == 2
        assert evo.consecutive == 1  # streak broken at turn 2

    def test_missing_ttp(self):
        tracker = MultiTurnTracker("s1")
        assert tracker.get_ttp_evolution("T9999") is None


class TestReset:
    def test_reset_clears_state(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"}, severity="high")
        tracker.record_turn(2, ttps={"T1021"}, severity="critical")
        tracker.reset()
        s = tracker.get_summary()
        assert s.total_turns == 0
        assert s.unique_ttps == set()


class TestSnapshots:
    def test_snapshot_to_dict(self):
        tracker = MultiTurnTracker("s1")
        snap = tracker.record_turn(1, ttps={"T1059"}, severity="info", attacker_input="whoami")
        d = snap.to_dict()
        assert d["turn"] == 1
        assert d["ttps"] == ["T1059"]
        assert d["severity"] == "info"
        assert d["artifacts_accessed"] is False


class TestSummarySerialization:
    def test_summary_to_dict(self):
        tracker = MultiTurnTracker("s1")
        tracker.record_turn(1, ttps={"T1059"}, severity="info")
        tracker.record_turn(2, ttps={"T1059", "T1021"}, severity="high")
        s = tracker.get_summary()
        d = s.to_dict()
        assert d["session_id"] == "s1"
        assert d["total_turns"] == 2
        assert d["escalation_detected"] is True
        assert isinstance(d["unique_ttps"], list)
        assert isinstance(d["ttp_evolutions"], list)
