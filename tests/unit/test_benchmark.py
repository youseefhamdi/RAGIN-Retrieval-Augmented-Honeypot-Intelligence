"""Unit tests for the RAGIN benchmarking harness."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from ragin.benchmark import (
    CTI_ACTOR_QUERIES,
    CTI_TECHNIQUE_QUERIES,
    PERSONA_REALISM_QUERIES,
    BenchmarkReport,
    BenchmarkResult,
    _score_actor_match,
    _score_memory_recall,
    _score_persona_realism,
    _score_technique_match,
    generate_report,
    run_cti_benchmarks,
    run_deception_benchmarks,
    run_memory_benchmarks,
    save_report,
)

# ── Scoring Functions ────────────────────────────────────────────────────────


class TestScoreTechniqueMatch:
    def test_exact_match(self) -> None:
        response = "This uses T1566.001 - Phishing Attachment"
        assert _score_technique_match(response, "T1566.001") >= 0.8

    def test_technique_number_only(self) -> None:
        response = "The T1566 technique involves phishing"
        score = _score_technique_match(response, "T1566.001")
        assert 0.3 <= score <= 0.7

    def test_no_match(self) -> None:
        response = "This is about web servers and Apache"
        assert _score_technique_match(response, "T1566.001") < 0.2

    def test_mitre_keyword_bonus(self) -> None:
        response = "This MITRE ATT&CK technique is about credential dumping"
        score = _score_technique_match(response, "T1003.001")
        assert 0.1 <= score <= 0.5


class TestScoreActorMatch:
    def test_exact_actor(self) -> None:
        response = "Salt Typhoon is a Chinese threat actor"
        score = _score_actor_match(response, "salt typhoon", "telecommunications")
        assert score >= 0.5

    def test_actor_and_sector(self) -> None:
        response = "APT28 targets government agencies and conducts espionage"
        score = _score_actor_match(response, "apt28", "government")
        assert score >= 0.7

    def test_no_match(self) -> None:
        response = "This is about a completely different topic"
        assert _score_actor_match(response, "apt28", "government") < 0.2


class TestScorePersonaRealism:
    def test_technical_response(self) -> None:
        response = "I'm running Apache 2.4.52 on port 443. The server is configured with mod_ssl and uses Let's Encrypt certificates."
        score = _score_persona_realism(response, ["specific version", "server details"])
        assert score >= 0.5

    def test_empty_response(self) -> None:
        assert _score_persona_realism("", ["some trait"]) == 0.0

    def test_refusal_response(self) -> None:
        response = "I'm not authorized to share that information. You'll need to submit a ticket through the help desk."
        score = _score_persona_realism(response, ["refusal or social engineering"])
        assert score >= 0.3


class TestScoreMemoryRecall:
    def test_perfect_recall(self) -> None:
        response = "The attacker used SSH to access the server and tried to escalate privileges"
        score = _score_memory_recall(response, ["ssh", "configuration", "privilege"])
        assert score >= 0.6

    def test_partial_recall(self) -> None:
        response = "The attacker used nmap for scanning"
        score = _score_memory_recall(response, ["nmap", "scan", "network"])
        assert 0.3 <= score <= 0.8

    def test_no_recall(self) -> None:
        response = "I don't have any information about that"
        assert _score_memory_recall(response, ["ssh", "nmap"]) == 0.0


# ── Benchmark Data Completeness ──────────────────────────────────────────────


class TestBenchmarkData:
    def test_cti_technique_queries_count(self) -> None:
        assert len(CTI_TECHNIQUE_QUERIES) >= 10

    def test_cti_actor_queries_count(self) -> None:
        assert len(CTI_ACTOR_QUERIES) >= 3

    def test_persona_queries_count(self) -> None:
        assert len(PERSONA_REALISM_QUERIES) >= 5

    def test_all_queries_have_required_fields(self) -> None:
        for qa in CTI_TECHNIQUE_QUERIES:
            assert "query" in qa
            assert "expected_technique" in qa
            assert "expected_tactic" in qa
            assert "category" in qa


# ── BenchmarkResult & BenchmarkReport ────────────────────────────────────────


class TestBenchmarkResult:
    def test_create_result(self) -> None:
        result = BenchmarkResult(
            name="test_benchmark",
            suite="cti",
            passed=True,
            score=0.85,
            latency_ms=120.5,
            details={"key": "value"},
        )
        assert result.name == "test_benchmark"
        assert result.passed is True
        assert result.score == 0.85
        assert result.error is None

    def test_create_failed_result(self) -> None:
        result = BenchmarkResult(
            name="failed_benchmark",
            suite="deception",
            passed=False,
            score=0.0,
            latency_ms=50.0,
            error="Connection timeout",
        )
        assert result.passed is False
        assert result.error == "Connection timeout"


class TestBenchmarkReport:
    def test_generate_report(self) -> None:
        results = [
            BenchmarkResult("r1", "cti", True, 0.9, 100.0),
            BenchmarkResult("r2", "cti", True, 0.7, 150.0),
            BenchmarkResult("r3", "memory", False, 0.1, 200.0, error="timeout"),
        ]
        report = generate_report(results, "all")
        assert report.total_tests == 3
        assert report.passed == 2
        assert report.failed == 1
        assert report.avg_score == pytest.approx(0.567, abs=0.01)
        assert report.avg_latency_ms == pytest.approx(150.0, abs=1.0)
        assert report.summary["pass_rate"] == "66.7%"

    def test_empty_report(self) -> None:
        report = generate_report([], "cti")
        assert report.total_tests == 0
        assert report.avg_score == 0.0


# ── Save Report ──────────────────────────────────────────────────────────────


class TestSaveReport:
    def test_save_creates_file(self, tmp_path: Path) -> None:
        report = BenchmarkReport(
            run_id="test_123",
            timestamp="2026-01-01T00:00:00Z",
            suite="cti",
            total_tests=1,
            passed=1,
            failed=0,
            avg_score=0.9,
            avg_latency_ms=100.0,
            results=[BenchmarkResult("r1", "cti", True, 0.9, 100.0)],
            summary={"pass_rate": "100%"},
        )
        path = save_report(report, tmp_path / "report.json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["run_id"] == "test_123"
        assert data["total_tests"] == 1
        assert len(data["results"]) == 1


# ── Async Benchmark Runs ────────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_run_cti_benchmarks_with_mock_adapter() -> None:
    mock_adapter = AsyncMock()
    mock_adapter.query_data = AsyncMock(
        return_value={"response": "This is T1566.001 - Phishing Attachment, used for initial access"}
    )

    results = await run_cti_benchmarks(mock_adapter)
    assert len(results) == len(CTI_TECHNIQUE_QUERIES) + len(CTI_ACTOR_QUERIES)
    assert all(r.suite == "cti" for r in results)
    assert all(r.latency_ms >= 0 for r in results)


@pytest.mark.asyncio()
async def test_run_cti_benchmarks_with_error() -> None:
    mock_adapter = AsyncMock()
    mock_adapter.query_data = AsyncMock(side_effect=Exception("LLM timeout"))

    results = await run_cti_benchmarks(mock_adapter)
    assert len(results) > 0
    assert all(not r.passed for r in results)
    assert all(r.error == "LLM timeout" for r in results)


@pytest.mark.asyncio()
async def test_run_deception_benchmarks_with_mock() -> None:
    mock_hisoka = AsyncMock()
    mock_response = MagicMock()
    mock_response.text = "I'm running Apache 2.4.52 on port 443 with mod_ssl enabled"
    mock_hisoka.generate_response = AsyncMock(return_value=mock_response)

    results = await run_deception_benchmarks(mock_hisoka)
    assert len(results) == len(PERSONA_REALISM_QUERIES)
    assert all(r.suite == "deception" for r in results)


@pytest.mark.asyncio()
async def test_run_memory_benchmarks_with_mock() -> None:
    mock_memory = AsyncMock()
    mock_memory.add_interaction = AsyncMock(return_value={"id": "mem1"})
    mock_memory.add_attacker_profile = AsyncMock(return_value={"id": "prof1"})
    mock_memory.search_attacker_history = AsyncMock(
        return_value=[
            {"id": "m1", "memory": "Attacker used SSH configuration", "score": 0.9},
            {"id": "m2", "memory": "Attacker tried privilege escalation", "score": 0.8},
        ]
    )

    results = await run_memory_benchmarks(mock_memory)
    assert len(results) > 0
    assert all(r.suite == "memory" for r in results)


@pytest.mark.asyncio()
async def test_run_all_suites_with_mocks() -> None:
    """Test running all suites with all components mocked."""
    from ragin.benchmark.run_benchmarks import _run_suite

    mock_adapter = AsyncMock()
    mock_adapter.query_data = AsyncMock(return_value={"response": "T1566.001 phishing attachment technique"})

    mock_hisoka = AsyncMock()
    mock_response = MagicMock()
    mock_response.text = "Running Apache 2.4.52"
    mock_hisoka.generate_response = AsyncMock(return_value=mock_response)

    mock_memory = AsyncMock()
    mock_memory.add_interaction = AsyncMock(return_value={"id": "m1"})
    mock_memory.add_attacker_profile = AsyncMock(return_value={"id": "p1"})
    mock_memory.search_attacker_history = AsyncMock(
        return_value=[{"id": "m1", "memory": "SSH config discussed", "score": 0.9}]
    )

    report = await _run_suite(
        "all",
        adapter=mock_adapter,
        hisoka=mock_hisoka,
        memory=mock_memory,
    )

    assert report.total_tests > 0
    assert len(report.results) > 0
    # Should have results from all three suites
    suites_found = {r.suite for r in report.results}
    assert "cti" in suites_found
    assert "deception" in suites_found
    assert "memory" in suites_found
