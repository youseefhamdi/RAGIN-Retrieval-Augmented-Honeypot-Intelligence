"""Verify honeytoken_triggered propagates from DeceptionResponse to cti_analysis."""

from __future__ import annotations

from unittest.mock import MagicMock

from ragin.cycle.harness import Harness
from ragin.cycle.session import Session


def _mock_deceiver(honeytoken_triggered: bool = False) -> MagicMock:
    d = MagicMock()
    d.generate_response.return_value = {
        "response_text": "Welcome to Ubuntu 20.04 LTS",
        "persona_used": "novice_linux_admin",
        "engagement_score": 0.75,
        "artifacts_injected": [],
        "honeytoken_triggered": honeytoken_triggered,
    }
    return d


def _mock_classifier() -> MagicMock:
    c = MagicMock()
    c.classify.return_value = {"skill_level": "intermediate", "confidence": 0.8}
    return c


def _mock_cti_engine() -> MagicMock:
    e = MagicMock()
    e.analyze.return_value = {
        "threat_summary": "SSH brute force attempt",
        "recommendations": ["rate limit", "honeytoken"],
    }
    return e


class TestHoneytokenPropagation_Process:
    def test_honeytoken_propagates_in_process(self, tmp_path):
        """honeytoken_triggered=True from deceiver should appear in cti_analysis."""
        harness = Harness(
            deceiver=_mock_deceiver(honeytoken_triggered=True),
            classifier=_mock_classifier(),
            cti_engine=_mock_cti_engine(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "cat /etc/shadow")

        assert result.cti_analysis.get("honeytoken_triggered") is True

    def test_no_honeytoken_when_false(self, tmp_path):
        """When deceiver returns honeytoken_triggered=False, cti_analysis should not have it."""
        harness = Harness(
            deceiver=_mock_deceiver(honeytoken_triggered=False),
            classifier=_mock_classifier(),
            cti_engine=_mock_cti_engine(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "cat /etc/shadow")

        assert result.cti_analysis.get("honeytoken_triggered") is not True

    def test_no_honeytoken_when_absent(self, tmp_path):
        """When deceiver omits honeytoken_triggered, cti_analysis should not have it."""
        d = MagicMock()
        d.generate_response.return_value = {
            "response_text": "Welcome",
            "persona_used": "novice",
            "engagement_score": 0.5,
            "artifacts_injected": [],
        }
        harness = Harness(
            deceiver=d,
            classifier=_mock_classifier(),
            cti_engine=_mock_cti_engine(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")

        assert result.cti_analysis.get("honeytoken_triggered") is not True


class TestHoneytokenPropagation_ProcessWithThreatModeling:
    def test_honeytoken_propagates_in_pwtm(self, tmp_path):
        """honeytoken_triggered=True should propagate via process_with_threat_modeling (used by bridge)."""
        harness = Harness(
            deceiver=_mock_deceiver(honeytoken_triggered=True),
            classifier=_mock_classifier(),
            cti_engine=_mock_cti_engine(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(
            session,
            "cat /etc/shadow",
        )

        assert result.cti_analysis.get("honeytoken_triggered") is True

    def test_no_honeytoken_when_false_pwtm(self, tmp_path):
        """When honeytoken_triggered=False, cti_analysis should not have it (pwtm path)."""
        harness = Harness(
            deceiver=_mock_deceiver(honeytoken_triggered=False),
            classifier=_mock_classifier(),
            cti_engine=_mock_cti_engine(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(
            session,
            "cat /etc/shadow",
        )

        assert result.cti_analysis.get("honeytoken_triggered") is not True

    def test_honeytoken_does_not_overwrite_existing_cti(self, tmp_path):
        """honeytoken_triggered should not overwrite other cti_analysis keys."""
        harness = Harness(
            deceiver=_mock_deceiver(honeytoken_triggered=True),
            classifier=_mock_classifier(),
            cti_engine=_mock_cti_engine(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(
            session,
            "cat /etc/shadow",
        )

        # Original CTI keys should still be present
        assert result.cti_analysis["threat_summary"] == "SSH brute force attempt"
        assert result.cti_analysis["honeytoken_triggered"] is True
