"""Integration tests for harness.process_with_threat_modeling()."""

from __future__ import annotations

from unittest.mock import MagicMock

from ragin.cycle.harness import Harness
from ragin.cycle.metrics import MTTATracker
from ragin.cycle.session import EventType, Session
from ragin.cycle.threat_modeling import (
    AttackChainBuilder,
    ThreatModeler,
    ThreatModelResponseVerifier,
)


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


def _mock_deceiver() -> MagicMock:
    d = MagicMock()
    d.generate_response.return_value = {
        "response_text": "Welcome to Ubuntu 20.04 LTS",
        "persona_used": "novice_linux_admin",
        "engagement_score": 0.75,
        "artifacts_injected": [],
    }
    return d


def _mock_verifier(passing: bool = True) -> MagicMock:
    v = MagicMock()
    v.verify.return_value = {
        "passed": passing,
        "issues": [] if passing else ["response too short"],
        "confidence": 0.9 if passing else 0.3,
    }
    return v


# ── Basic Integration ──────────────────────────────────────────────────


class TestProcessWithThreatModeling_Basic:
    def test_full_pipeline_with_all_components(self, tmp_path):
        harness = Harness(
            classifier=_mock_classifier(),
            cti_engine=_mock_cti_engine(),
            deceiver=_mock_deceiver(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(
            session,
            "cat /etc/shadow",
            threat_modeler=ThreatModeler(),
            response_verifier=ThreatModelResponseVerifier(),
            attack_chain_builder=AttackChainBuilder(),
        )

        assert result.response_text == "Welcome to Ubuntu 20.04 LTS"
        assert result.classification["skill_level"] == "intermediate"
        assert result.cti_analysis["threat_summary"] == "SSH brute force attempt"
        assert result.total_time_ms >= 0
        assert not result.error

    def test_no_components_fallback(self, tmp_path):
        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(session, "whoami")

        assert result.response_text == ""
        assert result.events_emitted >= 2  # INPUT + SYSTEM_RESPONSE
        assert not result.error

    def test_threat_modeler_only(self, tmp_path):
        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(
            session,
            "whoami",
            threat_modeler=ThreatModeler(),
        )

        # Threat model should be emitted even without other components
        events = list(session.event_log)
        event_types = [e["event_type"] for e in events]
        assert "threat_model" in event_types
        assert result.events_emitted >= 2  # INPUT + THREAT_MODEL + SYSTEM_RESPONSE


# ── Threat Model Emission ──────────────────────────────────────────────


class TestProcessWithThreatModeling_ThreatModel:
    def test_threat_model_emitted(self, tmp_path):
        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        harness.process_with_threat_modeling(
            session,
            "cat /etc/shadow",
            threat_modeler=ThreatModeler(),
        )

        events = list(session.event_log)
        tm_events = [e for e in events if e["event_type"] == "threat_model"]
        assert len(tm_events) == 1
        tm_data = tm_events[0]["data"]
        assert "overall_risk" in tm_data
        assert "threat_count" in tm_data

    def test_threat_model_high_risk_finding_emitted(self, tmp_path):
        """Fork bomb → critical → should emit a finding event."""
        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(
            session,
            ":(){ :|:& };:",
            threat_modeler=ThreatModeler(),
        )

        events = list(session.event_log)
        finding_events = [e for e in events if e["event_type"] == "finding"]
        # Fork bomb → critical risk → should emit a finding
        assert len(finding_events) >= 1
        fd = finding_events[0]["data"]
        assert fd["risk_level"] in ("high", "critical")
        assert fd["threat_count"] > 0

    def test_no_finding_for_low_risk(self, tmp_path):
        """Low risk → no finding event."""
        harness = Harness(classifier=_mock_classifier())
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        harness.process_with_threat_modeling(
            session,
            "echo hello",
            threat_modeler=ThreatModeler(),
        )

        events = list(session.event_log)
        finding_events = [e for e in events if e["event_type"] == "finding"]
        assert len(finding_events) == 0


# ── Threat-Model-Aware Verification ────────────────────────────────────


class TestProcessWithThreatModeling_Verification:
    def test_threat_model_in_context_for_verification(self, tmp_path):
        """The threat model should be available in context when verifying."""
        v = MagicMock()
        v.verify.return_value = {
            "passed": True,
            "issues": [],
            "confidence": 0.9,
            "recommendations": [],
        }

        harness = Harness(deceiver=_mock_deceiver())
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        harness.process_with_threat_modeling(
            session,
            "whoami",
            threat_modeler=ThreatModeler(),
            response_verifier=v,
        )

        # Verify was called — and context should have included threat_model
        assert v.verify.called
        call_ctx = v.verify.call_args[0][1]  # second positional arg is context
        assert "threat_model" in call_ctx

    def test_verification_emitted(self, tmp_path):
        harness = Harness(deceiver=_mock_deceiver())
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        harness.process_with_threat_modeling(
            session,
            "whoami",
            response_verifier=ThreatModelResponseVerifier(),
        )

        events = list(session.event_log)
        verif_events = [e for e in events if e["event_type"] == "verification"]
        assert len(verif_events) == 1
        assert verif_events[0]["data"]["passed"] is True

    def test_failed_verification_triggers_retry(self, tmp_path):
        """When verification fails, harness should retry with feedback."""
        v = MagicMock()
        # Fail first call, pass on retry
        v.verify.side_effect = [
            {"passed": False, "issues": ["honeypot leak"], "confidence": 0.3, "recommendations": []},
            {"passed": True, "issues": [], "confidence": 0.9, "recommendations": []},
        ]

        harness = Harness(deceiver=_mock_deceiver(), verifier=v, max_retries=2)
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(
            session,
            "whoami",
            response_verifier=v,
        )

        # Should have retried and eventually passed
        assert v.verify.call_count == 2


# ── Attack Chain Building ──────────────────────────────────────────────


class TestProcessWithThreatModeling_AttackChain:
    def test_attack_chain_built_with_observed_ttps(self, tmp_path):
        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))

        # Pre-populate context with observed TTPs
        session.emit(
            EventType.METRIC,
            {"observed_ttps": ["T1033", "T1082"], "ttp_history": []},
            source="pre_load",
        )

        harness.process_with_threat_modeling(
            session,
            "whoami",
            attack_chain_builder=AttackChainBuilder(),
        )

        events = list(session.event_log)
        chain_events = [e for e in events if e["event_type"] == "attack_chain"]
        assert len(chain_events) >= 1
        chain_data = chain_events[0]["data"]
        assert chain_data["step_count"] >= 2

    def test_no_attack_chain_without_ttps(self, tmp_path):
        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        harness.process_with_threat_modeling(
            session,
            "whoami",
            attack_chain_builder=AttackChainBuilder(),
        )

        events = list(session.event_log)
        chain_events = [e for e in events if e["event_type"] == "attack_chain"]
        assert len(chain_events) == 0


# ── MTTA Tracking ──────────────────────────────────────────────────────


class TestProcessWithThreatModeling_MTTA:
    def test_mtta_recorded(self, tmp_path):
        harness = Harness(classifier=_mock_classifier())
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        tracker = MTTATracker()

        result = harness.process_with_threat_modeling(
            session,
            "whoami",
            mtta_tracker=tracker,
        )

        # MTTA should have recorded the interaction
        stats = tracker.get_session_stats(session.session_id)
        assert stats is not None

    def test_mtta_records_threat_model_risk(self, tmp_path):
        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        tracker = MTTATracker()

        harness.process_with_threat_modeling(
            session,
            "whoami",
            threat_modeler=ThreatModeler(),
            mtta_tracker=tracker,
        )

        stats = tracker.get_session_stats(session.session_id)
        assert stats is not None


# ── Error Handling ──────────────────────────────────────────────────────


class TestProcessWithThreatModeling_Errors:
    def test_threat_modeler_exception_graceful(self, tmp_path):
        """If threat_modeler raises, pipeline should continue."""
        broken = MagicMock()
        broken.analyze.side_effect = RuntimeError("boom")

        harness = Harness(deceiver=_mock_deceiver())
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process_with_threat_modeling(
            session,
            "whoami",
            threat_modeler=broken,
        )

        # Should still produce a response
        assert result.response_text == "Welcome to Ubuntu 20.04 LTS"
        # Error event should be emitted
        events = list(session.event_log)
        error_events = [e for e in events if e["event_type"] == "error"]
        assert any("threat_modeling" in e["data"]["stage"] for e in error_events)

    def test_attack_chain_builder_exception_graceful(self, tmp_path):
        broken = MagicMock()
        broken.build_from_session_context.side_effect = RuntimeError("chain boom")

        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))

        # Should not raise
        result = harness.process_with_threat_modeling(
            session,
            "whoami",
            attack_chain_builder=broken,
        )
        assert not result.error

    def test_mtta_tracker_exception_graceful(self, tmp_path):
        broken = MagicMock()
        broken.record_interaction.side_effect = RuntimeError("mtta boom")

        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))

        result = harness.process_with_threat_modeling(
            session,
            "whoami",
            mtta_tracker=broken,
        )
        # Should not fail
        assert not result.error
