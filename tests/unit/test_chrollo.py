"""Unit tests for Chrollo — Behavioral Classification component.

Tests exercise the real chrollo module: models, FeatureExtractor,
ChrolloClassifier, SessionLogParser, and ChrolloPipeline.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum

import pytest

from ragin.chrollo import (
    FEATURE_NAMES,
    ChrolloClassifier,
    ChrolloPipeline,
    ClassificationResult,
    CommandEntry,
    FeatureExtractor,
    FileOperation,
    NetworkActivity,
    SessionLog,
    SessionLogParser,
    SkillLevel,
)

pytestmark = pytest.mark.unit

NOW = datetime.now(tz=timezone.utc)


def _make_session(
    session_id: str = "test",
    commands: list[CommandEntry] | None = None,
    file_ops: list[FileOperation] | None = None,
    net: list[NetworkActivity] | None = None,
    raw_log: str = "",
) -> SessionLog:
    return SessionLog(
        session_id=session_id,
        source_ip="10.0.0.1",
        start_time=NOW,
        end_time=NOW,
        commands=commands or [],
        file_operations=file_ops or [],
        network_activity=net or [],
        raw_log=raw_log,
    )


# ── SkillLevel ─────────────────────────────────────────────────────────────


class TestSkillLevelEnum:
    def test_all_values_exist(self):
        assert {s.value for s in SkillLevel} == {"novice", "intermediate", "expert", "apt"}

    def test_is_str_enum(self):
        assert issubclass(SkillLevel, str)
        assert issubclass(SkillLevel, Enum)


# ── Models ──────────────────────────────────────────────────────────────────


class TestCommandEntry:
    def test_sanitize_strips_surrounding_whitespace(self):
        cmd = CommandEntry(timestamp=NOW, command="  ls -la  ")
        assert cmd.command == "ls -la"

    def test_max_length_enforced(self):
        with pytest.raises(Exception, match="maximum allowed length"):
            CommandEntry(timestamp=NOW, command="x" * 4097)

    def test_optional_fields(self):
        cmd = CommandEntry(
            timestamp=NOW,
            command="whoami",
            working_directory="/tmp",
            user="root",
            exit_code=0,
            output_length=100,
        )
        assert cmd.user == "root"
        assert cmd.exit_code == 0


class TestFileOperation:
    def test_requires_timestamp(self):
        with pytest.raises(Exception, match="Field required"):
            FileOperation(operation="read", path="/etc/passwd")

    def test_valid_create(self):
        fo = FileOperation(timestamp=NOW, operation="create", path="/tmp/payload", size=1024)
        assert fo.size == 1024

    def test_max_path_length(self):
        with pytest.raises(Exception, match="maximum allowed length"):
            FileOperation(timestamp=NOW, operation="read", path="/a" * 1025)


class TestNetworkActivity:
    def test_requires_timestamp(self):
        with pytest.raises(Exception, match="Field required"):
            NetworkActivity(protocol="tcp")

    def test_valid_network(self):
        na = NetworkActivity(
            timestamp=NOW,
            protocol="https",
            destination_ip="1.2.3.4",
            destination_port=443,
            bytes_sent=1024,
            bytes_received=2048,
        )
        assert na.destination_port == 443
        assert na.bytes_sent == 1024

    def test_defaults(self):
        na = NetworkActivity(timestamp=NOW, protocol="tcp")
        assert na.source_ip == ""
        assert na.destination_port == 0


class TestSessionLog:
    def test_session_id_is_hashed(self):
        s = _make_session(session_id="abc123")
        # session_id is sha256 of "abc123" truncated to 64 chars
        import hashlib

        expected = hashlib.sha256(b"abc123").hexdigest()[:64]
        assert s.session_id == expected

    def test_empty_session_id_rejected(self):
        with pytest.raises(Exception):
            _make_session(session_id="")

    def test_long_session_id_rejected(self):
        with pytest.raises(Exception):
            _make_session(session_id="x" * 257)

    def test_invalid_ip_rejected(self):
        with pytest.raises(Exception):
            _make_session(session_id="a")
            SessionLog(
                session_id="a",
                source_ip="not-an-ip",
                start_time=NOW,
            )

    def test_valid_ipv6(self):
        s = SessionLog(
            session_id="ok",
            source_ip="::1",
            start_time=NOW,
        )
        # IPs are hashed for privacy — check we get a 64-char hex digest
        assert len(s.source_ip) == 64
        assert all(c in "0123456789abcdef" for c in s.source_ip)

    def test_raw_log_not_sanitized(self):
        s = _make_session(raw_log="log\x00\x01data")
        assert "\x00" in s.raw_log  # raw_log is NOT stripped

    def test_raw_log_max_length(self):
        with pytest.raises(Exception):
            _make_session(raw_log="x" * 1_000_001)

    def test_optional_tags_and_metadata(self):
        s = SessionLog(
            session_id="meta",
            start_time=NOW,
            tags=["apt", "lateral"],
            metadata={"source": "cowrie"},
        )
        assert s.tags == ["apt", "lateral"]
        assert s.metadata["source"] == "cowrie"


class TestClassificationRequest:
    def test_valid(self):
        from ragin.chrollo.models import ClassificationRequest

        s = _make_session()
        cr = ClassificationRequest(session_log=s)
        assert cr.request_id == ""


class TestEscalationPayload:
    def test_valid(self):
        from ragin.chrollo.models import EscalationPayload

        s = _make_session()
        ep = EscalationPayload(
            session_id="s1",
            skill_level=SkillLevel.EXPERT,
            confidence=0.85,
            session_log=s,
        )
        assert ep.features_used == []

    def test_confidence_bounds(self):
        from ragin.chrollo.models import EscalationPayload

        s = _make_session()
        with pytest.raises(Exception):
            EscalationPayload(
                session_id="s1",
                skill_level=SkillLevel.EXPERT,
                confidence=1.5,
                session_log=s,
            )


class TestEscalationResponse:
    def test_valid(self):
        from ragin.chrollo.models import EscalationResponse

        er = EscalationResponse(request_id="r1", status="accepted", message="ok")
        assert er.status == "accepted"

    def test_defaults(self):
        from ragin.chrollo.models import EscalationResponse

        er = EscalationResponse(request_id="r1")
        assert er.status == "accepted"
        assert er.message == ""


class TestTrainingSample:
    def test_valid(self):
        from ragin.chrollo.models import TrainingSample

        s = _make_session()
        ts = TrainingSample(session_log=s, skill_level=SkillLevel.NOVICE)
        assert ts.features == {}


# ── Feature Extraction ─────────────────────────────────────────────────────


class TestFeatureExtraction:
    def test_returns_all_features(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="ls -la"),
            ]
        )
        features = FeatureExtractor().extract(session)
        for name in FEATURE_NAMES:
            assert name in features, f"Missing feature: {name}"
            assert isinstance(features[name], float)

    def test_empty_session(self):
        features = FeatureExtractor().extract(_make_session())
        assert "command_complexity" in features
        assert features["command_complexity"] == 0.0

    def test_command_complexity(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="simple"),
                CommandEntry(timestamp=NOW, command="ls -la /etc/passwd"),
            ]
        )
        features = FeatureExtractor().extract(session)
        assert features["command_complexity"] > 0.0

    def test_tool_usage_diversity(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="ls"),
                CommandEntry(timestamp=NOW, command="cat /etc/passwd"),
            ]
        )
        features = FeatureExtractor().extract(session)
        assert features["tool_usage_diversity"] > 0.0

    def test_persistence_patterns(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="crontab -e"),
                CommandEntry(timestamp=NOW, command="systemctl enable backdoor"),
            ]
        )
        features = FeatureExtractor().extract(session)
        assert features["persistence_techniques"] > 0.0

    def test_privilege_escalation(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="sudo -i"),
                CommandEntry(timestamp=NOW, command="chmod 4700 /tmp/shell"),
            ]
        )
        features = FeatureExtractor().extract(session)
        assert features["privilege_escalation_attempts"] > 0.0

    def test_network_scan(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="nmap -sV 10.0.0.0/24"),
            ]
        )
        features = FeatureExtractor().extract(session)
        assert features["network_scan_detected"] == 1.0

    def test_credential_access(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="cat /etc/shadow"),
            ]
        )
        features = FeatureExtractor().extract(session)
        assert features["credential_access_attempts"] > 0.0

    def test_custom_tool_usage(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="python3 -c 'import os'"),
            ]
        )
        features = FeatureExtractor().extract(session)
        assert features["custom_tool_usage"] > 0.0

    def test_lateral_movement(self):
        session = _make_session(
            commands=[
                CommandEntry(timestamp=NOW, command="ssh -J user@host target"),
            ]
        )
        features = FeatureExtractor().extract(session)
        assert features["lateral_movement_indicators"] > 0.0

    def test_time_cv_zero_commands(self):
        features = FeatureExtractor().extract(_make_session())
        assert features["time_between_commands"] == 0.0

    def test_extract_batch(self):
        sessions = [
            _make_session(
                session_id=f"s{i}",
                commands=[
                    CommandEntry(timestamp=NOW, command=f"cmd{i}"),
                ],
            )
            for i in range(5)
        ]
        df = FeatureExtractor().extract_batch(sessions)
        assert len(df) == 5
        assert all(col in df.columns for col in FEATURE_NAMES)


# ── Classifier ──────────────────────────────────────────────────────────────


class TestClassifier:
    @staticmethod
    def _make_training_data(n: int = 20):
        data = []
        for i in range(n):
            level = SkillLevel.NOVICE if i < n // 2 else SkillLevel.EXPERT
            data.append(
                (
                    _make_session(
                        session_id=f"train_{i}",
                        commands=[CommandEntry(timestamp=NOW, command=f"cmd_{j}") for j in range(i % 10 + 1)],
                    ),
                    level,
                )
            )
        return data

    def test_train_and_classify(self, tmp_path):
        classifier = ChrolloClassifier(model_path=str(tmp_path / "model.pkl"))
        metrics = classifier.train(self._make_training_data(), n_estimators=10, cv_folds=2)
        assert "accuracy" in metrics
        assert metrics["accuracy"] >= 0.0

        result = classifier.classify(
            _make_session(
                session_id="test_c", commands=[CommandEntry(timestamp=NOW, command=f"adv_{j}") for j in range(5)]
            )
        )
        assert isinstance(result, ClassificationResult)
        assert result.skill_level in list(SkillLevel)
        assert 0.0 <= result.confidence <= 1.0

    def test_train_too_few_samples(self, tmp_path):
        classifier = ChrolloClassifier(model_path=str(tmp_path / "m.pkl"))
        with pytest.raises(ValueError, match="at least 10"):
            classifier.train(self._make_training_data(5))

    def test_feature_importance(self, tmp_path):
        classifier = ChrolloClassifier(model_path=str(tmp_path / "m.pkl"))
        classifier.train(self._make_training_data(), n_estimators=10, cv_folds=2)
        imp = classifier.get_feature_importance()
        assert len(imp) == len(FEATURE_NAMES)
        assert all(isinstance(v, float) for v in imp.values())

    def test_save_load(self, tmp_path):
        classifier = ChrolloClassifier(model_path=str(tmp_path / "model.pkl"))
        classifier.train(self._make_training_data(), n_estimators=10, cv_folds=2)
        assert (tmp_path / "model.pkl").exists()
        assert (tmp_path / "model.scaler.joblib").exists()

        loaded = ChrolloClassifier(model_path=str(tmp_path / "model.pkl"))
        result = loaded.classify(_make_session())
        assert isinstance(result, ClassificationResult)

    def test_classify_untrained_raises(self, tmp_path):
        classifier = ChrolloClassifier(model_path=str(tmp_path / "nonexistent.pkl"))
        with pytest.raises(RuntimeError):
            classifier.classify(_make_session())

    def test_load_nonexistent_model(self, tmp_path):
        classifier = ChrolloClassifier(model_path=str(tmp_path / "nonexistent.pkl"))
        assert classifier._loaded is False


class TestClassificationResult:
    def test_label_property(self):
        cr = ClassificationResult(
            skill_level=SkillLevel.APT,
            confidence=0.99,
            features_used=[],
            session_id="s1",
        )
        assert cr.label == "apt"


# ── Session Log Parser ─────────────────────────────────────────────────────


class TestSessionParsing:
    def test_parse_json_string(self):
        session_id = "parse_test"
        data = {
            "session_id": session_id,
            "source_ip": "10.0.0.1",
            "start_time": "2025-01-01T00:00:00Z",
            "commands": [
                {"timestamp": "2025-01-01T00:00:00Z", "command": "ls"},
                {"timestamp": "2025-01-01T00:00:05Z", "command": "whoami"},
            ],
        }
        session = SessionLogParser().parse_json(json.dumps(data))
        assert isinstance(session, SessionLog)
        assert len(session.commands) == 2

    def test_parse_json_dict(self):
        data = {
            "session_id": "dict_test",
            "start_time": "2025-01-01T00:00:00Z",
            "commands": [{"timestamp": "2025-01-01T00:00:00Z", "command": "pwd"}],
        }
        session = SessionLogParser().parse_json(data)
        assert len(session.commands) == 1

    def test_parse_raw_log(self):
        raw = (
            "SESSION_ID: raw123\n"
            "SOURCE_IP: 10.0.0.5\n"
            "2025-01-01T00:00:00Z COMMAND whoami\n"
            "2025-01-01T00:00:05Z COMMAND ls -la\n"
            "2025-01-01T00:00:10Z FILE_CREATE /tmp/payload\n"
            "2025-01-01T00:00:15Z NET_OUT 192.168.1.100:4444 1024 bytes\n"
        )
        session = SessionLogParser().parse(raw)
        assert isinstance(session, SessionLog)
        assert len(session.commands) >= 2
        assert len(session.file_operations) >= 1
        assert len(session.network_activity) >= 1

    def test_empty_input_raises(self):
        with pytest.raises(ValueError, match="Empty session log"):
            SessionLogParser().parse("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="Empty session log"):
            SessionLogParser().parse("   \n  \t  ")

    def test_normalize(self):
        raw_data = {"commands": ["ls", "whoami"], "ip": "10.0.0.1"}
        normalized = SessionLogParser().normalize(raw_data)
        assert isinstance(normalized, dict)
        assert len(normalized["commands"]) == 2

    def test_hashlib_id(self):
        from ragin.chrollo.session_parser import hashlib_id

        h = hashlib_id("test_seed")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_redact_pii(self):
        from ragin.chrollo.session_parser import _redact_pii

        text = "user john@example.com called 555-123-4567"
        redacted = _redact_pii(text)
        assert "john@example.com" not in redacted
        assert "555-123-4567" not in redacted
        assert "[REDACTED_EMAIL]" in redacted

    def test_redact_ssn(self):
        from ragin.chrollo.session_parser import _redact_pii

        assert "[REDACTED_SSN]" in _redact_pii("SSN: 123-45-6789")

    def test_parse_raw_log_auto_generates_session_id(self):
        session = SessionLogParser().parse("2025-01-01T00:00:00Z COMMAND pwd")
        assert len(session.session_id) == 64  # sha256 hex


# ── ChrolloPipeline ─────────────────────────────────────────────────────────


class TestChrolloPipeline:
    @staticmethod
    def _trained_pipeline(tmp_path) -> ChrolloPipeline:
        classifier = ChrolloClassifier(model_path=str(tmp_path / "m.pkl"))
        data = []
        for i in range(20):
            data.append(
                (
                    _make_session(commands=[CommandEntry(timestamp=NOW, command=f"cmd_{j}") for j in range(i % 5 + 1)]),
                    SkillLevel.NOVICE if i < 10 else SkillLevel.EXPERT,
                )
            )
        classifier.train(data, n_estimators=10, cv_folds=2)
        return ChrolloPipeline(classifier=classifier, gateway_url="http://localhost:9999")

    def test_process_session(self, tmp_path):
        pipeline = self._trained_pipeline(tmp_path)
        result = pipeline.process_session(_make_session())
        assert isinstance(result, ClassificationResult)

    def test_process_json(self, tmp_path):
        pipeline = self._trained_pipeline(tmp_path)
        result = pipeline.process_json(
            {
                "session_id": "pj",
                "start_time": "2025-01-01T00:00:00Z",
                "commands": [{"timestamp": "2025-01-01T00:00:00Z", "command": "ls"}],
            }
        )
        assert isinstance(result, ClassificationResult)

    def test_process_raw(self, tmp_path):
        pipeline = self._trained_pipeline(tmp_path)
        result = pipeline.process_raw("SESSION_ID: pr\n2025-01-01T00:00:00Z COMMAND ls\n")
        assert isinstance(result, ClassificationResult)

    def test_escalate_to_don_returns_error_when_gateway_down(self, tmp_path):
        pipeline = self._trained_pipeline(tmp_path)
        result = ClassificationResult(
            skill_level=SkillLevel.EXPERT,
            confidence=0.85,
            features_used=[],
            session_id="esc1",
        )
        resp = pipeline.escalate_to_don(result, _make_session())
        assert resp.status == "error"

    def test_escalate_to_hisoka_returns_error_when_gateway_down(self, tmp_path):
        pipeline = self._trained_pipeline(tmp_path)
        result = ClassificationResult(
            skill_level=SkillLevel.APT,
            confidence=0.99,
            features_used=[],
            session_id="esc2",
        )
        resp = pipeline.escalate_to_hisoka(result, _make_session())
        assert resp.status == "error"

    def test_build_headers(self):
        pipeline = ChrolloPipeline(classifier=ChrolloClassifier(), api_key="test-key")
        headers = pipeline._build_headers()
        assert headers["Authorization"] == "Bearer test-key"
        assert "application/json" in headers["Content-Type"]

    def test_build_headers_no_key(self):
        pipeline = ChrolloPipeline(classifier=ChrolloClassifier())
        headers = pipeline._build_headers()
        assert "Authorization" not in headers

    def test_rate_limit_wait(self):
        import time

        pipeline = ChrolloPipeline(classifier=ChrolloClassifier(), rate_limit_rps=100.0)
        start = time.monotonic()
        pipeline._rate_limit_wait()
        assert (time.monotonic() - start) < 1.0
