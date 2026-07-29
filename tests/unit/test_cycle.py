"""Tests for ragin.cycle — Session, Harness, Sandbox.

Validates:
- Session append-only semantics and crash recovery
- Harness stateless orchestration pipeline
- Sandbox attacker interaction isolation
"""

import os
from typing import Any
from unittest.mock import MagicMock

import pytest

from ragin.benchmark.effectiveness import EffectivenessMetrics
from ragin.cycle.coordination import VoteOutcome, VotingSystem
from ragin.cycle.harness import Harness
from ragin.cycle.sandbox import Sandbox, SandboxConfig
from ragin.cycle.session import Event, EventType, Session

# ═══════════════════════════════════════════════════════════════════════════════
# Session Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestEventType:
    def test_all_types_exist(self):
        expected = [
            "SESSION_START",
            "SESSION_END",
            "SESSION_RESUME",
            "ATTACKER_INPUT",
            "SYSTEM_RESPONSE",
            "CLASSIFICATION",
            "CTI_LOOKUP",
            "PERSONA_SELECT",
            "RESPONSE_GENERATE",
            "RESPONSE_VERIFY",
            "ARTIFACT_INJECT",
            "HONEYTOKEN_PLANT",
            "TTP_EXTRACT",
            "STRATEGY_UPDATE",
            "HEARTBEAT",
            "ERROR",
            "METRIC",
        ]
        for name in expected:
            assert hasattr(EventType, name), f"Missing EventType.{name}"


class TestEvent:
    def test_creation(self):
        e = Event(
            event_type=EventType.ATTACKER_INPUT,
            data={"cmd": "whoami"},
            source="sandbox",
        )
        assert len(e.event_id) == 12
        assert e.event_type == EventType.ATTACKER_INPUT
        assert e.data == {"cmd": "whoami"}
        assert e.source == "sandbox"
        assert e.timestamp is not None

    def test_to_dict_roundtrip(self):
        e = Event(
            event_type=EventType.SYSTEM_RESPONSE,
            data={"text": "hello"},
            source="hisoka",
        )
        d = e.to_dict()
        e2 = Event.from_dict(d)
        assert e2.event_type == EventType.SYSTEM_RESPONSE
        assert e2.data == {"text": "hello"}
        assert e2.source == "hisoka"
        assert e2.event_id == e.event_id


class TestSession:
    def test_create(self, tmp_path):
        s = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        assert s.session_id.startswith("ses-")
        assert s.event_count == 1  # SESSION_START event
        assert not s.is_closed

    def test_emit_appends_event(self, tmp_path):
        s = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        initial = s.event_count
        s.emit(EventType.ATTACKER_INPUT, {"cmd": "whoami"})
        assert s.event_count == initial + 1

    def test_emit_after_close_raises(self, tmp_path):
        s = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        s.close()
        with pytest.raises(RuntimeError):
            s.emit(EventType.ATTACKER_INPUT, {"cmd": "whoami"})

    def test_close(self, tmp_path):
        s = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        s.emit(EventType.ATTACKER_INPUT, {"cmd": "whoami"})
        s.close(reason="test_done")
        assert s.is_closed
        assert s.event_count == 3  # START + INPUT + END

    def test_build_context(self, tmp_path):
        s = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        s.emit(EventType.ATTACKER_INPUT, {"command": "whoami"})
        s.emit(EventType.SYSTEM_RESPONSE, {"text": "www-data"})
        ctx = s.build_context()
        assert ctx["source_ip"] == "10.0.0.1"
        assert ctx["interaction_count"] == 1
        assert ctx["attacker_inputs"][0] == {"command": "whoami"}
        assert ctx["system_responses"][0] == {"text": "www-data"}

    def test_crash_recovery(self, tmp_path):
        s1 = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        s1.emit(EventType.ATTACKER_INPUT, {"command": "ls -la"})
        s1.emit(EventType.SYSTEM_RESPONSE, {"text": "total 0"})
        sid = s1.session_id

        s2 = Session.wake(sid, session_dir=str(tmp_path))
        assert s2.session_id == sid
        assert s2.event_count == 4  # START + INPUT + RESPONSE + RESUME
        ctx = s2.build_context()
        assert ctx["interaction_count"] == 1
        assert ctx["attacker_inputs"][0] == {"command": "ls -la"}

    def test_replay(self, tmp_path):
        s = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        s.emit(EventType.ATTACKER_INPUT, {"cmd": "cmd1"})
        s.emit(EventType.ATTACKER_INPUT, {"cmd": "cmd2"})
        events = s.replay()
        types = [e.event_type for e in events]
        assert EventType.ATTACKER_INPUT in types
        assert EventType.SESSION_START in types

    def test_replay_since(self, tmp_path):
        s = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        e1 = s.emit(EventType.ATTACKER_INPUT, {"cmd": "cmd1"})
        e2 = s.emit(EventType.ATTACKER_INPUT, {"cmd": "cmd2"})
        events = s.replay_since(e1.event_id)
        assert len(events) >= 1  # at least cmd2

    def test_persistence_file_exists(self, tmp_path):
        s = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        s.emit(EventType.ATTACKER_INPUT, {"cmd": "test"})
        path = s._log_path
        assert os.path.exists(path)
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) >= 2  # at least START + INPUT

    def test_multiple_sessions_independent(self, tmp_path):
        s1 = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        s2 = Session.create(source_ip="10.0.0.2", session_dir=str(tmp_path))
        s1.emit(EventType.ATTACKER_INPUT, {"cmd": "cmd1"})
        s2.emit(EventType.ATTACKER_INPUT, {"cmd": "cmd2"})
        ctx1 = s1.build_context()
        ctx2 = s2.build_context()
        assert ctx1["attacker_inputs"][0] == {"cmd": "cmd1"}
        assert ctx2["attacker_inputs"][0] == {"cmd": "cmd2"}

    def test_wake_nonexistent_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            Session.wake("ses-nonexistent", session_dir=str(tmp_path))


# ═══════════════════════════════════════════════════════════════════════════════
# Harness Tests
# ═══════════════════════════════════════════════════════════════════════════════


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


class TestHarness:
    def test_process_full_pipeline(self, tmp_path):
        classifier = _mock_classifier()
        cti = _mock_cti_engine()
        deceiver = _mock_deceiver()
        harness = Harness(classifier=classifier, cti_engine=cti, deceiver=deceiver)
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")

        assert result.response_text == "Welcome to Ubuntu 20.04 LTS"
        assert result.classification["skill_level"] == "intermediate"
        assert result.cti_analysis["threat_summary"] == "SSH brute force attempt"
        assert result.events_emitted >= 4  # INPUT + CLASSIFY + CTI + RESPONSE + SYSTEM_RESPONSE
        assert not result.error

    def test_process_no_components(self, tmp_path):
        harness = Harness()
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")
        assert result.response_text == ""
        assert result.events_emitted >= 2  # INPUT + SYSTEM_RESPONSE

    def test_process_classifier_error(self, tmp_path):
        classifier = MagicMock()
        classifier.classify.side_effect = RuntimeError("model unavailable")
        harness = Harness(classifier=classifier, deceiver=_mock_deceiver())
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")
        assert result.classification["skill_level"] == "novice"
        assert result.classification["confidence"] == 0.0
        assert result.response_text == "Welcome to Ubuntu 20.04 LTS"

    def test_process_cti_error(self, tmp_path):
        cti = MagicMock()
        cti.analyze.side_effect = RuntimeError("CTI down")
        harness = Harness(cti_engine=cti, deceiver=_mock_deceiver())
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")
        assert result.cti_analysis["threat_summary"] == ""
        assert result.response_text == "Welcome to Ubuntu 20.04 LTS"

    def test_process_deceiver_error(self, tmp_path):
        deceiver = MagicMock()
        deceiver.generate_response.side_effect = RuntimeError("LLM timeout")
        harness = Harness(deceiver=deceiver)
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")
        assert result.response_text == "Error generating response."

    def test_harness_is_stateless(self, tmp_path):
        harness = Harness(
            classifier=_mock_classifier(),
            deceiver=_mock_deceiver(),
        )
        s1 = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        s2 = Session.create(source_ip="10.0.0.2", session_dir=str(tmp_path))
        r1 = harness.process(s1, "cmd1")
        r2 = harness.process(s2, "cmd2")
        assert r1.session_id != r2.session_id

    def test_wake_resume(self, tmp_path):
        classifier = _mock_classifier()
        deceiver = _mock_deceiver()
        harness = Harness(classifier=classifier, deceiver=deceiver)
        s1 = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        harness.process(s1, "whoami")
        harness.process(s1, "ls -la")
        sid = s1.session_id

        s2 = Session.wake(sid, session_dir=str(tmp_path))
        ctx = s2.build_context()
        assert s2.session_id == sid
        assert ctx["interaction_count"] == 2
        assert len(ctx["attacker_inputs"]) == 2

    def test_process_batch(self, tmp_path):
        harness = Harness(
            classifier=_mock_classifier(),
            deceiver=_mock_deceiver(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        results = [harness.process(session, cmd) for cmd in ["cmd1", "cmd2", "cmd3"]]
        assert len(results) == 3
        assert all(r.response_text == "Welcome to Ubuntu 20.04 LTS" for r in results)

    def test_verification_passes(self, tmp_path):
        verifier = _mock_verifier(passing=True)
        harness = Harness(
            deceiver=_mock_deceiver(),
            verifier=verifier,
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")
        assert result.passed_verification

    def test_verification_fails_retries(self, tmp_path):
        deceiver = _mock_deceiver()
        call_count = 0

        def gen_response(*args: Any, **kwargs: Any) -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "response_text": "short",
                    "persona_used": "novice",
                    "engagement_score": 0.3,
                    "artifacts_injected": [],
                }
            return {
                "response_text": "Welcome to Ubuntu 20.04 LTS. Here you will find...",
                "persona_used": "novice",
                "engagement_score": 0.75,
                "artifacts_injected": [],
            }

        deceiver.generate_response.side_effect = gen_response
        verifier = _mock_verifier(passing=False)
        harness = Harness(deceiver=deceiver, verifier=verifier, max_retries=2)
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")
        # First call (original) + retries: the harness retries when verification fails
        # Since max_retries=2 and verifier always fails, it retries up to 2 times
        assert call_count >= 2

    def test_pipeline_timing(self, tmp_path):
        harness = Harness(
            classifier=_mock_classifier(),
            deceiver=_mock_deceiver(),
        )
        session = Session.create(source_ip="10.0.0.1", session_dir=str(tmp_path))
        result = harness.process(session, "whoami")
        assert result.total_time_ms >= 0


# ═══════════════════════════════════════════════════════════════════════════════
# Sandbox Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSandbox:
    def test_handle_command_creates_session(self, tmp_path):
        harness = Harness(classifier=_mock_classifier(), deceiver=_mock_deceiver())
        sandbox = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        resp = sandbox.handle_command("10.0.0.1", "whoami")
        assert resp.session_id.startswith("ses-")
        assert resp.response_text == "Welcome to Ubuntu 20.04 LTS"
        assert resp.command_count >= 1

    def test_handle_command_reuses_session(self, tmp_path):
        harness = Harness(classifier=_mock_classifier(), deceiver=_mock_deceiver())
        sandbox = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        r1 = sandbox.handle_command("10.0.0.1", "whoami")
        r2 = sandbox.handle_command("10.0.0.1", "ls", session_id=r1.session_id)
        assert r1.session_id == r2.session_id
        assert r2.command_count > r1.command_count

    def test_max_commands_limit(self, tmp_path):
        harness = Harness(classifier=_mock_classifier(), deceiver=_mock_deceiver())
        sandbox = Sandbox(
            harness=harness,
            config=SandboxConfig(max_commands=3, session_dir=str(tmp_path)),
        )
        r1 = sandbox.handle_command("10.0.0.1", "cmd1")
        r2 = sandbox.handle_command("10.0.0.1", "cmd2", session_id=r1.session_id)
        r3 = sandbox.handle_command("10.0.0.1", "cmd3", session_id=r1.session_id)
        # After 3 commands, session is closed on next command
        r4 = sandbox.handle_command("10.0.0.1", "cmd4", session_id=r1.session_id)
        assert r4.error == "max_commands_reached"

    def test_get_session_context(self, tmp_path):
        harness = Harness(classifier=_mock_classifier(), deceiver=_mock_deceiver())
        sandbox = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        r1 = sandbox.handle_command("10.0.0.1", "whoami")
        ctx = sandbox.get_session_context(r1.session_id)
        assert ctx is not None
        assert ctx["source_ip"] == "10.0.0.1"

    def test_close_session(self, tmp_path):
        harness = Harness(deceiver=_mock_deceiver())
        sandbox = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        r1 = sandbox.handle_command("10.0.0.1", "whoami")
        assert sandbox.close_session(r1.session_id)
        session = sandbox._sessions[r1.session_id]
        assert session.is_closed

    def test_get_active_sessions(self, tmp_path):
        harness = Harness(deceiver=_mock_deceiver())
        sandbox = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        r1 = sandbox.handle_command("10.0.0.1", "cmd1")
        r2 = sandbox.handle_command("10.0.0.2", "cmd2")
        active = sandbox.get_active_sessions()
        assert len(active) == 2
        sandbox.close_session(r1.session_id)
        active = sandbox.get_active_sessions()
        assert len(active) == 1

    def test_handle_commands_batch(self, tmp_path):
        harness = Harness(classifier=_mock_classifier(), deceiver=_mock_deceiver())
        sandbox = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        responses = sandbox.handle_commands("10.0.0.1", ["whoami", "ls -la", "cat /etc/passwd"])
        assert len(responses) == 3
        assert len(set(r.session_id for r in responses)) == 1  # same session

    def test_get_metrics(self, tmp_path):
        harness = Harness(deceiver=_mock_deceiver())
        sandbox = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        sandbox.handle_command("10.0.0.1", "cmd1")
        sandbox.handle_command("10.0.0.2", "cmd2")
        metrics = sandbox.get_metrics()
        assert metrics["total_sessions"] == 2
        assert metrics["active_sessions"] == 2

    def test_sandbox_config_defaults(self):
        config = SandboxConfig()
        assert config.max_commands == 1000
        assert config.timeout_s == 30.0
        assert config.enable_artifacts is True
        assert config.enable_verification is True

    def test_unknown_session_wakes_from_disk(self, tmp_path):
        harness = Harness(classifier=_mock_classifier(), deceiver=_mock_deceiver())
        sandbox1 = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        r1 = sandbox1.handle_command("10.0.0.1", "whoami")
        sid = r1.session_id

        sandbox2 = Sandbox(harness=harness, config=SandboxConfig(session_dir=str(tmp_path)))
        r2 = sandbox2.handle_command("10.0.0.1", "ls", session_id=sid)
        assert r2.session_id == sid
        assert r2.command_count >= 2


# VotingSystem Tests


class TestVotingSystem:
    def test_basic_vote_passes(self):
        voter = VotingSystem(threshold=0.5)
        quality = MagicMock()
        quality.review.return_value = {"passed": True, "score": 0.9}
        voter.add_verifier(quality)
        result = voter.vote({"response_text": "test"}, {"session_id": "s1"})
        assert result.outcome == VoteOutcome.UNANIMOUS

    def test_vote_fails_below_threshold(self):
        voter = VotingSystem(threshold=0.8)
        verifier = MagicMock()
        verifier.review.return_value = {"passed": False, "score": 0.3}
        voter.add_verifier(verifier)
        result = voter.vote({"response_text": "bad"}, {"session_id": "s1"})
        assert result.outcome == VoteOutcome.FAILED

    def test_unanimity_required(self):
        voter = VotingSystem(threshold=0.5, require_unanimity=True)
        v1 = MagicMock()
        v1.review.return_value = {"passed": True, "score": 0.9}
        v2 = MagicMock()
        v2.review.return_value = {"passed": False, "score": 0.4}
        voter.add_verifier(v1)
        voter.add_verifier(v2)
        result = voter.vote({"response_text": "test"}, {"session_id": "s1"})
        assert result.outcome == VoteOutcome.SPLIT

    def test_multiple_verifiers_majority(self):
        voter = VotingSystem(threshold=0.5)
        for i in range(3):
            v = MagicMock()
            v.review.return_value = {"passed": True, "score": 0.9}
            voter.add_verifier(v)
        result = voter.vote({"response_text": "test"}, {"session_id": "s1"})
        assert result.outcome == VoteOutcome.UNANIMOUS

    def test_no_verifiers(self):
        voter = VotingSystem(threshold=0.5)
        result = voter.vote({"response_text": "test"}, {"session_id": "s1"})
        assert result.outcome == VoteOutcome.UNANIMOUS


# Bridge Scoring Tests


class TestBridgeScoring:
    def test_technique_exact_id_match(self):
        from ragin.benchmark.harness_bridge import _score_technique_match

        score = _score_technique_match("T1078.001", "T1078.001")
        assert score >= 0.8

    def test_technique_name_variant_match(self):
        from ragin.benchmark.harness_bridge import _score_technique_match

        score = _score_technique_match("Valid accounts are dangerous", "T1078.001")
        assert score >= 0.4

    def test_technique_no_match(self):
        from ragin.benchmark.harness_bridge import _score_technique_match

        score = _score_technique_match("", "T1078.001")
        assert score == 0.0

    def test_actor_exact_match(self):
        from ragin.benchmark.harness_bridge import _score_actor_match

        score = _score_actor_match("APT29 is targeting", "apt29", "government")
        assert score >= 0.6

    def test_actor_sector_match(self):
        from ragin.benchmark.harness_bridge import _score_actor_match

        score = _score_actor_match("targeting financial institutions", "apt29", "financial")
        assert score >= 0.3

    def test_actor_no_match(self):
        from ragin.benchmark.harness_bridge import _score_actor_match

        score = _score_actor_match("unrelated text", "apt29", "financial")
        assert score == 0.0

    def test_persona_realism_technical(self):
        from ragin.benchmark.harness_bridge import _score_persona_realism

        score = _score_persona_realism("Opened port 22 on server. Configured running service.", [])
        assert score >= 0.3

    def test_persona_realism_refusal(self):
        from ragin.benchmark.harness_bridge import _score_persona_realism

        score = _score_persona_realism("Not authorized to share this information.", [])
        assert score >= 0.3

    def test_persona_realism_short_response(self):
        from ragin.benchmark.harness_bridge import _score_persona_realism

        score = _score_persona_realism("Hi", [])
        assert score == 0.0


# Effectiveness Metrics Tests


class TestBaselineAdjustedComposite:
    def test_standard_composite(self):
        m = EffectivenessMetrics(
            total_sessions=10,
            sessions_with_engagement=10,
            honeytoken_triggers=5,
            honeytokens_deployed=10,
            persona_correct_assignments=8,
            persona_total_assignments=10,
            ttps_detected=7,
            ttps_detected_unique=5,
            cti_alerts_generated=7,
            true_positives=7,
            deception_artifacts_deployed=10,
            deception_artifacts_accessed=5,
        )
        normal = m.composite_score()
        adjusted = m.baseline_adjusted_composite()
        assert adjusted == normal

    def test_adjusted_when_honeytoken_zero(self):
        m = EffectivenessMetrics(
            total_sessions=10,
            sessions_with_engagement=10,
            honeytoken_triggers=0,
            honeytokens_deployed=10,
            persona_correct_assignments=8,
            persona_total_assignments=10,
            ttps_detected=7,
            ttps_detected_unique=5,
            cti_alerts_generated=7,
            true_positives=7,
        )
        adjusted = m.baseline_adjusted_composite()
        standard = m.composite_score()
        assert adjusted > standard

    def test_adjusted_when_artifact_zero(self):
        m = EffectivenessMetrics(
            total_sessions=10,
            sessions_with_engagement=10,
            honeytoken_triggers=5,
            honeytokens_deployed=10,
            persona_correct_assignments=8,
            persona_total_assignments=10,
            ttps_detected=7,
            ttps_detected_unique=5,
            cti_alerts_generated=7,
            true_positives=7,
            deception_artifacts_accessed=0,
        )
        adjusted = m.baseline_adjusted_composite()
        standard = m.composite_score()
        assert adjusted > standard

    def test_adjusted_both_zero(self):
        m = EffectivenessMetrics(
            total_sessions=10,
            sessions_with_engagement=10,
            honeytoken_triggers=0,
            honeytokens_deployed=10,
            persona_correct_assignments=8,
            persona_total_assignments=10,
            ttps_detected=7,
            ttps_detected_unique=5,
            cti_alerts_generated=7,
            true_positives=7,
            deception_artifacts_accessed=0,
        )
        adjusted = m.baseline_adjusted_composite()
        standard = m.composite_score()
        assert adjusted > standard
        assert 0.0 < adjusted <= 1.0
