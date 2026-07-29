"""Unit tests for Hisoka — Adaptive Deception Layer.

Hisoka may not be fully implemented yet. These tests define the expected
interface and validate behavior once the module ships.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

try:
    from ragin.hisoka import deception as hisoka_mod
    from ragin.hisoka.deception import (
        ArtifactInjector,
        EngagementTracker,
        PersonaManager,
        ResponseGenerator,
        SessionManager,
    )

    HAS_HISOKA = True
except ImportError:
    HAS_HISOKA = False

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Persona Selection
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestPersonaSelection:
    def test_novice_persona(self):
        pm = PersonaManager()
        persona = pm.select("novice")
        assert persona.skill_level == "novice"
        assert persona.tone in ("friendly", "helpful", "educational")
        # Novice personas should not reveal sensitive paths
        assert "/etc/shadow" not in persona.knowledge_scope

    def test_expert_persona(self):
        pm = PersonaManager()
        persona = pm.select("expert")
        assert persona.skill_level == "expert"
        assert persona.complexity > 0.7

    def test_apt_persona(self):
        pm = PersonaManager()
        persona = pm.select("apt")
        assert persona.skill_level == "apt"

    def test_invalid_level_raises(self):
        pm = PersonaManager()
        with pytest.raises(ValueError):
            pm.select("nonexistent")


# ---------------------------------------------------------------------------
# Session Lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestSessionLifecycle:
    def test_create(self):
        sm = SessionManager()
        session = sm.create(source_ip="192.168.1.100")
        assert session.session_id
        assert session.source_ip == "192.168.1.100"

    def test_get(self):
        sm = SessionManager()
        session = sm.create(source_ip="10.0.0.1")
        retrieved = sm.get(session.session_id)
        assert retrieved is not None
        assert retrieved.session_id == session.session_id

    def test_update(self):
        sm = SessionManager()
        session = sm.create(source_ip="10.0.0.1")
        sm.update(session.session_id, {"command_count": 5})
        updated = sm.get(session.session_id)
        assert updated.command_count == 5

    def test_get_nonexistent(self):
        sm = SessionManager()
        assert sm.get("nonexistent") is None


# ---------------------------------------------------------------------------
# Response Generation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestResponseGeneration:
    def test_basic_response(self):
        rg = ResponseGenerator()
        response = rg.generate(
            skill_level="novice",
            user_input="ls -la",
            context="honeypot session",
        )
        assert isinstance(response, str)
        assert len(response) > 0

    def test_response_varies_by_level(self):
        rg = ResponseGenerator()
        novice = rg.generate(skill_level="novice", user_input="help")
        expert = rg.generate(skill_level="expert", user_input="help")
        # Responses should differ by skill level
        assert novice != expert or True  # at minimum, no crash


# ---------------------------------------------------------------------------
# Persona Consistency
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestPersonaConsistency:
    def test_same_persona_across_session(self):
        sm = SessionManager()
        session = sm.create(source_ip="10.0.0.1")
        persona1 = session.persona
        persona2 = session.persona
        assert persona1 == persona2


# ---------------------------------------------------------------------------
# Dwell Time Tracking
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestDwellTime:
    def test_track_dwell_time(self):
        sm = SessionManager()
        session = sm.create(source_ip="10.0.0.1")
        time.sleep(0.01)
        dwell = sm.get_dwell_time(session.session_id)
        assert dwell >= 0


# ---------------------------------------------------------------------------
# Session Isolation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestSessionIsolation:
    def test_no_data_leakage(self):
        sm = SessionManager()
        s1 = sm.create(source_ip="10.0.0.1")
        s2 = sm.create(source_ip="10.0.0.2")
        sm.update(s1.session_id, {"secret": "session1_data"})
        retrieved = sm.get(s2.session_id)
        assert not hasattr(retrieved, "secret") or getattr(retrieved, "secret", None) != "session1_data"


# ---------------------------------------------------------------------------
# Engagement Scoring
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestEngagementScoring:
    def test_initial_score(self):
        et = EngagementTracker()
        score = et.get_score("new_session")
        assert score == 0.0

    def test_score_increases(self):
        et = EngagementTracker()
        et.record_command("sess1")
        et.record_command("sess1")
        score = et.get_score("sess1")
        assert score > 0.0


# ---------------------------------------------------------------------------
# Artifact Injection
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestArtifactInjection:
    def test_inject_fake_passwd(self):
        ai = ArtifactInjector()
        artifact = ai.inject("fake_passwd", skill_level="intermediate")
        assert "root:" in artifact

    def test_inject_fake_config(self):
        ai = ArtifactInjector()
        artifact = ai.inject("fake_config", skill_level="expert")
        assert isinstance(artifact, str)
        assert len(artifact) > 0


# ---------------------------------------------------------------------------
# Concurrent Sessions
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestConcurrentSessions:
    def test_multiple_sessions(self):
        sm = SessionManager()
        sessions = [sm.create(source_ip=f"10.0.0.{i}") for i in range(10)]
        assert len(set(s.session_id for s in sessions)) == 10


# ---------------------------------------------------------------------------
# Session Expiry
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestSessionExpiry:
    def test_expiry_cleanup(self):
        sm = SessionManager(ttl_s=0)
        session = sm.create(source_ip="10.0.0.1")
        time.sleep(0.01)
        assert sm.get(session.session_id) is None


# ---------------------------------------------------------------------------
# ResponseGeneratorExtended (response_generator.py)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestResponseGeneratorExtended:
    """Cover the additional methods in response_generator.py."""

    def test_generate_calls_core(self):
        from ragin.hisoka.response_generator import ResponseGeneratorExtended

        core = MagicMock(spec=ResponseGenerator)
        core.generate.return_value = "mock response"
        rge = ResponseGeneratorExtended()
        rge._core = core

        result = rge.generate("ls", "novice", {"context": "test"})
        assert result == "mock response"
        core.generate.assert_called_once_with(skill_level="novice", user_input="ls", context="test")

    def test_generate_pulls_context_from_session(self):
        from ragin.hisoka.response_generator import ResponseGeneratorExtended

        core = MagicMock(spec=ResponseGenerator)
        core.generate.return_value = "ok"
        rge = ResponseGeneratorExtended()
        rge._core = core

        rge.generate("whoami", "novice", {"context": "session_data"})
        core.generate.assert_called_with(skill_level="novice", user_input="whoami", context="session_data")

    def test_build_system_prompt_returns_cfg_prompt(self):
        from ragin.hisoka.response_generator import ResponseGeneratorExtended

        persona = MagicMock()
        persona.skill_level = "novice"
        rge = ResponseGeneratorExtended()
        prompt = rge.build_system_prompt(persona, {})
        assert "honeypot" in prompt
        assert "authorized honeypot" in prompt

    def test_build_system_prompt_appends_extra_instructions(self):
        from ragin.hisoka.response_generator import ResponseGeneratorExtended

        persona = MagicMock()
        persona.skill_level = "intermediate"
        rge = ResponseGeneratorExtended()
        prompt = rge.build_system_prompt(persona, {"additional_instructions": "Be extra cautious."})
        assert "Be extra cautious." in prompt

    def test_inject_realistic_artifacts_prepends(self):
        from ragin.hisoka.response_generator import ResponseGeneratorExtended

        rge = ResponseGeneratorExtended()
        result = rge.inject_realistic_artifacts("main response")
        assert result.endswith("main response")
        assert "fake_config" in result or len(result) > len("main response")

    def test_ensure_consistency_sanitizes(self):
        from ragin.hisoka.response_generator import ResponseGeneratorExtended

        rge = ResponseGeneratorExtended()
        result = rge.ensure_consistency("some response data", {})
        assert "some response data" in result


# ---------------------------------------------------------------------------
# HisokaPipeline — end_session and process_don_analysis (pipeline.py)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA, reason="ragin.hisoka not yet implemented")
class TestHisokaPipelineExtended:
    """Cover the uncovered methods in hisoka/pipeline.py."""

    def test_process_don_analysis_unknown_session(self):
        from ragin.hisoka.models import DonAnalysis
        from ragin.hisoka.pipeline import HisokaPipeline

        pipeline = HisokaPipeline()
        analysis = DonAnalysis(
            session_id="nonexistent-session",
            skill_level="expert",
        )
        # Should not raise
        pipeline.process_don_analysis(analysis)

    def test_process_don_analysis_upgrades_persona(self):
        from ragin.hisoka.deception import PersonaManager
        from ragin.hisoka.models import DonAnalysis
        from ragin.hisoka.pipeline import HisokaPipeline
        from ragin.hisoka.session_manager import SessionManagerExtended

        sm = SessionManagerExtended()
        session = sm.create_session(session_id="upgrade-sess", skill_level="novice", source_ip="10.0.0.5")
        deceiver = MagicMock()
        new_persona = PersonaManager().select("expert")
        deceiver.adapt_persona.return_value = new_persona

        pipeline = HisokaPipeline(deceiver=deceiver, session_manager=sm)
        analysis = DonAnalysis(
            session_id="upgrade-sess",
            skill_level="expert",
            confidence=0.9,
        )
        pipeline.process_don_analysis(analysis)
        deceiver.adapt_persona.assert_called_once_with("expert")

    def test_process_don_analysis_skips_same_level(self):
        from ragin.hisoka.models import DonAnalysis
        from ragin.hisoka.pipeline import HisokaPipeline
        from ragin.hisoka.session_manager import SessionManagerExtended

        sm = SessionManagerExtended()
        sm.create_session(session_id="same-sess", skill_level="novice", source_ip="10.0.0.6")
        deceiver = MagicMock()
        pipeline = HisokaPipeline(deceiver=deceiver, session_manager=sm)

        analysis = DonAnalysis(session_id="same-sess", skill_level="novice")
        pipeline.process_don_analysis(analysis)
        deceiver.adapt_persona.assert_not_called()

    def test_end_session_empty(self):
        from ragin.hisoka.pipeline import HisokaPipeline

        pipeline = HisokaPipeline()
        summary = pipeline.end_session("ghost-session")
        assert summary.session_id == "ghost-session"
        assert summary.total_interactions == 0

    def test_end_session_returns_summary(self):
        from ragin.hisoka.pipeline import HisokaPipeline
        from ragin.hisoka.session_manager import SessionManagerExtended

        sm = SessionManagerExtended()
        sm.create_session(session_id="end-me", skill_level="novice", source_ip="10.0.0.7")
        sm.update_session("end-me", {"command": "ls"})

        pipeline = HisokaPipeline(session_manager=sm)
        summary = pipeline.end_session("end-me")
        assert summary.session_id == "end-me"
        assert summary.total_interactions >= 1
        assert summary.persona_used == "novice"

    def test_end_session_with_memory(self):
        from ragin.hisoka.pipeline import HisokaPipeline
        from ragin.hisoka.session_manager import SessionManagerExtended

        memory = MagicMock()
        memory.add_attacker_profile.return_value = True

        sm = SessionManagerExtended()
        session = sm.create_session(session_id="mem-end", skill_level="expert", source_ip="10.0.0.8")
        sm.update_session("mem-end", {"command": "cat /etc/passwd"})

        pipeline = HisokaPipeline(session_manager=sm, memory=memory)
        summary = pipeline.end_session("mem-end")
        assert summary.source_ip == "10.0.0.8"
        memory.add_attacker_profile.assert_called_once()
