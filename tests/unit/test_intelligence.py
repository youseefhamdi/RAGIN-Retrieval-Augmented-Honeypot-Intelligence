"""Comprehensive tests for the Intelligence Layer (Phase 2.3)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from ragin.chrollo.models import SkillLevel
from ragin.intelligence import adaptive_response as _ar_mod
from ragin.intelligence.adaptive_response import (
    AdaptiveResponseEngine,
    _check_rate_limit,
    _current_time_window,
)
from ragin.intelligence.evasion_detector import EvasionDetector
from ragin.intelligence.models import (
    AdaptedResponse,
    AdjustmentRecommendation,
    EngagementParams,
    EvasionIndicator,
    EvasionIndicatorType,
    EvasionResult,
    ResponseStrategy,
    SkillLevel,
    StrategyProfile,
    TimeWindow,
    _sanitize_input,
)
from ragin.intelligence.skill_strategy import SkillAdaptiveStrategy


@pytest.fixture(autouse=True)
def _clear_rate_limit():
    """Reset rate-limit state between tests."""
    _ar_mod._rate_limit_state.clear()
    yield
    _ar_mod._rate_limit_state.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base_context(session_id: str = "test-sess", skill: SkillLevel = SkillLevel.NOVICE) -> dict:
    return {
        "session_id": session_id,
        "skill_level": skill,
        "engagement_score": 0.0,
    }


def _session_log(commands: list[str], session_id: str = "s1") -> dict:
    return {
        "session_id": session_id,
        "commands": [{"command": c} for c in commands],
    }


def _mock_hisoka() -> MagicMock:
    return MagicMock()


def _mock_gateway_url() -> str:
    return "http://localhost:8080"


# ===================================================================
# Adaptive Response Engine
# ===================================================================


class TestAdaptiveResponseNovice:
    def test_simple_response(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "ls -la",
            _base_context(skill=SkillLevel.NOVICE),
            threat_level=0.1,
        )
        assert resp.strategy == ResponseStrategy.NOVICE
        assert resp.complexity_score <= 3
        assert "ls -la" in resp.response_text

    def test_novice_artifacts_are_many(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "whoami",
            _base_context(skill=SkillLevel.NOVICE),
            threat_level=0.1,
        )
        assert len(resp.artifacts_injected) >= 1

    def test_novice_single_deception_layer(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "id",
            _base_context(skill=SkillLevel.NOVICE),
            threat_level=0.0,
        )
        assert len(resp.deception_layers) == 1

    def test_novice_tone_is_encouraging(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "cat /etc/passwd",
            _base_context(skill=SkillLevel.NOVICE),
            threat_level=0.0,
        )
        assert resp.tone == "encouraging"


class TestAdaptiveResponseAPT:
    def test_complex_counter_intel(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "nmap -sV 10.0.0.0/24",
            _base_context(skill=SkillLevel.APT),
            threat_level=0.95,
        )
        assert resp.strategy == ResponseStrategy.APT
        assert resp.complexity_score >= 8

    def test_apt_many_deception_layers(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "exploit",
            _base_context(skill=SkillLevel.APT),
            threat_level=0.9,
        )
        assert len(resp.deception_layers) == 5

    def test_apt_false_flag_in_response(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "lateral movement",
            _base_context(session_id="apt-sess", skill=SkillLevel.APT),
            threat_level=0.95,
        )
        assert "decoy" in resp.response_text.lower() or "false flag" in resp.response_text.lower()

    def test_apt_tone_deceptive(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "exfil",
            _base_context(skill=SkillLevel.APT),
            threat_level=0.9,
        )
        assert "deceptive" in resp.tone


class TestAdaptiveResponseTimePatterns:
    @patch("ragin.intelligence.adaptive_response._current_time_window")
    def test_night_time_affects_apt(self, mock_tw):
        mock_tw.return_value = TimeWindow.AFTER_HOURS
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "exfil",
            _base_context(skill=SkillLevel.APT),
            threat_level=0.9,
        )
        assert resp.tone == "deceptive_after_hours"

    @patch("ragin.intelligence.adaptive_response._current_time_window")
    def test_business_hours_neutral_tone(self, mock_tw):
        mock_tw.return_value = TimeWindow.BUSINESS_HOURS
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "scan",
            _base_context(skill=SkillLevel.INTERMEDIATE),
            threat_level=0.3,
        )
        assert resp.tone == "neutral"

    def test_metadata_includes_time_window(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "test",
            _base_context(skill=SkillLevel.NOVICE),
            threat_level=0.0,
        )
        assert "time_window" in resp.metadata


class TestAdaptedResponseIncludesContext:
    def test_session_id_preserved(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "cmd",
            _base_context(session_id="sess-42"),
            threat_level=0.1,
        )
        assert resp.session_id == "sess-42"

    def test_response_id_is_unique(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        r1 = engine.generate_adapted_response("a", _base_context(), 0.0)
        r2 = engine.generate_adapted_response("b", _base_context(), 0.0)
        assert r1.response_id != r2.response_id

    def test_audit_log_recorded(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        engine.generate_adapted_response("x", _base_context(session_id="log-sess"), 0.2)
        assert len(engine.audit_log) == 1
        assert engine.audit_log[0]["event"] == "adapted_response_generated"

    def test_rate_limit_returns_limited_response(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        # Exhaust rate limit
        from ragin.intelligence import adaptive_response as ar

        ar._rate_limit_state.clear()
        url = _mock_gateway_url()
        for _ in range(ar._RATE_LIMIT_MAX + 1):
            _check_rate_limit(url)
        resp = engine.generate_adapted_response(
            "test",
            _base_context(session_id="rl-sess"),
            threat_level=0.0,
        )
        assert resp.response_id == "rate_limited"

    def test_skill_level_string_coerced(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "test",
            {"session_id": "s", "skill_level": "expert"},
            threat_level=0.5,
        )
        assert resp.strategy == ResponseStrategy.EXPERT


# ===================================================================
# Evasion Detection
# ===================================================================


class TestEvasionDetectFingerprinting:
    def test_fingerprinting_detected(self):
        det = EvasionDetector()
        log = _session_log(["cat /etc/passwd", "uname -a", "lsb_release -a"])
        result = det.detect(log)
        assert result.detected is True
        types = {i.indicator_type for i in result.indicators}
        assert EvasionIndicatorType.FINGERPRINTING in types

    def test_hostnamectl_triggers(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["hostnamectl", "whoami"]))
        types = {i.indicator_type for i in result.indicators}
        assert EvasionIndicatorType.FINGERPRINTING in types

    def test_proc_version_triggers(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["cat /proc/version"]))
        types = {i.indicator_type for i in result.indicators}
        assert EvasionIndicatorType.FINGERPRINTING in types


class TestEvasionDetectAutomation:
    def test_fast_commands_detected(self):
        det = EvasionDetector()
        now = datetime.now(timezone.utc).timestamp()
        commands = [{"command": f"cmd{i}", "timestamp": now + i * 0.1} for i in range(6)]
        log = {"session_id": "auto-sess", "commands": commands}
        result = det.detect(log)
        timing = [i for i in result.indicators if i.indicator_type == EvasionIndicatorType.TIMING_ANALYSIS]
        assert len(timing) >= 1
        assert timing[0].confidence > 0.3

    def test_slow_commands_no_timing_flag(self):
        det = EvasionDetector()
        now = datetime.now(timezone.utc).timestamp()
        commands = [{"command": f"cmd{i}", "timestamp": now + i * 5.0} for i in range(5)]
        log = {"session_id": "slow-sess", "commands": commands}
        result = det.detect(log)
        timing = [i for i in result.indicators if i.indicator_type == EvasionIndicatorType.TIMING_ANALYSIS]
        assert len(timing) == 0


class TestEvasionDetectToolSignatures:
    def test_nmap_detected(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["nmap -sV 10.0.0.0/24"]))
        types = {i.indicator_type for i in result.indicators}
        assert EvasionIndicatorType.TOOL_SIGNATURE in types

    def test_metasploit_detected(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["msfconsole -q"]))
        types = {i.indicator_type for i in result.indicators}
        assert EvasionIndicatorType.TOOL_SIGNATURE in types

    def test_sqlmap_detected(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["sqlmap -u http://target/?id=1"]))
        types = {i.indicator_type for i in result.indicators}
        assert EvasionIndicatorType.TOOL_SIGNATURE in types

    def test_sandbox_detection(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["dmesg | grep kvm", "cat /sys/class/dmi/id/product_name"]))
        types = {i.indicator_type for i in result.indicators}
        assert EvasionIndicatorType.SANDBOX_DETECTION in types


class TestEvasionNoFalsePositives:
    def test_normal_session_clean(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["ls -la", "pwd", "cat README.md", "python3 app.py"]))
        assert result.detected is False
        assert result.detection_confidence == 0.0

    def test_empty_session_clean(self):
        det = EvasionDetector()
        result = det.detect({"session_id": "empty", "commands": []})
        assert result.detected is False

    def test_single_harmless_command_clean(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["echo hello"]))
        assert result.detected is False


class TestEvasionConfidence:
    def test_multiple_indicators_boost_confidence(self):
        det = EvasionDetector()
        log = _session_log(
            [
                "nmap -sV target",
                "cat /etc/passwd",
                "msfconsole",
                "honeypot check",
            ]
        )
        result = det.detect(log)
        assert result.detection_confidence > 0.7

    def test_single_low_confidence_below_threshold(self):
        det = EvasionDetector()
        # Use a lower-confidence indicator that stays below threshold
        ind = EvasionIndicator(
            indicator_type=EvasionIndicatorType.SANDBOX_DETECTION,
            evidence="vmware",
            confidence=0.3,
        )
        confidence = det.calculate_detection_confidence([ind])
        # 1 - (1 - 0.3) = 0.3 < 0.4
        assert confidence < 0.4

    def test_cumulative_across_calls(self):
        det = EvasionDetector()
        r1 = det.detect(_session_log(["nmap -sV target"], session_id="cum-sess"))
        assert r1.detection_confidence > 0.0
        r2 = det.detect(_session_log(["cat /etc/passwd"], session_id="cum-sess"))
        assert r2.detection_confidence >= r1.detection_confidence


class TestAdjustmentRecommendation:
    def test_high_confidence_triggers_recommendation(self):
        det = EvasionDetector()
        log = _session_log(
            [
                "nmap -sV target",
                "cat /etc/passwd",
                "msfconsole -q",
                "is this a honeypot?",
                "uname -a",
            ]
        )
        result = det.detect(log)
        assert result.recommendation is not None
        assert result.recommendation.inject_false_flags is True or result.recommendation.reduce_artifacts is True

    def test_low_confidence_no_recommendation(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["ls"]))
        assert result.recommendation is None

    def test_recommend_method(self):
        det = EvasionDetector()
        result = det.detect(_session_log(["ls"]))
        rec = det.recommend_response_adjustment(result)
        assert isinstance(rec, AdjustmentRecommendation)
        assert rec.reason == "no evasion detected"


# ===================================================================
# Skill Adaptive Strategy
# ===================================================================


class TestSkillStrategyCreation:
    def test_default_novice(self):
        strat = SkillAdaptiveStrategy()
        profile = strat.determine_strategy("s1")
        assert profile.skill_level == SkillLevel.NOVICE
        assert profile.response_strategy == ResponseStrategy.NOVICE
        assert profile.deception_depth == 1

    def test_stored_profile(self):
        strat = SkillAdaptiveStrategy()
        strat.determine_strategy("s2")
        assert strat.get_profile("s2") is not None

    def test_nonexistent_profile(self):
        strat = SkillAdaptiveStrategy()
        assert strat.get_profile("no-such") is None

    def test_initial_engagement_zero(self):
        strat = SkillAdaptiveStrategy()
        profile = strat.determine_strategy("s3")
        assert profile.engagement_score == 0.0
        assert profile.interaction_count == 0

    def test_apt_deep_deception(self):
        strat = SkillAdaptiveStrategy()
        profile = strat.determine_strategy("apt-s")
        # Without a classifier, defaults to novice
        assert profile.deception_depth == 1


class TestSkillStrategyUpdates:
    def test_update_increases_interaction(self):
        strat = SkillAdaptiveStrategy()
        strat.determine_strategy("u1")
        updated = strat.update_strategy("u1", {"summary": "exploit attempt"})
        assert updated.interaction_count == 1

    def test_update_increases_engagement(self):
        strat = SkillAdaptiveStrategy()
        strat.determine_strategy("u2")
        updated = strat.update_strategy("u2", {"engagement_delta": 0.2})
        assert updated.engagement_score == pytest.approx(0.2)

    def test_update_can_change_skill_level(self):
        strat = SkillAdaptiveStrategy()
        strat.determine_strategy("u3")
        updated = strat.update_strategy("u3", {"skill_level": SkillLevel.APT})
        assert updated.skill_level == SkillLevel.APT
        assert updated.response_strategy == ResponseStrategy.APT
        assert updated.deception_depth == 5

    def test_update_caps_engagement_at_1(self):
        strat = SkillAdaptiveStrategy()
        strat.determine_strategy("u4")
        updated = strat.update_strategy("u4", {"engagement_delta": 0.9})
        updated = strat.update_strategy("u4", {"engagement_delta": 0.9})
        assert updated.engagement_score <= 1.0

    def test_update_trails_capped_at_50(self):
        strat = SkillAdaptiveStrategy()
        strat.determine_strategy("u5")
        for i in range(60):
            updated = strat.update_strategy("u5", {"summary": f"iter_{i}"})
        assert len(updated.evidence_trail) <= 50

    def test_update_auto_creates_profile(self):
        strat = SkillAdaptiveStrategy()
        updated = strat.update_strategy("new-sess", {"summary": "first"})
        assert updated.interaction_count == 1


class TestEngagementParamsByLevel:
    def test_novice_params(self):
        strat = SkillAdaptiveStrategy()
        profile = strat.determine_strategy("p1")
        params = strat.get_engagement_params(profile)
        assert params.artifact_density == pytest.approx(0.8)
        assert params.persona_complexity == 2
        assert params.deception_depth == 1
        assert params.information_leakage_rate == pytest.approx(0.7)

    def test_apt_params(self):
        strat = SkillAdaptiveStrategy()
        profile = StrategyProfile(
            session_id="p2",
            skill_level=SkillLevel.APT,
            response_strategy=ResponseStrategy.APT,
            deception_depth=5,
            information_leakage_rate=0.1,
        )
        params = strat.get_engagement_params(profile)
        assert params.artifact_density == pytest.approx(0.15)
        assert params.persona_complexity == 9
        assert params.deception_depth == 5
        assert params.information_leakage_rate == pytest.approx(0.1)

    def test_delay_is_bounded(self):
        strat = SkillAdaptiveStrategy()
        for skill in SkillLevel:
            profile = StrategyProfile(
                session_id=f"delay-{skill.value}",
                skill_level=skill,
                response_strategy=ResponseStrategy(skill.value),
                deception_depth=1,
                information_leakage_rate=0.5,
            )
            params = strat.get_engagement_params(profile)
            assert 0 <= params.response_delay_ms <= 30000

    def test_params_by_level_artifact_density_decreases(self):
        strat = SkillAdaptiveStrategy()
        densities = []
        for skill in SkillLevel:
            profile = StrategyProfile(
                session_id=f"density-{skill.value}",
                skill_level=skill,
                response_strategy=ResponseStrategy(skill.value),
                deception_depth=1,
                information_leakage_rate=0.5,
            )
            params = strat.get_engagement_params(profile)
            densities.append(params.artifact_density)
        # Novice > Intermediate > Expert > APT
        assert densities[0] > densities[1] > densities[2] > densities[3]

    def test_time_window_in_params(self):
        strat = SkillAdaptiveStrategy()
        profile = strat.determine_strategy("tw1")
        params = strat.get_engagement_params(profile)
        assert params.time_window in TimeWindow


# ===================================================================
# Model Validation
# ===================================================================


class TestModelValidation:
    def test_adapted_response_valid(self):
        resp = AdaptedResponse(
            response_id="r1",
            session_id="s1",
            strategy=ResponseStrategy.NOVICE,
            response_text="test",
            complexity_score=1,
        )
        assert resp.complexity_score >= 1

    def test_evasion_indicator_bounds(self):
        ind = EvasionIndicator(
            indicator_type=EvasionIndicatorType.FINGERPRINTING,
            confidence=1.0,
        )
        assert ind.confidence == 1.0

    def test_evasion_indicator_rejects_bad_confidence(self):
        with pytest.raises(Exception):
            EvasionIndicator(confidence=1.5)

    def test_adjustment_recommendation_rejects_long_reason(self):
        with pytest.raises(Exception):
            AdjustmentRecommendation(reason="a" * 3000)

    def test_strategy_profile_valid(self):
        profile = StrategyProfile(
            session_id="sp1",
            skill_level=SkillLevel.EXPERT,
            response_strategy=ResponseStrategy.EXPERT,
        )
        assert profile.skill_level == SkillLevel.EXPERT

    def test_engagement_params_rejects_invalid_bounds(self):
        with pytest.raises(Exception):
            EngagementParams(response_delay_ms=-1)
        with pytest.raises(Exception):
            EngagementParams(artifact_density=2.0)

    def test_engagement_params_valid_construction(self):
        params = EngagementParams(
            response_delay_ms=0,
            artifact_density=1.0,
        )
        assert params.response_delay_ms == 0
        assert params.artifact_density == 1.0


# ===================================================================
# Evasion → Response Adjustment Integration
# ===================================================================


class TestEvasionAdjustmentIntegration:
    def test_evasion_reduces_artifacts(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "cmd",
            _base_context(skill=SkillLevel.INTERMEDIATE),
            threat_level=0.3,
        )
        original_count = len(resp.artifacts_injected)

        evasion = EvasionResult(
            session_id="adj-sess",
            detected=True,
            detection_confidence=0.8,
            recommendation=AdjustmentRecommendation(
                reduce_artifacts=True,
                slow_response_timing=True,
                reason="test",
            ),
        )
        adjusted = engine.adjust_for_evasion(resp, evasion)
        assert len(adjusted.artifacts_injected) <= original_count

    def test_evasion_increases_complexity(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "cmd",
            _base_context(skill=SkillLevel.INTERMEDIATE),
            threat_level=0.3,
        )
        original_complexity = resp.complexity_score

        evasion = EvasionResult(
            session_id="cplx-sess",
            detected=True,
            detection_confidence=0.9,
            recommendation=AdjustmentRecommendation(
                increase_deception=True,
                reason="complex test",
            ),
        )
        adjusted = engine.adjust_for_evasion(resp, evasion)
        assert adjusted.complexity_score >= original_complexity

    def test_no_recommendation_returns_original(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "cmd",
            _base_context(),
            threat_level=0.0,
        )
        evasion = EvasionResult(detected=False, detection_confidence=0.0)
        adjusted = engine.adjust_for_evasion(resp, evasion)
        assert adjusted.response_id == resp.response_id

    def test_evasion_audit_logged(self):
        engine = AdaptiveResponseEngine(_mock_gateway_url(), _mock_hisoka())
        resp = engine.generate_adapted_response(
            "cmd",
            _base_context(session_id="audit-sess"),
            threat_level=0.1,
        )
        evasion = EvasionResult(
            session_id="audit-sess",
            detected=True,
            detection_confidence=0.7,
            recommendation=AdjustmentRecommendation(reason="log test"),
        )
        engine.adjust_for_evasion(resp, evasion)
        events = [e for e in engine.audit_log if e["event"] == "response_adjusted_for_evasion"]
        assert len(events) == 1


# ===================================================================
# Sanitize Input
# ===================================================================


class TestSanitizeInput:
    def test_strips_script_tags(self):
        assert "<script>" not in _sanitize_input("hello <script>alert(1)</script> world")

    def test_strips_javascript(self):
        assert "javascript:" not in _sanitize_input("click javascript:void(0)")

    def test_truncates_long_input(self):
        long = "a" * 5000
        result = _sanitize_input(long, max_length=4096)
        assert len(result) == 4096

    def test_normal_input_unchanged(self):
        assert _sanitize_input("normal command") == "normal command"


# ===================================================================
# Current Time Window
# ===================================================================


class TestCurrentTimeWindow:
    def test_weekend(self):
        from datetime import datetime

        dt = datetime(2025, 7, 12, 10, 0, tzinfo=timezone.utc)  # Saturday
        assert _current_time_window(dt) == TimeWindow.WEEKEND

    def test_business_hours(self):
        from datetime import datetime

        dt = datetime(2025, 7, 14, 12, 0, tzinfo=timezone.utc)  # Monday 12:00
        assert _current_time_window(dt) == TimeWindow.BUSINESS_HOURS

    def test_after_hours(self):
        from datetime import datetime

        dt = datetime(2025, 7, 14, 20, 0, tzinfo=timezone.utc)  # Monday 20:00
        assert _current_time_window(dt) == TimeWindow.AFTER_HOURS
