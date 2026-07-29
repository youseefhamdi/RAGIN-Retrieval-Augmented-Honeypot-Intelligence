"""Skill-adaptive strategy — maps skill level to engagement parameters."""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ragin.chrollo.models import SkillLevel
from ragin.intelligence.adaptive_response import _current_time_window
from ragin.intelligence.models import (
    EngagementParams,
    ResponseStrategy,
    StrategyProfile,
    TimeWindow,
)

if TYPE_CHECKING:
    from ragin.chrollo.classifier import ChrolloClassifier
    from ragin.don.threat_mapper import ThreatMapper
    from ragin.hisoka.deceiver import AdaptiveDeceiver

logger = logging.getLogger(__name__)

_SKILL_TO_STRATEGY: dict[SkillLevel, ResponseStrategy] = {
    SkillLevel.NOVICE: ResponseStrategy.NOVICE,
    SkillLevel.INTERMEDIATE: ResponseStrategy.INTERMEDIATE,
    SkillLevel.EXPERT: ResponseStrategy.EXPERT,
    SkillLevel.APT: ResponseStrategy.APT,
}

_PARAMS_BY_SKILL: dict[SkillLevel, dict[str, Any]] = {
    SkillLevel.NOVICE: {
        "delay_range_ms": (50, 200),
        "artifact_density": 0.8,
        "persona_complexity": 2,
        "deception_depth": 1,
        "info_leakage_rate": 0.7,
    },
    SkillLevel.INTERMEDIATE: {
        "delay_range_ms": (200, 800),
        "artifact_density": 0.5,
        "persona_complexity": 5,
        "deception_depth": 2,
        "info_leakage_rate": 0.4,
    },
    SkillLevel.EXPERT: {
        "delay_range_ms": (500, 1500),
        "artifact_density": 0.3,
        "persona_complexity": 7,
        "deception_depth": 4,
        "info_leakage_rate": 0.2,
    },
    SkillLevel.APT: {
        "delay_range_ms": (800, 2500),
        "artifact_density": 0.15,
        "persona_complexity": 9,
        "deception_depth": 5,
        "info_leakage_rate": 0.1,
    },
}


def _compute_delay(params: dict[str, Any], time_window: TimeWindow) -> int:
    lo, hi = params["delay_range_ms"]
    base = (lo + hi) // 2
    if time_window == TimeWindow.AFTER_HOURS:
        base = int(base * 1.15)
    elif time_window == TimeWindow.WEEKEND:
        base = int(base * 0.9)
    return max(0, min(30000, base))


class SkillAdaptiveStrategy:
    """Determines and evolves engagement strategy per session."""

    def __init__(
        self,
        classifier: ChrolloClassifier | None = None,
        threat_mapper: ThreatMapper | None = None,
        deceiver: AdaptiveDeceiver | None = None,
    ) -> None:
        self._classifier = classifier
        self._threat_mapper = threat_mapper
        self._deceiver = deceiver
        self._profiles: dict[str, StrategyProfile] = {}
        logger.info("SkillAdaptiveStrategy initialized")

    def determine_strategy(self, session_id: str) -> StrategyProfile:
        skill_level = SkillLevel.NOVICE
        if self._classifier is not None:
            try:
                result = self._classifier.classify(session_id)
                if hasattr(result, "skill_level"):
                    raw = result.skill_level
                    skill_level = raw if isinstance(raw, SkillLevel) else SkillLevel(str(raw).lower())
            except Exception:
                logger.debug("Classifier unavailable, defaulting to NOVICE for %s", session_id)

        strategy = _SKILL_TO_STRATEGY.get(skill_level, ResponseStrategy.NOVICE)
        params = _PARAMS_BY_SKILL[skill_level]
        _current_time_window()

        profile = StrategyProfile(
            session_id=session_id,
            skill_level=skill_level,
            response_strategy=strategy,
            engagement_score=0.0,
            interaction_count=0,
            deception_depth=params["deception_depth"],
            information_leakage_rate=params["info_leakage_rate"],
            evidence_trail=[f"initial_strategy:{strategy.value}"],
            updated_at=datetime.now(timezone.utc),
        )

        self._profiles[session_id] = profile
        logger.info(
            "Strategy determined for session %s: skill=%s strategy=%s",
            session_id,
            skill_level.value,
            strategy.value,
        )
        return profile

    def update_strategy(self, session_id: str, new_evidence: dict[str, Any]) -> StrategyProfile:
        profile = self._profiles.get(session_id)
        if profile is None:
            profile = self.determine_strategy(session_id)

        interaction_count = profile.interaction_count + 1
        evidence_str = str(new_evidence.get("summary", ""))
        evidence_trail = list(profile.evidence_trail)
        if evidence_str:
            evidence_trail.append(f"iter_{interaction_count}:{evidence_str}")

        engagement = min(1.0, profile.engagement_score + new_evidence.get("engagement_delta", 0.05))

        new_skill_raw = new_evidence.get("skill_level")
        skill_level = profile.skill_level
        if new_skill_raw is not None:
            if isinstance(new_skill_raw, SkillLevel):
                skill_level = new_skill_raw
            else:
                with contextlib.suppress(ValueError):
                    skill_level = SkillLevel(str(new_skill_raw).lower())

        strategy = _SKILL_TO_STRATEGY.get(skill_level, profile.response_strategy)
        params = _PARAMS_BY_SKILL[skill_level]

        updated = StrategyProfile(
            session_id=session_id,
            skill_level=skill_level,
            response_strategy=strategy,
            engagement_score=engagement,
            interaction_count=interaction_count,
            deception_depth=params["deception_depth"],
            information_leakage_rate=params["info_leakage_rate"],
            evidence_trail=evidence_trail[-50:],
            updated_at=datetime.now(timezone.utc),
        )

        self._profiles[session_id] = updated
        return updated

    def get_engagement_params(self, strategy: StrategyProfile) -> EngagementParams:
        params = _PARAMS_BY_SKILL[strategy.skill_level]
        time_window = _current_time_window()
        delay = _compute_delay(params, time_window)

        return EngagementParams(
            response_delay_ms=delay,
            artifact_density=params["artifact_density"],
            persona_complexity=params["persona_complexity"],
            deception_depth=strategy.deception_depth,
            information_leakage_rate=strategy.information_leakage_rate,
            time_window=time_window,
        )

    def get_profile(self, session_id: str) -> StrategyProfile | None:
        return self._profiles.get(session_id)
