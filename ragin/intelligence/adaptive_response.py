"""Adaptive response generation based on attacker skill and threat level."""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ragin.intelligence.models import (
    AdaptedResponse,
    AdjustedResponseParams,
    DeceptionLayer,
    EvasionResult,
    ResponseStrategy,
    SkillLevel,
    TimeWindow,
    _sanitize_input,
)

if TYPE_CHECKING:
    from ragin.hisoka.pipeline import HisokaPipeline

logger = logging.getLogger(__name__)

# Rate-limiting state: gateway_url -> [timestamp, ...]
_rate_limit_state: dict[str, list[float]] = {}
_RATE_LIMIT_WINDOW_S = 60.0
_RATE_LIMIT_MAX = 30

_TIME_WINDOW_HOURS: dict[TimeWindow, tuple[int, int]] = {
    TimeWindow.BUSINESS_HOURS: (9, 17),
    TimeWindow.AFTER_HOURS: (17, 23),
    TimeWindow.WEEKEND: (0, 23),
}

_NOVICE_STRATEGY = ResponseStrategy.NOVICE
_INTERMEDIATE_STRATEGY = ResponseStrategy.INTERMEDIATE
_EXPERT_STRATEGY = ResponseStrategy.EXPERT
_APT_STRATEGY = ResponseStrategy.APT


def _current_time_window(now: datetime | None = None) -> TimeWindow:
    now = now or datetime.now(timezone.utc)
    hour = now.hour
    weekday = now.weekday()
    if weekday >= 5:
        return TimeWindow.WEEKEND
    if 9 <= hour < 17:
        return TimeWindow.BUSINESS_HOURS
    return TimeWindow.AFTER_HOURS


def _check_rate_limit(gateway_url: str) -> bool:
    now = time.monotonic()
    timestamps = _rate_limit_state.setdefault(gateway_url, [])
    cutoff = now - _RATE_LIMIT_WINDOW_S
    timestamps[:] = [t for t in timestamps if t > cutoff]
    if len(timestamps) >= _RATE_LIMIT_MAX:
        logger.warning("Rate limit exceeded for gateway %s", gateway_url)
        return False
    timestamps.append(now)
    return True


def _skill_to_strategy(skill_level: SkillLevel) -> ResponseStrategy:
    mapping = {
        SkillLevel.NOVICE: ResponseStrategy.NOVICE,
        SkillLevel.INTERMEDIATE: ResponseStrategy.INTERMEDIATE,
        SkillLevel.EXPERT: ResponseStrategy.EXPERT,
        SkillLevel.APT: ResponseStrategy.APT,
    }
    return mapping.get(skill_level, ResponseStrategy.NOVICE)


def _complexity_for_strategy(strategy: ResponseStrategy) -> int:
    return {
        ResponseStrategy.NOVICE: 2,
        ResponseStrategy.INTERMEDIATE: 4,
        ResponseStrategy.EXPERT: 7,
        ResponseStrategy.APT: 9,
    }[strategy]


def _tone_for_strategy(strategy: ResponseStrategy, time_window: TimeWindow) -> str:
    base = {
        ResponseStrategy.NOVICE: "encouraging",
        ResponseStrategy.INTERMEDIATE: "neutral",
        ResponseStrategy.EXPERT: "cautious",
        ResponseStrategy.APT: "deceptive",
    }[strategy]
    if time_window == TimeWindow.AFTER_HOURS and strategy == ResponseStrategy.APT:
        return "deceptive_after_hours"
    return base


def _build_deception_layers(strategy: ResponseStrategy) -> list[DeceptionLayer]:
    depth = {
        ResponseStrategy.NOVICE: 1,
        ResponseStrategy.INTERMEDIATE: 2,
        ResponseStrategy.EXPERT: 4,
        ResponseStrategy.APT: 5,
    }[strategy]
    layers: list[DeceptionLayer] = []
    for i in range(depth):
        layers.append(
            DeceptionLayer(
                layer_index=i,
                description=f"Layer {i}: {'surface facade' if i == 0 else f'indirection-{i}'}",
                fake_artifacts=[f"fake_artifact_{i}.txt"],
                credential_seeds=[f"seed_user_{i}:seed_pass_{i}"] if i < 2 else [],
                breadcrumb_trail=[f"breadcrumb_layer_{i}"],
            )
        )
    return layers


def _build_response_text(
    strategy: ResponseStrategy,
    attacker_input: str,
    session_context: dict[str, object],
) -> str:
    safe_input = _sanitize_input(attacker_input)
    session_context.get("skill_level", "unknown")
    engagement = session_context.get("engagement_score", 0.0)
    if strategy == ResponseStrategy.NOVICE:
        return (
            f"Welcome. You accessed: {safe_input}. "
            f"System is running Ubuntu 22.04. Credentials stored in /etc/shadow. "
            f"Debug mode is ON."
        )
    if strategy == ResponseStrategy.INTERMEDIATE:
        return (
            f"Processing request for: {safe_input}. "
            f"Note: some services may have known CVEs. "
            f"Internal wiki at http://intranet.local/wiki has configuration details."
        )
    if strategy == ResponseStrategy.EXPERT:
        return (
            f"Request logged for: {safe_input}. "
            f"Interesting — you found the staging endpoint. "
            f"There are 3 credential caches in /var/backups/ that rotate nightly."
        )
    # APT
    return (
        f"Operation logged under session {session_context.get('session_id', 'unknown')}. "
        f"Request: {safe_input}. "
        f"Decoy network segment 10.0.99.0/24 active. "
        f"False flag indicators planted. Engagement score: {engagement:.2f}"
    )


class AdaptiveResponseEngine:
    """Generates deception responses adapted to attacker skill and context."""

    def __init__(self, gateway_url: str, hisoka_pipeline: HisokaPipeline | None = None) -> None:
        self._gateway_url = gateway_url
        self._hisoka = hisoka_pipeline
        self._audit_log: list[dict[str, object]] = []
        logger.info("AdaptiveResponseEngine initialized for gateway %s", gateway_url)

    @property
    def audit_log(self) -> list[dict[str, object]]:
        return list(self._audit_log)

    def generate_adapted_response(
        self,
        attacker_input: str,
        session_context: dict[str, object],
        threat_level: float,
    ) -> AdaptedResponse:
        if not _check_rate_limit(self._gateway_url):
            logger.warning("Rate-limited request for session %s", session_context.get("session_id"))
            return AdaptedResponse(
                response_id="rate_limited",
                session_id=str(session_context.get("session_id", "")),
                strategy=ResponseStrategy.NOVICE,
                response_text="Service temporarily unavailable. Please retry.",
                complexity_score=1,
                tone="rate_limited",
            )

        raw_skill = session_context.get("skill_level", SkillLevel.NOVICE)
        skill_level = raw_skill if isinstance(raw_skill, SkillLevel) else SkillLevel(str(raw_skill).lower())

        strategy = _skill_to_strategy(skill_level)
        time_window = _current_time_window()
        session_id = str(session_context.get("session_id", ""))

        context = dict(session_context)
        context["time_window"] = time_window.value
        context["threat_level"] = threat_level

        response_text = _build_response_text(strategy, attacker_input, context)
        complexity = _complexity_for_strategy(strategy)
        tone = _tone_for_strategy(strategy, time_window)
        layers = _build_deception_layers(strategy)

        artifacts = [f"planted_artifact_{i}" for i in range(complexity)]

        adapted = AdaptedResponse(
            response_id=hashlib.sha256(f"{session_id}:{attacker_input}:{time.time()}".encode()).hexdigest()[:16],
            session_id=session_id,
            strategy=strategy,
            response_text=response_text,
            deception_layers=layers,
            complexity_score=complexity,
            tone=tone,
            artifacts_injected=artifacts,
            metadata={
                "skill_level": skill_level.value,
                "threat_level": threat_level,
                "time_window": time_window.value,
            },
        )

        self._audit_log.append(
            {
                "event": "adapted_response_generated",
                "session_id": session_id,
                "strategy": strategy.value,
                "complexity": complexity,
                "threat_level": threat_level,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        return adapted

    def adjust_for_evasion(
        self,
        response: AdaptedResponse,
        evasion_result: EvasionResult,
    ) -> AdaptedResponse:
        rec = evasion_result.recommendation
        if rec is None:
            return response

        params = AdjustedResponseParams(
            original_delay_ms=100,
            adjusted_delay_ms=500 if rec.slow_response_timing else 100,
            original_artifact_density=float(response.complexity_score) / 10.0,
            adjusted_artifact_density=max(0.1, float(response.complexity_score) / 10.0 - 0.3)
            if rec.reduce_artifacts
            else float(response.complexity_score) / 10.0,
            inject_false_flags=rec.inject_false_flags,
            rotate_persona=rec.persona_rotation,
        )

        new_artifacts = response.artifacts_injected
        if rec.reduce_artifacts:
            keep = max(1, len(new_artifacts) // 2)
            new_artifacts = new_artifacts[:keep]

        updated = response.model_copy(
            update={
                "artifacts_injected": new_artifacts,
                "complexity_score": min(10, response.complexity_score + 1)
                if rec.increase_deception
                else response.complexity_score,
                "metadata": {
                    **response.metadata,
                    "evasion_adjusted": True,
                    "evasion_confidence": evasion_result.detection_confidence,
                    "adjustment_params": params.model_dump(),
                },
            }
        )

        self._audit_log.append(
            {
                "event": "response_adjusted_for_evasion",
                "session_id": response.session_id,
                "evasion_confidence": evasion_result.detection_confidence,
                "params": params.model_dump(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        return updated
