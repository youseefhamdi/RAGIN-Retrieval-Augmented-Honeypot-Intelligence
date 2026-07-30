"""Adaptive deceiver — orchestrates persona selection and response generation."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from ragin.hisoka.deception import (
    ArtifactInjector,
    EngagementTracker,
    PersonaManager,
    ResponseGenerator,
)
from ragin.hisoka.honeytokens import HoneytokenConfig, HoneytokenEngine
from ragin.hisoka.memory import HisokaMemory
from ragin.hisoka.models import DeceptionResponse, Persona
from ragin.utils import CircuitBreaker, CostTracker, PromptTokenLimiter, _redact_pii

logger = logging.getLogger(__name__)


class AdaptiveDeceiver:
    """Top-level deception orchestrator.

    Receives attacker input and Don analysis, selects the appropriate persona,
    generates deceptive responses, and tracks engagement.

    Optionally uses :class:`HisokaMemory` to enrich prompts with
    cross-session attacker history for more convincing deception.
    """

    def __init__(
        self,
        gateway_url: str | None = None,
        config: dict[str, Any] | None = None,
        memory: HisokaMemory | None = None,
        api_key: str | None = None,
    ) -> None:
        self._persona_manager = PersonaManager()
        self._response_generator = ResponseGenerator(gateway_url=gateway_url, api_key=api_key)
        self._engagement_tracker = EngagementTracker()
        self._artifact_injector = ArtifactInjector()
        self._config = config or {}
        self._memory = memory

        # Per-session honeytoken engines — each session gets its own
        # token namespace so triggers don't cross-contaminate.
        self._honeytoken_engines: dict[str, HoneytokenEngine] = {}
        self._honeytoken_alerts: dict[str, list] = defaultdict(list)

        # Production infrastructure
        self._circuit_breaker = CircuitBreaker(threshold=5, timeout_s=60.0)
        self._cost_tracker = CostTracker(daily_budget_usd=20.0, monthly_budget_usd=2000.0, per_request_budget_usd=0.10)
        self._prompt_limiter = PromptTokenLimiter(max_prompt_tokens=32_000)

    def generate_response(
        self,
        attacker_input: str,
        session_context: dict[str, Any],
    ) -> DeceptionResponse:
        """Generate a full deception response for an attacker interaction.

        Applies PII redaction on attacker input before LLM calls, enforces
        budget and circuit breaker, and tracks costs from gateway responses.

        If ``session_context`` contains an ``attacker_history`` key (populated
        by the pipeline from Mem0 search results), it is injected into the
        prompt for continuity-aware deception.
        """
        session_id = session_context.get("session_id", "unknown")
        classification = session_context.get("classification", {})
        skill_level = classification.get("skill_level", session_context.get("skill_level", "novice"))

        self._persona_manager.select(skill_level)
        self._engagement_tracker.record_command(session_id)

        # PII redact attacker input before it reaches the LLM
        redacted_input = _redact_pii(attacker_input)

        # Budget enforcement
        if not self._cost_tracker.check_budget("hisoka"):
            logger.warning("Hisoka budget exhausted — returning static deception")
            response_text = self._static_fallback(skill_level, redacted_input)
        elif not self._circuit_breaker.allow():
            logger.warning("Hisoka circuit breaker open — static fallback")
            response_text = self._static_fallback(skill_level, redacted_input)
        else:
            # Build prompt — include attacker history if available
            prompt_text = f"{session_context.get('context', '')}\n{redacted_input}"

            attacker_history = session_context.get("attacker_history")
            if attacker_history:
                history_block = "\n".join(f"  - {h}" for h in attacker_history[:5])
                prompt_text = f"Known attacker history:\n{history_block}\n\n" f"Current command: {prompt_text}"

            # Prompt token limit check
            if not self._prompt_limiter.check(prompt_text):
                prompt_text = self._prompt_limiter.truncate(prompt_text)
                logger.warning("Hisoka prompt truncated to fit token budget")

            response_text = self._response_generator.generate(
                skill_level=skill_level,
                user_input=redacted_input,
                context=prompt_text,
            )

            # Track cost — we don't have usage from the response generator
            # so we estimate from the response length
            estimated_tokens = max(1, len(response_text) // 4)
            self._cost_tracker.record(
                "hisoka",
                "inclusionai/ling-3.0-flash:free",
                {"prompt_tokens": len(prompt_text) // 4, "completion_tokens": estimated_tokens},
            )
            self._circuit_breaker.record_success()

        # Inject artifacts for higher skill levels
        artifacts = []
        if skill_level in ("intermediate", "expert", "apt"):
            self._artifact_injector.inject("fake_config", skill_level=skill_level)
            artifacts.append("fake_config")

        # --- Honeytokens -------------------------------------------------
        # 1) Get / create a per-session engine
        ht_engine = self._honeytoken_engines.get(session_id)
        if ht_engine is None:
            ht_engine = HoneytokenEngine(
                HoneytokenConfig(
                    session_id=session_id,
                )
            )
            self._honeytoken_engines[session_id] = ht_engine

        # 2) Check if attacker is *using* a previously-planted token
        ht_alerts = ht_engine.check_triggers({"input": attacker_input})
        self._honeytoken_alerts[session_id].extend(ht_alerts)
        honeytoken_triggered = len(ht_alerts) > 0

        # 3) Inject fresh tokens into the outgoing response
        if not honeytoken_triggered:
            # Only plant new tokens when the attacker hasn't triggered
            # existing ones — avoids over-planting.
            ht_engine.inject(response_text, context=skill_level)

        engagement = self._engagement_tracker.get_score(session_id)

        return DeceptionResponse(
            session_id=session_id,
            response_text=response_text,
            persona_used=skill_level,
            artifacts_injected=artifacts,
            engagement_score=engagement,
            honeytoken_triggered=honeytoken_triggered,
        )

    def _static_fallback(self, skill_level: str, attacker_input: str) -> str:
        """Return a pre-crafted deceptive response when LLM is unavailable."""
        fallbacks = {
            "novice": "Permission denied. This operation is not authorized.",
            "intermediate": "Command not found. Did you mean 'help'?",
            "expert": "Segmentation fault (core dumped).",
            "apt": "Connection to remote host timed out.",
        }
        return fallbacks.get(skill_level, "Unknown command.")

    def adapt_persona(self, skill_level: str) -> Persona:
        """Switch to a persona matching the given skill level."""
        return self._persona_manager.select(skill_level)

    def maintain_consistency(self, session_id: str) -> dict[str, Any]:
        """Return session context that ensures persona consistency."""
        return {"session_id": session_id, "consistent": True}

    def calculate_engagement(self, session_log: list[dict[str, Any]]) -> float:
        """Measure dwell time potential from a session log."""
        if not session_log:
            return 0.0
        import math

        return min(1.0, math.log1p(len(session_log)) / 10.0)
