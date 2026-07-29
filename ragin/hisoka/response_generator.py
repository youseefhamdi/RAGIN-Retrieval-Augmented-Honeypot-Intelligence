"""Response generation for Hisoka — LLM-backed with artifact injection."""

from __future__ import annotations

import logging
from typing import Any

from ragin.hisoka.deception import (
    _PERSONA_CONFIGS,
    ArtifactInjector,
    _sanitize_input,
)
from ragin.hisoka.deception import (
    ResponseGenerator as _CoreResponseGenerator,
)

logger = logging.getLogger(__name__)


class ResponseGeneratorExtended:
    """Extended response generator with consistency enforcement and artifact injection."""

    def __init__(self, gateway_url: str | None = None) -> None:
        self._core = _CoreResponseGenerator(gateway_url=gateway_url)
        self._artifact_injector = ArtifactInjector()
        self._session_artifacts: dict[str, list[str]] = {}

    def generate(self, prompt: str, persona: Any, session_context: dict[str, Any]) -> str:
        """Generate a deception response using the LLM gateway.

        Args:
            prompt: The attacker's input.
            persona: Persona object or skill level string.
            session_context: Session state context.

        Returns:
            Generated response string.
        """
        skill_level = getattr(persona, "skill_level", str(persona))
        context = session_context.get("context", "")
        return self._core.generate(skill_level=skill_level, user_input=prompt, context=context)

    def build_system_prompt(self, persona: Any, context: dict[str, Any]) -> str:
        """Construct the system prompt from persona and context."""
        skill_level = getattr(persona, "skill_level", str(persona))
        cfg = _PERSONA_CONFIGS.get(skill_level, _PERSONA_CONFIGS["novice"])
        base = cfg["system_prompt"]
        extra = context.get("additional_instructions", "")
        return f"{base}\n{extra}" if extra else base

    def inject_realistic_artifacts(self, response: str) -> str:
        """Add fake config fragments or credential hints to the response."""
        return self._artifact_injector.inject("fake_config", skill_level="intermediate") + "\n" + response

    def ensure_consistency(self, response: str, session_context: dict[str, Any]) -> str:
        """Verify no contradictions with previously stated facts."""
        # Basic consistency: strip any real credential patterns
        sanitized = _sanitize_input(response)
        return sanitized
