"""Persona management for Hisoka — skill-matched deception personas."""

from __future__ import annotations

import logging
from typing import Any

from ragin.hisoka.deception import _PERSONA_CONFIGS, PersonaManager
from ragin.hisoka.models import Persona

logger = logging.getLogger(__name__)


class PersonaManagerExtended:
    """Extended persona management with persona switching and metadata."""

    PERSONAS: dict[str, dict[str, Any]] = _PERSONA_CONFIGS

    def __init__(self) -> None:
        self._core = PersonaManager()

    def get_persona(self, skill_level: str) -> Persona:
        """Return skill-matched persona."""
        return self._core.select(skill_level)

    def list_personas(self) -> list[str]:
        """Return all available persona skill levels."""
        return list(self.PERSONAS.keys())
