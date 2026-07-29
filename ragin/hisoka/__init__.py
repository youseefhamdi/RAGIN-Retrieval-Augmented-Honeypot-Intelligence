"""Hisoka — Adaptive Deception Layer (Phase 2.2).

Generates realistic, skill-appropriate deception responses to maximize
attacker dwell time. Receives threat analysis from Don and maintains
consistent persona per session.
"""

from ragin.hisoka.deception import (
    ArtifactInjector,
    EngagementTracker,
    PersonaManager,
    ResponseGenerator,
    SessionManager,
)
from ragin.hisoka.honeytokens import (
    HoneytokenAlert,
    HoneytokenConfig,
    HoneytokenEngine,
)
from ragin.hisoka.memory import HisokaMemory
from ragin.hisoka.models import (
    DeceptionResponse,
    DwellMetrics,
    Persona,
    SessionState,
)

__all__ = [
    "ArtifactInjector",
    "DeceptionResponse",
    "DwellMetrics",
    "EngagementTracker",
    "HisokaMemory",
    "HoneytokenAlert",
    "HoneytokenConfig",
    "HoneytokenEngine",
    "Persona",
    "PersonaManager",
    "ResponseGenerator",
    "SessionManager",
    "SessionState",
]
