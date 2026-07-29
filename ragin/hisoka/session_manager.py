"""Session management for Hisoka — in-memory with optional persistence hooks."""

from __future__ import annotations

import logging
from typing import Any

from ragin.hisoka.deception import SessionManager as _CoreSessionManager
from ragin.hisoka.memory import HisokaMemory
from ragin.hisoka.models import SessionState

logger = logging.getLogger(__name__)


class SessionManagerExtended:
    """Extended session manager with history tracking and optional Mem0 persistence.

    When a :class:`HisokaMemory` instance is provided, session create/update
    events are also persisted to Mem0, enabling cross-restart recovery.
    """

    def __init__(
        self,
        ttl_s: float | None = None,
        redis_url: str | None = None,
        memory: HisokaMemory | None = None,
    ) -> None:
        self._core = _CoreSessionManager(ttl_s=ttl_s)
        self._redis_url = redis_url
        self._histories: dict[str, list[dict[str, Any]]] = {}
        self._memory = memory

    def create_session(
        self,
        session_id: str | None = None,
        skill_level: str = "novice",
        source_ip: str = "",
    ) -> SessionState:
        """Create a new deception session."""
        session = self._core.create(source_ip=source_ip, skill_level=skill_level)
        if session_id:
            # Override auto-generated ID
            self._core._sessions.pop(session.session_id, None)
            session.session_id = session_id
            self._core._sessions[session_id] = session
        self._histories[session.session_id] = []

        # Persist session creation to Mem0
        if self._memory and source_ip:
            self._memory.add_interaction(
                attacker_ip=source_ip,
                session_id=session.session_id,
                attacker_input="[session started]",
                response=f"New session created with persona: {skill_level}",
                metadata={
                    "event": "session_start",
                    "skill_level": skill_level,
                },
            )

        return session

    def get_session(self, session_id: str) -> SessionState | None:
        """Retrieve a session by ID."""
        return self._core.get(session_id)

    def update_session(self, session_id: str, interaction: dict[str, Any]) -> None:
        """Record an interaction in the session."""
        self._core.update(session_id, {"command_count": (self._get_cmd_count(session_id) + 1)})
        self._histories.setdefault(session_id, []).append(interaction)

    def get_session_history(self, session_id: str) -> list[dict[str, Any]]:
        """Return the interaction history for a session."""
        return self._histories.get(session_id, [])

    def close_session(self, session_id: str) -> None:
        """Mark a session as closed."""
        session = self._core.get(session_id)
        if session:
            self._core.update(session_id, {"closed": True})

    def get_dwell_time(self, session_id: str) -> float:
        """Return elapsed seconds for the session."""
        return self._core.get_dwell_time(session_id)

    def _get_cmd_count(self, session_id: str) -> int:
        session = self._core.get(session_id)
        return session.command_count if session else 0
